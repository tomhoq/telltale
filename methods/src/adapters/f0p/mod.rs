//! `f0p`: passive TCP/IP stack fingerprinting from the SYN — p0f's approach
//! (TTL, window, MSS, option order), matched against the real p0f fingerprint
//! database (`methods/db/p0f.fp`, vendored unmodified — see `format.rs` and
//! `p0f.fp.LICENSE`). The name is `p0f` spelled backwards: same database,
//! our own (simplified) matcher rather than the p0f binary itself.
//!
//! One signature file, two sections. The SYN alone (`[tcp:request]`
//! signatures) is enough for an OS/stack guess and is all that's needed on a
//! bare port scan. When the session goes on to send an HTTP request, the
//! `[http:request]` signatures layer a client guess on top from header order
//! and the User-Agent — real p0f does the same thing, matching TCP and HTTP
//! characteristics out of one fingerprint file rather than treating them as
//! separate tools.
//!
//! What this does *not* attempt is a byte-exact reimplementation of p0f's own
//! matching engine — its quirk/ECN/sequence-number fuzziness rules are its
//! own C code, not reproduced here. What it does keep exact is the data: the
//! database is p0f's, unmodified, and every signature field this module
//! cannot yet check (see [`format::TcpSignature`]) is parsed and carried
//! through rather than silently discarded, so scoring can grow into it later.

mod format;

use std::net::IpAddr;
use std::path::Path;

use pf_core::{
    Confidence, Context, Evidence, Method, MethodManifest, Outcome, Result, TcpFeatures,
    TcpOptionKind, Transport,
};

use crate::db;
use format::{HttpHeaderExpectation, HttpSignature, P0fDb, PayloadClass, TcpSignature, WindowSpec};

/// Common initial TTLs real stacks send with. Used only as a fallback when no
/// signature matched at all — p0f's own database gives us the sender's
/// intended initial TTL directly once we do have a match, which is more
/// precise than guessing from this fixed list.
const COMMON_INITIAL_TTLS: [u8; 4] = [32, 64, 128, 255];

/// Hops between attacker and honeypot beyond this are treated as "this isn't
/// really the same initial TTL, just an unlucky low reading" rather than
/// trusted as a genuine distance.
const MAX_PLAUSIBLE_HOPS: u8 = 40;

fn nearest_initial_ttl(observed: u8) -> u8 {
    COMMON_INITIAL_TTLS
        .into_iter()
        .find(|&ttl| ttl >= observed)
        .unwrap_or(255)
}

fn score_tcp(observed: &TcpFeatures, payload_empty: bool, ip_version: u8, sig: &TcpSignature) -> f64 {
    let mut checks = 0.0_f64;
    let mut matches = 0.0_f64;

    if let Some(expected) = sig.ip_version {
        checks += 1.0;
        matches += (ip_version == expected) as u8 as f64;
    }

    checks += 1.0;
    let ttl_ok = if sig.ittl_is_ceiling {
        observed.ttl <= sig.initial_ttl
    } else {
        observed.ttl <= sig.initial_ttl && sig.initial_ttl - observed.ttl <= MAX_PLAUSIBLE_HOPS
    };
    matches += ttl_ok as u8 as f64;

    if let Some(mss) = sig.mss {
        checks += 1.0;
        matches += (observed.mss == Some(mss)) as u8 as f64;
    }

    match sig.window {
        WindowSpec::Any => {}
        WindowSpec::Fixed(window) => {
            checks += 1.0;
            matches += (observed.window == window) as u8 as f64;
        }
        WindowSpec::MssMultiple(n) => {
            checks += 1.0;
            let expected = observed.mss.map(|mss| mss as u32 * n);
            matches += (expected == Some(observed.window as u32)) as u8 as f64;
        }
        WindowSpec::Modulo(n) if n > 0 => {
            checks += 1.0;
            matches += (observed.window as u32 % n == 0) as u8 as f64;
        }
        WindowSpec::Modulo(_) => {}
        // Needs the `[mtu]` module's own guessing, which this parser does not
        // implement — not counted for or against a match.
        WindowSpec::MtuMultiple(_) => {}
    }

    // Real signatures carry a literal `scale` even when their `olayout` has
    // no `ws` option (the Linux 2.0 entry in the vendored db is one:
    // `mss::0` — no window-scaling option at all, yet a trailing `0`). That
    // placeholder isn't a claim about an observed scale, so only check it
    // when the layout actually declares a `ws` option.
    if sig.option_layout.contains(&TcpOptionKind::WindowScale) {
        if let Some(scale) = sig.window_scale {
            checks += 1.0;
            matches += (observed.window_scale == Some(scale)) as u8 as f64;
        }
    }

    // Always checked, including an empty layout: "no options at all" is
    // itself a real, diagnostic signature (several old or minimal stacks use
    // it), not a wildcard.
    checks += 1.0;
    matches += (observed.option_order == sig.option_layout) as u8 as f64;

    // Only `df` is currently observed among p0f's quirks — see
    // `TcpSignature::quirks`.
    if sig.quirks.iter().any(|q| q == "df") {
        checks += 1.0;
        matches += observed.df as u8 as f64;
    }

    match sig.payload_class {
        PayloadClass::Zero => {
            checks += 1.0;
            matches += payload_empty as u8 as f64;
        }
        PayloadClass::NonZero => {
            checks += 1.0;
            matches += (!payload_empty) as u8 as f64;
        }
        PayloadClass::Any => {}
    }

    matches / checks
}

/// Best match, preferring a specific (`s`) signature over a generic (`g`)
/// one even when a generic one scores higher — p0f's own README: "generic
/// signatures are considered only if no specific matches are found".
fn best_tcp_match<'a>(
    signatures: &'a [TcpSignature],
    observed: &TcpFeatures,
    payload_empty: bool,
    ip_version: u8,
    min_score: f64,
) -> Option<(&'a TcpSignature, f64)> {
    let mut specific_best: Option<(&TcpSignature, f64)> = None;
    let mut generic_best: Option<(&TcpSignature, f64)> = None;

    for sig in signatures {
        let score = score_tcp(observed, payload_empty, ip_version, sig);
        if score < min_score {
            continue;
        }
        let slot = if sig.specific {
            &mut specific_best
        } else {
            &mut generic_best
        };
        let better = match slot {
            Some((_, best)) => score > *best,
            None => true,
        };
        if better {
            *slot = Some((sig, score));
        }
    }

    specific_best.or(generic_best)
}

const HTTP_METHODS: [&str; 8] = [
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "CONNECT", "PATCH",
];

/// The little of an HTTP/1.x request `f0p` needs, in the shape p0f's own
/// `[http:request]` signatures match against.
struct ObservedHttpRequest {
    minor_version: Option<u8>,
    /// Lower-cased name, raw value, in wire order.
    headers: Vec<(String, String)>,
}

impl ObservedHttpRequest {
    /// `None` for anything that is not a request line followed by
    /// `Name: value` headers — including a TLS ClientHello, a raw TCP
    /// payload, or the honeypot's own HTTP response on the wrong direction.
    fn parse(payload: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(payload).ok()?;
        let normalized = text.replace("\r\n", "\n");
        let mut lines = normalized.split('\n');

        let request_line = lines.next()?;
        let mut parts = request_line.split(' ');
        let method = parts.next()?;
        if !HTTP_METHODS.contains(&method) {
            return None;
        }
        let _target = parts.next();
        let minor_version = parts
            .next()
            .and_then(|v| v.strip_prefix("HTTP/1."))
            .and_then(|v| v.trim().parse().ok());

        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }

        Some(ObservedHttpRequest {
            minor_version,
            headers,
        })
    }

    fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// p0f's README: "matched even if other headers appear in between, as long
/// as the list itself is matched in the specified sequence" — a subsequence
/// match, not a prefix one. An optional (`?`) header may be missing entirely
/// without failing the match; a required one that never appears fails it.
fn header_order_matches(observed: &ObservedHttpRequest, expected: &[HttpHeaderExpectation]) -> bool {
    let mut cursor = 0usize;
    for header in expected {
        let Some(offset) = observed.headers[cursor..]
            .iter()
            .position(|(name, _)| *name == header.name)
        else {
            if header.optional {
                continue;
            }
            return false;
        };
        let index = cursor + offset;
        if let Some(needle) = &header.value_contains {
            let (_, value) = &observed.headers[index];
            if !value.to_ascii_lowercase().contains(&needle.to_ascii_lowercase()) {
                return false;
            }
        }
        cursor = index + 1;
    }
    true
}

fn score_http(observed: &ObservedHttpRequest, sig: &HttpSignature) -> f64 {
    let mut checks = 0.0_f64;
    let mut matches = 0.0_f64;

    if let Some(expected) = sig.http_minor_version {
        checks += 1.0;
        matches += (observed.minor_version == Some(expected)) as u8 as f64;
    }

    checks += 1.0;
    matches += header_order_matches(observed, &sig.header_order) as u8 as f64;

    if !sig.header_absent.is_empty() {
        checks += 1.0;
        let clean = sig
            .header_absent
            .iter()
            .all(|absent| observed.header_value(absent).is_none());
        matches += clean as u8 as f64;
    }

    if let Some(expected) = &sig.expected_software {
        checks += 1.0;
        let user_agent = observed.header_value("user-agent").unwrap_or("");
        matches += user_agent
            .to_ascii_lowercase()
            .contains(&expected.to_ascii_lowercase()) as u8 as f64;
    }

    matches / checks
}

fn best_http_match<'a>(
    signatures: &'a [HttpSignature],
    observed: &ObservedHttpRequest,
    min_score: f64,
) -> Option<(&'a HttpSignature, f64)> {
    signatures
        .iter()
        .map(|sig| (sig, score_http(observed, sig)))
        .filter(|(_, score)| *score >= min_score)
        .max_by(|a, b| a.1.total_cmp(&b.1))
}

fn confidence_for(score: f64) -> Confidence {
    if score >= 0.95 {
        Confidence::Strong
    } else if score >= 0.85 {
        Confidence::Likely
    } else {
        Confidence::Weak
    }
}

pub struct F0p {
    manifest: MethodManifest,
    db: P0fDb,
    min_score: f64,
}

pub fn build(manifest: MethodManifest, manifest_dir: &Path) -> Result<Box<dyn Method>> {
    let min_score = manifest.param("min-score", 0.8);
    let db = manifest
        .database
        .as_ref()
        .map(|spec| db::load::<P0fDb>(&manifest.name, spec, manifest_dir))
        .transpose()?
        .unwrap_or_default();

    Ok(Box::new(F0p {
        manifest,
        db,
        min_score,
    }))
}

impl Method for F0p {
    fn manifest(&self) -> &MethodManifest {
        &self.manifest
    }

    fn extract(&self, ctx: &Context<'_>) -> Result<Outcome> {
        if ctx.session.key.transport != Transport::Tcp {
            return Ok(Outcome::NotApplicable);
        }

        // The SYN — always the first observation under the direction policy,
        // since it is what opened the session — carries everything the
        // `[tcp:request]` signatures match on. A source with no header-level
        // detail (a honeypot log, say) leaves `tcp` unset rather than
        // inventing one.
        let Some((syn, payload_empty)) = ctx
            .observations()
            .find_map(|o| o.tcp.as_ref().map(|tcp| (tcp, o.payload.is_empty())))
        else {
            return Ok(Outcome::NotApplicable);
        };

        let ip_version: u8 = match ctx.session.initiator.addr {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 6,
        };

        let best_tcp = best_tcp_match(
            &self.db.tcp_request,
            syn,
            payload_empty,
            ip_version,
            self.min_score,
        );

        let mut evidence = Vec::new();

        // The hop-count estimate needs no signature match at all — it falls
        // out of the observed TTL either way. A match gives the sender's
        // actual intended initial TTL, which is more precise than the
        // fallback guess at the nearest common value.
        let initial_ttl = best_tcp
            .map(|(sig, _)| sig.initial_ttl)
            .unwrap_or_else(|| nearest_initial_ttl(syn.ttl));
        evidence.push(Evidence::new(
            self.name(),
            ctx.session.initiator,
            "distance",
            initial_ttl.saturating_sub(syn.ttl).to_string(),
            Confidence::Weak,
        ));

        if let Some((sig, score)) = best_tcp {
            // `class == "!"` is p0f's own convention for a tool/application
            // signature rather than an OS one (NMap's raw-socket SYN
            // signatures live in `[tcp:request]` right alongside the OS
            // ones) — see p0f's README on the `label` line's `class` field.
            let key = if sig.class == "!" { "stack" } else { "os" };
            evidence.push(Evidence::new(
                self.name(),
                ctx.session.initiator,
                key,
                sig.label.clone(),
                confidence_for(score),
            ));
        }

        // Opportunistic: only present once the session has gone past the
        // SYN. `every-observation` is what gives this a second look each
        // time the session grows, so a request arriving later than the SYN
        // still gets picked up.
        if let Some(request) = ctx
            .observations()
            .find_map(|o| ObservedHttpRequest::parse(&o.payload))
        {
            if let Some((sig, score)) = best_http_match(&self.db.http_request, &request, self.min_score)
            {
                evidence.push(Evidence::new(
                    self.name(),
                    ctx.session.initiator,
                    "client",
                    sig.label.clone(),
                    confidence_for(score),
                ));
            }
        }

        Ok(if ctx.is_final {
            Outcome::Complete(evidence)
        } else {
            Outcome::Partial(evidence)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux_syn() -> TcpFeatures {
        TcpFeatures {
            ttl: 64,
            df: true,
            window: 1460 * 20,
            mss: Some(1460),
            window_scale: Some(7),
            sack_permitted: true,
            timestamp: true,
            option_order: vec![
                TcpOptionKind::Mss,
                TcpOptionKind::SackPermitted,
                TcpOptionKind::Timestamp,
                TcpOptionKind::Nop,
                TcpOptionKind::WindowScale,
            ],
        }
    }

    fn linux_signature() -> TcpSignature {
        format::parse(
            "[tcp:request]\n\
             label = s:unix:Linux:3.11 and newer\n\
             sig   = *:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0\n",
        )
        .tcp_request
        .remove(0)
    }

    #[test]
    fn a_full_match_against_the_real_grammar_scores_one() {
        assert_eq!(score_tcp(&linux_syn(), true, 4, &linux_signature()), 1.0);
    }

    #[test]
    fn a_hop_away_still_matches_via_the_signatures_own_initial_ttl() {
        let mut observed = linux_syn();
        observed.ttl = 59; // 5 hops between attacker and honeypot
        assert_eq!(score_tcp(&observed, true, 4, &linux_signature()), 1.0);
    }

    #[test]
    fn a_windows_ttl_does_not_match_a_linux_signature() {
        let mut observed = linux_syn();
        observed.ttl = 128;
        assert!(score_tcp(&observed, true, 4, &linux_signature()) < 1.0);
    }

    #[test]
    fn an_empty_option_layout_is_a_real_check_not_a_wildcard() {
        let sig = format::parse(
            "[tcp:request]\n\
             label = s:!:masscan:bare SYN\n\
             sig   = *:64:0:1460:1024,0:::0\n",
        )
        .tcp_request
        .remove(0);
        let mut observed = linux_syn();
        observed.option_order = vec![];
        observed.window = 1024;
        observed.mss = Some(1460);
        assert_eq!(score_tcp(&observed, true, 4, &sig), 1.0);

        let mut with_options = observed.clone();
        with_options.option_order = vec![TcpOptionKind::Mss];
        assert!(score_tcp(&with_options, true, 4, &sig) < 1.0);
    }

    #[test]
    fn http_request_parsing_extracts_headers_in_wire_order() {
        let payload =
            b"GET / HTTP/1.1\r\nHost: honeypot\r\nUser-Agent: curl/8.4.0\r\nAccept: */*\r\n\r\n";
        let request = ObservedHttpRequest::parse(payload).expect("a GET should parse");
        assert_eq!(request.minor_version, Some(1));
        assert_eq!(request.header_value("user-agent"), Some("curl/8.4.0"));
        assert_eq!(
            request.headers.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            vec!["host", "user-agent", "accept"]
        );
    }

    #[test]
    fn non_http_payload_does_not_parse() {
        assert!(ObservedHttpRequest::parse(b"\x16\x03\x01\x00\xa5").is_none());
    }

    #[test]
    fn curl_matches_its_real_signature() {
        let db = format::parse(
            "[http:request]\n\
             label = s:!:curl:\n\
             sig   = 1:User-Agent,Host,Accept=[*/*]:Connection,Accept-Encoding,Accept-Language,Accept-Charset:curl/\n",
        );
        let request = ObservedHttpRequest::parse(
            b"GET / HTTP/1.1\r\nUser-Agent: curl/8.4.0\r\nHost: honeypot\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        let (sig, score) = best_http_match(&db.http_request, &request, 0.8).expect("curl should match");
        assert_eq!(sig.label, "curl");
        assert_eq!(score, 1.0);
    }

    #[test]
    fn a_required_header_out_of_order_fails_the_match() {
        let db = format::parse(
            "[http:request]\n\
             label = s:!:curl:\n\
             sig   = 1:User-Agent,Host,Accept=[*/*]::curl/\n",
        );
        // Host before User-Agent: wrong order for this signature.
        let request = ObservedHttpRequest::parse(
            b"GET / HTTP/1.1\r\nHost: honeypot\r\nUser-Agent: curl/8.4.0\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        assert!(!header_order_matches(&request, &db.http_request[0].header_order));
    }

    /// Guards against ever hand-editing the vendored database: it should
    /// parse into a large, real signature set, not something suspiciously
    /// small or suspiciously round.
    #[test]
    fn the_vendored_p0f_database_parses_into_real_signatures() {
        let text = include_str!("../../../db/p0f.fp");
        let db = format::parse(text);
        assert!(
            db.tcp_request.len() > 50,
            "expected a real p0f TCP signature set, got {}",
            db.tcp_request.len()
        );
        assert!(
            db.http_request.len() > 20,
            "expected a real p0f HTTP signature set, got {}",
            db.http_request.len()
        );
        assert!(db.tcp_request.iter().any(|s| s.label.starts_with("Linux")));
        assert!(db.tcp_request.iter().any(|s| s.class == "!" && s.label.starts_with("NMap")));
        assert!(db.http_request.iter().any(|s| s.label == "curl"));
    }
}
