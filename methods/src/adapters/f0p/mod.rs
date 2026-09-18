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

/// Share of the checked fields that agree, every field counting the same.
/// Not a match test — [`fit_tcp`] is — only a measure of how close a
/// signature came, for reporting the nearest one when nothing matched.
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

    if !matches!(sig.window, WindowSpec::Any | WindowSpec::Modulo(0)) {
        checks += 1.0;
        matches += window_fits(observed, ip_version, sig.window) as u8 as f64;
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
    // it), not a wildcard. The padding after an EOL is part of the layout:
    // `eol+1` and `eol+3` are different stacks.
    checks += 1.0;
    let layout_ok =
        observed.option_order == sig.option_layout && observed.eol_padding == sig.eol_padding;
    matches += layout_ok as u8 as f64;

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

/// The observed SYN written the way p0f prints its own `raw_sig`
/// (`ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass`), so it can be
/// compared field by field with p0f's output and with database entries.
///
/// Not byte-identical to p0f everywhere, because `TcpFeatures` does not carry
/// everything p0f looks at: IP option length is not observed and prints `?`,
/// and `df` is the only quirk captured, so p0f's `id+`, `ecn`, `ts1-`, ...
/// never appear. The TTL is shown as p0f does, `<initial guess>+<distance>`,
/// and so is a window that is a whole number of segments, `mss*<n>`.
fn raw_signature(observed: &TcpFeatures, payload_empty: bool, ip_version: u8) -> String {
    let initial = nearest_initial_ttl(observed.ttl);
    let mss = observed.mss.map_or("*".to_string(), |mss| mss.to_string());
    let window = match observed.mss {
        Some(mss) if mss > 0 && observed.window % mss == 0 => {
            format!("mss*{}", observed.window / mss)
        }
        _ => observed.window.to_string(),
    };
    let quirks = if observed.df { "df" } else { "" };
    let pclass = if payload_empty { "0" } else { "+" };
    format!(
        "{ip_version}:{initial}+{}:?:{mss}:{window},{}:{}:{quirks}:{pclass}",
        initial - observed.ttl,
        observed.window_scale.unwrap_or(0),
        option_layout_text(&observed.option_order, observed.eol_padding),
    )
}

/// p0f's `olayout` syntax, where the EOL option carries its padding count:
/// `eol+<bytes>`.
fn option_layout_text(options: &[TcpOptionKind], eol_padding: Option<u8>) -> String {
    let mut tokens = Vec::new();
    for option in options {
        let token = match option {
            TcpOptionKind::Eol => format!("eol+{}", eol_padding.unwrap_or(0)),
            TcpOptionKind::Nop => "nop".to_string(),
            TcpOptionKind::Mss => "mss".to_string(),
            TcpOptionKind::WindowScale => "ws".to_string(),
            TcpOptionKind::SackPermitted => "sok".to_string(),
            TcpOptionKind::Sack => "sack".to_string(),
            TcpOptionKind::Timestamp => "ts".to_string(),
            TcpOptionKind::Other(kind) => format!("?{kind}"),
        };
        tokens.push(token);
    }
    tokens.join(",")
}

/// Whether the observed window satisfies a signature's `wsize`.
fn window_fits(observed: &TcpFeatures, ip_version: u8, spec: WindowSpec) -> bool {
    let window = observed.window as u32;
    match spec {
        WindowSpec::Any => true,
        WindowSpec::Fixed(expected) => observed.window == expected,
        WindowSpec::MssMultiple(n) => observed.mss.is_some_and(|mss| mss as u32 * n == window),
        // The MTU p0f means here is the one implied by the MSS: MSS plus the
        // minimal IP and TCP headers.
        WindowSpec::MtuMultiple(n) => {
            let headers = if ip_version == 6 { 60 } else { 40 };
            observed
                .mss
                .is_some_and(|mss| (mss as u32 + headers) * n == window)
        }
        WindowSpec::Modulo(0) => true,
        WindowSpec::Modulo(n) => window % n == 0,
    }
}

/// How one observed SYN stands against one signature, in p0f's terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fit {
    /// A field that identifies the stack differs: not this signature.
    Mismatch,
    /// Every checked field agrees.
    Exact,
    /// Everything identifying agrees, but TTL is out of range or an expected
    /// DF is missing — p0f's "fuzzy" match: the same stack, seen through
    /// something that rewrote a header on the way.
    Fuzzy,
}

/// p0f's matching rules for one `[tcp:request]` signature. The window, MSS,
/// scale, option layout and payload class identify a stack and must agree;
/// only TTL and a missing DF are forgiven, and then only as a fuzzy match.
/// Fields `TcpFeatures` does not carry (IP option length, quirks other than
/// DF) are not checked at all.
fn fit_tcp(observed: &TcpFeatures, payload_empty: bool, ip_version: u8, sig: &TcpSignature) -> Fit {
    if sig.ip_version.is_some_and(|expected| expected != ip_version) {
        return Fit::Mismatch;
    }
    if sig.mss.is_some_and(|expected| observed.mss != Some(expected)) {
        return Fit::Mismatch;
    }
    if !window_fits(observed, ip_version, sig.window) {
        return Fit::Mismatch;
    }
    // See `score_tcp` on why the scale only counts when the layout has `ws`.
    if sig.option_layout.contains(&TcpOptionKind::WindowScale)
        && sig
            .window_scale
            .is_some_and(|expected| observed.window_scale != Some(expected))
    {
        return Fit::Mismatch;
    }
    if observed.option_order != sig.option_layout || observed.eol_padding != sig.eol_padding {
        return Fit::Mismatch;
    }
    let payload_ok = match sig.payload_class {
        PayloadClass::Zero => payload_empty,
        PayloadClass::NonZero => !payload_empty,
        PayloadClass::Any => true,
    };
    if !payload_ok {
        return Fit::Mismatch;
    }

    // DF: p0f forgives the bit disappearing (a middlebox can clear it) but not
    // appearing where the signature has none. IPv6 has no DF bit at all —
    // `TcpFeatures` reports it as set there — so it is not compared.
    let sig_df = sig.quirks.iter().any(|q| q == "df");
    let df_ok = ip_version == 6 || observed.df == sig_df;
    if ip_version != 6 && observed.df && !sig_df {
        return Fit::Mismatch;
    }

    // TTL: a ceiling (`64-`) is a hard limit, since the tool randomizes below
    // it; a normal initial TTL out of range only makes the match fuzzy.
    if sig.ittl_is_ceiling && observed.ttl > sig.initial_ttl {
        return Fit::Mismatch;
    }
    let ttl_ok = sig.ittl_is_ceiling
        || (observed.ttl <= sig.initial_ttl
            && sig.initial_ttl - observed.ttl <= MAX_PLAUSIBLE_HOPS);

    if ttl_ok && df_ok {
        Fit::Exact
    } else {
        Fit::Fuzzy
    }
}

/// p0f's own precedence: the first exact specific signature; failing that,
/// the first exact generic one ("generic signatures are considered only if no
/// specific matches are found"); failing that, the first fuzzy one. File order
/// breaks ties, as in p0f.
fn best_tcp_match<'a>(
    signatures: &'a [TcpSignature],
    observed: &TcpFeatures,
    payload_empty: bool,
    ip_version: u8,
) -> Option<(&'a TcpSignature, Fit)> {
    let mut generic = None;
    let mut fuzzy = None;
    for sig in signatures {
        match fit_tcp(observed, payload_empty, ip_version, sig) {
            Fit::Exact if sig.specific => return Some((sig, Fit::Exact)),
            Fit::Exact => {
                generic.get_or_insert(sig);
            }
            Fit::Fuzzy => {
                fuzzy.get_or_insert(sig);
            }
            Fit::Mismatch => {}
        }
    }
    generic
        .map(|sig| (sig, Fit::Exact))
        .or(fuzzy.map(|sig| (sig, Fit::Fuzzy)))
}

fn tcp_confidence(sig: &TcpSignature, fit: Fit) -> Confidence {
    match fit {
        Fit::Exact if sig.specific => Confidence::Strong,
        Fit::Exact => Confidence::Likely,
        _ => Confidence::Weak,
    }
}

/// The signature sharing the most fields with the SYN, regardless of which
/// ones — for showing what the matcher came closest to when nothing matched.
/// The first in file order wins a tie.
fn nearest_tcp_signature<'a>(
    signatures: &'a [TcpSignature],
    observed: &TcpFeatures,
    payload_empty: bool,
    ip_version: u8,
) -> Option<(&'a TcpSignature, f64)> {
    let mut nearest: Option<(&TcpSignature, f64)> = None;
    for sig in signatures {
        let score = score_tcp(observed, payload_empty, ip_version, sig);
        if nearest.is_none_or(|(_, best)| score > best) {
            nearest = Some((sig, score));
        }
    }
    nearest
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

/// p0f's matching rules for one `[http:request]` signature: HTTP version,
/// header order and absent headers all have to agree. The User-Agent is not
/// part of the match — see [`software_agrees`].
fn http_fits(observed: &ObservedHttpRequest, sig: &HttpSignature) -> bool {
    sig.http_minor_version
        .is_none_or(|expected| observed.minor_version == Some(expected))
        && header_order_matches(observed, &sig.header_order)
        && sig
            .header_absent
            .iter()
            .all(|absent| observed.header_value(absent).is_none())
}

/// Whether the User-Agent claims the software the headers look like. p0f does
/// not reject a match over this; it flags the client as dishonest — a tool
/// that sets a browser's User-Agent but not its header order, say.
fn software_agrees(observed: &ObservedHttpRequest, sig: &HttpSignature) -> bool {
    let Some(expected) = &sig.expected_software else {
        return true;
    };
    observed
        .header_value("user-agent")
        .unwrap_or("")
        .to_ascii_lowercase()
        .contains(&expected.to_ascii_lowercase())
}

/// Same precedence as the TCP side: the first specific signature that fits,
/// else the first generic one.
fn best_http_match<'a>(
    signatures: &'a [HttpSignature],
    observed: &ObservedHttpRequest,
) -> Option<&'a HttpSignature> {
    let mut generic = None;
    for sig in signatures.iter().filter(|sig| http_fits(observed, sig)) {
        if sig.specific {
            return Some(sig);
        }
        generic.get_or_insert(sig);
    }
    generic
}

fn http_confidence(observed: &ObservedHttpRequest, sig: &HttpSignature) -> Confidence {
    match (sig.specific, software_agrees(observed, sig)) {
        (_, false) => Confidence::Weak,
        (true, true) => Confidence::Strong,
        (false, true) => Confidence::Likely,
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

        let best_tcp = best_tcp_match(&self.db.tcp_request, syn, payload_empty, ip_version);

        let mut evidence = Vec::new();

        // The fingerprint itself, in p0f's own notation, so a result can be
        // checked against p0f's output or the database by eye.
        let observed_sig = raw_signature(syn, payload_empty, ip_version);
        match best_tcp {
            Some((sig, fit)) => tracing::debug!(
                subject = ?ctx.session.initiator,
                observed = %observed_sig,
                matched = %sig.label,
                matched_sig = %sig.raw,
                ?fit,
                "f0p tcp match"
            ),
            None => {
                let nearest = nearest_tcp_signature(&self.db.tcp_request, syn, payload_empty, ip_version);
                tracing::debug!(
                    subject = ?ctx.session.initiator,
                    observed = %observed_sig,
                    nearest = nearest.map(|(sig, _)| sig.label.as_str()),
                    nearest_sig = nearest.map(|(sig, _)| sig.raw.as_str()),
                    nearest_score = nearest.map(|(_, score)| score),
                    "f0p tcp: no signature matches"
                );
                // Visible, but under its own key and never above Weak, so a
                // near miss cannot be read as a classification.
                if let Some((sig, _)) = nearest.filter(|(_, score)| *score >= self.min_score) {
                    evidence.push(Evidence::new(
                        self.name(),
                        ctx.session.initiator,
                        "nearest",
                        sig.label.clone(),
                        Confidence::Weak,
                    ));
                }
            }
        }
        evidence.push(Evidence::new(
            self.name(),
            ctx.session.initiator,
            "signature",
            observed_sig,
            Confidence::Weak,
        ));

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

        if let Some((sig, fit)) = best_tcp {
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
                tcp_confidence(sig, fit),
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
            if let Some(sig) = best_http_match(&self.db.http_request, &request) {
                evidence.push(Evidence::new(
                    self.name(),
                    ctx.session.initiator,
                    "client",
                    sig.label.clone(),
                    http_confidence(&request, sig),
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
            eol_padding: None,
        }
    }

    /// A real iPhone SYN, captured live:
    /// `4:64+0:?:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0`.
    fn iphone_syn() -> TcpFeatures {
        use TcpOptionKind::*;
        TcpFeatures {
            ttl: 64,
            df: true,
            window: 65535,
            mss: Some(1460),
            window_scale: Some(6),
            sack_permitted: true,
            timestamp: true,
            option_order: vec![Mss, Nop, WindowScale, Nop, Nop, Timestamp, SackPermitted, Eol],
            eol_padding: Some(1),
        }
    }

    fn vendored_db() -> P0fDb {
        format::parse(include_str!("../../../db/p0f.fp"))
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
    fn the_observed_syn_renders_in_p0f_raw_sig_notation() {
        let mut observed = linux_syn();
        observed.ttl = 61;
        assert_eq!(
            raw_signature(&observed, true, 4),
            "4:64+3:?:1460:mss*20,7:mss,sok,ts,nop,ws:df:0"
        );
    }

    #[test]
    fn eol_padding_renders_as_a_byte_count() {
        assert_eq!(
            raw_signature(&iphone_syn(), true, 4),
            "4:64+0:?:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0"
        );
    }

    /// The bug this guards: the observed layout ended `eol,eol` while the
    /// database's `eol+1` parsed to a single `eol`, so no Apple signature
    /// could ever pass the layout check.
    #[test]
    fn an_apple_syn_passes_the_layout_check_of_the_apple_signatures() {
        let db = vendored_db();
        let generic_mac = db
            .tcp_request
            .iter()
            .find(|sig| !sig.specific && sig.label.starts_with("Mac OS X"))
            .expect("the vendored db has a generic Mac OS X entry");
        assert_eq!(score_tcp(&iphone_syn(), true, 4, generic_mac), 1.0);
    }

    /// The signature p0f's database has for exactly this SYN is the generic
    /// Mac OS X one — every specific Apple entry lists a window scale of 1-4,
    /// and this phone sends 6. An exact generic match beats any near miss.
    #[test]
    fn an_iphone_matches_the_generic_mac_signature_exactly() {
        let db = vendored_db();
        let (sig, fit) = best_tcp_match(&db.tcp_request, &iphone_syn(), true, 4)
            .expect("the generic Mac OS X signature should match");
        assert_eq!(sig.label, "Mac OS X");
        assert!(!sig.specific);
        assert_eq!(fit, Fit::Exact);
        assert_eq!(tcp_confidence(sig, fit), Confidence::Likely);
    }

    /// FreeBSD 9 agrees on everything but the option layout, which is what
    /// the old share-of-fields scoring let through.
    #[test]
    fn a_different_option_layout_is_never_a_match() {
        let db = vendored_db();
        let freebsd = db
            .tcp_request
            .iter()
            .find(|sig| sig.label == "FreeBSD 9.x or newer")
            .unwrap();
        assert_eq!(fit_tcp(&iphone_syn(), true, 4, freebsd), Fit::Mismatch);
    }

    /// A current Linux SYN (MSS 1460, window `mss*44`, scale 7). p0f's
    /// specific entries stop at Linux 3.11's `mss*20`; what catches it is the
    /// generic Linux entry, whose window and scale are wildcards — the same
    /// answer real p0f gives.
    #[test]
    fn a_modern_linux_syn_falls_back_to_the_generic_linux_signature() {
        let mut modern_linux = linux_syn();
        modern_linux.window = 1460 * 44;
        let db = vendored_db();
        let (sig, fit) = best_tcp_match(&db.tcp_request, &modern_linux, true, 4).unwrap();
        assert_eq!(sig.label, "Linux 2.2.x-3.x");
        assert!(!sig.specific);
        assert_eq!(fit, Fit::Exact);
    }

    /// Linux's options with one NOP too many: no signature has that layout,
    /// so nothing matches, and the Linux entries are only the nearest.
    #[test]
    fn a_layout_nobody_sends_matches_nothing_but_has_a_nearest() {
        use TcpOptionKind::*;
        let mut odd = linux_syn();
        odd.option_order = vec![Mss, SackPermitted, Timestamp, Nop, WindowScale, Nop];
        let db = vendored_db();
        assert!(best_tcp_match(&db.tcp_request, &odd, true, 4).is_none());
        let (nearest, score) = nearest_tcp_signature(&db.tcp_request, &odd, true, 4).unwrap();
        assert!(nearest.label.starts_with("Linux"), "nearest was {}", nearest.label);
        assert!(score < 1.0);
    }

    #[test]
    fn a_window_that_is_a_whole_number_of_segments_renders_as_mss_multiple() {
        let mut observed = linux_syn();
        observed.mss = Some(1440);
        observed.window = 1440 * 45;
        assert!(raw_signature(&observed, true, 4).contains(":1440:mss*45,7:"));
    }

    #[test]
    fn a_different_padding_length_is_a_different_layout() {
        let db = vendored_db();
        let generic_mac = db
            .tcp_request
            .iter()
            .find(|sig| !sig.specific && sig.label.starts_with("Mac OS X"))
            .unwrap();
        let mut observed = iphone_syn();
        observed.eol_padding = Some(3);
        assert_eq!(fit_tcp(&observed, true, 4, generic_mac), Fit::Mismatch);
    }

    #[test]
    fn a_full_match_against_the_real_grammar_is_exact() {
        assert_eq!(fit_tcp(&linux_syn(), true, 4, &linux_signature()), Fit::Exact);
        assert_eq!(score_tcp(&linux_syn(), true, 4, &linux_signature()), 1.0);
    }

    #[test]
    fn a_hop_away_still_matches_via_the_signatures_own_initial_ttl() {
        let mut observed = linux_syn();
        observed.ttl = 59; // 5 hops between attacker and honeypot
        assert_eq!(fit_tcp(&observed, true, 4, &linux_signature()), Fit::Exact);
    }

    /// TTL alone does not rule a stack out in p0f — something on the path can
    /// rewrite it — it only makes the match fuzzy.
    #[test]
    fn a_ttl_out_of_range_makes_the_match_fuzzy() {
        let mut observed = linux_syn();
        observed.ttl = 128;
        assert_eq!(fit_tcp(&observed, true, 4, &linux_signature()), Fit::Fuzzy);
    }

    /// A ceiling (`64-`) is different: the tool randomizes under it, so a TTL
    /// above it is a different tool.
    #[test]
    fn a_ttl_above_a_ceiling_is_a_mismatch() {
        let sig = format::parse(
            "[tcp:request]\n\
             label = s:!:NMap:SYN scan\n\
             sig   = *:64-:0:1460:1024,0:mss::0\n",
        )
        .tcp_request
        .remove(0);
        let mut observed = linux_syn();
        observed.window = 1024;
        observed.df = false;
        observed.option_order = vec![TcpOptionKind::Mss];
        observed.ttl = 41;
        assert_eq!(fit_tcp(&observed, true, 4, &sig), Fit::Exact);
        observed.ttl = 65;
        assert_eq!(fit_tcp(&observed, true, 4, &sig), Fit::Mismatch);
    }

    #[test]
    fn df_disappearing_is_fuzzy_but_appearing_is_a_mismatch() {
        let mut no_df = linux_syn();
        no_df.df = false;
        assert_eq!(fit_tcp(&no_df, true, 4, &linux_signature()), Fit::Fuzzy);

        let sig_without_df = format::parse(
            "[tcp:request]\n\
             label = s:unix:Linux:3.11 and newer\n\
             sig   = *:64:0:*:mss*20,7:mss,sok,ts,nop,ws:id+:0\n",
        )
        .tcp_request
        .remove(0);
        assert_eq!(fit_tcp(&linux_syn(), true, 4, &sig_without_df), Fit::Mismatch);
    }

    /// IPv6 has no DF bit, so it neither helps nor hurts there.
    #[test]
    fn df_is_not_compared_on_ipv6() {
        let mut observed = linux_syn();
        observed.df = false;
        assert_eq!(fit_tcp(&observed, true, 6, &linux_signature()), Fit::Exact);
    }

    #[test]
    fn an_mtu_multiple_window_is_checked_against_the_mss_implied_mtu() {
        let sig = format::parse(
            "[tcp:request]\n\
             label = s:unix:Test:mtu\n\
             sig   = *:64:0:*:mtu*4,7:mss,sok,ts,nop,ws:df:0\n",
        )
        .tcp_request
        .remove(0);
        let mut observed = linux_syn();
        observed.window = 1500 * 4; // MSS 1460 + 40 bytes of IPv4/TCP headers
        assert_eq!(fit_tcp(&observed, true, 4, &sig), Fit::Exact);
        observed.window = 1460 * 4;
        assert_eq!(fit_tcp(&observed, true, 4, &sig), Fit::Mismatch);
    }

    #[test]
    fn an_exact_generic_match_beats_a_fuzzy_specific_one() {
        let db = format::parse(
            "[tcp:request]\n\
             label = s:unix:Specific:but TTL is off\n\
             sig   = *:128:0:*:mss*20,7:mss,sok,ts,nop,ws:df:0\n\
             label = g:unix:Generic:\n\
             sig   = *:64:0:*:mss*20,*:mss,sok,ts,nop,ws:df:0\n",
        );
        let (sig, fit) = best_tcp_match(&db.tcp_request, &linux_syn(), true, 4).unwrap();
        assert_eq!(sig.label, "Generic");
        assert_eq!(fit, Fit::Exact);
    }

    #[test]
    fn an_exact_specific_match_beats_an_exact_generic_one() {
        let db = format::parse(
            "[tcp:request]\n\
             label = g:unix:Generic:\n\
             sig   = *:64:0:*:mss*20,*:mss,sok,ts,nop,ws:df:0\n\
             label = s:unix:Specific:\n\
             sig   = *:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df:0\n",
        );
        let (sig, fit) = best_tcp_match(&db.tcp_request, &linux_syn(), true, 4).unwrap();
        assert_eq!(sig.label, "Specific");
        assert_eq!(tcp_confidence(sig, fit), Confidence::Strong);
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
        observed.df = false;
        assert_eq!(fit_tcp(&observed, true, 4, &sig), Fit::Exact);

        let mut with_options = observed.clone();
        with_options.option_order = vec![TcpOptionKind::Mss];
        assert_eq!(fit_tcp(&with_options, true, 4, &sig), Fit::Mismatch);
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
        let sig = best_http_match(&db.http_request, &request).expect("curl should match");
        assert_eq!(sig.label, "curl");
        assert_eq!(http_confidence(&request, sig), Confidence::Strong);
    }

    /// p0f flags this rather than rejecting it: the headers are curl's, the
    /// User-Agent claims a browser. Still a match, but only Weak.
    #[test]
    fn a_user_agent_that_disagrees_with_the_headers_is_weak_not_rejected() {
        let db = format::parse(
            "[http:request]\n\
             label = s:!:curl:\n\
             sig   = 1:User-Agent,Host,Accept=[*/*]::curl/\n",
        );
        let request = ObservedHttpRequest::parse(
            b"GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 Safari\r\nHost: honeypot\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        let sig = best_http_match(&db.http_request, &request).expect("the headers still fit curl");
        assert_eq!(http_confidence(&request, sig), Confidence::Weak);
    }

    #[test]
    fn a_specific_http_signature_beats_a_generic_one() {
        let db = format::parse(
            "[http:request]\n\
             label = g:!:Generic client:\n\
             sig   = *:Host::\n\
             label = s:!:curl:\n\
             sig   = 1:User-Agent,Host::curl/\n",
        );
        let request = ObservedHttpRequest::parse(
            b"GET / HTTP/1.1\r\nUser-Agent: curl/8.4.0\r\nHost: honeypot\r\n\r\n",
        )
        .unwrap();
        assert_eq!(best_http_match(&db.http_request, &request).unwrap().label, "curl");
    }

    #[test]
    fn a_wrong_http_version_is_not_a_match() {
        let db = format::parse(
            "[http:request]\n\
             label = s:!:curl:\n\
             sig   = 1:User-Agent,Host::curl/\n",
        );
        let request = ObservedHttpRequest::parse(
            b"GET / HTTP/1.0\r\nUser-Agent: curl/8.4.0\r\nHost: honeypot\r\n\r\n",
        )
        .unwrap();
        assert!(best_http_match(&db.http_request, &request).is_none());
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
