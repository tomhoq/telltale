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
//! The TCP matcher follows p0f's own rules (`fp_tcp.c`): every field of a
//! `[tcp:request]` signature is checked, quirks included, and p0f's fuzzy
//! cases — TTL out of range, `df`/`id+` disappearing, `id-`/`ecn` appearing —
//! are reproduced as fuzzy matches. The one deliberate difference is IPv6,
//! where the IPv4-only quirks of a `*` signature are not expected (see
//! [`quirks_fit`]).

mod format;

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::Path;

use pf_core::{
    Confidence, Context, Evidence, Method, MethodManifest, Outcome, Result, Stage, TcpFeatures,
    TcpOptionKind, TcpQuirk, Transport,
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
/// trusted as a genuine distance. p0f's own `MAX_DIST`.
const MAX_DIST: u8 = 35;

fn nearest_initial_ttl(observed: u8) -> u8 {
    COMMON_INITIAL_TTLS
        .into_iter()
        .find(|&ttl| ttl >= observed)
        .unwrap_or(255)
}

/// The initial TTL the hop count is measured from. The matched signature's
/// own, when the observed TTL fits it; otherwise the nearest common initial
/// value above the observed TTL. A fuzzy match whose TTL does not fit (a
/// TTL of 48 matched to a 128 Windows signature) would claim 80 hops — no
/// real path is that long, so that signature's TTL is not used.
fn distance_base(ttl: u8, matched: Option<&TcpSignature>) -> u8 {
    matched
        .filter(|sig| ttl_in_range(ttl, sig))
        .map(|sig| sig.initial_ttl)
        .unwrap_or_else(|| nearest_initial_ttl(ttl))
}

/// Share of the checked fields that agree, every field counting the same.
/// Not a match test — [`fit_tcp`] is — only a measure of how close a
/// signature came, for logging the nearest one when nothing matched.
fn score_tcp(observed: &TcpFeatures, payload_empty: bool, ip_version: u8, sig: &TcpSignature) -> f64 {
    let mut checks = 0.0_f64;
    let mut matches = 0.0_f64;
    let mut check = |agrees: bool| {
        checks += 1.0;
        matches += agrees as u8 as f64;
    };

    if let Some(expected) = sig.ip_version {
        check(ip_version == expected);
    }
    check(ttl_in_range(observed.ttl, sig));
    check(observed.ip_option_len == sig.ip_option_len);
    if let Some(mss) = sig.mss {
        check(observed.mss.unwrap_or(0) == mss);
    }
    if !matches!(sig.window, WindowSpec::Any | WindowSpec::Modulo(0)) {
        check(window_fits(observed, ip_version, sig.window));
    }
    if let Some(scale) = sig.window_scale {
        check(observed.window_scale.unwrap_or(0) == scale);
    }
    // Always checked, including an empty layout: "no options at all" is
    // itself a real, diagnostic signature (several old or minimal stacks use
    // it), not a wildcard. The padding after an EOL is part of the layout:
    // `eol+1` and `eol+3` are different stacks.
    check(observed.option_order == sig.option_layout && observed.eol_padding == sig.eol_padding);
    check(observed.quirks == expected_quirks(sig, ip_version));
    match sig.payload_class {
        PayloadClass::Zero => check(payload_empty),
        PayloadClass::NonZero => check(!payload_empty),
        PayloadClass::Any => {}
    }

    matches / checks
}

/// The observed SYN written the way p0f prints its own `raw_sig`
/// (`ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass`), so it can be
/// compared field by field with p0f's output and with database entries. The
/// TTL is shown as p0f does, `<initial guess>+<distance>`, and so is a window
/// that is a whole number of segments, `mss*<n>`.
fn raw_signature(observed: &TcpFeatures, payload_empty: bool, ip_version: u8) -> String {
    let initial = nearest_initial_ttl(observed.ttl);
    let mss = observed.mss.map_or("*".to_string(), |mss| mss.to_string());
    let window = match observed.mss {
        Some(mss) if mss > 0 && observed.window % mss == 0 => {
            format!("mss*{}", observed.window / mss)
        }
        _ => observed.window.to_string(),
    };
    let quirks = observed
        .quirks
        .iter()
        .map(|&quirk| format::quirk_token(quirk))
        .collect::<Vec<_>>()
        .join(",");
    let pclass = if payload_empty { "0" } else { "+" };
    format!(
        "{ip_version}:{initial}+{}:{}:{mss}:{window},{}:{}:{quirks}:{pclass}",
        initial - observed.ttl,
        observed.ip_option_len,
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
    /// Everything identifying agrees, but TTL is out of range or the quirks
    /// differ in a way a middlebox could explain — p0f's "fuzzy" match: the
    /// same stack, seen through something that rewrote a header on the way.
    Fuzzy,
}

/// IP-level quirks IPv6 has no header field for.
const IPV4_ONLY_QUIRKS: [TcpQuirk; 4] = [
    TcpQuirk::Df,
    TcpQuirk::NonZeroId,
    TcpQuirk::ZeroId,
    TcpQuirk::NonZeroReserved,
];

/// The quirks a signature expects on a SYN of this IP version. Most of p0f's
/// signatures are `*` — either version — yet list `df,id+`, which only IPv4
/// can carry. p0f would hold their absence against an IPv6 SYN as a fuzzy
/// match; this does not, since no IPv6 SYN could ever have them.
fn expected_quirks(sig: &TcpSignature, ip_version: u8) -> BTreeSet<TcpQuirk> {
    sig.quirks
        .iter()
        .copied()
        .filter(|quirk| ip_version != 6 || !IPV4_ONLY_QUIRKS.contains(quirk))
        .collect()
}

/// p0f's quirk rule: identical quirks are exact. Otherwise the difference is
/// forgiven, as a fuzzy match, only when it is something a middlebox does on
/// its own — clearing DF (which takes `id+` with it), zeroing the ID, or
/// setting ECN. Any other quirk gained or lost is a different stack.
fn quirks_fit(observed: &TcpFeatures, ip_version: u8, sig: &TcpSignature) -> Fit {
    let expected = expected_quirks(sig, ip_version);
    let lost_ok = expected
        .difference(&observed.quirks)
        .all(|quirk| matches!(quirk, TcpQuirk::Df | TcpQuirk::NonZeroId));
    let gained_ok = observed
        .quirks
        .difference(&expected)
        .all(|quirk| matches!(quirk, TcpQuirk::ZeroId | TcpQuirk::Ecn));
    if !(lost_ok && gained_ok) {
        Fit::Mismatch
    } else if observed.quirks == expected {
        Fit::Exact
    } else {
        Fit::Fuzzy
    }
}

/// Whether the observed TTL could have left the sender at the signature's
/// initial TTL. A ceiling (`64-`) takes anything at or below it, since the
/// tool randomizes under it.
fn ttl_in_range(ttl: u8, sig: &TcpSignature) -> bool {
    ttl <= sig.initial_ttl && (sig.ittl_is_ceiling || sig.initial_ttl - ttl <= MAX_DIST)
}

/// p0f's matching rules for one `[tcp:request]` signature (`fp_tcp.c`'s
/// `tcp_find_match`). The option layout, IP option length, MSS, window,
/// scale and payload class identify a stack and must agree. TTL out of range
/// and a middlebox-shaped quirk difference are forgiven, but only as a fuzzy
/// match. An absent MSS or window scale option counts as 0, as in p0f.
fn fit_tcp(observed: &TcpFeatures, payload_empty: bool, ip_version: u8, sig: &TcpSignature) -> Fit {
    if sig.ip_version.is_some_and(|expected| expected != ip_version) {
        return Fit::Mismatch;
    }
    if observed.option_order != sig.option_layout || observed.eol_padding != sig.eol_padding {
        return Fit::Mismatch;
    }
    if observed.ip_option_len != sig.ip_option_len {
        return Fit::Mismatch;
    }
    if sig.mss.is_some_and(|expected| observed.mss.unwrap_or(0) != expected) {
        return Fit::Mismatch;
    }
    if sig
        .window_scale
        .is_some_and(|expected| observed.window_scale.unwrap_or(0) != expected)
    {
        return Fit::Mismatch;
    }
    if !window_fits(observed, ip_version, sig.window) {
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

    let quirks = quirks_fit(observed, ip_version, sig);
    if quirks == Fit::Mismatch {
        return Fit::Mismatch;
    }

    // TTL: a ceiling (`64-`) is a hard limit, since the tool randomizes below
    // it; a normal initial TTL out of range only makes the match fuzzy.
    if sig.ittl_is_ceiling && observed.ttl > sig.initial_ttl {
        return Fit::Mismatch;
    }

    if quirks == Fit::Exact && ttl_in_range(observed.ttl, sig) {
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

/// Whether the User-Agent contains the signature's expected-software
/// substring (its `expsw` field, e.g. `Firefox/` or `curl/` — not the label,
/// which is free text). p0f does not reject a match over this; it flags the
/// client as dishonest — a tool that sets a browser's User-Agent but not its
/// header order, say. So does `f0p`: see `ua-conflict`.
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

/// How sure the header-order match is, by the spec's confidence rule: a
/// specific signature is Strong, a generic one Likely. The User-Agent does
/// not lower it — a disagreeing one is reported as its own `ua-conflict`
/// flag, since the headers may well be right and the claim wrong.
fn http_confidence(sig: &HttpSignature) -> Confidence {
    if sig.specific {
        Confidence::Strong
    } else {
        Confidence::Likely
    }
}

pub struct F0p {
    manifest: MethodManifest,
    db: P0fDb,
}

pub fn build(manifest: MethodManifest, manifest_dir: &Path) -> Result<Box<dyn Method>> {
    let db = manifest
        .database
        .as_ref()
        .map(|spec| db::load::<P0fDb>(&manifest.name, spec, manifest_dir))
        .transpose()?
        .unwrap_or_default();

    Ok(Box::new(F0p { manifest, db }))
}

impl Method for F0p {
    fn manifest(&self) -> &MethodManifest {
        &self.manifest
    }

    fn extract(&self, ctx: &Context<'_>) -> Result<Outcome> {
        if ctx.session.key.transport != Transport::Tcp {
            return Ok(Outcome::NotApplicable);
        }

        // The SYN carries everything the `[tcp:request]` signatures match on,
        // and only the SYN: every segment has TCP features, but an ACK or a
        // data segment is shaped by the connection, not the stack's defaults.
        // A session first seen mid-stream (capture started after the
        // handshake) has no SYN, and gets no guess rather than a wrong one.
        // A source with no header-level detail (a honeypot log, say) leaves
        // `tcp` unset rather than inventing one.
        let Some((syn, payload_empty)) = ctx
            .observations()
            .filter(|o| o.stage_hint == Some(Stage::Connect))
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
            // The nearest signature goes to the log only, for spotting gaps
            // in the database: a near miss can differ in exactly the field
            // that identifies the stack, so it is never reported as a result.
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
            }
        }
        evidence.push(Evidence::new(
            self.name(),
            ctx.session.initiator,
            "signature",
            observed_sig,
            Confidence::Weak,
        ));

        let initial_ttl = distance_base(syn.ttl, best_tcp.map(|(sig, _)| sig));
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
                    http_confidence(sig),
                ));
                if !software_agrees(&request, sig) {
                    let expected = sig.expected_software.as_deref().unwrap_or_default();
                    evidence.push(Evidence::new(
                        self.name(),
                        ctx.session.initiator,
                        "ua-conflict",
                        format!("headers look like {}, User-Agent lacks \"{expected}\"", sig.label),
                        Confidence::Strong,
                    ));
                }
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
            ip_option_len: 0,
            quirks: [TcpQuirk::Df, TcpQuirk::NonZeroId].into(),
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
    /// `4:64+0:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0`.
    /// The capture predates quirk decoding, which recorded only `df`; `id+`
    /// is assumed, as every Apple entry in p0f's database lists it.
    fn iphone_syn() -> TcpFeatures {
        use TcpOptionKind::*;
        TcpFeatures {
            ttl: 64,
            ip_option_len: 0,
            quirks: [TcpQuirk::Df, TcpQuirk::NonZeroId].into(),
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
            "4:64+3:0:1460:mss*20,7:mss,sok,ts,nop,ws:df,id+:0"
        );
    }

    #[test]
    fn eol_padding_renders_as_a_byte_count() {
        assert_eq!(
            raw_signature(&iphone_syn(), true, 4),
            "4:64+0:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0"
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

    /// The bug this guards: a TTL of 48 fuzzily matched to a Windows (128)
    /// signature reported a distance of 80.
    #[test]
    fn distance_ignores_a_signature_ttl_the_observed_one_does_not_fit() {
        let windows = format::parse(
            "[tcp:request]\n\
             label = s:win:Windows:NT kernel 5.x\n\
             sig   = *:128:0:*:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0\n",
        )
        .tcp_request
        .remove(0);
        assert_eq!(distance_base(48, Some(&windows)), 64);
        assert_eq!(distance_base(120, Some(&windows)), 128);
        assert_eq!(distance_base(48, None), 64);
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
        observed.quirks.clear();
        observed.option_order = vec![TcpOptionKind::Mss];
        observed.window_scale = None;
        observed.ttl = 41;
        assert_eq!(fit_tcp(&observed, true, 4, &sig), Fit::Exact);
        observed.ttl = 65;
        assert_eq!(fit_tcp(&observed, true, 4, &sig), Fit::Mismatch);
    }

    #[test]
    fn df_disappearing_is_fuzzy_but_appearing_is_a_mismatch() {
        let mut no_df = linux_syn();
        no_df.quirks.clear();
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
        observed.quirks.clear();
        assert_eq!(fit_tcp(&observed, true, 6, &linux_signature()), Fit::Exact);
    }

    /// `df` and `id+` both disappearing is what a middlebox clearing DF looks
    /// like; p0f still calls that the same stack, fuzzily.
    #[test]
    fn df_and_id_disappearing_together_is_fuzzy() {
        let mut observed = linux_syn();
        observed.quirks = BTreeSet::new();
        assert_eq!(fit_tcp(&observed, true, 4, &linux_signature()), Fit::Fuzzy);
    }

    #[test]
    fn ecn_or_a_zero_id_appearing_is_fuzzy() {
        for gained in [TcpQuirk::Ecn, TcpQuirk::ZeroId] {
            let mut observed = linux_syn();
            observed.quirks.insert(gained);
            assert_eq!(fit_tcp(&observed, true, 4, &linux_signature()), Fit::Fuzzy);
        }
    }

    /// Anything else a stack adds or drops is the stack, not the path.
    #[test]
    fn any_other_quirk_difference_is_a_mismatch() {
        let mut gained = linux_syn();
        gained.quirks.insert(TcpQuirk::ZeroSeq);
        assert_eq!(fit_tcp(&gained, true, 4, &linux_signature()), Fit::Mismatch);

        let sig = format::parse(
            "[tcp:request]\n\
             label = s:unix:Test:ack+\n\
             sig   = *:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+,ack+:0\n",
        )
        .tcp_request
        .remove(0);
        assert_eq!(fit_tcp(&linux_syn(), true, 4, &sig), Fit::Mismatch);
    }

    #[test]
    fn ip_options_must_match_in_length() {
        let mut observed = linux_syn();
        observed.ip_option_len = 4;
        assert_eq!(fit_tcp(&observed, true, 4, &linux_signature()), Fit::Mismatch);
    }

    #[test]
    fn every_quirk_renders_in_the_raw_signature_in_p0f_order() {
        let mut observed = linux_syn();
        observed.quirks.extend([TcpQuirk::Push, TcpQuirk::ZeroSeq, TcpQuirk::Ecn]);
        assert!(raw_signature(&observed, true, 4).ends_with(":df,id+,ecn,seq-,pushf+:0"));
    }

    fn extract_from(first: Stage) -> Outcome {
        use std::net::Ipv4Addr;
        use std::time::SystemTime;

        use pf_core::{Endpoint, Observation, Session};

        let manifest = MethodManifest::from_yaml(include_str!("../../../manifests/f0p.yaml"))
            .expect("the shipped manifest should parse");
        let f0p = F0p {
            manifest,
            db: vendored_db(),
        };
        let session = Session::open(Observation {
            at: SystemTime::UNIX_EPOCH,
            source: Endpoint {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
                port: 47236,
            },
            destination: Endpoint {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)),
                port: 80,
            },
            transport: Transport::Tcp,
            payload: Vec::new(),
            stage_hint: Some(first),
            tcp: Some(linux_syn()),
        });
        f0p.extract(&Context::new(&session, &[], false, false)).unwrap()
    }

    #[test]
    fn a_syn_is_fingerprinted() {
        let Outcome::Partial(evidence) = extract_from(Stage::Connect) else {
            panic!("a SYN should produce evidence");
        };
        assert!(evidence.iter().any(|e| e.key == "os"), "{evidence:?}");
    }

    /// The bug this guards: a session first seen mid-stream had its first ACK
    /// fingerprinted as though it were the SYN.
    #[test]
    fn a_session_without_a_syn_is_not_fingerprinted() {
        assert!(matches!(extract_from(Stage::Established), Outcome::NotApplicable));
    }

    #[test]
    fn an_mtu_multiple_window_is_checked_against_the_mss_implied_mtu() {
        let sig = format::parse(
            "[tcp:request]\n\
             label = s:unix:Test:mtu\n\
             sig   = *:64:0:*:mtu*4,7:mss,sok,ts,nop,ws:df,id+:0\n",
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
             sig   = *:128:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0\n\
             label = g:unix:Generic:\n\
             sig   = *:64:0:*:mss*20,*:mss,sok,ts,nop,ws:df,id+:0\n",
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
             sig   = *:64:0:*:mss*20,*:mss,sok,ts,nop,ws:df,id+:0\n\
             label = s:unix:Specific:\n\
             sig   = *:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0\n",
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
        observed.window_scale = None;
        observed.window = 1024;
        observed.mss = Some(1460);
        observed.quirks.clear();
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
        assert_eq!(http_confidence(sig), Confidence::Strong);
        assert!(software_agrees(&request, sig));
    }

    /// p0f flags this rather than rejecting it: the headers are curl's, the
    /// User-Agent claims a browser. Still a full-confidence match on the
    /// headers; the disagreement is a separate `ua-conflict` flag.
    #[test]
    fn a_user_agent_that_disagrees_with_the_headers_is_flagged_not_weakened() {
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
        assert_eq!(http_confidence(sig), Confidence::Strong);
        assert!(!software_agrees(&request, sig));
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
