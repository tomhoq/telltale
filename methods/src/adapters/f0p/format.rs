//! Parser for the real p0f fingerprint database format (`p0f.fp`).
//!
//! The grammar here is p0f's own — documented in its README section 5 — not
//! something this project invented. `methods/db/p0f.fp` is the file itself,
//! vendored unmodified from the p0f project (see `p0f.fp.LICENSE` next to
//! it); this module only reads it.
//!
//! Scope: only `[tcp:request]` and `[http:request]` are parsed — the SYN and
//! the client's own HTTP request, i.e. exactly the attacker's traffic into a
//! honeypot, which is what `f0p` fingerprints by default (see
//! `Context::observations` and the `--both-directions` flag). `[tcp:response]`,
//! `[http:response]` and `[mtu]` lines are recognised and skipped, not
//! mis-parsed as something else.
//!
//! A line this parser does not understand is dropped, not rejected — same
//! policy `pf_capture::decode` uses for wire bytes it cannot make sense of.
//! Do not fail the whole database over one line neither p0f nor this parser
//! has ever needed to reject outright.

use pf_core::{DatabaseSpec, Result, TcpOptionKind};

use crate::db::Database;

/// A `wsize` token from a `[tcp:request]` signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowSpec {
    Any,
    Fixed(u16),
    /// `mss*N` — window is exactly the segment's own MSS times `N`.
    MssMultiple(u32),
    /// `%N` — window is a multiple of `N`. Rare in practice; kept for
    /// completeness since the grammar documents it even though the shipped
    /// `[tcp:request]` signatures do not currently use it.
    Modulo(u32),
    /// `mtu*N` — window is `N` times the MTU the segment's own MSS implies
    /// (MSS plus minimal IP and TCP headers).
    MtuMultiple(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadClass {
    Zero,
    NonZero,
    Any,
}

/// One `[tcp:request]` signature, tied to the `label` line above it.
#[derive(Debug, Clone)]
pub struct TcpSignature {
    /// `s` (specific) vs `g` (generic, last-resort — p0f's own README: "generic
    /// signatures are considered only if no specific matches are found").
    pub specific: bool,
    /// OS family (`unix`, `win`, ...) from the label, or `!` for a
    /// tool/application signature (NMap's raw-socket sigs live in
    /// `[tcp:request]` under `!` right alongside the OS ones).
    pub class: String,
    /// Display name built from the label's `name` and `flavor`, e.g. "Linux
    /// 3.11 and newer" or "NMap SYN scan".
    pub label: String,
    /// The `sig = ...` value exactly as written in the database, for showing
    /// which entry matched next to the observed signature.
    pub raw: String,
    pub ip_version: Option<u8>,
    pub initial_ttl: u8,
    /// Trailing `-` on `ittl`: some userspace tools randomize TTL below a
    /// ceiling rather than using a fixed value, so any observed TTL at or
    /// below `initial_ttl` counts as a match, not just the hop-adjusted one.
    pub ittl_is_ceiling: bool,
    pub mss: Option<u16>,
    pub window: WindowSpec,
    pub window_scale: Option<u8>,
    pub option_layout: Vec<TcpOptionKind>,
    /// The `N` of a trailing `eol+N`: padding bytes after the EOL option.
    /// `None` when the layout has no EOL. Same shape as
    /// `TcpFeatures::eol_padding`, so the two compare directly.
    pub eol_padding: Option<u8>,
    /// Raw quirk tokens (`df`, `id+`, `ecn`, `ack+`, ...), kept verbatim.
    /// `f0p`'s matcher currently only checks `df`, because that is the only
    /// one `pf_core::TcpFeatures` observes yet — the ID/ECN/sequence/ack/urg
    /// quirks ride along unused rather than being silently dropped, so a
    /// later capture-layer extension has them ready to score.
    pub quirks: Vec<String>,
    pub payload_class: PayloadClass,
}

/// One expected header in an `[http:request]` signature's `horder` list.
#[derive(Debug, Clone)]
pub struct HttpHeaderExpectation {
    /// Lower-cased for matching.
    pub name: String,
    /// `Name=[value]` syntax: the header's value must contain this substring.
    pub value_contains: Option<String>,
    /// `?Name` syntax: the header may legitimately be missing (e.g.
    /// `Accept-Language` when the user has none configured) without failing
    /// the match, but if present must still appear in sequence.
    pub optional: bool,
}

/// One `[http:request]` signature.
#[derive(Debug, Clone)]
pub struct HttpSignature {
    /// `s` (specific) vs `g` (generic), with the same precedence as the TCP
    /// signatures.
    pub specific: bool,
    pub label: String,
    /// `0` / `1` from `HTTP/1.x`, or `None` for `*` (either).
    pub http_minor_version: Option<u8>,
    /// Headers expected in this order. p0f's README: "matched even if other
    /// headers appear in between, as long as the list itself is matched in
    /// the specified sequence" — a subsequence match, not a prefix one.
    pub header_order: Vec<HttpHeaderExpectation>,
    /// Header names (lower-cased) that must *not* appear anywhere.
    pub header_absent: Vec<String>,
    /// Expected substring in User-Agent. Informational in real p0f (it flags
    /// dishonest software rather than gating the match); `f0p` does the same,
    /// lowering the confidence of a match the User-Agent disagrees with.
    pub expected_software: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct P0fDb {
    pub tcp_request: Vec<TcpSignature>,
    pub http_request: Vec<HttpSignature>,
}

impl Database for P0fDb {
    const FORMATS: &'static [&'static str] = &["p0f"];

    fn load(text: &str, _spec: &DatabaseSpec) -> Result<Self> {
        Ok(parse(text))
    }
}

enum Section {
    Other,
    TcpRequest,
    HttpRequest,
}

struct PendingLabel {
    specific: bool,
    class: String,
    label: String,
}

pub fn parse(text: &str) -> P0fDb {
    let mut db = P0fDb::default();
    let mut section = Section::Other;
    let mut pending: Option<PendingLabel> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }

        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = match name {
                "tcp:request" => Section::TcpRequest,
                "http:request" => Section::HttpRequest,
                _ => Section::Other,
            };
            pending = None;
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();

        match key.trim() {
            "label" => pending = parse_label(value),
            "sig" => {
                let Some(current) = &pending else { continue };
                match section {
                    Section::TcpRequest => db.tcp_request.extend(parse_tcp_sig(value, current)),
                    Section::HttpRequest => {
                        db.http_request.extend(parse_http_sig(value, current))
                    }
                    Section::Other => {}
                }
            }
            // `sys`, `classes`, `ua_os`, and anything future versions of the
            // format add: not needed for matching, so deliberately ignored
            // rather than rejected — a format addition should not break
            // loading everything that came before it.
            _ => {}
        }
    }

    db
}

fn parse_label(value: &str) -> Option<PendingLabel> {
    let mut parts = value.splitn(4, ':');
    let ty = parts.next()?;
    let class = parts.next()?.to_string();
    let name = parts.next().unwrap_or("");
    let flavor = parts.next().unwrap_or("").trim();

    let label = if flavor.is_empty() {
        name.trim().to_string()
    } else {
        format!("{} {flavor}", name.trim())
    };

    Some(PendingLabel {
        specific: ty == "s",
        class,
        label,
    })
}

fn parse_tcp_sig(value: &str, current: &PendingLabel) -> Option<TcpSignature> {
    // ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
    let mut fields = value.splitn(8, ':');
    let ver = fields.next()?;
    let ittl = fields.next()?;
    let _olen = fields.next()?;
    let mss = fields.next()?;
    let wsize_scale = fields.next()?;
    let olayout = fields.next()?;
    let quirks = fields.next()?;
    let pclass = fields.next()?;

    let ip_version = match ver {
        "*" => None,
        "4" => Some(4),
        "6" => Some(6),
        _ => return None,
    };

    let (ittl_is_ceiling, ittl_digits) = match ittl.strip_suffix('-') {
        Some(rest) => (true, rest),
        None => (false, ittl),
    };
    let initial_ttl: u8 = ittl_digits.parse().ok()?;

    let mss = match mss {
        "*" => None,
        digits => digits.parse().ok(),
    };

    let (wsize, scale) = wsize_scale.split_once(',')?;
    let window = parse_window(wsize);
    let window_scale = match scale {
        "*" => None,
        digits => digits.parse().ok(),
    };

    let option_layout = olayout
        .split(',')
        .filter(|t| !t.is_empty())
        .map(parse_option_token)
        .collect();
    // p0f's `eol+N`: EOL, then N bytes of padding. `eol` alone would be no
    // padding, though p0f always writes the count.
    let eol_padding = olayout
        .split(',')
        .find_map(|t| t.strip_prefix("eol"))
        .map(|rest| rest.strip_prefix('+').and_then(|n| n.parse().ok()).unwrap_or(0));

    let quirks = quirks
        .split(',')
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect();

    let payload_class = match pclass {
        "0" => PayloadClass::Zero,
        "+" => PayloadClass::NonZero,
        _ => PayloadClass::Any,
    };

    Some(TcpSignature {
        specific: current.specific,
        class: current.class.clone(),
        label: current.label.clone(),
        raw: value.trim().to_string(),
        ip_version,
        initial_ttl,
        ittl_is_ceiling,
        mss,
        window,
        window_scale,
        option_layout,
        eol_padding,
        quirks,
        payload_class,
    })
}

fn parse_window(token: &str) -> WindowSpec {
    if token == "*" {
        return WindowSpec::Any;
    }
    if let Some(n) = token.strip_prefix("mss*") {
        return n.parse().map(WindowSpec::MssMultiple).unwrap_or(WindowSpec::Any);
    }
    if let Some(n) = token.strip_prefix("mtu*") {
        return n.parse().map(WindowSpec::MtuMultiple).unwrap_or(WindowSpec::Any);
    }
    if let Some(n) = token.strip_prefix('%') {
        return n.parse().map(WindowSpec::Modulo).unwrap_or(WindowSpec::Any);
    }
    token.parse().map(WindowSpec::Fixed).unwrap_or(WindowSpec::Any)
}

fn parse_option_token(token: &str) -> TcpOptionKind {
    if let Some(id) = token.strip_prefix('?').and_then(|s| s.parse().ok()) {
        return TcpOptionKind::Other(id);
    }
    match token {
        "nop" => TcpOptionKind::Nop,
        "mss" => TcpOptionKind::Mss,
        "ws" => TcpOptionKind::WindowScale,
        "sok" => TcpOptionKind::SackPermitted,
        "sack" => TcpOptionKind::Sack,
        "ts" => TcpOptionKind::Timestamp,
        _ if token.starts_with("eol") => TcpOptionKind::Eol,
        _ => TcpOptionKind::Other(0),
    }
}

fn parse_http_sig(value: &str, current: &PendingLabel) -> Option<HttpSignature> {
    // ver:horder:habsent:expsw
    let parts = split_top_level(value, ':');
    let ver = parts.first().copied().unwrap_or("*");
    let horder = parts.get(1).copied().unwrap_or("");
    let habsent = parts.get(2).copied().unwrap_or("");
    let expsw = parts.get(3).copied().unwrap_or("").trim();

    let http_minor_version = match ver {
        "0" => Some(0),
        "1" => Some(1),
        _ => None,
    };

    let header_order = split_top_level(horder, ',')
        .into_iter()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(parse_header_expectation)
        .collect();

    let header_absent = split_top_level(habsent, ',')
        .into_iter()
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();

    let expected_software = (!expsw.is_empty()).then(|| expsw.to_string());

    Some(HttpSignature {
        specific: current.specific,
        label: current.label.clone(),
        http_minor_version,
        header_order,
        header_absent,
        expected_software,
    })
}

fn parse_header_expectation(token: &str) -> HttpHeaderExpectation {
    let (optional, token) = match token.strip_prefix('?') {
        Some(rest) => (true, rest),
        None => (false, token),
    };

    match token.find("=[") {
        Some(open) => {
            let name = &token[..open];
            let value = token[open + 2..].strip_suffix(']').unwrap_or(&token[open + 2..]);
            HttpHeaderExpectation {
                name: name.trim().to_ascii_lowercase(),
                value_contains: Some(value.to_string()),
                optional,
            }
        }
        None => HttpHeaderExpectation {
            name: token.trim().to_ascii_lowercase(),
            value_contains: None,
            optional,
        },
    }
}

/// Split on `delim`, but not inside `[...]` — several `horder` values contain
/// a literal comma (`Accept-Encoding=[gzip, deflate]`), so a plain
/// `str::split` would cut them in half.
fn split_top_level(s: &str, delim: char) -> Vec<&str> {
    let mut result = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;

    for (i, ch) in s.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => depth -= 1,
            c if c == delim && depth <= 0 => {
                result.push(&s[start..i]);
                start = i + ch.len_utf8();
            }
            _ => {}
        }
    }
    result.push(&s[start..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_specific_linux_tcp_signature() {
        let text = "\
[tcp:request]

label = s:unix:Linux:3.11 and newer
sig   = *:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0
";
        let db = parse(text);
        assert_eq!(db.tcp_request.len(), 1);
        let sig = &db.tcp_request[0];
        assert!(sig.specific);
        assert_eq!(sig.class, "unix");
        assert_eq!(sig.label, "Linux 3.11 and newer");
        assert_eq!(sig.ip_version, None);
        assert_eq!(sig.initial_ttl, 64);
        assert!(!sig.ittl_is_ceiling);
        assert_eq!(sig.mss, None);
        assert_eq!(sig.window, WindowSpec::MssMultiple(20));
        assert_eq!(sig.window_scale, Some(10));
        assert_eq!(
            sig.option_layout,
            vec![
                TcpOptionKind::Mss,
                TcpOptionKind::SackPermitted,
                TcpOptionKind::Timestamp,
                TcpOptionKind::Nop,
                TcpOptionKind::WindowScale,
            ]
        );
        assert_eq!(sig.eol_padding, None);
        assert_eq!(sig.quirks, vec!["df", "id+"]);
        assert_eq!(sig.payload_class, PayloadClass::Zero);
    }

    #[test]
    fn eol_padding_is_parsed_into_its_own_count() {
        let text = "\
[tcp:request]

label = g:unix:Mac OS X:
sig   = *:64:0:*:65535,*:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0
";
        let sig = &parse(text).tcp_request[0];
        assert_eq!(sig.option_layout.last(), Some(&TcpOptionKind::Eol));
        assert_eq!(sig.option_layout.len(), 8);
        assert_eq!(sig.eol_padding, Some(1));
    }

    #[test]
    fn a_ceiling_ttl_keeps_its_trailing_dash() {
        let text = "\
[tcp:request]

label = s:!:NMap:SYN scan
sig   = *:64-:0:1460:1024,0:mss::0
";
        let sig = &parse(text).tcp_request[0];
        assert_eq!(sig.class, "!");
        assert_eq!(sig.initial_ttl, 64);
        assert!(sig.ittl_is_ceiling);
    }

    #[test]
    fn other_sections_and_directives_are_skipped_not_misparsed() {
        let text = "\
classes = win,unix,other

[mtu]
label = Ethernet or modem
sig   = 1500

[tcp:response]
label = s:unix:Linux:should not appear
sig   = *:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0

[tcp:request]
label = s:unix:Linux:should appear
sig   = *:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0
";
        let db = parse(text);
        assert_eq!(db.tcp_request.len(), 1);
        assert_eq!(db.tcp_request[0].label, "Linux should appear");
    }

    #[test]
    fn parses_curl_http_signature() {
        let text = "\
[http:request]

label = s:!:curl:
sig   = 1:User-Agent,Host,Accept=[*/*]:Connection,Accept-Encoding,Accept-Language,Accept-Charset:curl/
";
        let sig = &parse(text).http_request[0];
        assert_eq!(sig.label, "curl");
        assert_eq!(sig.http_minor_version, Some(1));
        assert_eq!(sig.header_order.len(), 3);
        assert_eq!(sig.header_order[0].name, "user-agent");
        assert_eq!(sig.header_order[2].name, "accept");
        assert_eq!(sig.header_order[2].value_contains.as_deref(), Some("*/*"));
        assert_eq!(
            sig.header_absent,
            vec!["connection", "accept-encoding", "accept-language", "accept-charset"]
        );
        assert_eq!(sig.expected_software.as_deref(), Some("curl/"));
    }

    #[test]
    fn a_bracketed_value_with_a_comma_does_not_split_the_header_list() {
        let text = "\
[http:request]

label = s:!:Example:1.x
sig   = *:Host,Accept-Encoding=[gzip, deflate],User-Agent::
";
        let sig = &parse(text).http_request[0];
        assert_eq!(sig.header_order.len(), 3);
        assert_eq!(sig.header_order[1].name, "accept-encoding");
        assert_eq!(
            sig.header_order[1].value_contains.as_deref(),
            Some("gzip, deflate")
        );
    }

    #[test]
    fn an_optional_header_is_marked_not_required() {
        let text = "\
[http:request]

label = s:!:Example:1.x
sig   = *:Host,?Referer,User-Agent::
";
        let sig = &parse(text).http_request[0];
        assert!(sig.header_order[1].optional);
        assert_eq!(sig.header_order[1].name, "referer");
    }
}
