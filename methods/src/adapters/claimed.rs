//! What the client *says* it is: the HTTP `User-Agent` header, matched
//! against a hand-maintained list of known libraries, scanners, and research
//! crawlers — exactly the traffic a honeypot's HTTP surface actually sees.
//!
//! Unlike `f0p` or `ja4`, nothing here fingerprints how the client behaves:
//! any tool can send any User-Agent. The output is a claim, for `fusion` to
//! check against the fingerprints, never a finding on its own.
//!
//! SSH/FTP banners are a natural future extension (the manifest's
//! `required-stage: app-data` is already protocol-agnostic) but nothing
//! needs them yet, so this only looks at HTTP for now.

use std::path::Path;

use pf_core::{Confidence, Context, Evidence, Method, MethodManifest, Outcome, Result};
use serde::Deserialize;

use super::http_request::{first_request, FirstRequest};
use crate::db::{self, Database};

/// One `methods/db/user-agents.yaml` entry. A rule fires when the observed
/// User-Agent matches *any* of its patterns — several real-world variants of
/// the same tool often need separate patterns (e.g. ZAP's UA has changed
/// naming across versions).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ClaimRule {
    pub client: String,
    /// `library` | `scanner` | `crawler` | `malformed` — coarse enough to be
    /// useful to `fusion` later without pretending to know every taxonomy.
    pub category: String,
    /// User-Agent equals this, case-insensitively, exactly.
    #[serde(default)]
    pub exact: Vec<String>,
    /// User-Agent starts with this, case-insensitively. Also the only match
    /// kind version extraction anchors on — see `extract_version`.
    #[serde(default)]
    pub prefix: Vec<String>,
    /// This substring appears anywhere in the User-Agent, case-insensitively.
    #[serde(default)]
    pub contains: Vec<String>,
}

impl ClaimRule {
    fn matches(&self, ua_lower: &str) -> bool {
        self.exact.iter().any(|p| ua_lower == p.to_ascii_lowercase())
            || self
                .prefix
                .iter()
                .any(|p| ua_lower.starts_with(p.to_ascii_lowercase().as_str()))
            || self
                .contains
                .iter()
                .any(|p| ua_lower.contains(p.to_ascii_lowercase().as_str()))
    }
}

/// One `os:` entry of `methods/db/user-agents.yaml`: the OS a User-Agent
/// says it runs on. The first entry that matches wins, so the database lists
/// the specific before the general (an iPhone's User-Agent also says "like
/// Mac OS X", an Android one "Linux").
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct OsRule {
    /// This substring appears in the User-Agent, case-insensitively.
    pub contains: String,
    /// The OS claimed, e.g. `Windows 10`.
    pub os: String,
    /// A version follows this substring (`iPhone OS 18_7` -> `18.7`), and
    /// is appended to `os`.
    #[serde(default)]
    pub version_after: Option<String>,
}

impl OsRule {
    fn claim(&self, ua_lower: &str) -> Option<String> {
        if !ua_lower.contains(&self.contains.to_ascii_lowercase()) {
            return None;
        }
        let version = self.version_after.as_ref().and_then(|anchor| {
            let anchor = anchor.to_ascii_lowercase();
            let at = ua_lower.find(&anchor)? + anchor.len();
            let version: String = ua_lower[at..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '_' || *c == '.')
                .map(|c| if c == '_' { '.' } else { c })
                .collect();
            let version = version.trim_end_matches('.').to_string();
            (!version.is_empty()).then_some(version)
        });
        Some(match version {
            Some(v) => format!("{} {v}", self.os),
            None => self.os.clone(),
        })
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ClaimDb {
    #[serde(default)]
    pub rules: Vec<ClaimRule>,
    #[serde(default)]
    pub os: Vec<OsRule>,
}

impl Database for ClaimDb {
    const FORMATS: &'static [&'static str] = &["rules"];

    fn load(text: &str, _spec: &pf_core::DatabaseSpec) -> Result<Self> {
        Ok(serde_yaml::from_str(text)?)
    }
}

/// Whatever comes after a matched `prefix` pattern, up to the next
/// whitespace/`)`/`;` — covers `curl/8.4.0`, `Go-http-client/1.1`,
/// `sqlmap/1.7#stable (http://sqlmap.org)` alike. `None` for a rule that
/// matched only via `exact`/`contains`, where there's no unambiguous anchor
/// to extract a version after.
fn extract_version(user_agent: &str, ua_lower: &str, rule: &ClaimRule) -> Option<String> {
    let prefix_lower = rule
        .prefix
        .iter()
        .map(|p| p.to_ascii_lowercase())
        .find(|p| ua_lower.starts_with(p.as_str()))?;

    // Safe to slice the original string at this byte offset: every prefix in
    // the database is plain ASCII, so lower-casing does not change its length.
    let rest = &user_agent[prefix_lower.len()..];
    let version: String = rest
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ')' && *c != ';')
        .collect();

    (!version.is_empty()).then_some(version)
}

const HTTP_METHODS: [&str; 8] = [
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "CONNECT", "PATCH",
];

/// `None` for anything that isn't an HTTP/1.x request at all. `Some("")` for
/// one that is but sends no `User-Agent` header — itself a real signal many
/// bare scripts and scanners give away, folded into the same "(no
/// user-agent)" rule as a literally empty header value.
fn http_user_agent(payload: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(payload).ok()?;
    let normalized = text.replace("\r\n", "\n");
    let mut lines = normalized.split('\n');

    let request_line = lines.next()?;
    let method = request_line.split(' ').next()?;
    if !HTTP_METHODS.contains(&method) {
        return None;
    }

    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("user-agent") {
            return Some(value.trim().to_string());
        }
    }

    Some(String::new())
}

pub struct Claimed {
    manifest: MethodManifest,
    db: ClaimDb,
    /// Cap on how many bytes to scan, so a large transfer cannot make this
    /// method expensive.
    max_bytes: usize,
}

pub fn build(manifest: MethodManifest, manifest_dir: &Path) -> Result<Box<dyn Method>> {
    let max_bytes = manifest.param("max-bytes", 4096);
    let db = manifest
        .database
        .as_ref()
        .map(|spec| db::load::<ClaimDb>(&manifest.name, spec, manifest_dir))
        .transpose()?
        .unwrap_or_default();

    Ok(Box::new(Claimed {
        manifest,
        db,
        max_bytes,
    }))
}

impl Method for Claimed {
    fn manifest(&self) -> &MethodManifest {
        &self.manifest
    }

    fn extract(&self, ctx: &Context<'_>) -> Result<Outcome> {
        let head = match first_request(ctx, self.max_bytes) {
            FirstRequest::Nothing => return Ok(Outcome::NotApplicable),
            FirstRequest::Incomplete => return Ok(Outcome::NoMatch),
            // Not HTTP from its first bytes (SSH, TLS, ...): nothing to
            // claim, now or later, so done rather than looked at again on
            // every packet.
            FirstRequest::NotHttp => return Ok(Outcome::Complete(Vec::new())),
            FirstRequest::Head(head) => head,
        };
        let Some(user_agent) = http_user_agent(&head) else {
            return Ok(Outcome::Complete(Vec::new()));
        };

        // The claim itself is always reported, whether or not a rule knows it:
        // a browser's User-Agent is as much a claim as curl's, and the one
        // fusion most needs to check against the fingerprints.
        let subject = ctx.session.initiator;
        let mut evidence = vec![Evidence::new(
            self.name(),
            subject,
            "user-agent",
            if user_agent.is_empty() { "(none)".to_string() } else { user_agent.clone() },
            Confidence::Weak,
        )];

        let ua_lower = user_agent.to_ascii_lowercase();
        if let Some(rule) = self.db.rules.iter().find(|r| r.matches(&ua_lower)) {
            // Weak by the spec's confidence rule: a self-reported claim is
            // never evidence of what the client is, however exact the match.
            evidence.push(Evidence::new(self.name(), subject, "client", rule.client.clone(), Confidence::Weak));
            evidence.push(Evidence::new(self.name(), subject, "category", rule.category.clone(), Confidence::Weak));
            if let Some(version) = extract_version(&user_agent, &ua_lower, rule) {
                evidence.push(Evidence::new(self.name(), subject, "version", version, Confidence::Weak));
            }
        }
        // The OS it says it runs on: self-reported like the rest, so Weak,
        // and exactly what fusion checks against the TCP stack.
        if let Some(os) = self.db.os.iter().find_map(|rule| rule.claim(&ua_lower)) {
            evidence.push(Evidence::new(self.name(), subject, "os", os, Confidence::Weak));
        }

        // A User-Agent match is a settled claim, not one that refines with
        // more traffic — unlike f0p's every-observation re-confirmation,
        // there is nothing to revise later.
        Ok(Outcome::Complete(evidence))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> ClaimDb {
        serde_yaml::from_str(include_str!("../../db/user-agents.yaml"))
            .expect("shipped user-agents.yaml should parse")
    }

    fn request(user_agent: &str) -> Vec<u8> {
        format!("GET / HTTP/1.1\r\nHost: honeypot\r\nUser-Agent: {user_agent}\r\nAccept: */*\r\n\r\n")
            .into_bytes()
    }

    fn identify<'a>(db: &'a ClaimDb, user_agent: &str) -> Option<&'a ClaimRule> {
        let ua_lower = user_agent.to_ascii_lowercase();
        db.rules.iter().find(|r| r.matches(&ua_lower))
    }

    #[test]
    fn curl_is_identified_as_a_library_with_its_version() {
        let db = db();
        let rule = identify(&db, "curl/8.4.0").expect("curl should match");
        assert_eq!(rule.client, "curl");
        assert_eq!(rule.category, "library");
        assert_eq!(
            extract_version("curl/8.4.0", "curl/8.4.0", rule),
            Some("8.4.0".to_string())
        );
    }

    #[test]
    fn nmap_nse_is_identified_as_a_scanner() {
        let db = db();
        let rule = identify(
            &db,
            "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
        )
        .expect("Nmap NSE UA should match");
        assert_eq!(rule.client, "Nmap");
        assert_eq!(rule.category, "scanner");
    }

    #[test]
    fn shodan_is_identified_as_a_crawler() {
        let db = db();
        let rule = identify(&db, "Mozilla/5.0 (compatible; Shodan/1.1)").expect("Shodan should match");
        assert_eq!(rule.category, "crawler");
    }

    #[test]
    fn a_bare_go_http_client_is_a_library_not_flagged_as_malformed() {
        // Suspicious-in-context is fusion's job (os-client-mismatch), not
        // `claimed`'s — `claimed` only reports the claim.
        let db = db();
        let rule = identify(&db, "Go-http-client/1.1").expect("Go-http-client should match");
        assert_eq!(rule.category, "library");
    }

    #[test]
    fn an_empty_user_agent_header_and_a_missing_one_are_the_same_rule() {
        let db = db();
        let present_but_empty = identify(&db, "").expect("empty UA should match");
        assert_eq!(present_but_empty.category, "malformed");
        assert_eq!(present_but_empty.client, "(no user-agent)");
    }

    #[test]
    fn a_bare_mozilla_five_oh_is_flagged_malformed() {
        let db = db();
        let rule = identify(&db, "Mozilla/5.0").expect("bare Mozilla/5.0 should match");
        assert_eq!(rule.category, "malformed");
    }

    #[test]
    fn http_user_agent_distinguishes_missing_header_from_non_http_payload() {
        assert_eq!(
            http_user_agent(&request("sqlmap/1.7#stable")),
            Some("sqlmap/1.7#stable".to_string())
        );
        assert_eq!(
            http_user_agent(b"GET / HTTP/1.1\r\nHost: honeypot\r\n\r\n"),
            Some(String::new())
        );
        assert_eq!(http_user_agent(b"\x16\x03\x01\x00\xa5"), None);
    }

    #[test]
    fn shipped_user_agents_db_parses() {
        let db = db();
        assert!(db.rules.len() > 15, "expected a real rule set, got {}", db.rules.len());
    }

    // ------------------------------------------------ on a session

    fn shipped() -> Box<dyn Method> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("manifests");
        let manifest = MethodManifest::from_yaml(&std::fs::read_to_string(dir.join("claimed.yaml")).unwrap()).unwrap();
        build(manifest, &dir).unwrap()
    }

    fn run(packets: &[(bool, &[u8])], is_final: bool) -> Outcome {
        let session = crate::adapters::http_request::test_support::session(packets);
        shipped().extract(&Context::new(&session, &[], is_final, false)).unwrap()
    }

    fn keys(outcome: &Outcome) -> Vec<&str> {
        outcome.evidence().iter().map(|e| e.key.as_str()).collect()
    }

    /// SSH, TLS: done from the first bytes with nothing to say, so the
    /// registry stops invoking it instead of rescanning every later packet.
    #[test]
    fn a_connection_that_is_not_http_is_done_at_once() {
        let get = b"GET / HTTP/1.1\r\nUser-Agent: curl/8.5.0\r\n\r\n";
        for first in [b"SSH-2.0-OpenSSH_9.6\r\n".as_slice(), &[0x16, 0x03, 0x01, 0x02, 0x00]] {
            let outcome = run(&[(true, first), (true, get)], false);
            assert!(matches!(&outcome, Outcome::Complete(e) if e.is_empty()), "{outcome:?}");
        }
    }

    /// A request head over two segments: waits for the second, then reads it whole.
    #[test]
    fn a_request_split_over_segments_is_read_whole() {
        let head = b"GET / HTTP/1.1\r\nHost: honeypot\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n";
        let (a, b) = head.split_at(30);
        assert!(matches!(run(&[(true, a)], false), Outcome::NoMatch));
        let outcome = run(&[(true, a), (true, b)], false);
        assert!(matches!(outcome, Outcome::Complete(_)), "{outcome:?}");
        assert!(keys(&outcome).contains(&"client"), "{outcome:?}");
    }

    /// The OS a User-Agent claims, mobile before desktop.
    #[test]
    fn the_user_agent_names_its_os() {
        let db = db();
        let os = |ua: &str| db.os.iter().find_map(|r| r.claim(&ua.to_ascii_lowercase()));
        let iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6.2 Mobile/15E148 Safari/604.1 Brave";
        assert_eq!(os(iphone).as_deref(), Some("iOS 18.7"));
        assert_eq!(os("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0").as_deref(), Some("Windows 10"));
        assert_eq!(os("Mozilla/5.0 (Linux; Android 13; Pixel 7) Chrome/120.0").as_deref(), Some("Android 13"));
        assert_eq!(os("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15").as_deref(), Some("Mac OS X 10.15.7"));
        assert_eq!(os("Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0").as_deref(), Some("Linux"));
        assert_eq!(os("Mozilla/5.0 (compatible; Microsoft-WebDAV)"), None);
        assert_eq!(os("curl/8.5.0"), None);
    }
}
