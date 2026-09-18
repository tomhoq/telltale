//! Identifies client software from the HTTP `User-Agent` header, matched
//! against a hand-maintained list of known libraries, scanners, and research
//! crawlers — exactly the traffic a honeypot's HTTP surface actually sees.
//!
//! SSH/FTP banners are a natural future extension (the manifest's
//! `required-stage: app-data` is already protocol-agnostic) but nothing
//! needs them yet, so this only looks at HTTP for now.

use std::path::Path;

use pf_core::{Confidence, Context, Evidence, Method, MethodManifest, Outcome, Result};
use serde::Deserialize;

use crate::db::{self, Database};

/// One `methods/db/banners.yaml` entry. A rule fires when the observed
/// User-Agent matches *any* of its patterns — several real-world variants of
/// the same tool often need separate patterns (e.g. ZAP's UA has changed
/// naming across versions).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct BannerRule {
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

impl BannerRule {
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

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct BannerDb {
    #[serde(default)]
    pub rules: Vec<BannerRule>,
}

impl Database for BannerDb {
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
fn extract_version(user_agent: &str, ua_lower: &str, rule: &BannerRule) -> Option<String> {
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

pub struct Banner {
    manifest: MethodManifest,
    db: BannerDb,
    /// Cap on how many bytes to scan, so a large transfer cannot make this
    /// method expensive.
    max_bytes: usize,
}

pub fn build(manifest: MethodManifest, manifest_dir: &Path) -> Result<Box<dyn Method>> {
    let max_bytes = manifest.param("max-bytes", 4096);
    let db = manifest
        .database
        .as_ref()
        .map(|spec| db::load::<BannerDb>(&manifest.name, spec, manifest_dir))
        .transpose()?
        .unwrap_or_default();

    Ok(Box::new(Banner {
        manifest,
        db,
        max_bytes,
    }))
}

impl Method for Banner {
    fn manifest(&self) -> &MethodManifest {
        &self.manifest
    }

    fn extract(&self, ctx: &Context<'_>) -> Result<Outcome> {
        let scanned: usize = ctx
            .observations()
            .map(|o| o.payload.len())
            .take_while(|len| *len <= self.max_bytes)
            .sum();

        if scanned == 0 {
            return Ok(Outcome::NotApplicable);
        }

        let Some(user_agent) = ctx.observations().find_map(|o| http_user_agent(&o.payload)) else {
            return Ok(Outcome::NoMatch);
        };

        let ua_lower = user_agent.to_ascii_lowercase();
        let Some(rule) = self.db.rules.iter().find(|r| r.matches(&ua_lower)) else {
            return Ok(Outcome::NoMatch);
        };

        // A string match here is about as certain as passive fingerprinting
        // gets — no fuzzy scoring involved, unlike f0p's TCP signatures.
        let mut evidence = vec![
            Evidence::new(self.name(), ctx.session.initiator, "client", rule.client.clone(), Confidence::Strong),
            Evidence::new(self.name(), ctx.session.initiator, "category", rule.category.clone(), Confidence::Strong),
        ];
        if let Some(version) = extract_version(&user_agent, &ua_lower, rule) {
            evidence.push(Evidence::new(
                self.name(),
                ctx.session.initiator,
                "version",
                version,
                Confidence::Strong,
            ));
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

    fn db() -> BannerDb {
        serde_yaml::from_str(include_str!("../../db/banners.yaml"))
            .expect("shipped banners.yaml should parse")
    }

    fn request(user_agent: &str) -> Vec<u8> {
        format!("GET / HTTP/1.1\r\nHost: honeypot\r\nUser-Agent: {user_agent}\r\nAccept: */*\r\n\r\n")
            .into_bytes()
    }

    fn identify<'a>(db: &'a BannerDb, user_agent: &str) -> Option<&'a BannerRule> {
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
        // banner's — banner only identifies.
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
    fn shipped_banners_db_parses() {
        let db = db();
        assert!(db.rules.len() > 15, "expected a real rule set, got {}", db.rules.len());
    }
}
