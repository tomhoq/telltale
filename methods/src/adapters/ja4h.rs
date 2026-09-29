//! JA4H: FoxIO's HTTP client fingerprint, computed in-process from the
//! client's first HTTP/1.x request. FoxIO's `ja4` CLI is the reference to
//! check this against, not something this calls.
//!
//! `ja4h = a_b_c_d`:
//! - `a`: method (2 letters), version (`10`/`11`), `c`/`n` for a Cookie
//!   header, `r`/`n` for a Referer, header count (not counting those two,
//!   capped at 99), and the first 4 characters of the primary
//!   Accept-Language with hyphens dropped, zero-padded (`enus`, or `0000`
//!   when there is none).
//! - `b`: hash of the header names in wire order, Cookie and Referer left out.
//! - `c`: hash of the sorted cookie names.
//! - `d`: hash of the sorted cookie name=value pairs.
//!
//! Unlike `claimed`, this is how the client behaves, not what it says: a
//! tool can copy a browser's User-Agent far more easily than its header
//! order. A hit in `ja4h_fingerprint.csv` (Cobalt Strike, IcedID, curl,
//! browsers, ...) is reported as the client, device or OS it names; the
//! lookup ignores `d` (see [`Ja4h::sections`]).
//!
//! JA4H licensing: FoxIO License 1.1 (see `methods/db/ja4.LICENSE`); fine for
//! this non-profit research use.
//!
//! Not covered: HTTP/2, which on a honeypot arrives inside TLS and never
//! reaches this method as plaintext.

use std::path::Path;

use pf_core::{Confidence, Context, Evidence, Method, MethodManifest, Outcome, Result};

use super::ja4_common::{hash12, label_evidence, match_sections, Ja4hDb};
use crate::db;

/// JA4H's two-letter method codes. Any other method is not fingerprinted,
/// as in FoxIO's implementation.
const METHODS: [(&str, &str); 9] = [
    ("CONNECT", "co"),
    ("DELETE", "de"),
    ("GET", "ge"),
    ("HEAD", "he"),
    ("OPTIONS", "op"),
    ("PATCH", "pa"),
    ("POST", "po"),
    ("PUT", "pu"),
    ("TRACE", "tr"),
];

/// The parts of one HTTP/1.x request JA4H is made of. Header names keep their
/// wire case: JA4H hashes them as sent, so `user-agent` and `User-Agent` are
/// different clients.
#[derive(Debug)]
struct Request {
    method: &'static str,
    version: &'static str,
    has_cookie: bool,
    has_referer: bool,
    /// Every header name but Cookie and Referer, in order, duplicates kept.
    headers: Vec<String>,
    accept_language: Option<String>,
    /// From the first Cookie header, split on `; `, value `None` for a bare
    /// name.
    cookies: Vec<(String, Option<String>)>,
}

impl Request {
    /// `None` for anything but a complete HTTP/1.x request head. Complete
    /// matters: a head cut off mid-segment would count too few headers and
    /// yield a fingerprint no real client has.
    fn parse(payload: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(payload).ok()?;
        let (head, _body) = text.split_once("\r\n\r\n")?;
        let mut lines = head.split("\r\n");

        let mut request_line = lines.next()?.split(' ');
        let method = request_line.next()?;
        let method = METHODS.iter().find(|(m, _)| *m == method)?.1;
        let _target = request_line.next()?;
        let version = match request_line.next()? {
            "HTTP/1.0" => "10",
            "HTTP/1.1" => "11",
            _ => return None,
        };

        let mut request = Request {
            method,
            version,
            has_cookie: false,
            has_referer: false,
            headers: Vec::new(),
            accept_language: None,
            cookies: Vec::new(),
        };
        for line in lines {
            let (name, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.trim();
            if name.eq_ignore_ascii_case("cookie") {
                if !request.has_cookie {
                    request.cookies = value
                        .split("; ")
                        .filter(|c| !c.is_empty())
                        .map(|c| match c.split_once('=') {
                            Some((n, v)) => (n.to_string(), Some(v.to_string())),
                            None => (c.to_string(), None),
                        })
                        .collect();
                }
                request.has_cookie = true;
            } else if name.eq_ignore_ascii_case("referer") {
                request.has_referer = true;
            } else {
                if name.eq_ignore_ascii_case("accept-language") && request.accept_language.is_none() {
                    request.accept_language = Some(value.to_string());
                }
                request.headers.push(name.to_string());
            }
        }
        Some(request)
    }

    /// `ja4h_a`, the readable part.
    fn prefix(&self) -> String {
        format!(
            "{}{}{}{}{:02}{}",
            self.method,
            self.version,
            if self.has_cookie { 'c' } else { 'n' },
            if self.has_referer { 'r' } else { 'n' },
            self.headers.len().min(99),
            primary_language(self.accept_language.as_deref().unwrap_or("")),
        )
    }

    fn fingerprint(&self) -> String {
        let mut cookies = self.cookies.clone();
        cookies.sort_unstable();
        let names = cookies
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let pairs = cookies
            .iter()
            .map(|(name, value)| match value {
                Some(value) => format!("{name}={value}"),
                None => name.clone(),
            })
            .collect::<Vec<_>>()
            .join(",");
        let headers = self.headers.join(",");
        format!(
            "{}_{}_{}_{}",
            self.prefix(),
            hash12(&headers),
            hash12(&names),
            hash12(&pairs)
        )
    }
}

/// `en-US,en;q=0.9` -> `enus`: the first language, hyphens dropped, lower
/// case, cut or zero-padded to 4. No Accept-Language at all is `0000`.
fn primary_language(accept_language: &str) -> String {
    let mut lang: String = accept_language
        .trim_start()
        .split(',')
        .next()
        .unwrap_or("")
        .replace('-', "")
        .to_lowercase()
        .chars()
        .take(4)
        .collect();
    while lang.chars().count() < 4 {
        lang.push('0');
    }
    lang
}

pub struct Ja4h {
    manifest: MethodManifest,
    db: Ja4hDb,
    /// Sections the database lookup compares: `a_b_c` by default. `d` is the
    /// cookie values, which differ per visitor (session IDs), so no database
    /// entry could match it for anyone but the visitor it was recorded from.
    sections: usize,
}

pub fn build(manifest: MethodManifest, manifest_dir: &Path) -> Result<Box<dyn Method>> {
    let db = manifest
        .database
        .as_ref()
        .map(|spec| db::load::<Ja4hDb>(&manifest.name, spec, manifest_dir))
        .transpose()?
        .unwrap_or_default();
    let sections = match_sections(&manifest, 3);
    Ok(Box::new(Ja4h { manifest, db, sections }))
}

impl Method for Ja4h {
    fn manifest(&self) -> &MethodManifest {
        &self.manifest
    }

    fn extract(&self, ctx: &Context<'_>) -> Result<Outcome> {
        let Some(request) = ctx.observations().find_map(|o| Request::parse(&o.payload)) else {
            return Ok(Outcome::NoMatch);
        };
        let ja4h = request.fingerprint();

        let subject = ctx.session.initiator;
        let matches = self.db.0.lookup(&ja4h, self.sections);
        let mut evidence = label_evidence(self.name(), subject, &matches);
        evidence.push(Evidence::new(self.name(), subject, "ja4h", ja4h, Confidence::Weak));
        // The first request is the one fingerprinted; later ones on the same
        // connection do not change it.
        Ok(Outcome::Complete(evidence))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FoxIO's own test case (`rust/ja4/src/http.rs`), rebuilt as the wire
    /// request it came from.
    fn cnn_request() -> Vec<u8> {
        let cookie = "FastAB=0=6859,1=8174,2=4183,3=3319,4=3917,5=2557,6=4259,7=6070,8=0804,9=6453,10=1942,11=4435,12=4143,13=9445,14=6957,15=8682,16=1885,17=1825,18=3760,19=0929; sato=1; countryCode=US; stateCode=VA; geoData=purcellville|VA|20132|US|NA|-400|broadband|39.160|-77.700|511; usprivacy=1---; umto=1; _dd_s=logs=1&id=b5c2d770-eaba-4847-8202-390c4552ff9a&created=1686159462724&expire=1686160422726";
        format!(
            "GET / HTTP/1.1\r\n\
             Host: www.cnn.com\r\n\
             Cookie: {cookie}\r\n\
             Sec-Ch-Ua: \r\n\
             Sec-Ch-Ua-Mobile: ?0\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/114.0.5735.110\r\n\
             Sec-Ch-Ua-Platform: \"\"\r\n\
             Accept: */*\r\n\
             Sec-Fetch-Site: same-origin\r\n\
             Sec-Fetch-Mode: cors\r\n\
             Sec-Fetch-Dest: empty\r\n\
             Sec-Fetch-Mode: cors\r\n\
             Sec-Fetch-Dest: empty\r\n\
             Referer: https://www.cnn.com/\r\n\
             Accept-Encoding: gzip, deflate\r\n\
             Accept-Language: en-US,en;q=0.9\r\n\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn matches_foxios_reference_fingerprint() {
        let ja4h = Request::parse(&cnn_request()).unwrap().fingerprint();
        assert_eq!(ja4h, "ge11cr13enus_88d2d584d47f_0f2659b474bf_161698816dab");
    }

    /// curl sends Host, User-Agent, Accept — no language, no cookies.
    #[test]
    fn curl_has_no_language_and_zero_cookie_hashes() {
        let request = Request::parse(
            b"GET / HTTP/1.1\r\nHost: honeypot\r\nUser-Agent: curl/8.4.0\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        let ja4h = request.fingerprint();
        assert!(ja4h.starts_with("ge11nn030000_"), "{ja4h}");
        assert!(ja4h.ends_with("_000000000000_000000000000"), "{ja4h}");
    }

    #[test]
    fn curl_is_labelled_from_the_shipped_database() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("db/ja4h_fingerprint.csv");
        let db = super::super::ja4_common::FingerprintDb::parse(
            &std::fs::read_to_string(path).unwrap(),
            "ja4h_fingerprint",
        )
        .unwrap();
        let ja4h = Request::parse(
            b"GET / HTTP/1.1\r\nHost: honeypot\r\nUser-Agent: curl/8.4.0\r\nAccept: */*\r\n\r\n",
        )
        .unwrap()
        .fingerprint();
        let found = db.lookup(&ja4h, 3);
        assert_eq!(found.len(), 1, "{ja4h}: {found:?}");
        assert_eq!(found[0].label(), "curl");
        assert!(found[0].complete);
    }

    #[test]
    fn primary_language_follows_foxio() {
        assert_eq!(primary_language("da, en-GB;q=0.8, en;q=0.7"), "da00");
        assert_eq!(primary_language("en-US,en;q=0.9"), "enus");
        assert_eq!(primary_language(""), "0000");
    }

    #[test]
    fn an_unfinished_head_or_non_http_is_not_fingerprinted() {
        assert!(Request::parse(b"GET / HTTP/1.1\r\nHost: honeypot\r\n").is_none());
        assert!(Request::parse(b"\x16\x03\x01\x00\xa5").is_none());
        assert!(Request::parse(b"FOO / HTTP/1.1\r\n\r\n").is_none());
    }
}
