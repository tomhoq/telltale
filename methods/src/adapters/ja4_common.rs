//! What the JA4 methods (`ja4`, `ja4h`, `ja4t`) share: FoxIO's truncated
//! hash, and the loader for their fingerprint databases
//! (`methods/db/<name>_fingerprint.csv`, ja4db exports — one file per
//! method, so each still owns its own database).
//!
//! JA4+ (everything but plain JA4) is under the FoxIO License 1.1 — see
//! `methods/db/ja4.LICENSE`; fine for this non-profit research use.

use pf_core::{Confidence, DatabaseSpec, Endpoint, Error, Evidence, MethodManifest, Result};
use sha2::{Digest, Sha256};

use crate::db::Database;

/// FoxIO's `hash12`: the first 12 hex characters of SHA-256, or twelve zeros
/// for an empty input — so "no cookies" reads as zeros rather than as the
/// hash of nothing.
pub fn hash12(s: &str) -> String {
    if s.is_empty() {
        return "0".repeat(12);
    }
    Sha256::digest(s.as_bytes())[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Which label column of the database a row filled. Decides the evidence
/// key: an OS is not a client, and a Hue bridge is neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LabelKind {
    /// `application` or `library`.
    Client,
    Device,
    Os,
}

impl LabelKind {
    pub fn key(self) -> &'static str {
        match self {
            LabelKind::Client => "client",
            LabelKind::Device => "device",
            LabelKind::Os => "os",
        }
    }
}

/// One labelled row.
#[derive(Debug, Clone)]
pub struct Entry {
    pub sections: Vec<String>,
    pub kind: LabelKind,
    pub label: String,
}

/// What one fingerprint matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub kind: LabelKind,
    /// Every distinct label the database gives this fingerprint, sorted. More
    /// than one is common — Chrome 41 through 45 share a JA4 — and all of
    /// them are the honest answer.
    pub labels: Vec<String>,
    /// Every compared section was in the entry. False when the database
    /// only had the leading ones (a partial entry).
    pub complete: bool,
}

impl Match {
    pub fn label(&self) -> String {
        self.labels.join(" | ")
    }
}

/// A JA4 fingerprint database: its labelled rows only.
///
/// The ja4db exports are mostly unlabelled sightings (a fingerprint and the
/// User-Agent it came with); only rows naming an application, library,
/// device or OS can identify anything, so only those are kept.
#[derive(Debug, Clone, Default)]
pub struct FingerprintDb {
    pub entries: Vec<Entry>,
}

impl FingerprintDb {
    /// Parse a ja4db CSV, reading the fingerprint from `column`.
    ///
    /// A fingerprint with anything but `[A-Za-z0-9_-]` in it is dropped: the
    /// exports carry some rows with raw bytes where a hash should be, and
    /// some with an unparsed language (`en;q`). Neither is a fingerprint any
    /// real computation produces.
    pub fn parse(text: &str, column: &str) -> Result<Self> {
        let bad = |reason: String| Error::Database {
            method: column.to_string(),
            reason,
        };
        let mut reader = csv::ReaderBuilder::new()
            .flexible(true)
            .from_reader(text.as_bytes());
        let header = reader.headers().map_err(|e| bad(e.to_string()))?.clone();
        let find = |name: &str| header.iter().position(|h| h.trim().eq_ignore_ascii_case(name));
        let fingerprint = find(column).ok_or_else(|| bad(format!("no `{column}` column")))?;
        let labels: Vec<(usize, LabelKind)> = [
            ("application", LabelKind::Client),
            ("library", LabelKind::Client),
            ("device", LabelKind::Device),
            ("os", LabelKind::Os),
        ]
        .into_iter()
        .filter_map(|(name, kind)| find(name).map(|i| (i, kind)))
        .collect();

        let mut entries = Vec::new();
        for record in reader.records() {
            // One malformed row is dropped, not the whole database.
            let Ok(record) = record else { continue };
            let Some(value) = record.get(fingerprint).map(str::trim) else {
                continue;
            };
            let well_formed = !value.is_empty()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
            if !well_formed {
                continue;
            }
            let Some((label, kind)) = labels.iter().find_map(|&(i, kind)| {
                let label = record.get(i)?.trim();
                (!label.is_empty()).then(|| (label.to_string(), kind))
            }) else {
                continue;
            };
            entries.push(Entry {
                sections: value.split('_').map(str::to_string).collect(),
                kind,
                label,
            });
        }
        Ok(Self { entries })
    }

    /// Match `fingerprint` on its first `sections` sections only. The rest
    /// are left out on purpose, per method: JA4H's cookie values differ per
    /// visitor, JA4TScan's retransmission timings are not in a passive JA4T.
    ///
    /// An entry with fewer sections than that matches on the ones it has
    /// (the database leaves out a per-victim section for some malware). A
    /// hash section shorter than 12 hex characters matches as a prefix: the
    /// database has a few truncated ones (Cobalt Strike's `4da5efaf0cb`).
    ///
    /// Of the entries that match, the most specific win; their labels are
    /// merged, one [`Match`] per label kind.
    pub fn lookup(&self, fingerprint: &str, sections: usize) -> Vec<Match> {
        let observed: Vec<&str> = fingerprint.split('_').take(sections).collect();
        // How many sections of an entry take part: never past the limit.
        let compared = |entry: &Entry| entry.sections.len().min(sections);
        let fits = |entry: &Entry| {
            compared(entry) <= observed.len()
                && entry.sections[..compared(entry)].iter().zip(&observed).all(|(want, got)| {
                    want == got || (is_truncated_hash(want) && got.starts_with(want.as_str()))
                })
        };
        let matched: Vec<&Entry> = self.entries.iter().filter(|e| fits(e)).collect();
        let Some(best) = matched.iter().map(|e| compared(e)).max() else {
            return Vec::new();
        };

        let mut by_kind: Vec<Match> = Vec::new();
        for entry in matched.into_iter().filter(|e| compared(e) == best) {
            let found = match by_kind.iter_mut().find(|m| m.kind == entry.kind) {
                Some(found) => found,
                None => {
                    by_kind.push(Match {
                        kind: entry.kind,
                        labels: Vec::new(),
                        complete: best == observed.len(),
                    });
                    by_kind.last_mut().expect("just pushed")
                }
            };
            if !found.labels.contains(&entry.label) {
                found.labels.push(entry.label.clone());
            }
        }
        for found in &mut by_kind {
            found.labels.sort();
        }
        by_kind.sort_by_key(|m| m.kind);
        by_kind
    }
}

/// One evidence item per matched label kind (`client`, `device`, `os`).
/// Strong only when the entry covered every compared section and named one
/// thing; a partial entry or a fingerprint several labels share is Likely.
pub fn label_evidence(method: &str, subject: Endpoint, matches: &[Match]) -> Vec<Evidence> {
    matches
        .iter()
        .map(|found| {
            let confidence = if found.complete && found.labels.len() == 1 {
                Confidence::Strong
            } else {
                Confidence::Likely
            };
            Evidence::new(method, subject, found.kind.key(), found.label(), confidence)
        })
        .collect()
}

/// How many leading sections a method matches on, from its manifest's
/// `match-sections` param.
pub fn match_sections(manifest: &MethodManifest, default: usize) -> usize {
    manifest.param("match-sections", default)
}

fn is_truncated_hash(section: &str) -> bool {
    (8..12).contains(&section.len()) && section.bytes().all(|b| b.is_ascii_hexdigit())
}

macro_rules! fingerprint_db {
    ($name:ident, $column:literal) => {
        #[doc = concat!("The `", $column, "` database.")]
        #[derive(Debug, Clone, Default)]
        pub struct $name(pub FingerprintDb);

        impl Database for $name {
            const FORMATS: &'static [&'static str] = &["ja4db-csv"];

            fn load(text: &str, _spec: &DatabaseSpec) -> Result<Self> {
                FingerprintDb::parse(text, $column).map($name)
            }
        }
    };
}

fingerprint_db!(Ja4Db, "ja4_fingerprint");
fingerprint_db!(Ja4hDb, "ja4h_fingerprint");
fingerprint_db!(Ja4tDb, "ja4t_fingerprint");

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str =
        "application,library,device,os,user_agent_string,certificate_authority,verified,notes,observation_count,ja4h_fingerprint\n";

    fn db(rows: &str) -> FingerprintDb {
        FingerprintDb::parse(&format!("{HEADER}{rows}"), "ja4h_fingerprint").unwrap()
    }

    #[test]
    fn hash12_matches_foxio() {
        // FoxIO's own test vector.
        assert_eq!(hash12("551d0f,551d25,551d11"), "aae71e8db6d7");
        assert_eq!(hash12(""), "000000000000");
    }

    #[test]
    fn sections_past_the_limit_are_ignored() {
        // The database's `d` is the hash of an empty string; ours is zeros.
        let db = db("curl,,,,,,true,,1,ge11nn030000_fe444ad14866_000000000000_e3b0c44298fc\n");
        let found = db.lookup("ge11nn030000_fe444ad14866_000000000000_000000000000", 3);
        assert_eq!(found[0].label(), "curl");
        assert!(found[0].complete);
        assert!(db.lookup("ge11nn030000_fe444ad14866_000000000000_000000000000", 4).is_empty());
    }

    #[test]
    fn a_partial_or_truncated_entry_matches_but_is_not_complete() {
        let db = db("IcedID Dropper,,,,,,true,,1,ge11cn020000_9ed1ff1f7b03\n\
                     Cobalt Strike beacon,,,,,,true,,1,ge11cn060000_4e59edc1297a_4da5efaf0cb\n");
        let icedid = db.lookup("ge11cn020000_9ed1ff1f7b03_cd8dafe26982_111111111111", 3);
        assert_eq!(icedid[0].label(), "IcedID Dropper");
        assert!(!icedid[0].complete);
        let cobalt = db.lookup("ge11cn060000_4e59edc1297a_4da5efaf0cb7_222222222222", 3);
        assert_eq!(cobalt[0].label(), "Cobalt Strike beacon");
    }

    #[test]
    fn a_short_non_hash_section_is_not_a_prefix() {
        let db = FingerprintDb::parse(
            "application,library,device,os,ja4t_fingerprint\nNmap,,,,1024_2_1460_00\n",
            "ja4t_fingerprint",
        )
        .unwrap();
        assert!(db.lookup("1024_2-4-8_1460_00", 4).is_empty());
    }

    #[test]
    fn several_labels_for_one_fingerprint_are_all_reported() {
        let db = db("Chrome 42.0,,,,,,true,,1,ge11nn11enus_aaaaaaaaaaaa_000000000000_000000000000\n\
                     Chrome 41.0,,,,,,true,,1,ge11nn11enus_aaaaaaaaaaaa_000000000000_000000000000\n\
                     ,,,Windows 10,,,true,,1,ge11nn11enus_aaaaaaaaaaaa_000000000000_000000000000\n");
        let found = db.lookup("ge11nn11enus_aaaaaaaaaaaa_000000000000_000000000000", 3);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].label(), "Chrome 41.0 | Chrome 42.0");
        assert_eq!(found[1].kind, LabelKind::Os);
    }

    #[test]
    fn unlabelled_and_malformed_rows_are_dropped() {
        let db = db(",,,,curl/8.0,,false,,1,ge11nn030000_fe444ad14866_000000000000_e3b0c44298fc\n\
                     Junk,,,,,,true,,1,ge10nn11en;q_98f2d2d6eb8f_000000000000_e\n\
                     Junk,,,,,,true,,1,\"t12d000600_\x03\nP\x7fCN_e28d05d9ca73\"\n");
        assert!(db.entries.is_empty(), "{:?}", db.entries);
    }
}
