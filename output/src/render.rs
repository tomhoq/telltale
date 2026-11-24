//! Turning a [`ProfileStore`] into something a human or a pipeline reads.
//!
//! Both renderers must work mid-run, not only at the end — in streaming mode
//! this gets called repeatedly on a store that is still filling up. That is why
//! provisional evidence is marked rather than hidden.

use std::cmp::Ordering;

use pf_core::profile::Attribute;
use pf_core::{Confidence, Endpoint, FieldKind, Profile, ProfileStore, Verdict};

/// Profiles sorted by verdict (scanners first), then endpoint.
fn sorted_profiles(store: &ProfileStore) -> Vec<(&Endpoint, &Profile)> {
    let mut rows: Vec<_> = store.iter().collect();
    rows.sort_by_key(|(endpoint, profile)| {
        (
            match profile.verdict {
                Verdict::Scanner => 0,
                Verdict::Unknown => 1,
                Verdict::Benign => 2,
            },
            endpoint.addr,
            endpoint.port,
        )
    });
    rows
}

pub fn render_text(store: &ProfileStore) -> String {
    let mut out = String::new();

    for (endpoint, profile) in sorted_profiles(store) {
        out.push_str(&format!(
            "{}:{} [{}]\n",
            endpoint.addr,
            endpoint.port,
            verdict_label(profile.verdict)
        ));
        let mut attributes: Vec<_> = profile.attributes.iter().collect();
        attributes.sort_by_key(|(key, _)| key.as_str());
        // The key already names the method (`f0p.os`).
        for (key, attribute) in attributes {
            // Only a classification is a guess with a confidence (see the
            // spec's confidence rule). A raw value (fingerprint, hop count,
            // header as sent) or a flag is a fact about the traffic.
            match attribute.kind {
                FieldKind::Classification => out.push_str(&format!(
                    "  {key:<20} {} ({:?})\n",
                    attribute.value, attribute.confidence
                )),
                _ => out.push_str(&format!("  {key:<20} {}\n", attribute.value)),
            }
        }
    }

    if out.is_empty() {
        out.push_str("no profiles\n");
    }
    out
}

pub fn render_json(store: &ProfileStore) -> String {
    let profiles: Vec<_> = store
        .iter()
        .map(|(endpoint, profile)| serde_json::json!({ "endpoint": endpoint, "profile": profile }))
        .collect();
    serde_json::to_string_pretty(&profiles).unwrap_or_else(|_| "[]".into())
}

/// One line per profile, for tailing a live run.
pub fn render_line(endpoint: &pf_core::Endpoint, profile: &Profile) -> String {
    let mut attributes: Vec<_> = profile.attributes.iter().collect();
    attributes.sort_by_key(|(key, _)| key.as_str());
    let attrs: String = attributes
        .iter()
        .map(|(key, attribute)| format!("{key}={}", attribute.value))
        .collect::<Vec<_>>()
        .join(" ");

    format!(
        "{}:{} {} {}({} attrs, {} evidence)",
        endpoint.addr,
        endpoint.port,
        verdict_label(profile.verdict),
        if attrs.is_empty() { String::new() } else { format!("{attrs} ") },
        profile.attributes.len(),
        profile.evidence.len()
    )
}

/// `--pretty` group headings, in the order shown. Grouping is by the kind each
/// manifest declares for the field, never by key name, so a new method's
/// output lands in the right group without a change here.
const PRETTY_GROUPS: [(FieldKind, &str); 4] = [
    (FieldKind::Classification, "answers"),
    (FieldKind::Flag, "flags"),
    (FieldKind::Score, "scores"),
    (FieldKind::RawSignature, "signatures"),
];

/// A profile's attributes of one kind: answers strongest first, everything
/// else by key.
fn attributes_of(profile: &Profile, kind: FieldKind) -> Vec<(&String, &Attribute)> {
    let mut rows: Vec<_> = profile.attributes.iter().filter(|(_, a)| a.kind == kind).collect();
    rows.sort_by(|(key_a, a), (key_b, b)| {
        let strongest_first = match kind {
            FieldKind::Classification => b.confidence.cmp(&a.confidence),
            _ => Ordering::Equal,
        };
        strongest_first.then_with(|| key_a.cmp(key_b))
    });
    rows
}

/// Every attribute in `--pretty` order: answers, flags, scores, signatures.
fn pretty_order(profile: &Profile) -> Vec<(&String, &Attribute)> {
    PRETTY_GROUPS
        .iter()
        .flat_map(|&(kind, _)| attributes_of(profile, kind))
        .collect()
}

/// `key  value  confidence`, with the confidence only on a classification
/// (only a guess has one, as in [`render_text`]).
fn pretty_row(indent: &str, key: &str, attribute: &Attribute, key_width: usize, value_width: usize) -> String {
    if attribute.kind == FieldKind::Classification {
        format!(
            "{indent}{key:<key_width$}  {:<value_width$}  {}\n",
            attribute.value,
            confidence_label(attribute.confidence)
        )
    } else {
        format!("{indent}{key:<key_width$}  {}\n", attribute.value)
    }
}

fn width<'a>(texts: impl Iterator<Item = &'a str>) -> usize {
    texts.map(|t| t.chars().count()).max().unwrap_or(0)
}

/// The end-of-capture summary for `--pretty`: one block per endpoint, its
/// attributes grouped by kind (answers first), columns aligned per group.
pub fn render_pretty(store: &ProfileStore) -> String {
    let mut out = String::new();
    for (endpoint, profile) in sorted_profiles(store) {
        out.push_str(&format!(
            "{}:{}  {}\n",
            endpoint.addr,
            endpoint.port,
            verdict_label(profile.verdict)
        ));
        if profile.attributes.is_empty() {
            out.push_str("  (no attributes)\n");
        }
        for (kind, heading) in PRETTY_GROUPS {
            let rows = attributes_of(profile, kind);
            if rows.is_empty() {
                continue;
            }
            let key_width = width(rows.iter().map(|(k, _)| k.as_str()));
            let value_width = width(rows.iter().map(|(_, a)| a.value.as_str()));
            out.push_str(&format!("  {heading}\n"));
            for (key, attribute) in rows {
                out.push_str(&pretty_row("    ", key, attribute, key_width, value_width));
            }
        }
        out.push('\n');
    }
    if out.is_empty() {
        out.push_str("no profiles\n");
    }
    out
}

/// A live update for `--pretty`: the endpoint's whole profile so far, one
/// attribute per line in `--pretty` order, wrapped in braces.
pub fn render_pretty_block(endpoint: &Endpoint, profile: &Profile) -> String {
    let rows = pretty_order(profile);
    let key_width = width(rows.iter().map(|(k, _)| k.as_str()));
    let value_width = width(
        rows.iter()
            .filter(|(_, a)| a.kind == FieldKind::Classification)
            .map(|(_, a)| a.value.as_str()),
    );
    let mut out = format!(
        "{}:{}  {} {{\n",
        endpoint.addr,
        endpoint.port,
        verdict_label(profile.verdict)
    );
    for (key, attribute) in rows {
        out.push_str(&pretty_row("  ", key, attribute, key_width, value_width));
    }
    out.push('}');
    out
}

fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Weak => "weak",
        Confidence::Likely => "likely",
        Confidence::Strong => "strong",
    }
}

fn verdict_label(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Scanner => "SCANNER",
        Verdict::Benign => "benign",
        Verdict::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use pf_core::Evidence;

    use super::*;

    const CLIENT: Endpoint = Endpoint {
        addr: IpAddr::V4(Ipv4Addr::new(45, 33, 78, 24)),
        port: 37385,
    };

    fn claim(method: &str, key: &str, value: &str, kind: FieldKind, confidence: Confidence) -> Evidence {
        let mut evidence = Evidence::new(method, CLIENT, key, value, confidence);
        evidence.kind = kind;
        evidence
    }

    /// A ZMap SYN as the shipped methods describe it: answers of mixed
    /// confidence, a score and signatures.
    fn store() -> ProfileStore {
        use Confidence::*;
        use FieldKind::*;
        let mut store = ProfileStore::new();
        for evidence in [
            claim("f0p", "signature", "4:255+19:0:1460:65535,0:mss::0", RawSignature, Weak),
            claim("f0p", "os", "Linux 2.2.x-3.x (barebone)", Classification, Weak),
            claim("ja4t", "client", "Modified ZMap", Classification, Strong),
            claim("tcpcluster", "hint-distance", "0.120", Score, Weak),
            claim("f0p", "distance", "19", RawSignature, Weak),
            claim("tcpcluster", "os", "scanner", Classification, Strong),
        ] {
            store.record(evidence);
        }
        store
    }

    #[test]
    fn pretty_groups_by_kind_answers_strongest_first() {
        let expected = "\
45.33.78.24:37385  unknown
  answers
    ja4t.client    Modified ZMap               strong
    tcpcluster.os  scanner                     strong
    f0p.os         Linux 2.2.x-3.x (barebone)  weak
  scores
    tcpcluster.hint-distance  0.120
  signatures
    f0p.distance   19
    f0p.signature  4:255+19:0:1460:65535,0:mss::0

";
        assert_eq!(render_pretty(&store()), expected);
    }

    /// One attribute per line, same order, braces around the endpoint, and
    /// the confidence column aligned over the answers only.
    #[test]
    fn pretty_live_block_is_one_attribute_per_line_in_braces() {
        let store = store();
        let expected = "\
45.33.78.24:37385  unknown {
  ja4t.client               Modified ZMap               strong
  tcpcluster.os             scanner                     strong
  f0p.os                    Linux 2.2.x-3.x (barebone)  weak
  tcpcluster.hint-distance  0.120
  f0p.distance              19
  f0p.signature             4:255+19:0:1460:65535,0:mss::0
}";
        assert_eq!(render_pretty_block(&CLIENT, store.get(&CLIENT).unwrap()), expected);
    }

    #[test]
    fn pretty_says_so_when_there_is_nothing() {
        assert_eq!(render_pretty(&ProfileStore::new()), "no profiles\n");
        let mut store = ProfileStore::new();
        store.set_verdict(CLIENT, Verdict::Unknown);
        assert_eq!(render_pretty(&store), "45.33.78.24:37385  unknown\n  (no attributes)\n\n");
    }
}
