use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::evidence::{Confidence, Evidence};
use crate::observation::Endpoint;
use crate::report::Report;
use crate::session::SessionId;
/* Profile.rs

Stores classification and attribute information about endpoints, keyed by the endpoint itself.
*/

/// High-level classification of the observed endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    #[default]
    Unknown,
    Benign,
    /// Automated scanner classification.
    Scanner,
}

/// Everything currently believed about one endpoint.
///
/// Derived, never edited in place: [`ProfileStore`] rebuilds it from the
/// latest report of every session that mentions the endpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Profile {
    pub verdict: Verdict,
    pub attributes: HashMap<String, Attribute>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    pub value: String,
    pub confidence: Confidence,
    pub method: String,
}

impl Profile {
    /// Fold one claim in. Stronger confidence wins; at equal confidence the
    /// later claim wins.
    fn fold(&mut self, evidence: Evidence) {
        match self.attributes.get(&evidence.key) {
            Some(existing) if existing.confidence > evidence.confidence => {}
            // TODO: conflicting equal-confidence claims from different methods.
            // Taking the later one is a placeholder — decide whether to keep
            // both and let fusion arbitrate.
            _ => {
                self.attributes.insert(
                    evidence.key.clone(),
                    Attribute {
                        value: evidence.value.clone(),
                        confidence: evidence.confidence,
                        method: evidence.method.clone(),
                    },
                );
            }
        }
        self.evidence.push(evidence);
    }
}

/// In-memory accumulator, keyed by the endpoint being judged.
#[derive(Debug, Default)]
pub struct ProfileStore {
    profiles: HashMap<Endpoint, Profile>,
    /// The current report for every session; profiles are rebuilt from these.
    reports: HashMap<SessionId, Report>,
    /// Which sessions' current reports mention each endpoint, so a rebuild
    /// touches only those.
    mentions: HashMap<Endpoint, HashSet<SessionId>>,
}

impl ProfileStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take in one pass's report, replacing that session's previous one.
    ///
    /// A report older than the one already held — an earlier provisional pass
    /// that finished after a later one — is dropped, so a final answer is
    /// never overwritten by a stale guess. Returns whether anything changed.
    pub fn apply(&mut self, report: Report) -> bool {
        let id = report.session;
        if self
            .reports
            .get(&id)
            .is_some_and(|current| current.revision >= report.revision)
        {
            return false;
        }

        let now: HashSet<Endpoint> = report.evidence.iter().map(|e| e.subject).collect();
        let before: HashSet<Endpoint> = self
            .reports
            .insert(id, report)
            .map(|old| old.evidence.iter().map(|e| e.subject).collect())
            .unwrap_or_default();

        for subject in before.difference(&now) {
            if let Some(sessions) = self.mentions.get_mut(subject) {
                sessions.remove(&id);
            }
        }
        for subject in &now {
            self.mentions.entry(*subject).or_default().insert(id);
        }

        for subject in before.union(&now) {
            self.rebuild(*subject);
        }
        true
    }

    /// Recompute one endpoint's profile from its sessions' current reports.
    ///
    /// Cost grows with the number of sessions that mention the endpoint. The
    /// subject includes the source port, so that is normally one; a scanner
    /// reusing a fixed source port is the case that would make this hot.
    fn rebuild(&mut self, subject: Endpoint) {
        let mut reports: Vec<&Report> = self
            .mentions
            .get(&subject)
            .into_iter()
            .flatten()
            .filter_map(|id| self.reports.get(id))
            .collect();

        // Nothing mentions it any more, and no verdict was set by hand.
        if reports.is_empty()
            && self
                .profiles
                .get(&subject)
                .map_or(true, |p| p.verdict == Verdict::Unknown)
        {
            self.profiles.remove(&subject);
            self.mentions.remove(&subject);
            return;
        }

        // Packet-time order, so "the later claim wins" does not depend on
        // which worker finished first.
        reports.sort_by_key(|report| report.session.started_at);

        let profile = self.profiles.entry(subject).or_default();
        profile.attributes.clear();
        profile.evidence.clear();
        for evidence in reports
            .iter()
            .flat_map(|report| &report.evidence)
            .filter(|evidence| evidence.subject == subject)
        {
            profile.fold(evidence.clone());
        }
    }

    pub fn set_verdict(&mut self, subject: Endpoint, verdict: Verdict) {
        self.profiles.entry(subject).or_default().verdict = verdict;
    }

    pub fn get(&self, subject: &Endpoint) -> Option<&Profile> {
        self.profiles.get(subject)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Endpoint, &Profile)> {
        self.profiles.iter()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::observation::Transport;
    use crate::report::Revision;
    use crate::session::SessionKey;

    fn endpoint(port: u16) -> Endpoint {
        Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port,
        }
    }

    fn session(started_secs: u64) -> SessionId {
        SessionId {
            key: SessionKey::new(endpoint(40000), endpoint(22), Transport::Tcp),
            started_at: SystemTime::UNIX_EPOCH + Duration::from_secs(started_secs),
        }
    }

    fn report(session: SessionId, observations: usize, is_final: bool, os: &str) -> Report {
        Report {
            session,
            revision: Revision { observations, is_final },
            evidence: vec![Evidence::new("tcp-syn", endpoint(40000), "os", os, Confidence::Likely)],
        }
    }

    fn os(store: &ProfileStore) -> Option<&str> {
        let profile = store.get(&endpoint(40000))?;
        profile.attributes.get("os").map(|a| a.value.as_str())
    }

    #[test]
    fn a_newer_pass_replaces_rather_than_appends() {
        let mut store = ProfileStore::new();
        store.apply(report(session(0), 1, false, "linux"));
        store.apply(report(session(0), 5, true, "windows"));

        assert_eq!(os(&store), Some("windows"));
        assert_eq!(store.get(&endpoint(40000)).unwrap().evidence.len(), 1);
    }

    #[test]
    fn a_stale_pass_arriving_late_is_ignored() {
        let mut store = ProfileStore::new();
        assert!(store.apply(report(session(0), 5, true, "windows")));
        assert!(!store.apply(report(session(0), 3, false, "linux")));

        assert_eq!(os(&store), Some("windows"));
    }

    #[test]
    fn the_final_pass_beats_a_provisional_one_over_the_same_packets() {
        let mut store = ProfileStore::new();
        store.apply(report(session(0), 5, true, "windows"));
        assert!(!store.apply(report(session(0), 5, false, "linux")));

        assert_eq!(os(&store), Some("windows"));
    }

    #[test]
    fn a_claim_a_later_pass_drops_disappears() {
        let mut store = ProfileStore::new();
        store.apply(report(session(0), 1, false, "linux"));
        store.apply(Report {
            evidence: Vec::new(),
            ..report(session(0), 5, true, "")
        });

        assert!(store.get(&endpoint(40000)).is_none());
    }

    #[test]
    fn a_reopened_flow_does_not_replace_the_earlier_session() {
        let mut store = ProfileStore::new();
        store.apply(report(session(0), 5, true, "linux"));
        store.apply(report(session(100), 1, false, "linux"));

        assert_eq!(store.get(&endpoint(40000)).unwrap().evidence.len(), 2);
    }
}
