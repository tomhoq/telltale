use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::evidence::{Confidence, Evidence};
use crate::observation::Endpoint;
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Profile {
    pub verdict: Verdict,
    /// Keyed `<method>.<key>` (`f0p.os`, `banner.client`), so each method's
    /// claims stay visible side by side rather than one method's answer
    /// hiding another's. Weighing them against each other is fusion's job.
    pub attributes: HashMap<String, Attribute>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    pub value: String,
    pub confidence: Confidence,
    pub method: String,
}

/// The name an attribute is stored and shown under: `<method>.<key>`.
pub fn attribute_key(method: &str, key: &str) -> String {
    format!("{method}.{key}")
}

/// In-memory accumulator, keyed by the endpoint being judged.
#[derive(Debug, Default)]
pub struct ProfileStore {
    profiles: HashMap<Endpoint, Profile>,
}

impl ProfileStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one claim in, under its method's own name for the key. Within one
    /// method a stronger claim is kept over a weaker one; equal confidence
    /// overwrites (a streaming re-run refining its own provisional answer).
    pub fn record(&mut self, evidence: Evidence) {
        let profile = self.profiles.entry(evidence.subject).or_default();
        let key = attribute_key(&evidence.method, &evidence.key);

        let keep_existing = profile
            .attributes
            .get(&key)
            .is_some_and(|existing| existing.confidence > evidence.confidence);
        if !keep_existing {
            profile.attributes.insert(
                key,
                Attribute {
                    value: evidence.value.clone(),
                    confidence: evidence.confidence,
                    method: evidence.method.clone(),
                },
            );
        }

        profile.evidence.push(evidence);
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

    use super::*;

    fn subject() -> Endpoint {
        Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            port: 50726,
        }
    }

    fn claim(method: &str, key: &str, value: &str, confidence: Confidence) -> Evidence {
        Evidence::new(method, subject(), key, value, confidence)
    }

    #[test]
    fn the_same_key_from_two_methods_is_kept_apart() {
        let mut store = ProfileStore::new();
        store.record(claim("f0p", "client", "Safari", Confidence::Likely));
        store.record(claim("banner", "client", "curl", Confidence::Strong));

        let attributes = &store.get(&subject()).unwrap().attributes;
        assert_eq!(attributes["f0p.client"].value, "Safari");
        assert_eq!(attributes["banner.client"].value, "curl");
    }

    #[test]
    fn within_a_method_a_weaker_claim_does_not_replace_a_stronger_one() {
        let mut store = ProfileStore::new();
        store.record(claim("f0p", "os", "Linux", Confidence::Strong));
        store.record(claim("f0p", "os", "FreeBSD", Confidence::Weak));
        assert_eq!(store.get(&subject()).unwrap().attributes["f0p.os"].value, "Linux");

        store.record(claim("f0p", "os", "Linux 3.11", Confidence::Strong));
        assert_eq!(store.get(&subject()).unwrap().attributes["f0p.os"].value, "Linux 3.11");
    }
}
