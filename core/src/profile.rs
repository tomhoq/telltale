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
    pub attributes: HashMap<String, Attribute>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    pub value: String,
    pub confidence: Confidence,
    pub method: String,
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

    /// Fold one claim in. Stronger confidence wins; equal confidence from the
    /// same method overwrites (a streaming re-run refining its own provisional
    /// answer); equal confidence from a different method is a genuine conflict.
    pub fn record(&mut self, evidence: Evidence) {
        let profile = self.profiles.entry(evidence.subject).or_default();

        match profile.attributes.get(&evidence.key) {
            Some(existing) if existing.confidence > evidence.confidence => {}
            Some(existing)
                if existing.confidence == evidence.confidence
                    && existing.method != evidence.method
                    && existing.value != evidence.value =>
            {
                // TODO: conflicting equal-confidence claims from different
                // methods. Recording the newest is a placeholder — decide
                // whether to keep both and let fusion arbitrate.
                profile.attributes.insert(
                    evidence.key.clone(),
                    Attribute {
                        value: evidence.value.clone(),
                        confidence: evidence.confidence,
                        method: evidence.method.clone(),
                    },
                );
            }
            _ => {
                profile.attributes.insert(
                    evidence.key.clone(),
                    Attribute {
                        value: evidence.value.clone(),
                        confidence: evidence.confidence,
                        method: evidence.method.clone(),
                    },
                );
            }
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
