use serde::{Deserialize, Serialize};

use crate::observation::Endpoint;

/// A single claim a method makes about an endpoint.
///
/// Deliberately flat: the fusion method consumes evidence from every other
/// method, so a shared shape matters more than expressiveness. `key` must be
/// declared in the producing method's `OutputSchema`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Producing method's name, matching its manifest.
    pub method: String,
    pub subject: Endpoint,
    pub key: String,
    pub value: String,
    pub confidence: Confidence,
    /// True when produced before the session finished, so a later invocation may
    /// supersede it.
    #[serde(default)]
    pub provisional: bool,
}

impl Evidence {
    pub fn new(
        method: impl Into<String>,
        subject: Endpoint,
        key: impl Into<String>,
        value: impl Into<String>,
        confidence: Confidence,
    ) -> Self {
        Self {
            method: method.into(),
            subject,
            key: key.into(),
            value: value.into(),
            confidence,
            provisional: false,
        }
    }

    pub fn provisional(mut self) -> Self {
        self.provisional = true;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    Weak,
    Likely,
    Strong,
}
