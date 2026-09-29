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
    /// What sort of value this is, from the producing method's output schema.
    /// Stamped by the registry, never by the method itself.
    #[serde(default)]
    pub kind: FieldKind,
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
            kind: FieldKind::default(),
            provisional: false,
        }
    }

    pub fn provisional(mut self) -> Self {
        self.provisional = true;
        self
    }
}

/// The spec's fixed output vocabulary. Only a `classification` is a
/// conclusion with a meaningful confidence; a `raw-signature` is what was
/// measured on the wire (a fingerprint, a hop count, a header as sent), so
/// renderers show it without one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FieldKind {
    #[default]
    Classification,
    Flag,
    Score,
    RawSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    Weak,
    Likely,
    Strong,
}
