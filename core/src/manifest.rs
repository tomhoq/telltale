//! Method manifests: the YAML surface that makes the tool extensible.
//!
//! A method is declared in YAML — what stage of a session it needs, when to run
//! it, which database it owns, what it emits, and its tunable parameters — and
//! implemented in Rust by an adapter that provides [`crate::Method::extract`].
//! Trying a different parameter configuration, or disabling a method, should
//! never require a recompile.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::session::Stage;

/// One `methods/manifests/*.yaml` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct MethodManifest {
    /// Must match the adapter registered in `pf-methods`.
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// The method is not invoked until the session has reached this stage.
    pub required_stage: Stage,

    pub invocation: Invocation,

    /// This method's own reference data. Each method owns its database rather
    /// than sharing one: p0f signatures, ja4 hash lists, and the fusion method's
    /// combination rules have nothing useful in common.
    #[serde(default)]
    pub database: Option<DatabaseSpec>,

    pub output: OutputSchema,

    /// Free-form knobs read by the adapter. Untyped on purpose — this is where
    /// parameter sweeps happen without touching Rust.
    #[serde(default)]
    pub params: BTreeMap<String, serde_yaml::Value>,
}

impl MethodManifest {
    pub fn from_yaml(yaml: &str) -> crate::Result<Self> {
        Ok(serde_yaml::from_str(yaml)?)
    }

    /// Typed access to a `params` entry, with the adapter's default.
    pub fn param<T: serde::de::DeserializeOwned>(&self, key: &str, default: T) -> T {
        self.params
            .get(key)
            .and_then(|v| serde_yaml::from_value(v.clone()).ok())
            .unwrap_or(default)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Invocation {
    pub trigger: Trigger,
    /// Higher runs first. Fusion methods want a low priority so the evidence
    /// they combine already exists.
    #[serde(default)]
    pub priority: i32,
    /// Give up on a single invocation after this long, in milliseconds.
    #[serde(default = "default_budget_ms")]
    pub budget_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Trigger {
    /// Run once, the first time `required_stage` is reached; its result is
    /// reused for the rest of the session. Run again only if it returned
    /// `Outcome::Partial`, which asks for more of the session.
    StageReached,
    /// Re-run on every new observation once the stage is reached, whatever it
    /// returned last time. Streaming mode only; requires `extract()` to be
    /// idempotent over the session-so-far.
    EveryObservation,
    /// Run once when the session closes or times out.
    SessionEnd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DatabaseSpec {
    /// Relative to the manifest's directory.
    pub path: String,
    /// Adapter-defined, e.g. `p0f`, `json-lines`, `rules`.
    pub format: String,
}

/// What the method promises to emit. The registry validates evidence against
/// this so a manifest and its adapter cannot silently drift apart.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct OutputSchema {
    pub fields: Vec<FieldSpec>,
}

impl OutputSchema {
    pub fn declares(&self, key: &str) -> bool {
        self.fields.iter().any(|f| f.name == key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FieldSpec {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

fn default_true() -> bool {
    true
}

fn default_budget_ms() -> u64 {
    250
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_manifest() {
        let manifest = MethodManifest::from_yaml(
            r#"
name: tcp-syn
required-stage: connect
invocation:
  trigger: stage-reached
output:
  fields:
    - name: os
"#,
        )
        .expect("manifest should parse");

        assert_eq!(manifest.name, "tcp-syn");
        assert_eq!(manifest.required_stage, Stage::Connect);
        assert!(manifest.enabled);
        assert!(manifest.output.declares("os"));
    }
}
