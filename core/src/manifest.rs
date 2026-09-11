//! Method manifests: the YAML surface that makes the tool extensible.
//!
//! A method is declared in YAML — its layer, the protocol events that fire it,
//! how it is invoked, which database it owns, what it emits, and its tunable
//! parameters — and implemented in Rust by an adapter (or an external program).
//! The manifest is metadata and configuration only: no parsing logic lives in
//! YAML. Trying a different parameter configuration, or disabling a method,
//! never requires a recompile.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::trigger::TriggerEvent;

/// One `methods/manifests/*.yaml` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct MethodManifest {
    /// Unique among loaded manifests; what results are attributed to.
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_true")]
    pub enabled: bool,

    pub layer: Layer,

    /// The protocol events that fire this method. Each event on each packet
    /// fires it once, with that packet.
    pub triggers: Vec<TriggerEvent>,

    pub invocation: Invocation,

    /// This method's own reference data. Each method owns its database rather
    /// than sharing one: p0f signatures, ja4 hash lists, and the fusion method's
    /// combination rules have nothing useful in common.
    #[serde(default)]
    pub database: Option<DatabaseSpec>,

    /// Every field the method may emit. Results are checked against it, and
    /// output renders from it, so a new method's output displays without any
    /// output code changing.
    pub output_schema: Vec<FieldSpec>,

    /// Free-form knobs read by the adapter. Untyped on purpose — this is where
    /// parameter sweeps happen without touching Rust.
    #[serde(default)]
    pub params: BTreeMap<String, serde_yaml::Value>,
}

impl MethodManifest {
    /// Parse and check the parts serde cannot: at least one trigger, and no
    /// field declared twice.
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let manifest: Self = serde_yaml::from_str(yaml)?;

        let invalid = |reason: String| Error::Manifest {
            path: manifest.name.clone(),
            reason,
        };
        if manifest.triggers.is_empty() {
            return Err(invalid("`triggers` is empty, so nothing would ever run it".into()));
        }
        let mut seen = HashSet::new();
        if let Some(duplicate) = manifest
            .output_schema
            .iter()
            .find(|spec| !seen.insert(spec.field.as_str()))
        {
            return Err(invalid(format!(
                "field `{}` is declared twice in `output-schema`",
                duplicate.field
            )));
        }

        Ok(manifest)
    }

    /// Typed access to a `params` entry, with the adapter's default.
    pub fn param<T: serde::de::DeserializeOwned>(&self, key: &str, default: T) -> T {
        self.params
            .get(key)
            .and_then(|v| serde_yaml::from_value(v.clone()).ok())
            .unwrap_or(default)
    }

    /// The schema entry for a field, if declared.
    pub fn field(&self, name: &str) -> Option<&FieldSpec> {
        self.output_schema.iter().find(|spec| spec.field == name)
    }
}

/// Which layer of the fingerprinting stack the method works at. Used to group
/// methods for single- versus multi-layer evaluation; the framework itself
/// does not interpret it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Layer {
    L1,
    L2,
    L3,
}

/// How the framework runs the method. Either way it looks the same from the
/// dispatcher's point of view.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Invocation {
    #[serde(flatten)]
    pub target: InvocationTarget,
    /// Give up on a single call after this long. Mandatory in effect for
    /// external programs: one hung process must never block the pipeline.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum InvocationTarget {
    /// Rust code compiled into the binary, registered under this adapter name.
    /// Several manifests may share one adapter with different `params`.
    InProcess { adapter: String },
    /// A separate program, run per call.
    External {
        command: String,
        #[serde(default)]
        args: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DatabaseSpec {
    /// Relative to the manifest's directory.
    pub path: String,
    /// Adapter-defined, e.g. `p0f`, `json-lines`, `rules`.
    pub format: String,
}

/// One field a method may emit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FieldSpec {
    pub field: String,
    #[serde(rename = "type")]
    pub ty: FieldType,
    pub kind: FieldKind,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FieldType {
    String,
    Integer,
    Float,
    Bool,
}

/// What a field *means*, which is all output needs to know to display it.
///
/// A small fixed vocabulary on purpose: a new method must fit one of these.
/// Extending it is a last resort, for a genuine structural need, never to suit
/// one method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FieldKind {
    /// A label: an OS, a client, a verdict.
    Classification,
    /// A yes/no property: known scanner, header order anomaly.
    Flag,
    /// A number on a scale: a confidence, a distance, a weighted score.
    Score,
    /// The fingerprint itself, as computed: a ja4 hash, a p0f signature.
    RawSignature,
}

fn default_true() -> bool {
    true
}

fn default_timeout_ms() -> u64 {
    250
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
name: tcp-syn
layer: L1
triggers: [tcp-syn, tcp-syn-ack]
invocation:
  type: in-process
  adapter: tcp-syn
output-schema:
  - field: os
    type: string
    kind: classification
"#;

    #[test]
    fn parses_a_minimal_manifest() {
        let manifest = MethodManifest::from_yaml(MINIMAL).expect("manifest should parse");

        assert_eq!(manifest.name, "tcp-syn");
        assert_eq!(manifest.layer, Layer::L1);
        assert_eq!(manifest.triggers, [TriggerEvent::TcpSyn, TriggerEvent::TcpSynAck]);
        assert!(manifest.enabled);
        assert!(matches!(
            &manifest.invocation.target,
            InvocationTarget::InProcess { adapter } if adapter == "tcp-syn"
        ));
        assert_eq!(manifest.invocation.timeout_ms, 250);
        let os = manifest.field("os").expect("os is declared");
        assert_eq!((os.ty, os.kind), (FieldType::String, FieldKind::Classification));
    }

    #[test]
    fn parses_an_external_invocation() {
        let yaml = MINIMAL.replace(
            "  type: in-process\n  adapter: tcp-syn\n",
            "  type: external\n  command: p0f-client\n  args: [\"-s\", \"sock\"]\n  timeout-ms: 200\n",
        );
        let manifest = MethodManifest::from_yaml(&yaml).expect("manifest should parse");

        assert!(matches!(
            &manifest.invocation.target,
            InvocationTarget::External { command, args } if command == "p0f-client" && args.len() == 2
        ));
        assert_eq!(manifest.invocation.timeout_ms, 200);
    }

    #[test]
    fn a_manifest_without_triggers_is_rejected() {
        let yaml = MINIMAL.replace("triggers: [tcp-syn, tcp-syn-ack]", "triggers: []");
        assert!(MethodManifest::from_yaml(&yaml).is_err());
    }

    #[test]
    fn an_unknown_kind_is_rejected() {
        let yaml = MINIMAL.replace("kind: classification", "kind: vibes");
        assert!(MethodManifest::from_yaml(&yaml).is_err());
    }
}
