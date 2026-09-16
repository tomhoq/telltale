//! Run configuration — `config/pipeline.yaml`.
//!
//! Same principle as the method manifests: trying a different configuration is
//! an edit to YAML, not to Rust.

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PipelineConfig {
    /// Directory of method manifests.
    #[serde(default = "default_manifest_dir")]
    pub manifest_dir: String,

    /// Inactivity timeout for session assembly, in seconds. When it fires,
    /// methods still waiting on a stage report partial or no result rather than
    /// holding the session open.
    #[serde(default = "default_timeout_secs")]
    pub session_timeout_secs: u64,

    /// Worker threads. One job is one session.
    #[serde(default = "default_workers")]
    pub workers: usize,

    pub output: OutputMode,

    /// Analyse both directions of a session instead of just the traffic
    /// incoming from its initiator (the attacker, on a honeypot). Off by
    /// default: passive fingerprinting is about the client hitting the
    /// honeypot, not the honeypot's own responses, and honeypot logs often
    /// only capture the incoming side anyway. Overridable per run with
    /// `--both-directions`.
    #[serde(default)]
    pub both_directions: bool,
}

/// The decision that shapes everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputMode {
    /// Assemble the whole session, then score it once. Simpler and more
    /// accurate; useless for anything that has to react while traffic flows.
    PerSession,
    /// Emit a best guess as data arrives and refine it. Requires every method to
    /// be re-runnable on partial data — which the `Method` contract already
    /// demands, so both modes work against the same adapters.
    InferenceTime,
}

impl PipelineConfig {
    pub fn load(path: impl AsRef<Path>) -> pf_core::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(serde_yaml::from_str(&text)?)
    }

    pub fn session_timeout(&self) -> Duration {
        Duration::from_secs(self.session_timeout_secs)
    }
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            manifest_dir: default_manifest_dir(),
            session_timeout_secs: default_timeout_secs(),
            workers: default_workers(),
            output: OutputMode::PerSession,
            both_directions: false,
        }
    }
}

fn default_manifest_dir() -> String {
    "methods/manifests".into()
}

fn default_timeout_secs() -> u64 {
    30
}

fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
