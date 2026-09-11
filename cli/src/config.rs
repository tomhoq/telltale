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

    /// Inactivity timeout for session assembly, in seconds. When it fires, the
    /// session ends with whatever results it has; nothing waits for traffic
    /// that never came.
    #[serde(default = "default_timeout_secs")]
    pub session_timeout_secs: u64,

    /// Worker threads. One job is one method answering one trigger event.
    #[serde(default = "default_workers")]
    pub workers: usize,

    pub output: OutputMode,
}

/// How results are surfaced. Both read the same result stream; the pipeline
/// runs identically either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputMode {
    /// Batch: each session once it is finalized, with its full result list.
    PerSession,
    /// Inference: each result the moment a method reports it.
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
