use std::path::{Path, PathBuf};

use pf_core::{Error, Observation, Result};

use crate::Source;

/// Ingests a honeypot's structured log.
///
/// The odd one out: there are no packets here, so `payload` is often empty and
/// the log's own semantics supply `stage_hint` directly. Methods that need raw
/// bytes will correctly report `NotApplicable` on these sessions — that is the
/// design working, not a gap.
pub struct HoneypotLogSource {
    path: PathBuf,
    /// Which honeypot wrote it; each has its own schema.
    format: String,
}

impl HoneypotLogSource {
    pub fn open(path: impl AsRef<Path>, format: impl Into<String>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(Error::Capture(format!("no such file: {}", path.display())));
        }
        Ok(Self {
            path,
            format: format.into(),
        })
    }
}

impl Source for HoneypotLogSource {
    fn describe(&self) -> String {
        format!("honeypot:{}:{}", self.format, self.path.display())
    }

    fn next_observation(&mut self) -> Result<Option<Observation>> {
        // TODO: one deserializer per honeypot format, each mapping its records
        // onto Observation + stage_hint.
        Err(Error::Capture(format!(
            "honeypot log format `{}` is not implemented yet",
            self.format
        )))
    }
}
