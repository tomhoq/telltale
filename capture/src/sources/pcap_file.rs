use std::path::{Path, PathBuf};

use pf_core::{Error, Observation, Result};

use crate::Source;

/// Offline replay of a capture file — the source to use in tests, since it makes
/// a run deterministic.
pub struct PcapFileSource {
    path: PathBuf,
}

impl PcapFileSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(Error::Capture(format!("no such file: {}", path.display())));
        }
        Ok(Self { path })
    }
}

impl Source for PcapFileSource {
    fn describe(&self) -> String {
        format!("pcap:{}", self.path.display())
    }

    fn next_observation(&mut self) -> Result<Option<Observation>> {
        // TODO: iterate packets with pcap-file and decode into Observation.
        // Note: replay must use the packet's own timestamp, not wall clock, or
        // the assembler's idle timeout will expire everything at once.
        Err(Error::Capture(format!(
            "pcap replay of {} is not implemented yet",
            self.path.display()
        )))
    }
}
