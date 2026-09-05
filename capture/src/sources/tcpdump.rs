use pf_core::{Error, Observation, Result};

use crate::Source;

/// Reads tcpdump's output — either a piped child process or a saved transcript.
///
/// Worth keeping separate from [`super::PcapFileSource`]: this is the path for
/// hosts where the tool cannot open a raw socket itself but tcpdump can.
pub struct TcpdumpSource {
    command: String,
}

impl TcpdumpSource {
    pub fn spawn(command: impl Into<String>) -> Result<Self> {
        Ok(Self {
            command: command.into(),
        })
    }
}

impl Source for TcpdumpSource {
    fn describe(&self) -> String {
        format!("tcpdump:{}", self.command)
    }

    fn next_observation(&mut self) -> Result<Option<Observation>> {
        // TODO: prefer `tcpdump -w -` and reuse the pcap decoder rather than
        // parsing the human-readable text output, which is lossy and versioned.
        Err(Error::Capture(
            "tcpdump ingestion is not implemented yet".into(),
        ))
    }
}
