use pf_core::{Error, Observation, Result};

use crate::Source;

/// Live capture from a network interface.
pub struct LiveSource {
    interface: String,
    /// in the future: BPF filter can b applied at the kernel, so uninteresting traffic never reaches
    /// user space.
    filter: Option<String>,
}

impl LiveSource {
    // Into<String> accepts flexible argument types, e.g. &str, String, etc.
    pub fn open(interface: impl Into<String>, filter: Option<String>) -> Result<Self> {
        Ok(Self {
            interface: interface.into(),
            filter,
        })
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub fn filter(&self) -> Option<&str> {
        self.filter.as_deref() // as_deref() converts Option<String> to Option<&str>
    }
}

impl Source for LiveSource {
    fn describe(&self) -> String {
        format!("live:{}", self.interface)
    }

    fn next_observation(&mut self) -> Result<Option<Observation>> {
        // TODO: open the datalink channel, apply `filter`, read a frame, decode
        // ip/transport, build an Observation.
        Err(Error::Capture(format!(
            "live capture on `{}` is not implemented yet",
            self.interface
        )))
    }
}
