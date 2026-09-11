//! Where observations come from.
//!
//! One trait, several origins. Everything downstream consumes
//! [`pf_core::Observation`]s and never learns which [`Source`] produced them,
//! which is what makes adding a source an additive change.

pub mod decode;
#[cfg(windows)]
pub mod npcap;
pub mod sources;

pub use sources::{HoneypotLogSource, LiveSource, PcapFileSource, TcpdumpSource};

use pf_core::{Observation, Result};

/// A stream of observations.
///
/// Pulled rather than pushed: the caller owns the loop, so it can interleave
/// reads with the assembler's idle-timeout sweep without a second thread.
pub trait Source {
    /// Short, stable identifier for logs and evidence provenance — `live:eth0`,
    /// `pcap:/tmp/scan.pcap`.
    fn describe(&self) -> String;

    /// Next observation, blocking until one is available.
    ///
    /// `Ok(None)` means the source is exhausted and will never produce another
    /// observation; a finite source returns it at end of input, and an endless
    /// one (a live interface) never does. Frames the pipeline has no use for —
    /// ARP, a truncated header — are skipped internally rather than surfaced as
    /// errors, so a returned `Err` means the source itself is broken.
    fn next_observation(&mut self) -> Result<Option<Observation>>;
}
