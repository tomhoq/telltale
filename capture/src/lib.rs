//! One shared listener, many possible origins.
//!
//! A [`Source`] yields [`Observation`]s from a variety of origins (live NIC,
//! pcap, tcpdump output, or a honeypot log) behind a single unified trait.

pub mod sources;

pub use sources::{HoneypotLogSource, LiveSource, PcapFileSource, TcpdumpSource};

use pf_core::{Observation, Result};

pub trait Source {
    /// A human-readable description of where this data comes from, for logs.
    fn describe(&self) -> String;

    /// Next observation, or `None` when the source is exhausted. A live source
    /// blocks; a finite source (pcap, log file) ends.
    fn next_observation(&mut self) -> Result<Option<Observation>>;
}

/// Drain a source into a callback until it ends.
pub fn for_each<S, F>(source: &mut S, mut f: F) -> Result<()>
where
    S: Source + ?Sized,
    F: FnMut(Observation),
{
    while let Some(observation) = source.next_observation()? {
        f(observation);
    }
    Ok(())
}
