//! Smoke test for a capture source: print what it observes.
//!
//! Needs CAP_NET_RAW — `sudo -E cargo run -p pf-capture --example sniff -- lo`.

use std::env;

use pf_capture::{LiveSource, Source};
use pf_core::Result;

fn main() -> Result<()> {
    let interface = env::args().nth(1).unwrap_or_else(|| "lo".into());
    let limit: usize = env::args()
        .nth(2)
        .and_then(|n| n.parse().ok())
        .unwrap_or(10);

    let mut source = LiveSource::open(interface, None)?;
    println!("{}", source.describe());

    for _ in 0..limit {
        let Some(observation) = source.next_observation()? else {
            break;
        };
        println!(
            "{:?} {}:{} -> {}:{} {} bytes {:?}",
            observation.transport,
            observation.source.addr,
            observation.source.port,
            observation.destination.addr,
            observation.destination.port,
            observation.payload.len(),
            observation.stage_hint,
        );
    }

    Ok(())
}
