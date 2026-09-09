//! Session correlation and worker pool dispatch engine.
//!
//! Groups raw packet observations into [`pf_core::Session`]s and dispatches
//! analytical fingerprinting jobs to a multi-threaded worker pool.

pub mod correlator;
pub mod worker_pool;

pub use correlator::{Assembler, Emitted, SessionCorrelator};
pub use worker_pool::{Dispatcher, Job};
