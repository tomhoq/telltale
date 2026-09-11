//! Session correlation, trigger classification and worker pool dispatch.
//!
//! Groups packet observations into [`pf_core::Session`]s, classifies each
//! packet into [`pf_core::TriggerEvent`]s, and runs the methods listening for
//! those events on a multi-threaded worker pool. [`Engine`] ties the three
//! together.

pub mod classifier;
pub mod correlator;
pub mod engine;
pub mod worker_pool;

pub use classifier::classify;
pub use correlator::{Assembler, SessionCorrelator};
pub use engine::Engine;
pub use worker_pool::{Dispatcher, Done, Job};
