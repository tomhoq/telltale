//! The vocabulary every other crate agrees on.
//!
//! No I/O and no parsing of wire formats lives here. `capture` produces
//! [`Observation`]s and assembles them into [`Session`]s, `methods` turns
//! sessions into [`Evidence`], and `dashboard` renders the result. Because they
//! all depend on this crate and not on each other, a new capture source or a new
//! method is an additive change.

pub mod error;
pub mod evidence;
pub mod manifest;
pub mod method;
pub mod observation;
pub mod profile;
pub mod report;
pub mod session;

pub use error::{Error, Result};
pub use evidence::{Confidence, Evidence};
pub use manifest::{DatabaseSpec, Invocation, MethodManifest, OutputSchema, Trigger};
pub use method::{Context, Method, Outcome};
pub use observation::{Direction, Endpoint, Observation, Transport};
pub use profile::{Profile, ProfileStore, Verdict};
pub use report::{Report, Revision};
pub use session::{Session, SessionId, SessionKey, SessionState, Stage};
