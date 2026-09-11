//! The vocabulary every other crate agrees on.
//!
//! No I/O and no parsing of wire formats lives here. `capture` produces
//! [`Observation`]s, `dispatch` groups them into [`Session`]s and classifies
//! them into [`TriggerEvent`]s, `methods` turn triggers into [`ResultEntry`]s,
//! and `output` presents them. Because they all depend on this crate and not
//! on each other, a new capture source or a new method is an additive change.

pub mod error;
pub mod manifest;
pub mod method;
pub mod observation;
pub mod result;
pub mod session;
pub mod trigger;
pub mod update;

pub use error::{Error, Result};
pub use manifest::{
    DatabaseSpec, FieldKind, FieldSpec, FieldType, Invocation, InvocationTarget, Layer,
    MethodManifest,
};
pub use method::{Context, Method};
pub use observation::{Direction, Endpoint, Observation, TcpHeader, Transport};
pub use result::{FieldValue, Fields, ResultEntry};
pub use session::{Session, SessionId, SessionKey, SessionState};
pub use trigger::TriggerEvent;
pub use update::Update;
