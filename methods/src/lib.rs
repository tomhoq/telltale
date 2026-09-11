//! The methods themselves, plus the adapter registry.
//!
//! Adding a method:
//!
//! 1. write `manifests/<name>.yaml` — layer, triggers, invocation, database,
//!    output schema, parameters;
//! 2. add an adapter module under [`adapters`] implementing [`pf_core::Method`];
//! 3. register its constructor in [`builtin_adapters`].
//!
//! Re-running with different parameters, or turning a method off, is step 1
//! alone — no recompile. So is a second configuration of an existing adapter:
//! another manifest naming the same `adapter`.

pub mod adapters;
pub mod db;
pub mod registry;

pub use registry::{builtin_adapters, AdapterFactory, MethodId, Registry};
