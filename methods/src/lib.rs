//! The methods themselves, plus the adapter registry.
//!
//! Adding a method:
//!
//! 1. write `manifests/<name>.yaml` — required stage, trigger, database, output
//!    schema, parameters;
//! 2. add an adapter module under [`adapters`] implementing [`pf_core::Method`];
//! 3. register its constructor in [`builtin_adapters`].
//!
//! Re-running with different parameters, or turning a method off, is step 1
//! alone — no recompile.

pub mod adapters;
pub mod db;
pub mod registry;

pub use registry::{builtin_adapters, AdapterFactory, Registry};
