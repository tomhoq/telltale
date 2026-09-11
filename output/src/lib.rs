//! Batch mode and inference mode consumers, plus dashboard/CLI rendering.
//!
//! A library, not a binary, on purpose: the CLI renders text today, and a web or
//! TUI front end later reuses the same data without a rewrite.

pub mod consumer;
pub mod render;

pub use render::{render_result_json, render_result_text, render_session_json, render_session_text};
