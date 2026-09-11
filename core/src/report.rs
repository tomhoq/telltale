use serde::{Deserialize, Serialize};

use crate::evidence::Evidence;
use crate::session::{Session, SessionId};

/// How far into its session an analysis pass looked.
///
/// Passes of one session can run on different workers and finish in any
/// order, so this — not arrival order — decides which result is current.
/// Field order is significant: `Ord` is derived, comparing observation count
/// first and finality second, so the final pass wins even when it saw no more
/// packets than the last provisional one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Revision {
    pub observations: usize,
    pub is_final: bool,
}

impl Revision {
    pub fn of(session: &Session, is_final: bool) -> Self {
        Self {
            observations: session.observations.len(),
            is_final,
        }
    }
}

/// Everything one pass over one session concluded.
///
/// The whole answer as of that pass, not an increment: a newer report for the
/// same session replaces the older one outright, which is how a provisional
/// claim that a later pass no longer makes disappears.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub session: SessionId,
    pub revision: Revision,
    pub evidence: Vec<Evidence>,
}
