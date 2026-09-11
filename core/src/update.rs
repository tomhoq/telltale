use crate::observation::Endpoint;
use crate::result::ResultEntry;
use crate::session::{Session, SessionId};

/// The result stream the dispatch engine publishes.
///
/// Batch and inference consumers read the same stream and differ only in
/// which updates they act on and when they surface them; the pipeline itself
/// does not fork.
#[derive(Debug, Clone)]
pub enum Update {
    /// A method reported; the entry has been appended to that session's
    /// results.
    Result {
        session: SessionId,
        /// Who opened the session — the key orders its endpoints by address,
        /// which says nothing about which one is the client.
        initiator: Endpoint,
        entry: ResultEntry,
    },
    /// A session is over and every method it fired, `session-end` ones
    /// included, has reported. Its result list is complete and final.
    Finalized(Session),
}
