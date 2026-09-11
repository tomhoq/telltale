//! Batch and inference mode consumers over the engine's result stream.
//!
//! Both read the same [`Update`]s; they differ only in what they surface and
//! when. Neither changes, merges or drops a result.

use crossbeam_channel::Receiver;
use pf_core::{Endpoint, ResultEntry, Session, SessionId, Update};

/// Batch mode: each session once, when it is finalized, with its complete
/// result list. Returns how many sessions were shown.
pub fn batch(updates: Receiver<Update>, mut on_session: impl FnMut(&Session)) -> usize {
    let mut shown = 0;
    for update in updates {
        if let Update::Finalized(session) = update {
            on_session(&session);
            shown += 1;
        }
    }
    shown
}

/// Inference mode: every result the moment it is appended.
///
/// TODO (step 3): the watcher proper — an early-decision rule over the
/// stream, emitting a verdict and revising it when later results contradict
/// it.
pub fn inference(
    updates: Receiver<Update>,
    mut on_result: impl FnMut(&SessionId, Endpoint, &ResultEntry),
) -> usize {
    let mut shown = 0;
    for update in updates {
        if let Update::Result {
            session,
            initiator,
            entry,
        } = update
        {
            on_result(&session, initiator, &entry);
            shown += 1;
        }
    }
    shown
}
