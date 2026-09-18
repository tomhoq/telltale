//! Batch and inference mode consumers.

use crossbeam_channel::Receiver;
use pf_core::{Evidence, ProfileStore};

/// Consumes evidence batches after sessions are finished.
pub struct BatchConsumer;

impl BatchConsumer {
    /// Collect all incoming evidence batches into a [`ProfileStore`].
    pub fn consume(results: Receiver<Vec<Evidence>>) -> ProfileStore {
        let mut store = ProfileStore::new();
        for batch in results {
            for evidence in batch {
                store.record(evidence);
            }
        }
        store
    }
}

/// An incremental watcher/consumer that can process evidence as it arrives.
pub struct InferenceConsumer;

impl InferenceConsumer {
    /// Process incoming evidence incrementally into a [`ProfileStore`].
    ///
    /// Each message is one method's result for one pass over a session, sent
    /// the moment that method finished. `on_update` sees it once it is
    /// recorded — whole, so a method that reports several keys at once is one
    /// update, not several.
    pub fn consume_streaming<F>(results: Receiver<Vec<Evidence>>, mut on_update: F) -> ProfileStore
    where
        F: FnMut(&[Evidence], &ProfileStore),
    {
        let mut store = ProfileStore::new();
        for update in results {
            for evidence in &update {
                store.record(evidence.clone());
            }
            on_update(&update, &store);
        }
        store
    }
}
