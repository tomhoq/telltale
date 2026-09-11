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
    /// Process incoming evidence batches incrementally into a [`ProfileStore`].
    pub fn consume_streaming<F>(results: Receiver<Vec<Evidence>>, mut on_evidence: F) -> ProfileStore
    where
        F: FnMut(&Evidence, &ProfileStore),
    {
        let mut store = ProfileStore::new();
        for batch in results {
            for evidence in batch {
                store.record(evidence.clone());
                on_evidence(&evidence, &store);
            }
        }
        store
    }
}
