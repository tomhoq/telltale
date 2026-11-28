//! Batch and inference mode consumers.

use std::time::{Duration, Instant};

use crossbeam_channel::Receiver;
use pf_core::{Evidence, ProfileStore};

/// Consumes evidence batches after sessions are finished.
pub struct BatchConsumer;

impl BatchConsumer {
    /// Collect all incoming evidence batches into a [`ProfileStore`].
    pub fn consume(results: Receiver<Vec<Evidence>>) -> ProfileStore {
        Self::consume_timed(results).0
    }

    /// [`BatchConsumer::consume`], also returning the time spent recording
    /// evidence: the consumer's own work, not its waiting for results.
    pub fn consume_timed(results: Receiver<Vec<Evidence>>) -> (ProfileStore, Duration) {
        let mut store = ProfileStore::new();
        let mut busy = Duration::ZERO;
        for batch in results {
            let started = Instant::now();
            for evidence in batch {
                store.record(evidence);
            }
            busy += started.elapsed();
        }
        (store, busy)
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
    pub fn consume_streaming<F>(results: Receiver<Vec<Evidence>>, on_update: F) -> ProfileStore
    where
        F: FnMut(&[Evidence], &ProfileStore),
    {
        Self::consume_streaming_timed(results, on_update).0
    }

    /// [`InferenceConsumer::consume_streaming`], also returning the time spent
    /// recording evidence and in `on_update` (rendering, printing): the
    /// consumer's own work, not its waiting for results.
    pub fn consume_streaming_timed<F>(results: Receiver<Vec<Evidence>>, mut on_update: F) -> (ProfileStore, Duration)
    where
        F: FnMut(&[Evidence], &ProfileStore),
    {
        let mut store = ProfileStore::new();
        let mut busy = Duration::ZERO;
        for update in results {
            let started = Instant::now();
            for evidence in &update {
                store.record(evidence.clone());
            }
            on_update(&update, &store);
            busy += started.elapsed();
        }
        (store, busy)
    }
}
