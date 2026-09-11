//! Batch and inference mode consumers.

use crossbeam_channel::Receiver;
use pf_core::{ProfileStore, Report};

/// Consumes reports after sessions are finished.
pub struct BatchConsumer;

impl BatchConsumer {
    /// Collect every report into a [`ProfileStore`].
    pub fn consume(results: Receiver<Report>) -> ProfileStore {
        let mut store = ProfileStore::new();
        for report in results {
            store.apply(report);
        }
        store
    }
}

/// An incremental watcher/consumer that can process reports as they arrive.
pub struct InferenceConsumer;

impl InferenceConsumer {
    /// Fold reports in as they arrive, calling `on_update` after each one that
    /// changed the store. Stale reports — superseded before they arrived — do
    /// not trigger it.
    pub fn consume_streaming<F>(results: Receiver<Report>, mut on_update: F) -> ProfileStore
    where
        F: FnMut(&Report, &ProfileStore),
    {
        let mut store = ProfileStore::new();
        for report in results {
            // The store keeps its own copy; the callback gets the original.
            if store.apply(report.clone()) {
                on_update(&report, &store);
            }
        }
        store
    }
}
