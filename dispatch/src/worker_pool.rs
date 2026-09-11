//! Worker pool: one job is one pass over a session, and each worker runs the
//! registry over it.
//!
//! Sharding by session rather than by method keeps every method's view of a
//! session on one thread, which is what lets [`pf_core::Method::extract`] stay
//! lock-free — and it lets the fusion method see the other methods' evidence
//! without any cross-thread coordination. A session is also pinned to one
//! worker for its whole life, so its passes run in order next to its
//! [`SessionMemo`], and a method that already settled is never re-run.

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::sync::Arc;
use std::thread;

use crossbeam_channel::{Receiver, Sender};
use pf_core::{Report, Revision, Session, SessionId};
use pf_methods::{Registry, SessionMemo};

/// One unit of work.
pub struct Job {
    pub session: Session,
    /// The session is closed or timed out; this is its last pass.
    pub is_final: bool,
}

pub struct Dispatcher {
    /// One queue per worker. Which one a job goes to is a hash of its session
    /// key, so every pass of a session lands on the same worker.
    queues: Vec<Sender<Job>>,
    workers: Vec<thread::JoinHandle<()>>, // cpu count
    hasher: RandomState,
}

impl Dispatcher {
    /// Spawn `workers` threads sharing one registry.
    ///
    /// Results arrive on the returned receiver. Passes of one session arrive
    /// in order, since one worker runs them all; across sessions there is no
    /// defined order, so the consumer must not depend on one.
    ///
    /// Arc defines a thread-safe reference-counting pointer, which allows multiple threads to share ownership of the same data.
    /// In this case, it is used to share the `Registry` instance among the worker threads.
    pub fn spawn(registry: Arc<Registry>, workers: usize) -> (Self, Receiver<Report>) {
        let (result_tx, result_rx) = crossbeam_channel::unbounded::<Report>();

        let (queues, handles) = (0..workers.max(1))
            .map(|id| {
                // message queue for the jobs this worker owns
                let (job_tx, jobs) = crossbeam_channel::unbounded::<Job>();
                let results = result_tx.clone();
                let registry = Arc::clone(&registry);

                let handle = thread::Builder::new()
                    .name(format!("pf-worker-{id}"))
                    .spawn(move || {
                        // What each in-flight session's methods have concluded
                        // so far. Private to this thread; no lock needed.
                        let mut memos: HashMap<SessionId, SessionMemo> = HashMap::new();

                        for job in jobs {
                            let id = job.session.id();
                            let memo = memos.entry(id).or_default();
                            let evidence = registry.analyze(&job.session, job.is_final, memo);
                            if job.is_final {
                                memos.remove(&id);
                            }

                            let report = Report {
                                session: id,
                                revision: Revision::of(&job.session, job.is_final),
                                evidence,
                            };
                            if results.send(report).is_err() {
                                break; // consumer went away
                            }
                        }
                    })
                    .expect("worker thread should spawn");

                (job_tx, handle)
            })
            .unzip();

        (
            Self {
                queues,
                workers: handles,
                hasher: RandomState::new(),
            },
            result_rx,
        )
    }

    pub fn submit(&self, job: Job) {
        // Pinning trades balance for order: one very busy session cannot be
        // spread across workers.
        let worker = self.hasher.hash_one(job.session.key) % self.queues.len() as u64;

        // TODO: unbounded queues mean a burst of sessions is absorbed as memory.
        // Bound this and decide the backpressure policy — block the capture
        // thread, or drop the oldest and count it.
        let _ = self.queues[worker as usize].send(job);
    }

    /// Close the queues and wait for every worker to drain its own.
    pub fn shutdown(self) {
        drop(self.queues);
        for worker in self.workers {
            let _ = worker.join();
        }
    }
}
