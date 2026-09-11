//! Worker pool: one job is one session, and each worker runs the whole registry
//! over it.
//!
//! Sharding by session rather than by method keeps every method's view of a
//! session on one thread, which is what lets [`pf_core::Method::extract`] stay
//! lock-free — and it lets the fusion method see the other methods' evidence
//! without any cross-thread coordination.

use std::sync::Arc;
use std::thread;

use crossbeam_channel::{Receiver, Sender};
use pf_core::{Evidence, Session};
use pf_methods::Registry;

/// One unit of work.
pub struct Job {
    pub session: Session,
    /// The session is closed or timed out; this is its last pass.
    pub is_final: bool,
}

pub struct Dispatcher {
    jobs: Sender<Job>,
    workers: Vec<thread::JoinHandle<()>>, // cpu count
}

impl Dispatcher {
    /// Spawn `workers` threads sharing one registry.
    ///
    /// Results arrive on the returned receiver, unordered — two sessions
    /// finishing on different threads have no defined relative order, so the
    /// consumer must not depend on one.
    /// 
    /// Arc defines a thread-safe reference-counting pointer, which allows multiple threads to share ownership of the same data. 
    /// In this case, it is used to share the `Registry` instance among the worker threads.
    pub fn spawn(registry: Arc<Registry>, workers: usize) -> (Self, Receiver<Vec<Evidence>>) {
        // message queue for jobs to be processed by worker threads
        let (job_tx, job_rx) = crossbeam_channel::unbounded::<Job>(); 
        let (result_tx, result_rx) = crossbeam_channel::unbounded::<Vec<Evidence>>();

        let handles = (0..workers.max(1))
            .map(|id| {
                let jobs: Receiver<Job> = job_rx.clone();
                let results = result_tx.clone();
                let registry = Arc::clone(&registry);

                thread::Builder::new()
                    .name(format!("pf-worker-{id}"))
                    .spawn(move || {
                        for job in jobs {
                            let evidence = registry.analyze(&job.session, job.is_final);
                            if results.send(evidence).is_err() {
                                break; // consumer went away
                            }
                        }
                    })
                    .expect("worker thread should spawn")
            })
            .collect();

        (
            Self {
                jobs: job_tx,
                workers: handles,
            },
            result_rx,
        )
    }

    pub fn submit(&self, job: Job) {
        // TODO: unbounded queues mean a burst of sessions is absorbed as memory.
        // Bound this and decide the backpressure policy — block the capture
        // thread, or drop the oldest and count it.
        let _ = self.jobs.send(job);
    }

    /// Close the queue and wait for every worker to drain it.
    pub fn shutdown(self) {
        drop(self.jobs);
        for worker in self.workers {
            let _ = worker.join();
        }
    }
}
