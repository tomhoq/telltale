//! Worker pool: one job is one method answering one trigger.
//!
//! Jobs share one queue, so any worker takes any job: many sessions run at
//! once, and within a session several methods fired by the same packet run at
//! once too. Methods cannot block each other, and nothing here waits on a
//! particular job.

use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::thread;

use crossbeam_channel::{Receiver, Sender};
use pf_core::{Context, ResultEntry, Session, SessionId, TriggerEvent};
use pf_methods::{MethodId, Registry};

/// One unit of work.
pub struct Job {
    pub method: MethodId,
    pub trigger: TriggerEvent,
    /// The session as it was when the event fired. Shared by every method the
    /// event fired, and read-only.
    pub session: Arc<Session>,
    /// Index into `session.observations` of the packet that raised the event;
    /// `None` for session events.
    pub packet: Option<usize>,
}

/// A finished job. Sent for every job, even one that found nothing, so the
/// engine can tell when a session has nothing left in flight.
pub struct Done {
    pub session: SessionId,
    pub results: Vec<ResultEntry>,
}

pub struct Dispatcher {
    jobs: Sender<Job>,
    workers: Vec<thread::JoinHandle<()>>, // cpu count
}

impl Dispatcher {
    /// Spawn `workers` threads sharing one registry.
    ///
    /// Arc defines a thread-safe reference-counting pointer, which allows multiple threads to share ownership of the same data.
    /// In this case, it is used to share the `Registry` instance among the worker threads.
    pub fn spawn(registry: Arc<Registry>, workers: usize) -> (Self, Receiver<Done>) {
        // message queue for jobs to be processed by worker threads
        let (job_tx, job_rx) = crossbeam_channel::unbounded::<Job>();
        let (done_tx, done_rx) = crossbeam_channel::unbounded::<Done>();

        let handles = (0..workers.max(1))
            .map(|id| {
                let jobs: Receiver<Job> = job_rx.clone();
                let done = done_tx.clone();
                let registry = Arc::clone(&registry);

                thread::Builder::new()
                    .name(format!("pf-worker-{id}"))
                    .spawn(move || {
                        for job in jobs {
                            let results = run(&registry, &job);
                            let finished = Done {
                                session: job.session.id(),
                                results,
                            };
                            if done.send(finished).is_err() {
                                break; // engine went away
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
            done_rx,
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

/// A panicking method is treated like a failing one: logged, no results. It
/// must not take its worker down, or the engine would wait forever for a
/// `Done` that never comes.
fn run(registry: &Registry, job: &Job) -> Vec<ResultEntry> {
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        let ctx = Context {
            trigger: job.trigger,
            packet: job.packet.map(|index| &job.session.observations[index]),
            session: &job.session,
        };
        registry.run(job.method, &ctx)
    }));
    outcome.unwrap_or_else(|_| {
        tracing::error!(
            method = %registry.method(job.method).name(),
            trigger = ?job.trigger,
            "method panicked"
        );
        Vec::new()
    })
}
