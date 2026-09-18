//! Worker pool: one job is one session, run against an analyze function
//! supplied by the caller.
//!
//! This crate stays generic on purpose: it knows how to correlate sessions
//! and fan them out to a thread pool, nothing about what methods exist or how
//! they are registered. That is `pf-methods`' concern; wiring the two
//! together is the binary's job (see `pf-cli`). Sharding by session rather
//! than by method keeps every method's view of a session on one thread, which
//! is what lets [`pf_core::Method::extract`] stay lock-free — and it lets a
//! fusion-style method see the other methods' evidence without any
//! cross-thread coordination.

use std::sync::Arc;
use std::thread;

use crossbeam_channel::{Receiver, Sender};
use pf_core::{Evidence, Session};

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
    /// Spawn `workers` threads, each running `analyze` over the jobs it pulls
    /// off the shared queue.
    ///
    /// `analyze` is the caller's method registry, or anything else that can
    /// turn a session into evidence — this crate does not know or care which.
    /// It is shared read-only across every worker (via the `Arc` this wraps
    /// it in), so whatever state it closes over must be `Send + Sync`, the
    /// same requirement `Arc` itself imposes.
    ///
    /// `analyze` reports through the callback it is given, as often as it has
    /// something: each call is sent on as one message straight away, so a
    /// result reaches the consumer without waiting for the rest of the pass.
    ///
    /// Results arrive on the returned receiver, unordered — two sessions
    /// finishing on different threads have no defined relative order, so the
    /// consumer must not depend on one.
    pub fn spawn<F>(workers: usize, analyze: F) -> (Self, Receiver<Vec<Evidence>>)
    where
        F: Fn(&Session, bool, &mut dyn FnMut(Vec<Evidence>)) + Send + Sync + 'static,
    {
        let analyze = Arc::new(analyze);
        // message queue for jobs to be processed by worker threads
        let (job_tx, job_rx) = crossbeam_channel::unbounded::<Job>();
        let (result_tx, result_rx) = crossbeam_channel::unbounded::<Vec<Evidence>>();

        let handles = (0..workers.max(1))
            .map(|id| {
                let jobs: Receiver<Job> = job_rx.clone();
                let results = result_tx.clone();
                let analyze = Arc::clone(&analyze);

                thread::Builder::new()
                    .name(format!("pf-worker-{id}"))
                    .spawn(move || {
                        for job in jobs {
                            let mut consumer_gone = false;
                            analyze(&job.session, job.is_final, &mut |evidence| {
                                consumer_gone |= results.send(evidence).is_err();
                            });
                            if consumer_gone {
                                break;
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    use pf_core::{Confidence, Endpoint, Observation, Transport};

    use super::*;

    fn session() -> Session {
        let host = |last, port| Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)),
            port,
        };
        Session::open(Observation {
            at: SystemTime::UNIX_EPOCH,
            source: host(10, 47236),
            destination: host(8, 5173),
            transport: Transport::Tcp,
            payload: Vec::new(),
            stage_hint: None,
            tcp: None,
        })
    }

    /// Each report from `analyze` is its own message, so the consumer can act
    /// on the first before the second exists.
    #[test]
    fn every_emit_is_sent_as_its_own_message() {
        let (dispatcher, results) = Dispatcher::spawn(1, |session: &Session, _, emit: &mut dyn FnMut(Vec<Evidence>)| {
            for method in ["fast", "slow"] {
                emit(vec![Evidence::new(method, session.initiator, "k", "v", Confidence::Weak)]);
            }
        });
        dispatcher.submit(Job {
            session: session(),
            is_final: false,
        });
        dispatcher.shutdown();

        let methods: Vec<String> = results.iter().map(|update| update[0].method.clone()).collect();
        assert_eq!(methods, ["fast", "slow"]);
    }
}
