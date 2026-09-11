//! The dispatch engine: packet in, results out.
//!
//! For every packet: add it to its session, classify it into trigger events,
//! and hand each method listening for those events to the worker pool. As
//! methods report, their entries are appended to the session's result list
//! and published as [`Update`]s. When a session ends — timeout, or the source
//! running out — the engine first waits for every job the session still has
//! in flight, then fires `session-end` methods on the complete result list,
//! and only then publishes the finished session.
//!
//! Lives on the capture thread and is the only thing that touches sessions,
//! so none of this needs a lock.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender};
use pf_core::{Observation, Session, SessionId, TriggerEvent, Update};
use pf_methods::Registry;

use crate::classifier::classify;
use crate::correlator::Assembler;
use crate::worker_pool::{Dispatcher, Done, Job};

/// A session that is over but not yet published.
struct Closing {
    session: Session,
    /// Its `session-end` methods have been fired.
    ended: bool,
}

pub struct Engine {
    registry: Arc<Registry>,
    assembler: Assembler,
    pool: Dispatcher,
    done: Receiver<Done>,
    /// Jobs submitted and not yet reported, per session.
    in_flight: HashMap<SessionId, usize>,
    closing: HashMap<SessionId, Closing>,
    updates: Sender<Update>,
}

impl Engine {
    pub fn new(
        registry: Arc<Registry>,
        session_timeout: Duration,
        workers: usize,
    ) -> (Self, Receiver<Update>) {
        let (pool, done) = Dispatcher::spawn(Arc::clone(&registry), workers);
        let (updates, receiver) = crossbeam_channel::unbounded();
        let engine = Self {
            registry,
            assembler: Assembler::new(session_timeout),
            pool,
            done,
            in_flight: HashMap::new(),
            closing: HashMap::new(),
            updates,
        };
        (engine, receiver)
    }

    pub fn ingest(&mut self, observation: Observation) {
        // Fold in whatever finished since the last packet, so the snapshot
        // methods get below includes those results.
        self.collect();

        let now = observation.at;
        let events = classify(&observation);
        let key = self.assembler.ingest(observation);

        if !events.is_empty() {
            let session = self
                .assembler
                .get(&key)
                .expect("the session was just ingested into");
            let snapshot = Arc::new(session.clone());
            let packet = snapshot.observations.len() - 1;
            for event in events {
                self.fire(event, &snapshot, Some(packet));
            }
        }

        // Packet time, not wall-clock: a replayed capture expires sessions
        // exactly as the live traffic would have.
        for session in self.assembler.expire(now) {
            self.close(session);
        }
    }

    /// The source is exhausted: end every session and wait until each one has
    /// been published.
    pub fn finish(mut self) {
        for session in self.assembler.drain() {
            self.close(session);
        }
        while !self.closing.is_empty() {
            match self.done.recv() {
                Ok(done) => self.complete(done),
                // Every worker is gone, so nothing else will report.
                Err(_) => break,
            }
        }
        for (_, closing) in self.closing.drain() {
            let _ = self.updates.send(Update::Finalized(closing.session));
        }
        self.pool.shutdown();
    }

    /// Hand every method listening for `trigger` to the pool. Returns how many
    /// were fired.
    fn fire(&mut self, trigger: TriggerEvent, session: &Arc<Session>, packet: Option<usize>) -> usize {
        let methods = self.registry.methods_for(trigger);
        for &method in methods {
            self.pool.submit(Job {
                method,
                trigger,
                session: Arc::clone(session),
                packet,
            });
        }
        if !methods.is_empty() {
            *self.in_flight.entry(session.id()).or_default() += methods.len();
        }
        methods.len()
    }

    /// Fold in every finished job without waiting.
    fn collect(&mut self) {
        while let Ok(done) = self.done.try_recv() {
            self.complete(done);
        }
    }

    fn complete(&mut self, done: Done) {
        let id = done.session;
        if let Some(count) = self.in_flight.get_mut(&id) {
            *count -= 1;
            if *count == 0 {
                self.in_flight.remove(&id);
            }
        }

        let session = match self.closing.get_mut(&id) {
            Some(closing) => Some(&mut closing.session),
            None => self.assembler.find_mut(&id),
        };
        match session {
            Some(session) => {
                for entry in done.results {
                    session.append(entry.clone());
                    let _ = self.updates.send(Update::Result {
                        session: id,
                        initiator: session.initiator,
                        entry,
                    });
                }
            }
            // Not reachable while sessions wait for their jobs before closing;
            // publish rather than lose the results if it ever is.
            None => {
                for entry in done.results {
                    let _ = self.updates.send(Update::Result {
                        session: id,
                        initiator: id.key.low,
                        entry,
                    });
                }
            }
        }

        if self.closing.contains_key(&id) {
            self.try_finalize(id);
        }
    }

    fn close(&mut self, session: Session) {
        let id = session.id();
        self.closing.insert(
            id,
            Closing {
                session,
                ended: false,
            },
        );
        self.try_finalize(id);
    }

    /// Advance a closing session as far as it can go: once nothing is in
    /// flight, fire its `session-end` methods; once those have reported too,
    /// publish it.
    fn try_finalize(&mut self, id: SessionId) {
        if self.in_flight.contains_key(&id) {
            return;
        }
        let already_ended = match self.closing.get_mut(&id) {
            Some(closing) => std::mem::replace(&mut closing.ended, true),
            None => return,
        };
        if !already_ended {
            let snapshot = Arc::new(self.closing[&id].session.clone());
            if self.fire(TriggerEvent::SessionEnd, &snapshot, None) > 0 {
                return;
            }
        }
        if let Some(closing) = self.closing.remove(&id) {
            let _ = self.updates.send(Update::Finalized(closing.session));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, SystemTime};

    use pf_core::{
        Context, Endpoint, FieldValue, Fields, Method, MethodManifest, SessionState, TcpHeader,
        Transport,
    };

    use super::*;

    /// Counts its calls and reports how many results the session already held.
    struct Probe {
        manifest: MethodManifest,
        calls: Arc<AtomicUsize>,
    }

    impl Method for Probe {
        fn manifest(&self) -> &MethodManifest {
            &self.manifest
        }

        fn extract(&self, ctx: &Context<'_>) -> pf_core::Result<Vec<Fields>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let seen = ctx.session.results.len() as i64;
            Ok(vec![Fields::from([("seen".to_string(), FieldValue::from(seen))])])
        }
    }

    fn probe(name: &str, trigger: &str) -> (Box<dyn Method>, Arc<AtomicUsize>) {
        let manifest = MethodManifest::from_yaml(&format!(
            "name: {name}\nlayer: L1\ntriggers: [{trigger}]\n\
             invocation: {{ type: in-process, adapter: probe }}\n\
             output-schema:\n  - {{ field: seen, type: integer, kind: score }}\n"
        ))
        .expect("probe manifest should parse");
        let calls = Arc::new(AtomicUsize::new(0));
        let method = Probe {
            manifest,
            calls: Arc::clone(&calls),
        };
        (Box::new(method), calls)
    }

    const CLIENT: u16 = 40000;
    const SERVER: u16 = 443;

    fn packet(secs: u64, client_port: u16, to_server: bool, flags: u8, payload: &[u8]) -> Observation {
        let endpoint = |port| Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, if port == SERVER { 1 } else { 9 })),
            port,
        };
        let (source, destination) = if to_server {
            (endpoint(client_port), endpoint(SERVER))
        } else {
            (endpoint(SERVER), endpoint(client_port))
        };
        Observation {
            at: SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
            source,
            destination,
            transport: Transport::Tcp,
            ttl: Some(64),
            tcp: Some(TcpHeader {
                flags,
                window: 29200,
                options: Vec::new(),
            }),
            payload: payload.to_vec(),
        }
    }

    fn finalized(updates: Receiver<Update>) -> Vec<Session> {
        updates
            .into_iter()
            .filter_map(|update| match update {
                Update::Finalized(session) => Some(session),
                Update::Result { .. } => None,
            })
            .collect()
    }

    const SYN: u8 = TcpHeader::SYN;
    const SYN_ACK: u8 = TcpHeader::SYN | TcpHeader::ACK;
    const ACK: u8 = TcpHeader::ACK;
    const PSH_ACK: u8 = TcpHeader::PSH | TcpHeader::ACK;
    const CLIENT_HELLO: &[u8] = &[0x16, 0x03, 0x01, 0x00, 0x40, 0x01, 0x00];

    /// The point of event triggers: the SYN method runs on the SYN and is not
    /// run again because a ClientHello arrives later in the same session.
    #[test]
    fn each_method_runs_once_per_event_it_listens_for() {
        let (syn, syn_calls) = probe("syn", "tcp-syn");
        let (tls, tls_calls) = probe("tls", "tls-client-hello");
        let registry = Arc::new(Registry::new(vec![syn, tls]).unwrap());
        let (mut engine, updates) = Engine::new(registry, Duration::from_secs(30), 4);

        engine.ingest(packet(0, CLIENT, true, SYN, b""));
        engine.ingest(packet(0, CLIENT, false, SYN_ACK, b""));
        engine.ingest(packet(0, CLIENT, true, ACK, b""));
        engine.ingest(packet(1, CLIENT, true, PSH_ACK, CLIENT_HELLO));
        engine.ingest(packet(1, CLIENT, false, PSH_ACK, b"server bytes"));
        engine.finish();

        assert_eq!(syn_calls.load(Ordering::SeqCst), 1);
        assert_eq!(tls_calls.load(Ordering::SeqCst), 1);
        let sessions = finalized(updates);
        assert_eq!(sessions.len(), 1);
        let mut methods: Vec<&str> = sessions[0].results.iter().map(|r| r.method.as_str()).collect();
        methods.sort();
        assert_eq!(methods, ["syn", "tls"]);
    }

    /// Session-end methods wait for everything else the session fired, so a
    /// fusion method always reads the complete result list.
    #[test]
    fn session_end_methods_see_every_earlier_result() {
        let (syn, _) = probe("syn", "tcp-syn");
        let (tls, _) = probe("tls", "tls-client-hello");
        let (end, end_calls) = probe("end", "session-end");
        let registry = Arc::new(Registry::new(vec![syn, tls, end]).unwrap());
        let (mut engine, updates) = Engine::new(registry, Duration::from_secs(30), 4);

        engine.ingest(packet(0, CLIENT, true, SYN, b""));
        engine.ingest(packet(1, CLIENT, true, PSH_ACK, CLIENT_HELLO));
        engine.finish();

        assert_eq!(end_calls.load(Ordering::SeqCst), 1);
        let session = &finalized(updates)[0];
        let end_entry = session.results.last().expect("end reported");
        assert_eq!(end_entry.method, "end");
        assert_eq!(end_entry.fields["seen"], FieldValue::Integer(2));
        assert_eq!(session.results.len(), 3);
    }

    #[test]
    fn a_quiet_session_times_out_and_the_same_flow_later_starts_a_new_one() {
        let (syn, syn_calls) = probe("syn", "tcp-syn");
        let registry = Arc::new(Registry::new(vec![syn]).unwrap());
        let (mut engine, updates) = Engine::new(registry, Duration::from_secs(30), 2);

        engine.ingest(packet(0, CLIENT, true, SYN, b""));
        // Another flow, 100 s later, moves the clock past the first one's timeout.
        engine.ingest(packet(100, CLIENT + 1, true, SYN, b""));
        // The first flow again: a new session under the same key.
        engine.ingest(packet(101, CLIENT, true, SYN, b""));
        engine.finish();

        assert_eq!(syn_calls.load(Ordering::SeqCst), 3);
        let sessions = finalized(updates);
        assert_eq!(sessions.len(), 3);
        let timed_out = sessions
            .iter()
            .filter(|s| s.state == SessionState::TimedOut)
            .count();
        assert_eq!(timed_out, 1);
        assert!(sessions.iter().all(|s| s.results.len() == 1));
    }

    #[test]
    fn every_result_is_published_as_it_is_appended() {
        let (syn, _) = probe("syn", "tcp-syn");
        let (end, _) = probe("end", "session-end");
        let registry = Arc::new(Registry::new(vec![syn, end]).unwrap());
        let (mut engine, updates) = Engine::new(registry, Duration::from_secs(30), 2);

        engine.ingest(packet(0, CLIENT, true, SYN, b""));
        engine.finish();

        let kinds: Vec<&str> = updates
            .into_iter()
            .map(|update| match update {
                Update::Result { .. } => "result",
                Update::Finalized(_) => "finalized",
            })
            .collect();
        assert_eq!(kinds, ["result", "result", "finalized"]);
    }
}
