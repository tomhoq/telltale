use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use pf_core::{Observation, Session, SessionKey, SessionState, Stage};

/// What the assembler/correlator wants the dispatcher to do after ingesting one observation.
#[derive(Debug, Clone)]
pub enum Emitted {
    /// A new session appeared. Its first stage is reached.
    Opened(SessionKey),
    /// An existing session reached a new stage, so methods gated on it can
    /// now run. Streaming mode re-analyses here.
    Advanced(SessionKey),
    /// An existing session grew without changing stage. Only
    /// `every-observation` methods have anything new to say.
    Updated(SessionKey),
    /// The session is finished — closed or timed out — and will not change again.
    Finished(Session),
}

/// 5-tuple + timeout session correlation.
///
/// Single-threaded on purpose: this sits on the capture thread and hands
/// completed work to the worker pool, so it never needs a lock.
pub struct Assembler {
    timeout: Duration,
    sessions: HashMap<SessionKey, Session>,
}

/// Alias for [`Assembler`] to match the terminology in the spec.
pub type SessionCorrelator = Assembler;

impl Assembler {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            sessions: HashMap::new(),
        }
    }

    pub fn get(&self, key: &SessionKey) -> Option<&Session> {
        self.sessions.get(key)
    }

    pub fn ingest(&mut self, observation: Observation) -> Emitted {
        let key = SessionKey::new(
            observation.source,
            observation.destination,
            observation.transport,
        );

        match self.sessions.get_mut(&key) {
            Some(session) => {
                // TODO: infer stage transitions from the packet itself
                // (SYN/ACK -> Established, ClientHello -> TlsClientHello,
                // FIN/RST -> Closed) instead of relying only on stage_hint.
                if session.push(observation) {
                    Emitted::Advanced(key)
                } else {
                    Emitted::Updated(key)
                }
            }
            None => {
                self.sessions.insert(key, Session::open(observation));
                Emitted::Opened(key)
            }
        }
    }

    /// Close out every session idle for longer than the timeout.
    ///
    /// This is the mechanism behind the "no blocking" rule: a session whose
    /// methods are still waiting for a stage that never arrived gets finished
    /// anyway, and those methods report partial or no result.
    pub fn expire(&mut self, now: SystemTime) -> Vec<Session> {
        let stale: Vec<SessionKey> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.is_idle_at(now, self.timeout))
            .map(|(k, _)| *k)
            .collect();

        stale
            .into_iter()
            .filter_map(|key| self.sessions.remove(&key))
            .map(|mut session| {
                session.state = SessionState::TimedOut;
                session.advance(Stage::Closed);
                session
            })
            .collect()
    }

    /// Finish everything still open — call once the source is exhausted.
    pub fn drain(&mut self) -> Vec<Session> {
        self.sessions
            .drain()
            .map(|(_, mut session)| {
                if session.state == SessionState::Active {
                    session.state = SessionState::Closed;
                }
                session.advance(Stage::Closed);
                session
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}
