use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use pf_core::{Observation, Session, SessionId, SessionKey, SessionState};

/// 5-tuple + timeout session correlation.
///
/// Single-threaded on purpose: this sits on the capture thread, so it never
/// needs a lock.
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

    /// Add an observation to its session, opening one if this flow has none.
    /// Returns the session's key.
    pub fn ingest(&mut self, observation: Observation) -> SessionKey {
        let key = SessionKey::new(
            observation.source,
            observation.destination,
            observation.transport,
        );
        match self.sessions.get_mut(&key) {
            Some(session) => session.push(observation),
            None => {
                self.sessions.insert(key, Session::open(observation));
            }
        }
        key
    }

    pub fn get(&self, key: &SessionKey) -> Option<&Session> {
        self.sessions.get(key)
    }

    /// The open session with exactly this identity — not a newer session that
    /// has since opened under the same key.
    pub fn find_mut(&mut self, id: &SessionId) -> Option<&mut Session> {
        self.sessions
            .get_mut(&id.key)
            .filter(|session| session.started_at == id.started_at)
    }

    /// Close out every session idle for longer than the timeout.
    ///
    /// This is what keeps the pipeline from ever waiting on traffic: a session
    /// that went quiet is finished with whatever results it has.
    pub fn expire(&mut self, now: SystemTime) -> Vec<Session> {
        let stale: Vec<SessionKey> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.is_idle_at(now, self.timeout))
            .map(|(k, _)| *k)
            .collect();

        let mut expired: Vec<Session> = stale
            .into_iter()
            .filter_map(|key| self.sessions.remove(&key))
            .map(|mut session| {
                session.state = SessionState::TimedOut;
                session
            })
            .collect();
        expired.sort_by_key(|session| session.started_at);
        expired
    }

    /// Finish everything still open — call once the source is exhausted.
    /// Oldest first, so output follows the capture rather than hash order.
    pub fn drain(&mut self) -> Vec<Session> {
        let mut sessions: Vec<Session> = self
            .sessions
            .drain()
            .map(|(_, mut session)| {
                session.state = SessionState::Closed;
                session
            })
            .collect();
        sessions.sort_by_key(|session| session.started_at);
        sessions
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}
