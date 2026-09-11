use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::observation::{Direction, Endpoint, Observation, Transport};
use crate::result::ResultEntry;

/// Canonical, direction-independent identity of a flow.
///
/// Built by sorting the two endpoints so that both directions of the same
/// conversation land in the same bucket; the initiator is tracked separately on
/// [`Session`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionKey {
    pub low: Endpoint,
    pub high: Endpoint,
    pub transport: Transport,
}

impl SessionKey {
    pub fn new(a: Endpoint, b: Endpoint, transport: Transport) -> Self {
        let (low, high) = if a <= b { (a, b) } else { (b, a) };
        Self {
            low,
            high,
            transport,
        }
    }
}

/// Identity of one session over time.
///
/// The key alone is not enough: once a session times out, the same flow can
/// open a new session under the same key, and results for the two must not
/// be mixed up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId {
    pub key: SessionKey,
    pub started_at: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionState {
    Active,
    /// Finished because the source ran out.
    Closed,
    /// The inactivity timeout fired. Whatever results exist are the session's
    /// results; nothing waits for traffic that never came.
    TimedOut,
}

/// Everything seen so far in one flow, and everything methods said about it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub key: SessionKey,
    /// Whoever sent the first observation — for a honeypot, the client being
    /// fingerprinted.
    pub initiator: Endpoint,
    pub started_at: SystemTime,
    pub last_seen_at: SystemTime,
    pub state: SessionState,
    /// Observations in arrival order.
    ///
    /// TODO: cap this. A scanner hammering one port should not be able to grow a
    /// session unboundedly — decide on a ring buffer or a byte budget before
    /// this runs against real traffic.
    pub observations: Vec<Observation>,
    /// Append-only. Entries are added as methods report and are never edited
    /// or removed.
    pub results: Vec<ResultEntry>,
}

impl Session {
    pub fn open(observation: Observation) -> Self {
        let key = SessionKey::new(
            observation.source,
            observation.destination,
            observation.transport,
        );
        Self {
            key,
            initiator: observation.source,
            started_at: observation.at,
            last_seen_at: observation.at,
            state: SessionState::Active,
            observations: vec![observation],
            results: Vec::new(),
        }
    }

    pub fn id(&self) -> SessionId {
        SessionId {
            key: self.key,
            started_at: self.started_at,
        }
    }

    pub fn push(&mut self, observation: Observation) {
        self.last_seen_at = observation.at;
        self.observations.push(observation);
    }

    /// The only way results enter a session.
    pub fn append(&mut self, entry: ResultEntry) {
        self.results.push(entry);
    }

    pub fn direction_of(&self, observation: &Observation) -> Direction {
        if observation.source == self.initiator {
            Direction::ToResponder
        } else {
            Direction::ToInitiator
        }
    }

    /// Observations sent by the initiator — usually all a method cares about.
    pub fn from_initiator(&self) -> impl Iterator<Item = &Observation> {
        self.observations
            .iter()
            .filter(|o| o.source == self.initiator)
    }

    pub fn is_idle_at(&self, now: SystemTime, timeout: Duration) -> bool {
        now.duration_since(self.last_seen_at)
            .map(|idle| idle >= timeout)
            .unwrap_or(false)
    }
}
