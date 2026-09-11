use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::observation::{Direction, Endpoint, Observation, Transport};

/// How far a session has progressed.
///
/// Declaration order is significant: `Ord` is derived, and a manifest's
/// `required_stage` is satisfied when the session has reached a stage that is
/// greater than or equal to it. Insert new stages in the right place, not at the
/// end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    /// First packet seen; for TCP that is the SYN.
    Connect,
    /// Transport handshake complete.
    Established,
    /// TLS ClientHello observed (what ja4-style methods need).
    TlsClientHello,
    /// Application bytes flowing in either direction.
    AppData,
    /// Peer closed, or the timeout fired.
    Closed,
}

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
/// replace each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId {
    pub key: SessionKey,
    pub started_at: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionState {
    Active,
    /// Closed cleanly by a peer.
    Closed,
    /// The inactivity timeout fired. Methods still run, but anything that needed
    /// a stage this session never reached reports partial or no result rather
    /// than holding the session open.
    TimedOut,
}

/// The unit of work handed to methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub key: SessionKey,
    /// Whoever sent the first observation. For scanner detection this is the
    /// endpoint being judged.
    pub initiator: Endpoint,
    pub started_at: SystemTime,
    pub last_seen_at: SystemTime,
    pub state: SessionState,
    /// Furthest stage reached, monotonic.
    pub stage: Stage,
    /// Observations in arrival order.
    ///
    /// TODO: cap this. A scanner hammering one port should not be able to grow a
    /// session unboundedly — decide on a ring buffer or a byte budget before
    /// this runs against real traffic.
    pub observations: Vec<Observation>,
}

impl Session {
    pub fn open(observation: Observation) -> Self {
        let key = SessionKey::new(
            observation.source,
            observation.destination,
            observation.transport,
        );
        let stage = observation.stage_hint.unwrap_or(Stage::Connect);
        Self {
            key,
            initiator: observation.source,
            started_at: observation.at,
            last_seen_at: observation.at,
            state: SessionState::Active,
            stage,
            observations: vec![observation],
        }
    }

    pub fn id(&self) -> SessionId {
        SessionId {
            key: self.key,
            started_at: self.started_at,
        }
    }

    /// Append an observation. Returns whether it moved the session to a new
    /// stage — the moment methods gated on that stage become runnable.
    pub fn push(&mut self, observation: Observation) -> bool {
        self.last_seen_at = observation.at;
        let advanced = match observation.stage_hint {
            Some(hint) => self.advance(hint),
            None => false,
        };
        self.observations.push(observation);
        advanced
    }

    /// Stages only move forward. Returns whether this one did.
    pub fn advance(&mut self, stage: Stage) -> bool {
        if stage > self.stage {
            self.stage = stage;
            true
        } else {
            false
        }
    }

    pub fn reached(&self, stage: Stage) -> bool {
        self.stage >= stage
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
