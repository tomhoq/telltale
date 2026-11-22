use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::evidence::Evidence;
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
    /// Each behind an `Arc`: in inference mode a snapshot of the session goes
    /// to a worker on every packet while the assembler keeps appending, so a
    /// clone copies one pointer per observation instead of every payload,
    /// option list and quirk set. Observations are never changed once pushed.
    /// Read them through [`Session::observations`] or
    /// [`Session::from_initiator`], which yield `&Observation`.
    ///
    /// TODO: cap this. A scanner hammering one port should not be able to grow a
    /// session unboundedly — decide on a ring buffer or a byte budget before
    /// this runs against real traffic.
    pub observations: Vec<Arc<Observation>>,
    /// Methods that are done with this session. Shared by every snapshot of
    /// it (a clone shares it), so it outlives the snapshot a method finished
    /// on. Bookkeeping for the registry, not session data: not serialized.
    #[serde(skip)]
    pub completed: Arc<CompletedMethods>,
}

/// The evidence of each method that returned
/// [`Outcome::Complete`](crate::Outcome::Complete) on a session, by method
/// name. `Complete` means "do not invoke me again", so the registry skips the
/// method on later passes, yet still hands this evidence to the methods after
/// it in a pass (fusion reads the others' evidence).
#[derive(Debug, Default)]
pub struct CompletedMethods(Mutex<HashMap<String, Arc<[Evidence]>>>);

impl CompletedMethods {
    /// What the method said when it completed, if it has.
    pub fn get(&self, method: &str) -> Option<Arc<[Evidence]>> {
        self.lock().get(method).cloned()
    }

    /// Keeps the first record: two snapshots of a session can run on two
    /// workers at once and both complete the same method.
    pub fn record(&self, method: &str, evidence: &[Evidence]) {
        self.lock()
            .entry(method.to_string())
            .or_insert_with(|| evidence.into());
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Arc<[Evidence]>>> {
        // A panic elsewhere while holding it leaves the map itself valid.
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
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
            observations: vec![Arc::new(observation)],
            completed: Arc::default(),
        }
    }

    pub fn push(&mut self, observation: Observation) {
        self.last_seen_at = observation.at;
        if let Some(hint) = observation.stage_hint {
            self.advance(hint);
        }
        self.observations.push(Arc::new(observation));
    }

    /// Every observation, both directions, in arrival order.
    pub fn observations(&self) -> impl Iterator<Item = &Observation> {
        self.observations.iter().map(|o| &**o)
    }

    /// Stages only move forward.
    pub fn advance(&mut self, stage: Stage) {
        if stage > self.stage {
            self.stage = stage;
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
        self.observations().filter(|o| o.source == self.initiator)
    }

    pub fn is_idle_at(&self, now: SystemTime, timeout: Duration) -> bool {
        now.duration_since(self.last_seen_at)
            .map(|idle| idle >= timeout)
            .unwrap_or(false)
    }
}
