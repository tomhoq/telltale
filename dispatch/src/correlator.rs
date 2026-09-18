use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use pf_core::{Observation, Session, SessionKey, SessionState, Stage};

/// What the assembler/correlator wants the dispatcher to do after ingesting one observation.
#[derive(Debug, Clone)]
pub enum Emitted {
    /// A new session appeared.
    Opened(SessionKey),
    /// An existing session grew. Streaming-mode methods re-run here.
    Updated(SessionKey),
    /// The session is finished — closed or timed out — and will not change again.
    Finished(Session),
}

/// The stage a segment's payload proves the session has reached, if any. A
/// TLS ClientHello is its own stage, which is what `ja4`-style methods wait
/// for; any other bytes mean application data is flowing, which is what
/// `banner`-style methods wait for.
fn payload_stage(payload: &[u8]) -> Option<Stage> {
    if payload.is_empty() {
        return None;
    }
    // TLS record header: handshake (0x16), major version 3, then two bytes of
    // minor version and two of length; the handshake type after it is 1 for
    // ClientHello.
    let client_hello = payload.len() > 5 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01;
    Some(if client_hello {
        Stage::TlsClientHello
    } else {
        Stage::AppData
    })
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

        // The flags only say where the handshake is; whether application
        // bytes have started is read off the payload here.
        // TODO: FIN/RST -> Closed, from session lifecycle (see
        // `pf_capture::decode::tcp_stage` on why not from one packet).
        let payload_stage = payload_stage(&observation.payload);

        match self.sessions.get_mut(&key) {
            Some(session) => {
                session.push(observation);
                if let Some(stage) = payload_stage {
                    session.advance(stage);
                }
                Emitted::Updated(key)
            }
            None => {
                let mut session = Session::open(observation);
                if let Some(stage) = payload_stage {
                    session.advance(stage);
                }
                self.sessions.insert(key, session);
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use pf_core::{Endpoint, Transport};

    use super::*;

    fn segment(from_port: u16, stage_hint: Option<Stage>, payload: &[u8]) -> Observation {
        let host = |last, port| Endpoint {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)),
            port,
        };
        let (source, destination) = if from_port == 80 {
            (host(1, 80), host(7, 50905))
        } else {
            (host(7, 50905), host(1, 80))
        };
        Observation {
            at: SystemTime::UNIX_EPOCH,
            source,
            destination,
            transport: Transport::Tcp,
            payload: payload.to_vec(),
            stage_hint,
            tcp: None,
        }
    }

    fn stage_after(segments: Vec<Observation>) -> Stage {
        let mut assembler = Assembler::new(Duration::from_secs(30));
        let mut key = None;
        for segment in segments {
            key = Some(match assembler.ingest(segment) {
                Emitted::Opened(key) | Emitted::Updated(key) => key,
                Emitted::Finished(_) => unreachable!("nothing finishes mid-ingest here"),
            });
        }
        assembler.get(&key.unwrap()).unwrap().stage
    }

    #[test]
    fn a_handshake_alone_is_established_not_app_data() {
        let stage = stage_after(vec![
            segment(50905, Some(Stage::Connect), b""),
            segment(80, Some(Stage::Established), b""),
            segment(50905, Some(Stage::Established), b""),
        ]);
        assert_eq!(stage, Stage::Established);
    }

    /// What `banner` waits for: before this, no session ever reached
    /// `app-data` until it timed out.
    #[test]
    fn an_http_request_reaches_app_data() {
        let stage = stage_after(vec![
            segment(50905, Some(Stage::Connect), b""),
            segment(80, Some(Stage::Established), b""),
            segment(
                50905,
                Some(Stage::Established),
                b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8.5.0\r\n\r\n",
            ),
        ]);
        assert_eq!(stage, Stage::AppData);
    }

    #[test]
    fn a_tls_client_hello_reaches_its_own_stage() {
        let client_hello = [0x16, 0x03, 0x01, 0x00, 0xa5, 0x01, 0x00, 0x00, 0xa1];
        let stage = stage_after(vec![
            segment(50905, Some(Stage::Connect), b""),
            segment(50905, Some(Stage::Established), &client_hello),
        ]);
        assert_eq!(stage, Stage::TlsClientHello);
    }
}
