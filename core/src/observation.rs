use std::net::IpAddr;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::session::Stage;

/// One normalized record out of a capture source.
///
/// Every source — live interface, pcap file, tcpdump output, honeypot log —
/// produces these, which is what lets the rest of the pipeline stay
/// source-agnostic. A source that genuinely cannot fill a field (a honeypot log
/// with no raw payload, say) leaves it empty rather than inventing one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub at: SystemTime,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub transport: Transport,
    /// Bytes above the transport header, if the source has them.
    pub payload: Vec<u8>,
    /// A source that already knows what it is looking at (a honeypot log saying
    /// "TLS ClientHello") can say so; otherwise the assembler infers the stage.
    pub stage_hint: Option<Stage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Endpoint {
    pub addr: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    Tcp,
    Udp,
    Quic,
    Other(u8),
}

/// Which way an observation travelled relative to the session initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    /// Initiator -> responder. Honeypot logs often only see this direction, so it's the default.
    ToResponder,
    ToInitiator,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_serialization() {
        let yaml = serde_yaml::to_string(&Transport::Quic).unwrap();
        assert_eq!(yaml.trim(), "quic");
        let deserialized: Transport = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized, Transport::Quic);
    }
}

