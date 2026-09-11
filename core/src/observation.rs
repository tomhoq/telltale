use std::net::IpAddr;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// One normalized record out of a capture source — the spec's `Packet`.
///
/// Every source — live interface, pcap file, tcpdump output, honeypot log —
/// produces these, which is what lets the rest of the pipeline stay
/// source-agnostic. A source that genuinely cannot fill a field (a honeypot log
/// with no raw payload, say) leaves it empty rather than inventing one.
///
/// Carries the parsed header fields methods fingerprint on, not an
/// interpretation of them: deciding that a packet is a SYN or a ClientHello is
/// the dispatcher's trigger classifier's job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub at: SystemTime,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub transport: Transport,
    /// IPv4 TTL or IPv6 hop limit, as it arrived.
    pub ttl: Option<u8>,
    /// Present for TCP only.
    pub tcp: Option<TcpHeader>,
    /// Bytes above the transport header, if the source has them.
    pub payload: Vec<u8>,
}

/// The TCP header fields stack fingerprinting reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpHeader {
    /// Raw flag bits; see [`TcpHeader::SYN`] and friends.
    pub flags: u8,
    pub window: u16,
    /// The options block exactly as sent, unparsed. Option order is itself a
    /// fingerprint, so nothing here normalizes it.
    pub options: Vec<u8>,
}

impl TcpHeader {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;

    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
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
