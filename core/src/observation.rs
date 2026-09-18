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
    /// Raw TCP/IP stack characteristics — TTL, window, options — for any
    /// method that does passive stack fingerprinting from them. `None` for
    /// non-TCP transports, and for any source that cannot see header-level
    /// detail (a honeypot log, say).
    #[serde(default)]
    pub tcp: Option<TcpFeatures>,
}

/// The header-level detail one TCP segment carries, in the order and shape
/// p0f-style fingerprinting keys on. Values are read as-is off the wire and
/// interpreted nowhere in this crate — a method's own signature database
/// decides what they mean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpFeatures {
    /// IP TTL / hop limit as received — already decremented by however many
    /// hops the packet crossed, not the sender's initial value.
    pub ttl: u8,
    /// IPv4 Don't Fragment bit. IPv6 has no equivalent flag (fragmentation is
    /// a separate extension header we do not walk yet), so this is always
    /// `true` there.
    pub df: bool,
    pub window: u16,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub timestamp: bool,
    /// Option kinds in wire order, including repeats and padding NOPs — the
    /// order and padding are as diagnostic as which options are present. Ends
    /// at the EOL option, if there is one: what follows it is padding, not
    /// options, and is counted in `eol_padding` instead.
    pub option_order: Vec<TcpOptionKind>,
    /// Bytes after the EOL option that fill the options area out to its
    /// 4-byte boundary — p0f's `eol+N`. `None` when no EOL was sent.
    #[serde(default)]
    pub eol_padding: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TcpOptionKind {
    Eol,
    Nop,
    Mss,
    WindowScale,
    SackPermitted,
    Sack,
    Timestamp,
    Other(u8),
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

