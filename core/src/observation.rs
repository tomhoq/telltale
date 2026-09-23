use std::collections::BTreeSet;
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
    /// Bytes of IPv4 header options (header length minus the fixed 20) —
    /// p0f's `olen`. Always 0 on IPv6, which carries options as extension
    /// headers instead.
    #[serde(default)]
    pub ip_option_len: u8,
    /// Every IP/TCP header oddity p0f keys on, whichever layer it came from.
    #[serde(default)]
    pub quirks: BTreeSet<TcpQuirk>,
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

impl TcpFeatures {
    /// IPv4 Don't Fragment bit. Never set on IPv6, which has no such flag.
    pub fn df(&self) -> bool {
        self.quirks.contains(&TcpQuirk::Df)
    }
}

/// p0f's header quirks: things a stack sets, or leaves set, that the protocol
/// does not require and that differ from one implementation to the next.
/// Declared in the order p0f prints them in a signature, which the derived
/// `Ord` keeps, so a `BTreeSet` of these iterates in p0f's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TcpQuirk {
    /// IPv4 Don't Fragment set (`df`).
    Df,
    /// DF set, yet a non-zero IPv4 ID (`id+`).
    NonZeroId,
    /// DF clear, yet a zero IPv4 ID (`id-`).
    ZeroId,
    /// ECN in use: the IP ECN field, or TCP's ECE/CWR/NS (`ecn`).
    Ecn,
    /// IPv4 reserved ("must be zero") flag set (`0+`).
    NonZeroReserved,
    /// Non-zero IPv6 flow label (`flow`).
    Flow,
    /// Sequence number zero (`seq-`).
    ZeroSeq,
    /// ACK flag clear, yet a non-zero acknowledgement number (`ack+`).
    NonZeroAck,
    /// ACK flag set, yet a zero acknowledgement number (`ack-`).
    ZeroAck,
    /// URG flag clear, yet a non-zero urgent pointer (`uptr+`).
    NonZeroUrgentPtr,
    /// URG flag set (`urgf+`).
    Urg,
    /// PSH flag set (`pushf+`).
    Push,
    /// Own timestamp zero (`ts1-`).
    ZeroTimestamp,
    /// Peer timestamp non-zero on an initial SYN (`ts2+`).
    NonZeroPeerTimestamp,
    /// Non-zero bytes after the EOL option (`opt+`).
    NonZeroPadding,
    /// Window scale above the maximum of 14 (`exws`).
    ExcessiveWindowScale,
    /// Malformed options: a bad length, or one running off the header (`bad`).
    BadOptions,
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

