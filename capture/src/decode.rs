//! Wire bytes to [`Observation`].
//!
//! Kept out of the individual sources because a live interface, a pcap replay
//! and `tcpdump -w -` all hand over the same frames; only the way they arrive
//! differs.
//!
//! Everything here parses attacker-controlled input, so no length field is
//! trusted on its own: each header length is re-derived and clamped against the
//! bytes that actually arrived, and a frame that does not add up is dropped
//! rather than decoded on a guess. Dropping is spelled `None`, not `Err` — on a
//! live interface, undecodable frames are constant background noise, and a
//! source that failed on them would not survive its first second of traffic.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::SystemTime;

use pf_core::{Endpoint, Observation, Stage, TcpFeatures, TcpOptionKind, TcpQuirk, Transport};
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet};
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;

const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_TAG_LEN: usize = 4;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

/// The IPv4 flag bit RFC 791 reserves, "must be zero". pnet names DF and MF
/// but not this one.
const IPV4_RESERVED_FLAG: u8 = 0b100;
/// The two ECN bits at the bottom of the IPv4 TOS / IPv6 traffic class.
const ECN_MASK: u8 = 0b11;
/// TCP's ECN-nonce bit, the lowest bit of the nibble pnet calls `reserved`.
const TCP_NS: u8 = 0b0001;
/// RFC 7323: a window scale shift above this is invalid.
const MAX_WINDOW_SCALE: u8 = 14;

/// Stacked VLAN tags to unwrap before giving up. Two covers 802.1Q and QinQ;
/// the bound is what stops a crafted frame from walking us off the end.
const MAX_VLAN_TAGS: usize = 2;

/// Decode one Ethernet frame, `at` being when it was captured.
///
/// Returns `None` for anything that is not IP — ARP, LLDP, STP — and for
/// malformed headers.
pub fn ethernet_frame(frame: &[u8], at: SystemTime) -> Option<Observation> {
    let ethernet = EthernetPacket::new(frame)?;
    let mut ethertype = ethernet.get_ethertype();
    let mut payload = &frame[ETHERNET_HEADER_LEN..];

    // The tags themselves carry nothing the pipeline uses, so unwrap them and
    // decode what is inside. A tagged frame is otherwise invisible to us, which
    // on a trunk port would be most of the traffic.
    for _ in 0..MAX_VLAN_TAGS {
        if !is_vlan(ethertype) {
            break;
        }
        if payload.len() < VLAN_TAG_LEN {
            return None;
        }
        ethertype = EtherType(u16::from_be_bytes([payload[2], payload[3]]));
        payload = &payload[VLAN_TAG_LEN..];
    }

    match ethertype {
        EtherTypes::Ipv4 | EtherTypes::Ipv6 => ip_packet(payload, at),
        _ => None,
    }
}

/// Decode a bare IP packet — what a point-to-point link (tun, ppp) delivers,
/// with no link-layer header in front of it.
pub fn ip_packet(packet: &[u8], at: SystemTime) -> Option<Observation> {
    match packet.first()? >> 4 {
        4 => ipv4(packet, at),
        6 => ipv6(packet, at),
        _ => None,
    }
}

fn is_vlan(ethertype: EtherType) -> bool {
    matches!(ethertype.0, 0x8100 | 0x88a8 | 0x9100)
}

fn ipv4(packet: &[u8], at: SystemTime) -> Option<Observation> {
    let ip = Ipv4Packet::new(packet)?;

    let header_len = ip.get_header_length() as usize * 4;
    if !(IPV4_MIN_HEADER_LEN..=packet.len()).contains(&header_len) {
        return None;
    }
    // The shorter of what the header claims and what arrived: a padded frame
    // carries trailing bytes that are not payload, a truncated one claims more
    // than it has.
    let end = (ip.get_total_length() as usize).clamp(header_len, packet.len());

    // Only the first fragment carries a transport header. The rest are dropped
    // rather than parsed against whatever happens to sit at offset zero — and a
    // session cannot start on one anyway.
    if ip.get_fragment_offset() != 0 {
        return None;
    }

    // p0f's IPv4 quirks. The ID only means something relative to DF: a stack
    // that forbids fragmentation has no use for an ID, so which way it goes
    // there is a choice the stack made.
    let mut quirks = BTreeSet::new();
    let flags = ip.get_flags();
    let id = ip.get_identification();
    if flags & Ipv4Flags::DontFragment != 0 {
        quirks.insert(TcpQuirk::Df);
        if id != 0 {
            quirks.insert(TcpQuirk::NonZeroId);
        }
    } else if id == 0 {
        quirks.insert(TcpQuirk::ZeroId);
    }
    if flags & IPV4_RESERVED_FLAG != 0 {
        quirks.insert(TcpQuirk::NonZeroReserved);
    }
    if ip.get_ecn() != 0 {
        quirks.insert(TcpQuirk::Ecn);
    }

    transport(
        ip.get_next_level_protocol(),
        IpAddr::V4(ip.get_source()),
        IpAddr::V4(ip.get_destination()),
        &packet[header_len..end],
        at,
        IpLayer {
            ttl: ip.get_ttl(),
            option_len: (header_len - IPV4_MIN_HEADER_LEN) as u8,
            quirks,
        },
    )
}

fn ipv6(packet: &[u8], at: SystemTime) -> Option<Observation> {
    let ip = Ipv6Packet::new(packet)?;
    let end =
        (IPV6_HEADER_LEN + ip.get_payload_length() as usize).clamp(IPV6_HEADER_LEN, packet.len());

    // TODO: walk the hop-by-hop/routing/fragment extension header chain. Until
    // then a packet carrying one decodes as `Transport::Other(proto)`, which
    // loses the ports but is at least not a TCP header read off the wrong
    // offset.

    // IPv6 has neither DF nor an ID in its fixed header; its quirks are a
    // flow label and ECN in the traffic class.
    let mut quirks = BTreeSet::new();
    if ip.get_flow_label() != 0 {
        quirks.insert(TcpQuirk::Flow);
    }
    if ip.get_traffic_class() & ECN_MASK != 0 {
        quirks.insert(TcpQuirk::Ecn);
    }

    transport(
        ip.get_next_header(),
        IpAddr::V6(ip.get_source()),
        IpAddr::V6(ip.get_destination()),
        &packet[IPV6_HEADER_LEN..end],
        at,
        IpLayer {
            ttl: ip.get_hop_limit(),
            option_len: 0,
            quirks,
        },
    )
}

/// What the IP header contributes to [`TcpFeatures`].
struct IpLayer {
    ttl: u8,
    option_len: u8,
    quirks: BTreeSet<TcpQuirk>,
}

fn transport(
    protocol: IpNextHeaderProtocol,
    source: IpAddr,
    destination: IpAddr,
    segment: &[u8],
    at: SystemTime,
    ip: IpLayer,
) -> Option<Observation> {
    let (transport, source_port, destination_port, payload, stage_hint, tcp) = match protocol {
        IpNextHeaderProtocols::Tcp => {
            let tcp_packet = TcpPacket::new(segment)?;
            let header_len = tcp_packet.get_data_offset() as usize * 4;
            if !(TCP_MIN_HEADER_LEN..=segment.len()).contains(&header_len) {
                return None;
            }
            (
                Transport::Tcp,
                tcp_packet.get_source(),
                tcp_packet.get_destination(),
                &segment[header_len..],
                tcp_stage(tcp_packet.get_flags()),
                Some(tcp_features(&tcp_packet, ip)),
            )
        }
        IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(segment)?;
            let end = (udp.get_length() as usize).clamp(UDP_HEADER_LEN, segment.len());
            (
                Transport::Udp,
                udp.get_source(),
                udp.get_destination(),
                &segment[UDP_HEADER_LEN..end],
                None,
                None,
            )
        }
        // ICMP, ESP, GRE and friends: no ports to report, but the flow is still
        // worth correlating, so it is kept with the raw bytes intact.
        other => (Transport::Other(other.0), 0, 0, segment, None, None),
    };

    Some(Observation {
        at,
        source: Endpoint {
            addr: source,
            port: source_port,
        },
        destination: Endpoint {
            addr: destination,
            port: destination_port,
        },
        transport,
        payload: payload.to_vec(),
        stage_hint,
        tcp,
    })
}

/// Every TCP/IP stack characteristic a passive fingerprinting method might
/// want off one segment: what the IP header contributed (TTL, option length,
/// its quirks), plus the TCP window, options and quirks as they arrived on
/// the wire — order, padding and all, since which options a stack sends and
/// in what order is as diagnostic as their values. Which of this is actually
/// diagnostic is a method's call, not this crate's; it is carried on
/// [`Observation`] as-is.
///
/// The quirks are p0f's, computed the way p0f computes them, so a method
/// matching p0f's database compares like with like.
fn tcp_features(tcp: &TcpPacket, ip: IpLayer) -> TcpFeatures {
    let mut quirks = ip.quirks;
    let flags = tcp.get_flags();
    let is_initial_syn = flags & (TcpFlags::SYN | TcpFlags::ACK) == TcpFlags::SYN;

    if flags & (TcpFlags::ECE | TcpFlags::CWR) != 0 || tcp.get_reserved() & TCP_NS != 0 {
        quirks.insert(TcpQuirk::Ecn);
    }
    if tcp.get_sequence() == 0 {
        quirks.insert(TcpQuirk::ZeroSeq);
    }
    // An acknowledgement number is only meaningful under ACK. A RST without
    // ACK may still echo one, so that alone is not held against the stack.
    if flags & TcpFlags::ACK != 0 {
        if tcp.get_acknowledgement() == 0 {
            quirks.insert(TcpQuirk::ZeroAck);
        }
    } else if tcp.get_acknowledgement() != 0 && flags & TcpFlags::RST == 0 {
        quirks.insert(TcpQuirk::NonZeroAck);
    }
    if flags & TcpFlags::URG != 0 {
        quirks.insert(TcpQuirk::Urg);
    } else if tcp.get_urgent_ptr() != 0 {
        quirks.insert(TcpQuirk::NonZeroUrgentPtr);
    }
    if flags & TcpFlags::PSH != 0 {
        quirks.insert(TcpQuirk::Push);
    }

    let mut mss = None;
    let mut window_scale = None;
    let mut sack_permitted = false;
    let mut timestamp = false;
    let mut option_order = Vec::new();
    let mut eol_padding = None;

    // Walked by hand rather than with pnet's option iterator: a malformed
    // option is itself a quirk (`bad`), and so is non-zero padding after EOL
    // (`opt+`), and the iterator hides both. Like p0f, an option is listed
    // before its length is checked, and the walk stops at the first one that
    // runs off the end of the header.
    let raw = tcp.get_options_raw();
    let mut at = 0usize;
    while at < raw.len() {
        let kind = match raw[at] {
            0 => TcpOptionKind::Eol,
            1 => TcpOptionKind::Nop,
            2 => TcpOptionKind::Mss,
            3 => TcpOptionKind::WindowScale,
            4 => TcpOptionKind::SackPermitted,
            5 => TcpOptionKind::Sack,
            8 => TcpOptionKind::Timestamp,
            other => TcpOptionKind::Other(other),
        };
        option_order.push(kind);

        match kind {
            // Whatever follows EOL pads the header out to its 4-byte
            // boundary. It is not more options, so it is counted rather than
            // decoded — but a stack that pads with anything but zeros is
            // leaking something, and that is worth knowing.
            TcpOptionKind::Eol => {
                let padding = &raw[at + 1..];
                eol_padding = Some(padding.len() as u8);
                if padding.iter().any(|&byte| byte != 0) {
                    quirks.insert(TcpQuirk::NonZeroPadding);
                }
                break;
            }
            TcpOptionKind::Nop => {
                at += 1;
                continue;
            }
            _ => {}
        }

        // Every other option is kind, length (counting both), then data.
        let Some(&len) = raw.get(at + 1) else {
            quirks.insert(TcpQuirk::BadOptions);
            break;
        };
        let len = len as usize;
        if len < 2 || at + len > raw.len() {
            quirks.insert(TcpQuirk::BadOptions);
            break;
        }
        let data = &raw[at + 2..at + len];
        let valid_len = match kind {
            TcpOptionKind::Mss => data.len() == 2,
            TcpOptionKind::WindowScale => data.len() == 1,
            TcpOptionKind::SackPermitted => data.is_empty(),
            // One to four blocks of two 32-bit edges.
            TcpOptionKind::Sack => (8..=32).contains(&data.len()) && data.len() % 8 == 0,
            TcpOptionKind::Timestamp => data.len() == 8,
            _ => true,
        };
        if !valid_len {
            quirks.insert(TcpQuirk::BadOptions);
        }

        match kind {
            TcpOptionKind::Mss if valid_len => mss = Some(u16::from_be_bytes([data[0], data[1]])),
            TcpOptionKind::WindowScale if valid_len => {
                window_scale = Some(data[0]);
                if data[0] > MAX_WINDOW_SCALE {
                    quirks.insert(TcpQuirk::ExcessiveWindowScale);
                }
            }
            TcpOptionKind::SackPermitted => sack_permitted = true,
            TcpOptionKind::Timestamp => {
                timestamp = true;
                if valid_len {
                    let own = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    let peer = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                    if own == 0 {
                        quirks.insert(TcpQuirk::ZeroTimestamp);
                    }
                    // Nothing to echo yet on an initial SYN.
                    if peer != 0 && is_initial_syn {
                        quirks.insert(TcpQuirk::NonZeroPeerTimestamp);
                    }
                }
            }
            _ => {}
        }
        at += len;
    }

    TcpFeatures {
        ttl: ip.ttl,
        ip_option_len: ip.option_len,
        quirks,
        window: tcp.get_window(),
        mss,
        window_scale,
        sack_permitted,
        timestamp,
        option_order,
        eol_padding,
    }
}

/// What the TCP flags establish on their own, and no more.
///
/// FIN and RST deliberately do not map to [`Stage::Closed`]. `Stage` is ordered
/// and `Closed` is its maximum, so a bare SYN scan answered with a RST would
/// satisfy every manifest's `required_stage` gate — the exact traffic this tool
/// exists to catch would look like a completed conversation. Closing is the
/// assembler's call, made from session lifecycle rather than from one packet.
///
/// The flags are not preserved anywhere else: [`Observation`] has no field for
/// them. A method that needs to distinguish a RST from a FIN will have to add
/// one.
fn tcp_stage(flags: u8) -> Option<Stage> {
    match (flags & TcpFlags::SYN != 0, flags & TcpFlags::ACK != 0) {
        (true, false) => Some(Stage::Connect),
        (true, true) => Some(Stage::Established),
        // A mid-stream segment proves the handshake happened but says nothing
        // about what its bytes are; the assembler reads the payload for that.
        (false, true) => Some(Stage::Established),
        (false, false) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: [u8; 4] = [10, 0, 0, 9];
    const DST: [u8; 4] = [10, 0, 0, 1];

    fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0xff; 12];
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn ipv4(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x45, 0x00];
        packet.extend_from_slice(&((IPV4_MIN_HEADER_LEN + payload.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol, 0, 0]);
        packet.extend_from_slice(&SRC);
        packet.extend_from_slice(&DST);
        packet.extend_from_slice(payload);
        packet
    }

    fn tcp(source: u16, destination: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut segment = Vec::new();
        segment.extend_from_slice(&source.to_be_bytes());
        segment.extend_from_slice(&destination.to_be_bytes());
        segment.extend_from_slice(&[0; 8]); // seq + ack
        segment.extend_from_slice(&[0x50, flags]); // data offset 5 words, flags
        segment.extend_from_slice(&[0; 6]); // window + checksum + urgent
        segment.extend_from_slice(payload);
        segment
    }

    fn udp(source: u16, destination: u16, payload: &[u8]) -> Vec<u8> {
        let mut datagram = Vec::new();
        datagram.extend_from_slice(&source.to_be_bytes());
        datagram.extend_from_slice(&destination.to_be_bytes());
        datagram.extend_from_slice(&((UDP_HEADER_LEN + payload.len()) as u16).to_be_bytes());
        datagram.extend_from_slice(&[0, 0]); // checksum
        datagram.extend_from_slice(payload);
        datagram
    }

    /// Like `tcp`, but with a raw options block — padded to a 4-byte boundary
    /// with NOPs, same as a real stack would — so `tcp_features` has something
    /// to parse.
    fn tcp_with_options(
        source: u16,
        destination: u16,
        flags: u8,
        options: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut padded = options.to_vec();
        while padded.len() % 4 != 0 {
            padded.push(0x01); // NOP
        }
        let data_offset_words = ((TCP_MIN_HEADER_LEN + padded.len()) / 4) as u8;

        let mut segment = Vec::new();
        segment.extend_from_slice(&source.to_be_bytes());
        segment.extend_from_slice(&destination.to_be_bytes());
        segment.extend_from_slice(&[0; 8]); // seq + ack
        segment.push(data_offset_words << 4);
        segment.push(flags);
        segment.extend_from_slice(&0x7120u16.to_be_bytes()); // window
        segment.extend_from_slice(&[0, 0]); // checksum
        segment.extend_from_slice(&[0, 0]); // urgent
        segment.extend_from_slice(&padded);
        segment.extend_from_slice(payload);
        segment
    }

    #[test]
    fn decodes_a_tcp_syn() {
        let frame = ethernet(0x0800, &ipv4(6, &tcp(51234, 22, TcpFlags::SYN, &[])));
        let observation = ethernet_frame(&frame, SystemTime::UNIX_EPOCH).unwrap();

        assert_eq!(observation.source.addr, IpAddr::from(SRC));
        assert_eq!(observation.source.port, 51234);
        assert_eq!(observation.destination.addr, IpAddr::from(DST));
        assert_eq!(observation.destination.port, 22);
        assert_eq!(observation.transport, Transport::Tcp);
        assert_eq!(observation.stage_hint, Some(Stage::Connect));
        assert!(observation.payload.is_empty());
    }

    #[test]
    fn syn_ack_and_mid_stream_segments_are_established() {
        for flags in [TcpFlags::SYN | TcpFlags::ACK, TcpFlags::PSH | TcpFlags::ACK] {
            let frame = ethernet(0x0800, &ipv4(6, &tcp(22, 51234, flags, b"hello")));
            let observation = ethernet_frame(&frame, SystemTime::UNIX_EPOCH).unwrap();
            assert_eq!(observation.stage_hint, Some(Stage::Established));
        }
    }

    /// A RST must not advance the session past the stages a method needs, or a
    /// refused SYN scan would satisfy every `required_stage` gate.
    #[test]
    fn rst_does_not_report_a_stage() {
        let frame = ethernet(0x0800, &ipv4(6, &tcp(22, 51234, TcpFlags::RST, &[])));
        let observation = ethernet_frame(&frame, SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!(observation.stage_hint, None);
    }

    #[test]
    fn unwraps_a_vlan_tag() {
        let tagged = {
            let mut payload = vec![0x00, 0x2a]; // priority + VLAN id 42
            payload.extend_from_slice(&0x0800u16.to_be_bytes());
            payload.extend_from_slice(&ipv4(6, &tcp(51234, 443, TcpFlags::SYN, &[])));
            ethernet(0x8100, &payload)
        };

        let observation = ethernet_frame(&tagged, SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!(observation.destination.port, 443);
    }

    #[test]
    fn udp_payload_stops_at_the_length_field() {
        // Frame padded to the 60-byte Ethernet minimum: the trailing zeros are
        // not payload and must not reach the methods.
        let mut frame = ethernet(0x0800, &ipv4(17, &udp(51234, 53, b"query")));
        frame.resize(60, 0);

        let observation = ethernet_frame(&frame, SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!(observation.transport, Transport::Udp);
        assert_eq!(observation.payload, b"query");
    }

    /// Apple stacks end their options with EOL and a padding byte (p0f's
    /// `eol+1`). The padding is counted, not reported as more EOL options.
    #[test]
    fn padding_after_eol_is_counted_not_listed() {
        let options = [
            2, 4, 0x05, 0xB4, // MSS
            1, // NOP
            3, 3, 6, // window scale
            1, 1, // NOP NOP
            8, 10, 0, 0, 0, 1, 0, 0, 0, 0, // timestamp
            4, 2, // SACK permitted
            0, // EOL
            0, // padding
        ];
        let frame = ethernet(
            0x0800,
            &ipv4(6, &tcp_with_options(51234, 443, TcpFlags::SYN, &options, &[])),
        );
        let tcp = ethernet_frame(&frame, SystemTime::UNIX_EPOCH)
            .unwrap()
            .tcp
            .expect("a TCP segment should carry features");

        use TcpOptionKind::*;
        assert_eq!(
            tcp.option_order,
            vec![Mss, Nop, WindowScale, Nop, Nop, Timestamp, SackPermitted, Eol]
        );
        assert_eq!(tcp.eol_padding, Some(1));
    }

    /// Three bytes of padding, and non-zero ones: still padding, not options.
    #[test]
    fn everything_after_eol_is_padding_whatever_its_value() {
        let options = [
            2, 4, 0x05, 0xB4, // MSS
            0, // EOL
            8, 10, 0, // would parse as a truncated timestamp if walked
        ];
        let frame = ethernet(
            0x0800,
            &ipv4(6, &tcp_with_options(51234, 443, TcpFlags::SYN, &options, &[])),
        );
        let tcp = ethernet_frame(&frame, SystemTime::UNIX_EPOCH)
            .unwrap()
            .tcp
            .expect("a TCP segment should carry features");

        assert_eq!(tcp.option_order, vec![TcpOptionKind::Mss, TcpOptionKind::Eol]);
        assert_eq!(tcp.eol_padding, Some(3));
        assert!(tcp.quirks.contains(&TcpQuirk::NonZeroPadding));
    }

    #[test]
    fn zero_padding_after_eol_is_not_a_quirk() {
        let options = [2, 4, 0x05, 0xB4, 0, 0, 0, 0]; // MSS, EOL, 3 zero bytes
        let tcp = syn_features(&options);
        assert_eq!(tcp.eol_padding, Some(3));
        assert!(!tcp.quirks.contains(&TcpQuirk::NonZeroPadding));
    }

    /// The decode of one SYN carrying `options`, straight to its features.
    fn syn_features(options: &[u8]) -> TcpFeatures {
        let frame = ethernet(
            0x0800,
            &ipv4(6, &tcp_with_options(51234, 443, TcpFlags::SYN, options, &[])),
        );
        ethernet_frame(&frame, SystemTime::UNIX_EPOCH)
            .unwrap()
            .tcp
            .expect("a TCP segment should carry features")
    }

    /// The test builders send DF with a zero ID and a zero sequence number —
    /// exactly p0f's `df` and `seq-`, and nothing else.
    #[test]
    fn a_plain_syn_carries_only_the_quirks_it_has() {
        let tcp = syn_features(&[]);
        assert_eq!(
            tcp.quirks.into_iter().collect::<Vec<_>>(),
            vec![TcpQuirk::Df, TcpQuirk::ZeroSeq]
        );
        assert_eq!(tcp.ip_option_len, 0);
    }

    #[test]
    fn ip_id_and_sequence_quirks_follow_p0f() {
        let mut frame = ethernet(0x0800, &ipv4(6, &tcp(51234, 22, TcpFlags::SYN, &[])));
        let ip = ETHERNET_HEADER_LEN;
        let tcp_at = ip + IPV4_MIN_HEADER_LEN;
        frame[ip + 4..ip + 6].copy_from_slice(&0x1234u16.to_be_bytes()); // IP ID
        frame[tcp_at + 4..tcp_at + 8].copy_from_slice(&7u32.to_be_bytes()); // seq
        let quirks = ethernet_frame(&frame, SystemTime::UNIX_EPOCH).unwrap().tcp.unwrap().quirks;
        assert_eq!(
            quirks.into_iter().collect::<Vec<_>>(),
            vec![TcpQuirk::Df, TcpQuirk::NonZeroId]
        );

        // No DF and a zero ID is `id-`; the reserved flag is `0+`.
        frame[ip + 4..ip + 6].copy_from_slice(&[0, 0]);
        frame[ip + 6] = 0x80;
        let quirks = ethernet_frame(&frame, SystemTime::UNIX_EPOCH).unwrap().tcp.unwrap().quirks;
        assert_eq!(
            quirks.into_iter().collect::<Vec<_>>(),
            vec![TcpQuirk::ZeroId, TcpQuirk::NonZeroReserved]
        );
    }

    #[test]
    fn tcp_header_quirks_follow_p0f() {
        let mut frame = ethernet(
            0x0800,
            &ipv4(6, &tcp(51234, 22, TcpFlags::SYN | TcpFlags::PSH | TcpFlags::ECE, &[])),
        );
        let tcp_at = ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        frame[tcp_at + 8..tcp_at + 12].copy_from_slice(&9u32.to_be_bytes()); // ack, no ACK flag
        frame[tcp_at + 18..tcp_at + 20].copy_from_slice(&1u16.to_be_bytes()); // urgent ptr, no URG
        let quirks = ethernet_frame(&frame, SystemTime::UNIX_EPOCH).unwrap().tcp.unwrap().quirks;
        for quirk in [
            TcpQuirk::Ecn,
            TcpQuirk::NonZeroAck,
            TcpQuirk::NonZeroUrgentPtr,
            TcpQuirk::Push,
        ] {
            assert!(quirks.contains(&quirk), "missing {quirk:?} in {quirks:?}");
        }
    }

    #[test]
    fn ipv4_options_are_counted() {
        let mut packet = ipv4(6, &tcp(51234, 22, TcpFlags::SYN, &[]));
        packet[0] = 0x46; // IHL 6 words: 4 bytes of options
        packet.splice(IPV4_MIN_HEADER_LEN..IPV4_MIN_HEADER_LEN, [1, 1, 1, 0]);
        let total = packet.len() as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        let tcp = ip_packet(&packet, SystemTime::UNIX_EPOCH).unwrap().tcp.unwrap();
        assert_eq!(tcp.ip_option_len, 4);
    }

    #[test]
    fn timestamp_and_window_scale_quirks_follow_p0f() {
        let options = [
            8, 10, 0, 0, 0, 0, 0, 0, 0, 5, // own timestamp 0, peer timestamp 5
            3, 3, 15, // window scale past the maximum
        ];
        let tcp = syn_features(&options);
        for quirk in [
            TcpQuirk::ZeroTimestamp,
            TcpQuirk::NonZeroPeerTimestamp,
            TcpQuirk::ExcessiveWindowScale,
        ] {
            assert!(tcp.quirks.contains(&quirk), "missing {quirk:?} in {:?}", tcp.quirks);
        }
        assert_eq!(tcp.window_scale, Some(15));
    }

    /// An option that runs off the end of the header is listed, marked `bad`,
    /// and ends the walk, the way p0f does it.
    #[test]
    fn a_truncated_option_is_bad_and_stops_the_walk() {
        let options = [2, 4, 0x05, 0xB4, 8, 10, 0, 0]; // MSS, then a timestamp cut short
        let tcp = syn_features(&options);
        assert!(tcp.quirks.contains(&TcpQuirk::BadOptions));
        assert_eq!(tcp.option_order, vec![TcpOptionKind::Mss, TcpOptionKind::Timestamp]);
        assert_eq!(tcp.mss, Some(1460));
    }

    #[test]
    fn a_wrong_option_length_is_bad() {
        let options = [2, 3, 0x05, 3, 3, 7, 0, 0]; // MSS claiming 3 bytes, then ws
        let tcp = syn_features(&options);
        assert!(tcp.quirks.contains(&TcpQuirk::BadOptions));
        assert_eq!(tcp.mss, None);
        assert_eq!(tcp.window_scale, Some(7));
    }

    #[test]
    fn no_eol_means_no_padding() {
        let options = [2, 4, 0x05, 0xB4]; // MSS alone, already 4 bytes
        let frame = ethernet(
            0x0800,
            &ipv4(6, &tcp_with_options(51234, 443, TcpFlags::SYN, &options, &[])),
        );
        let tcp = ethernet_frame(&frame, SystemTime::UNIX_EPOCH)
            .unwrap()
            .tcp
            .expect("a TCP segment should carry features");

        assert_eq!(tcp.eol_padding, None);
    }

    #[test]
    fn tcp_features_captures_ttl_window_and_options_in_order() {
        // mss=1460, sack-permitted, timestamp(1,0), nop, wscale=7 — a plausible
        // Linux-style SYN option layout, already a multiple of 4 bytes.
        let options = [
            2, 4, 0x05, 0xB4, // MSS
            4, 2, // SACK permitted
            8, 10, 0, 0, 0, 1, 0, 0, 0, 0, // timestamp
            1, // NOP
            3, 3, 7, // window scale
        ];
        let frame = ethernet(
            0x0800,
            &ipv4(6, &tcp_with_options(51234, 22, TcpFlags::SYN, &options, &[])),
        );
        let observation = ethernet_frame(&frame, SystemTime::UNIX_EPOCH).unwrap();

        let tcp = observation.tcp.expect("a TCP segment should carry features");
        assert_eq!(tcp.ttl, 64);
        assert!(tcp.df());
        assert_eq!(tcp.window, 0x7120);
        assert_eq!(tcp.mss, Some(1460));
        assert_eq!(tcp.window_scale, Some(7));
        assert!(tcp.sack_permitted);
        assert!(tcp.timestamp);
        assert_eq!(
            tcp.option_order,
            vec![
                TcpOptionKind::Mss,
                TcpOptionKind::SackPermitted,
                TcpOptionKind::Timestamp,
                TcpOptionKind::Nop,
                TcpOptionKind::WindowScale,
            ]
        );
    }

    #[test]
    fn non_tcp_transports_carry_no_tcp_features() {
        let frame = ethernet(0x0800, &ipv4(17, &udp(51234, 53, b"query")));
        let observation = ethernet_frame(&frame, SystemTime::UNIX_EPOCH).unwrap();
        assert!(observation.tcp.is_none());
    }

    #[test]
    fn non_ip_frames_are_skipped() {
        let arp = ethernet(0x0806, &[0; 28]);
        assert!(ethernet_frame(&arp, SystemTime::UNIX_EPOCH).is_none());
    }

    #[test]
    fn a_lying_header_length_is_rejected_not_trusted() {
        let mut frame = ethernet(0x0800, &ipv4(6, &tcp(51234, 22, TcpFlags::SYN, &[])));
        frame[ETHERNET_HEADER_LEN] = 0x4f; // IHL 15 words, past the end
        assert!(ethernet_frame(&frame, SystemTime::UNIX_EPOCH).is_none());
    }

    #[test]
    fn non_initial_fragments_are_dropped() {
        let mut frame = ethernet(0x0800, &ipv4(6, &tcp(51234, 22, TcpFlags::SYN, &[])));
        frame[ETHERNET_HEADER_LEN + 6] = 0x00;
        frame[ETHERNET_HEADER_LEN + 7] = 0xb9; // fragment offset != 0
        assert!(ethernet_frame(&frame, SystemTime::UNIX_EPOCH).is_none());
    }

    #[test]
    fn other_protocols_keep_the_flow_without_ports() {
        let frame = ethernet(0x0800, &ipv4(1, &[8, 0, 0, 0, 0, 0, 0, 0])); // ICMP echo
        let observation = ethernet_frame(&frame, SystemTime::UNIX_EPOCH).unwrap();

        assert_eq!(observation.transport, Transport::Other(1));
        assert_eq!(observation.source.port, 0);
        assert_eq!(observation.payload.len(), 8);
    }
}
