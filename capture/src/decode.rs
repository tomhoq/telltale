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

use std::net::IpAddr;
use std::time::SystemTime;

use pf_core::{Endpoint, Observation, Stage, Transport};
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;

const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_TAG_LEN: usize = 4;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

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

    transport(
        ip.get_next_level_protocol(),
        IpAddr::V4(ip.get_source()),
        IpAddr::V4(ip.get_destination()),
        &packet[header_len..end],
        at,
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
    transport(
        ip.get_next_header(),
        IpAddr::V6(ip.get_source()),
        IpAddr::V6(ip.get_destination()),
        &packet[IPV6_HEADER_LEN..end],
        at,
    )
}

fn transport(
    protocol: IpNextHeaderProtocol,
    source: IpAddr,
    destination: IpAddr,
    segment: &[u8],
    at: SystemTime,
) -> Option<Observation> {
    let (transport, source_port, destination_port, payload, stage_hint) = match protocol {
        IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(segment)?;
            let header_len = tcp.get_data_offset() as usize * 4;
            if !(TCP_MIN_HEADER_LEN..=segment.len()).contains(&header_len) {
                return None;
            }
            (
                Transport::Tcp,
                tcp.get_source(),
                tcp.get_destination(),
                &segment[header_len..],
                tcp_stage(tcp.get_flags()),
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
            )
        }
        // ICMP, ESP, GRE and friends: no ports to report, but the flow is still
        // worth correlating, so it is kept with the raw bytes intact.
        other => (Transport::Other(other.0), 0, 0, segment, None),
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
    })
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
