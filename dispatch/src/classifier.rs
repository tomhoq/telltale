//! Packet to protocol events: the step between capture and dispatch.
//!
//! Byte-prefix checks only — enough to decide *which* methods to run, not to
//! parse anything. Parsing the ClientHello or the request is the method's job,
//! so a new method never needs this file unless it needs a new event.

use pf_core::{Observation, TcpHeader, TriggerEvent};

/// HTTP/1.x request methods, each with the space that must follow it, so a
/// payload merely starting with `GETTER` is not a request.
const HTTP_METHODS: [&[u8]; 9] = [
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

/// The events one packet raises; usually none, rarely more than one (a SYN
/// carrying data).
///
/// Only the start of the payload is looked at: a ClientHello or request split
/// across TCP segments is recognised by its first segment, and the method
/// receives that segment.
pub fn classify(observation: &Observation) -> Vec<TriggerEvent> {
    let mut events = Vec::new();
    let Some(tcp) = &observation.tcp else {
        return events;
    };

    if tcp.has(TcpHeader::SYN) {
        events.push(if tcp.has(TcpHeader::ACK) {
            TriggerEvent::TcpSynAck
        } else {
            TriggerEvent::TcpSyn
        });
    }
    if let Some(event) = payload_event(&observation.payload) {
        events.push(event);
    }
    events
}

fn payload_event(payload: &[u8]) -> Option<TriggerEvent> {
    // TLS record: content type 22 (handshake), major version 3, then after the
    // 5-byte record header the handshake type.
    if let [0x16, 0x03, _, _, _, handshake, ..] = payload {
        return match handshake {
            0x01 => Some(TriggerEvent::TlsClientHello),
            0x02 => Some(TriggerEvent::TlsServerHello),
            _ => None,
        };
    }
    if payload.starts_with(b"SSH-") {
        return Some(TriggerEvent::SshBanner);
    }
    if payload.starts_with(b"HTTP/1.") {
        return Some(TriggerEvent::HttpResponse);
    }
    if HTTP_METHODS.iter().any(|method| payload.starts_with(method)) {
        return Some(TriggerEvent::HttpRequest);
    }
    None
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    use pf_core::{Endpoint, Transport};

    use super::*;

    fn packet(tcp: Option<u8>, payload: &[u8]) -> Observation {
        let endpoint = |port| Endpoint {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        };
        Observation {
            at: SystemTime::UNIX_EPOCH,
            source: endpoint(40000),
            destination: endpoint(443),
            transport: if tcp.is_some() { Transport::Tcp } else { Transport::Udp },
            ttl: Some(64),
            tcp: tcp.map(|flags| TcpHeader {
                flags,
                window: 0,
                options: Vec::new(),
            }),
            payload: payload.to_vec(),
        }
    }

    const ACK: u8 = TcpHeader::ACK;
    const PSH_ACK: u8 = TcpHeader::PSH | TcpHeader::ACK;

    #[test]
    fn syn_and_syn_ack_are_told_apart() {
        assert_eq!(classify(&packet(Some(TcpHeader::SYN), b"")), [TriggerEvent::TcpSyn]);
        assert_eq!(
            classify(&packet(Some(TcpHeader::SYN | ACK), b"")),
            [TriggerEvent::TcpSynAck]
        );
    }

    #[test]
    fn a_bare_ack_raises_nothing() {
        assert!(classify(&packet(Some(ACK), b"")).is_empty());
        assert!(classify(&packet(Some(TcpHeader::RST), b"")).is_empty());
    }

    #[test]
    fn tls_hellos_are_recognised_by_record_and_handshake_type() {
        let hello = |kind| [0x16, 0x03, 0x01, 0x02, 0x00, kind, 0x00];
        assert_eq!(classify(&packet(Some(PSH_ACK), &hello(1))), [TriggerEvent::TlsClientHello]);
        assert_eq!(classify(&packet(Some(PSH_ACK), &hello(2))), [TriggerEvent::TlsServerHello]);
        // Certificate, not a hello.
        assert!(classify(&packet(Some(PSH_ACK), &hello(11))).is_empty());
    }

    #[test]
    fn application_banners_are_recognised() {
        let cases: [(&[u8], TriggerEvent); 4] = [
            (b"SSH-2.0-OpenSSH_9.6\r\n", TriggerEvent::SshBanner),
            (b"GET / HTTP/1.1\r\n", TriggerEvent::HttpRequest),
            (b"OPTIONS * HTTP/1.1\r\n", TriggerEvent::HttpRequest),
            (b"HTTP/1.1 200 OK\r\n", TriggerEvent::HttpResponse),
        ];
        for (payload, event) in cases {
            assert_eq!(classify(&packet(Some(PSH_ACK), payload)), [event]);
        }
    }

    #[test]
    fn a_method_name_without_its_space_is_not_a_request() {
        assert!(classify(&packet(Some(PSH_ACK), b"GETTER")).is_empty());
    }

    #[test]
    fn a_syn_carrying_data_raises_both() {
        assert_eq!(
            classify(&packet(Some(TcpHeader::SYN), b"GET / HTTP/1.1\r\n")),
            [TriggerEvent::TcpSyn, TriggerEvent::HttpRequest]
        );
    }

    #[test]
    fn non_tcp_raises_nothing_yet() {
        assert!(classify(&packet(None, b"GET / HTTP/1.1\r\n")).is_empty());
    }
}
