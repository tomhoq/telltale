//! The client's first HTTP/1.x request head, shared by `claimed` and `ja4h`.
//!
//! On a TCP connection an HTTP client speaks first, so its request head is the
//! start of what it sends. The head is read from there and nowhere else: once
//! the first bytes are not an HTTP method, the connection is not HTTP, and a
//! method can say it is done instead of searching every later packet again
//! (on a long SSH or TLS session that search ran once per packet over the
//! whole session).
//!
//! A head can span several TCP segments; the client's payloads are joined in
//! arrival order, up to a byte cap. A UDP flow is read the same way, from its
//! first datagram: SIP scanners send `OPTIONS ... SIP/2.0` with a User-Agent
//! (`friendly-scanner`) that `claimed` reports.

use pf_core::Context;

/// Every method `claimed` or `ja4h` recognises. Only decides "could this be
/// HTTP"; each parser still checks its own list.
const HTTP_METHODS: [&str; 9] = ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "CONNECT", "PATCH", "TRACE"];

/// Longest method name plus the space after it.
const LONGEST_METHOD: usize = "OPTIONS ".len();

#[derive(Debug, PartialEq, Eq)]
pub enum FirstRequest {
    /// The client has sent no payload yet.
    Nothing,
    /// The client's first bytes are not an HTTP/1.x request: done, for good.
    NotHttp,
    /// A request has started but its head has not ended yet.
    Incomplete,
    /// The request head, up to and including the blank line that ends it. Or,
    /// once the byte cap is reached or the session is over, as much of an
    /// unfinished head as there is; a parser that needs a complete head
    /// (`ja4h`) rejects that itself.
    Head(Vec<u8>),
}

/// The start of what the session's initiator sent, read as an HTTP request.
/// At most `max_bytes` are joined, so a large upload costs no more than a
/// small one. A segment identical to one already taken is skipped as a
/// retransmission.
pub fn first_request(ctx: &Context<'_>, max_bytes: usize) -> FirstRequest {
    let initiator = ctx.session.initiator;
    let mut stream: Vec<u8> = Vec::new();
    let mut taken: Vec<&[u8]> = Vec::new();
    for observation in ctx.observations().filter(|o| o.source == initiator && !o.payload.is_empty()) {
        if stream.len() >= max_bytes {
            break;
        }
        let payload = observation.payload.as_slice();
        if taken.contains(&payload) {
            continue;
        }
        taken.push(payload);
        let room = max_bytes - stream.len();
        stream.extend_from_slice(&payload[..payload.len().min(room)]);
    }

    if stream.is_empty() {
        return FirstRequest::Nothing;
    }
    match starts_like_http(&stream) {
        Some(false) => return FirstRequest::NotHttp,
        None => {
            return if ctx.is_final || stream.len() >= max_bytes {
                FirstRequest::NotHttp
            } else {
                FirstRequest::Incomplete
            }
        }
        Some(true) => {}
    }

    if let Some(end) = head_end(&stream) {
        stream.truncate(end);
        FirstRequest::Head(stream)
    } else if ctx.is_final || stream.len() >= max_bytes {
        FirstRequest::Head(stream)
    } else {
        FirstRequest::Incomplete
    }
}

/// `Some(true)` once the bytes open with an HTTP method and a space,
/// `Some(false)` once they cannot, `None` while too few have arrived to tell
/// (`GE`, say).
fn starts_like_http(stream: &[u8]) -> Option<bool> {
    let shown = &stream[..stream.len().min(LONGEST_METHOD)];
    match shown.iter().position(|&b| b == b' ') {
        Some(space) => Some(HTTP_METHODS.iter().any(|m| m.as_bytes() == &shown[..space])),
        None if shown.len() == LONGEST_METHOD => Some(false),
        None if HTTP_METHODS.iter().any(|m| m.as_bytes().starts_with(shown)) => None,
        None => Some(false),
    }
}

/// Just past the blank line ending the head: `\r\n\r\n`, or a bare `\n\n`
/// from a sloppy client.
fn head_end(stream: &[u8]) -> Option<usize> {
    let crlf = stream.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
    let lf = stream.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Sessions for the HTTP methods' tests: the client's SYN, then packets.
#[cfg(test)]
pub(crate) mod test_support {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    use pf_core::{Endpoint, Observation, Session, Stage, Transport};

    const CLIENT: Endpoint = Endpoint {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
        port: 50000,
    };
    const SERVER: Endpoint = Endpoint {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)),
        port: 80,
    };

    fn packet(from_client: bool, payload: &[u8]) -> Observation {
        let (source, destination) = if from_client { (CLIENT, SERVER) } else { (SERVER, CLIENT) };
        Observation {
            at: SystemTime::UNIX_EPOCH,
            source,
            destination,
            transport: Transport::Tcp,
            payload: payload.to_vec(),
            stage_hint: Some(if payload.is_empty() { Stage::Connect } else { Stage::AppData }),
            tcp: None,
        }
    }

    /// A session of the client's SYN followed by these packets.
    pub(crate) fn session(packets: &[(bool, &[u8])]) -> Session {
        let mut s = Session::open(packet(true, b""));
        for (from_client, payload) in packets {
            s.push(packet(*from_client, payload));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use pf_core::Session;

    use super::test_support::session;
    use super::*;

    fn read(s: &Session, both_directions: bool, is_final: bool, max: usize) -> FirstRequest {
        first_request(&Context::new(s, &[], is_final, both_directions), max)
    }

    const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8.5.0\r\n\r\n";

    #[test]
    fn a_whole_head_in_one_segment() {
        let s = session(&[(true, GET)]);
        assert_eq!(read(&s, false, false, 4096), FirstRequest::Head(GET.to_vec()));
    }

    #[test]
    fn nothing_sent_yet() {
        assert_eq!(read(&session(&[]), false, false, 4096), FirstRequest::Nothing);
    }

    /// SSH, TLS or anything binary: not HTTP from the first bytes, so the
    /// method can stop. The server speaking first (an SSH banner) does not
    /// count, even when both directions are in view.
    #[test]
    fn other_protocols_are_not_http() {
        assert_eq!(read(&session(&[(true, b"SSH-2.0-OpenSSH_9.6\r\n")]), false, false, 4096), FirstRequest::NotHttp);
        assert_eq!(read(&session(&[(true, &[0x16, 0x03, 0x01, 0x02, 0x00])]), false, false, 4096), FirstRequest::NotHttp);
        let banner_first = session(&[(false, b"SSH-2.0-OpenSSH_9.6\r\n"), (true, GET)]);
        assert_eq!(read(&banner_first, true, false, 4096), FirstRequest::Head(GET.to_vec()));
    }

    /// A head split over segments waits for the rest, is joined, and a
    /// retransmitted segment is not joined twice.
    #[test]
    fn a_split_head_is_joined() {
        let (a, b) = GET.split_at(20);
        assert_eq!(read(&session(&[(true, a)]), false, false, 4096), FirstRequest::Incomplete);
        assert_eq!(read(&session(&[(true, a), (true, a), (true, b)]), false, false, 4096), FirstRequest::Head(GET.to_vec()));
    }

    /// Too few bytes to know: wait, unless the session is over.
    #[test]
    fn a_partial_method_waits() {
        assert_eq!(read(&session(&[(true, b"GE")]), false, false, 4096), FirstRequest::Incomplete);
        assert_eq!(read(&session(&[(true, b"GE")]), false, true, 4096), FirstRequest::NotHttp);
        assert_eq!(read(&session(&[(true, b"GX")]), false, false, 4096), FirstRequest::NotHttp);
    }

    /// The cap bounds the work: an unfinished head is handed over as it is
    /// once the cap is reached, and so is one cut short by the session ending.
    #[test]
    fn the_cap_and_the_end_hand_over_an_unfinished_head() {
        const UNFINISHED: &[u8] = b"GET / HTTP/1.1\r\nCookie: aaaaaaaaaaaaaaaaaaaaaaaa";
        let s = session(&[(true, UNFINISHED)]);
        assert_eq!(read(&s, false, false, 4096), FirstRequest::Incomplete);
        assert_eq!(read(&s, false, false, 20), FirstRequest::Head(b"GET / HTTP/1.1\r\nCook".to_vec()));
        assert_eq!(read(&s, false, true, 4096), FirstRequest::Head(UNFINISHED.to_vec()));
    }

    /// Only the start counts: a request after some other bytes is not one.
    #[test]
    fn a_request_later_in_the_stream_is_not_looked_for() {
        assert_eq!(read(&session(&[(true, b"hello\r\n"), (true, GET)]), false, false, 4096), FirstRequest::NotHttp);
    }
}
