use serde::{Deserialize, Serialize};

/// A protocol event that fires methods.
///
/// Methods list the events they want in their manifest's `triggers`; the
/// dispatcher classifies each packet into events and runs exactly the methods
/// that asked for them, once per event. So a method keyed on the SYN never
/// runs again because a later packet in the same session was a ClientHello.
///
/// Add an event when a method needs one; the classifier in `pf-dispatch` is
/// the other half of that change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TriggerEvent {
    // Raised by one packet. The method gets that packet.
    /// SYN without ACK: a connection attempt.
    TcpSyn,
    /// SYN+ACK: the responder accepting one.
    TcpSynAck,
    /// A TLS record carrying a ClientHello.
    TlsClientHello,
    /// A TLS record carrying a ServerHello.
    TlsServerHello,
    /// An HTTP/1.x request line.
    HttpRequest,
    /// An HTTP/1.x status line.
    HttpResponse,
    /// An SSH identification string (`SSH-2.0-...`), from either side.
    SshBanner,

    // Raised by the session, not a packet. The method gets no packet.
    /// The session timed out or the source ended, and every method its packets
    /// fired has already reported — so `session.results` is complete.
    SessionEnd,
}

impl TriggerEvent {
    /// Raised by the session rather than by a packet.
    pub fn is_session_event(self) -> bool {
        matches!(self, TriggerEvent::SessionEnd)
    }
}
