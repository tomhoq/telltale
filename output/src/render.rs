//! Turning sessions and results into something a human or a pipeline reads.
//!
//! Generic over fields: nothing here knows any method's output by name, so a
//! new method's results display with no change in this file.
//!
//! TODO (step 3): render by each field's declared `kind` (classification,
//! flag, score, raw-signature) from the manifests' output schemas.

use std::time::{SystemTime, UNIX_EPOCH};

use pf_core::{Endpoint, ResultEntry, Session, SessionId, SessionKey};
use serde_json::{json, Value};

/// A finished session and its result list, as indented text.
pub fn render_session_text(session: &Session) -> String {
    let responder = responder(&session.key, session.initiator);
    let mut out = format!(
        "{} -> {} {:?} ({} packets, {:?})\n",
        endpoint(session.initiator),
        endpoint(responder),
        session.key.transport,
        session.observations.len(),
        session.state,
    );
    if session.results.is_empty() {
        out.push_str("  no results\n");
    }
    for entry in in_packet_order(session) {
        out.push_str(&format!("  {}\n", result_text(entry)));
    }
    out
}

/// One finished session as a single JSON line.
pub fn render_session_json(session: &Session) -> String {
    let value = json!({
        "session": session_json(&session.id(), session.initiator),
        "state": session.state,
        "last-seen": epoch_seconds(session.last_seen_at),
        "packets": session.observations.len(),
        "results": in_packet_order(session).map(result_json).collect::<Vec<_>>(),
    });
    format!("{value}\n")
}

/// One result as it arrives, as a text line naming its session.
pub fn render_result_text(session: &SessionId, initiator: Endpoint, entry: &ResultEntry) -> String {
    format!(
        "{} -> {} {}\n",
        endpoint(initiator),
        endpoint(responder(&session.key, initiator)),
        result_text(entry)
    )
}

/// One result as it arrives, as a single JSON line.
pub fn render_result_json(session: &SessionId, initiator: Endpoint, entry: &ResultEntry) -> String {
    let mut value = result_json(entry);
    value["session"] = session_json(session, initiator);
    format!("{value}\n")
}

/// The session's results ordered by the packet that fired them. The stored
/// list is in the order methods finished, which with concurrent workers is
/// not the order things happened; display follows the capture instead. Stable,
/// so entries from one packet keep their relative order.
fn in_packet_order(session: &Session) -> impl Iterator<Item = &ResultEntry> {
    let mut entries: Vec<&ResultEntry> = session.results.iter().collect();
    entries.sort_by_key(|entry| entry.timestamp);
    entries.into_iter()
}

fn result_text(entry: &ResultEntry) -> String {
    let fields: Vec<String> = entry
        .fields
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    format!(
        "[{} on {}] {}",
        entry.method,
        serde_json::to_value(entry.trigger)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default(),
        fields.join(" ")
    )
}

fn result_json(entry: &ResultEntry) -> Value {
    json!({
        "method": entry.method,
        "trigger": entry.trigger,
        "time": epoch_seconds(entry.timestamp),
        "fields": entry.fields,
    })
}

fn session_json(id: &SessionId, initiator: Endpoint) -> Value {
    json!({
        "initiator": endpoint(initiator),
        "responder": endpoint(responder(&id.key, initiator)),
        "transport": id.key.transport,
        "started": epoch_seconds(id.started_at),
    })
}

fn responder(key: &SessionKey, initiator: Endpoint) -> Endpoint {
    if key.low == initiator {
        key.high
    } else {
        key.low
    }
}

fn endpoint(endpoint: Endpoint) -> String {
    match endpoint.addr {
        std::net::IpAddr::V4(addr) => format!("{addr}:{}", endpoint.port),
        std::net::IpAddr::V6(addr) => format!("[{addr}]:{}", endpoint.port),
    }
}

fn epoch_seconds(time: SystemTime) -> f64 {
    time.duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs_f64())
        .unwrap_or(0.0)
}
