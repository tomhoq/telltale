//! Turning a [`ProfileStore`] into something a human or a pipeline reads.
//!
//! Both renderers must work mid-run, not only at the end — in streaming mode
//! this gets called repeatedly on a store that is still filling up. That is why
//! provisional evidence is marked rather than hidden.

use pf_core::{Profile, ProfileStore, Verdict};

pub fn render_text(store: &ProfileStore) -> String {
    let mut out = String::new();

    // Sort profiles by verdict and endpoint.
    let mut rows: Vec<_> = store.iter().collect();
    rows.sort_by_key(|(endpoint, profile)| {
        (
            match profile.verdict {
                Verdict::Scanner => 0,
                Verdict::Unknown => 1,
                Verdict::Benign => 2,
            },
            endpoint.addr,
            endpoint.port,
        )
    });

    for (endpoint, profile) in rows {
        out.push_str(&format!(
            "{}:{} [{}]\n",
            endpoint.addr,
            endpoint.port,
            verdict_label(profile.verdict)
        ));
        let mut attributes: Vec<_> = profile.attributes.iter().collect();
        attributes.sort_by_key(|(key, _)| key.as_str());
        // The key already names the method (`f0p.os`).
        for (key, attribute) in attributes {
            out.push_str(&format!(
                "  {key:<20} {} ({:?})\n",
                attribute.value, attribute.confidence
            ));
        }
    }

    if out.is_empty() {
        out.push_str("no profiles\n");
    }
    out
}

pub fn render_json(store: &ProfileStore) -> String {
    let profiles: Vec<_> = store
        .iter()
        .map(|(endpoint, profile)| serde_json::json!({ "endpoint": endpoint, "profile": profile }))
        .collect();
    serde_json::to_string_pretty(&profiles).unwrap_or_else(|_| "[]".into())
}

/// One line per profile, for tailing a live run.
pub fn render_line(endpoint: &pf_core::Endpoint, profile: &Profile) -> String {
    let mut attributes: Vec<_> = profile.attributes.iter().collect();
    attributes.sort_by_key(|(key, _)| key.as_str());
    let attrs: String = attributes
        .iter()
        .map(|(key, attribute)| format!("{key}={}", attribute.value))
        .collect::<Vec<_>>()
        .join(" ");

    format!(
        "{}:{} {} {}({} attrs, {} evidence)",
        endpoint.addr,
        endpoint.port,
        verdict_label(profile.verdict),
        if attrs.is_empty() { String::new() } else { format!("{attrs} ") },
        profile.attributes.len(),
        profile.evidence.len()
    )
}

fn verdict_label(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Scanner => "SCANNER",
        Verdict::Benign => "benign",
        Verdict::Unknown => "unknown",
    }
}
