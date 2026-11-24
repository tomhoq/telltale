//! `tcpcluster`: the thesis's final TCP method (SPEC 9.4.8 of the thesis
//! repository, exported by `scripts/export_telltale.py --anchors`), an OS
//! classifier. For one connection, once the client has replied to the
//! SYN-ACK:
//!
//! 1. the *raw key* — the exact integer inputs of the A1+A2+B features (SYN
//!    options, window, MSS, scale, header bits, TTL bucket, then the client's
//!    reply to the SYN-ACK) — is looked up in the fingerprint set: every tuple
//!    seen in the reference traffic or the labeled hosts. A hit gives its
//!    cluster's family and version set, and the encoder never runs;
//! 2. on a miss, the contrastive encoder embeds the features, and the nearest
//!    member of a named cluster, within that member's threshold, names it;
//! 3. failing that, the nearest anchor (a labeled tuple in no named cluster)
//!    within epsilon does;
//! 4. a tuple still unnamed gets the "closest known OS" hint: the family of
//!    the nearest named-cluster member, if it is close enough.
//!
//! Versions are a *set* (an era: `windows/{10|8.1}`), never one version.
//! Comparing this family with other methods' is fusion's job.

mod features;
mod model;

use std::net::IpAddr;
use std::path::Path;

use pf_core::{
    Confidence, Context, Error, Evidence, Method, MethodManifest, Observation, Outcome, Result,
    TcpFeatures, TcpHeader, TcpOptionKind, TcpQuirk, Transport,
};

pub use features::{featurize, raw_key, Handshake, Record, Syn};
pub use model::{Hit, Model, Name};

pub struct TcpCluster {
    manifest: MethodManifest,
    model: Model,
    params: Params,
}

/// The manifest's knobs.
#[derive(Debug, Clone)]
pub struct Params {
    /// Hint only within this embedding distance.
    pub hint_max_distance: f32,
    /// Families never given as a hint.
    pub hint_skip_families: Vec<String>,
    /// When the server's SYN-ACK is not in view, take it to have sent window
    /// scaling exactly when the client offered it.
    pub assume_server_scales: bool,
}

impl Params {
    fn from(manifest: &MethodManifest) -> Self {
        Self {
            hint_max_distance: manifest.param("hint-max-distance", 0.2805),
            hint_skip_families: manifest.param("hint-skip-families", vec!["scanner".to_string()]),
            assume_server_scales: manifest.param("assume-server-scales", true),
        }
    }
}

pub fn build(manifest: MethodManifest, manifest_dir: &Path) -> Result<Box<dyn Method>> {
    let spec = manifest.database.as_ref().ok_or_else(|| Error::Database {
        method: manifest.name.clone(),
        reason: "no database: the manifest must point at the export's meta.json".into(),
    })?;
    if spec.format != "telltale-anchors" {
        return Err(Error::Database {
            method: manifest.name.clone(),
            reason: format!("format `{}` not supported (expected telltale-anchors)", spec.format),
        });
    }
    let model = Model::load(&manifest_dir.join(&spec.path)).map_err(|reason| Error::Database {
        method: manifest.name.clone(),
        reason,
    })?;
    let params = Params::from(&manifest);
    Ok(Box::new(TcpCluster {
        manifest,
        model,
        params,
    }))
}

/// The extractor's option tokens for one segment (`parse_options` in
/// `extract_connections.py`): EOL ends the list and is not a token, and an
/// option the walk could not read is `OTHER` whatever its kind byte said.
fn option_tokens(tcp: &TcpFeatures) -> Vec<String> {
    let mut toks: Vec<String> = tcp
        .option_order
        .iter()
        .take_while(|k| **k != TcpOptionKind::Eol)
        .map(|k| {
            match k {
                TcpOptionKind::Nop => "NOP",
                TcpOptionKind::Mss => "MSS",
                TcpOptionKind::WindowScale => "WS",
                TcpOptionKind::SackPermitted => "SOK",
                TcpOptionKind::Sack => "SACK",
                TcpOptionKind::Timestamp => "TS",
                TcpOptionKind::Other(30) => "MPTCP",
                TcpOptionKind::Other(34) => "TFO",
                TcpOptionKind::Other(_) | TcpOptionKind::Eol => "OTHER",
            }
            .to_string()
        })
        .collect();
    if tcp.options_truncated {
        if let Some(last) = toks.last_mut() {
            *last = "OTHER".into();
        }
    }
    toks
}

fn syn_record(obs: &Observation, tcp: &TcpFeatures) -> Syn {
    let h = &tcp.header;
    let isn_eq_dst = match obs.destination.addr {
        IpAddr::V4(dst) => h.seq == u32::from(dst),
        IpAddr::V6(_) => false,
    };
    Syn {
        options: Some(option_tokens(tcp)),
        window: Some(tcp.window.into()),
        mss: tcp.mss.map(Into::into),
        wscale: tcp.window_scale.map(Into::into),
        df: Some(tcp.df()),
        ipid: h.ip_id.map(Into::into),
        ece: Some(h.has(TcpHeader::ECE)),
        cwr: Some(h.has(TcpHeader::CWR)),
        ts_val: h.timestamps.map(|(own, _)| own.into()),
        ts_ecr: h.timestamps.map(|(_, peer)| peer.into()),
        urg_ptr_no_flag: Some(tcp.quirks.contains(&TcpQuirk::NonZeroUrgentPtr)),
        ack_nonzero: Some(h.ack != 0 && !h.has(TcpHeader::ACK)),
        reserved_bits: Some(h.reserved != 0),
        payload_len: Some(obs.payload.len() as u64),
        eol_pad: Some(tcp.eol_padding.unwrap_or(0).into()),
        isn_eq_dst: Some(isn_eq_dst),
        ttl: Some(tcp.ttl.into()),
    }
}

fn is_syn(t: &TcpFeatures) -> bool {
    t.header.has(TcpHeader::SYN) && !t.header.has(TcpHeader::ACK)
}

/// The connection as the extractor records it, once the client replied to
/// the SYN-ACK: `None` while it has not, unless the session is final.
///
/// Reads only what the run's direction policy hands methods. The client's
/// side is enough: a reply to a SYN-ACK is an ACK or RST carrying the ISN + 1
/// — nothing else the client sends after its SYN does. Under
/// `--both-directions` the SYN-ACK itself is in view and used as the
/// extractor uses it (it must acknowledge the ISN; a server RST before it
/// means no handshake). Without it, two things cannot be seen:
///
/// - whether the server scales its window, which decides whether the ACK's
///   window is shifted: taken to be so when the client offered scaling
///   (`assume-server-scales`; a server may only send it then, and the stacks
///   a honeypot runs on do);
/// - a server that answered a client which then went silent (the
///   extractor's `NONE`): recorded as no handshake, as an unanswered SYN.
fn connection(ctx: &Context<'_>, assume_server_scales: bool) -> Option<Record> {
    let initiator = ctx.session.initiator;
    let mut packets = ctx.observations().filter_map(|o| o.tcp.as_ref().map(|t| (o, t)));
    let (syn_obs, syn_tcp) = packets.by_ref().find(|(o, t)| o.source == initiator && is_syn(t))?;
    let syn = syn_record(syn_obs, syn_tcp);
    let isn = syn_tcp.header.seq;

    // What the SYN-ACK said, when it is in view.
    let mut syn_ack: Option<bool> = None; // Some(server sent WS)
    for (o, t) in packets {
        let h = &t.header;
        if o.source != initiator {
            if h.has(TcpHeader::SYN) && h.has(TcpHeader::ACK) {
                if h.ack == isn.wrapping_add(1) {
                    syn_ack = Some(option_tokens(t).iter().any(|k| k == "WS"));
                }
            } else if h.has(TcpHeader::RST) && syn_ack.is_none() {
                return Some(Record { syn, hs: None }); // refused
            }
            continue;
        }
        if is_syn(t) {
            if h.seq == isn {
                continue; // retransmitted SYN
            }
            break; // port reuse: a new connection starts here
        }
        if h.seq != isn.wrapping_add(1) || !(h.has(TcpHeader::RST) || h.has(TcpHeader::ACK)) {
            continue;
        }
        let server_ws = syn_ack.unwrap_or(assume_server_scales);
        let hs = if h.has(TcpHeader::RST) {
            Handshake {
                outcome: Some("RST".into()),
                ack_window_bytes: None,
                ack_ttl: Some(t.ttl.into()),
                ack_ipid: h.ip_id.map(Into::into),
            }
        } else {
            let window = u64::from(t.window);
            // Python shifts without bound; no real stack sends a scale
            // anywhere near the cap (RFC 7323 stops at 14).
            let bytes = match syn_tcp.window_scale {
                Some(ws) if server_ws => window << ws.min(48),
                _ => window,
            };
            Handshake {
                outcome: Some("ACK".into()),
                ack_window_bytes: Some(bytes),
                ack_ttl: Some(t.ttl.into()),
                ack_ipid: h.ip_id.map(Into::into),
            }
        };
        return Some(Record { syn, hs: Some(hs) });
    }

    ctx.is_final.then(|| Record {
        syn,
        hs: syn_ack.map(|_| Handshake {
            outcome: Some("NONE".into()),
            ..Default::default()
        }),
    })
}

/// What the method concluded for one connection.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    pub raw_key: String,
    pub known: bool,
    /// Where the name came from; `None` when nothing named the tuple.
    pub hit: Option<Hit>,
    pub name: Option<Name>,
    /// Closest known family and its distance, for a tuple nothing named.
    pub hint: Option<(String, f32)>,
}

impl TcpCluster {
    /// Fingerprint set first; the encoder only on a miss, or to hint an
    /// unnamed known tuple.
    pub fn answer(&self, rec: &Record) -> Answer {
        let key = raw_key(rec);
        let known = self.model.fingerprints.get(&key);
        let embed = || self.model.encoder.embed(&featurize(rec));
        let (hit, name, embedding) = match known {
            Some(k) => {
                let hit = match (k.cluster, k.anchor) {
                    (c, _) if c >= 0 => Some(Hit::Cluster(c)),
                    (_, a) if a >= 0 => Some(Hit::Anchor(a)),
                    _ => None,
                };
                (hit, k.name.clone(), None)
            }
            None => {
                let e = embed();
                let found = self.model.classify(&e);
                (found.map(|(h, _)| h), found.map(|(_, n)| n.clone()), Some(e))
            }
        };
        let hint = if name.is_none() {
            let e = embedding.unwrap_or_else(embed);
            self.model
                .hint(&e, self.params.hint_max_distance, &self.params.hint_skip_families)
                .map(|(f, d)| (f.to_string(), d))
        } else {
            None
        };
        Answer {
            raw_key: key,
            known: known.is_some(),
            hit,
            name,
            hint,
        }
    }

    pub fn model(&self) -> &Model {
        &self.model
    }
}

impl Method for TcpCluster {
    fn manifest(&self) -> &MethodManifest {
        &self.manifest
    }

    fn extract(&self, ctx: &Context<'_>) -> Result<Outcome> {
        if ctx.session.key.transport != Transport::Tcp {
            return Ok(Outcome::NotApplicable);
        }
        let initiator = ctx.session.initiator;
        if !ctx
            .observations()
            .any(|o| o.source == initiator && o.tcp.as_ref().is_some_and(is_syn))
        {
            // First seen mid-stream, or a source without header detail.
            return Ok(Outcome::NotApplicable);
        }
        let Some(rec) = connection(ctx, self.params.assume_server_scales) else {
            return Ok(Outcome::Partial(Vec::new())); // handshake still open
        };

        let answer = self.answer(&rec);
        tracing::debug!(subject = ?initiator, raw_key = %answer.raw_key, hit = ?answer.hit, "tcpcluster");
        let ev = |key: &str, value: String, confidence| Evidence::new(self.name(), initiator, key, value, confidence);

        let mut evidence = Vec::new();
        if let Some(name) = &answer.name {
            // A fingerprint hit is an exact match on an entry naming one
            // family; the encoder's nearest neighbour is a fuzzy one.
            let (family_conf, versions_conf) = if answer.known {
                let single = name.versions.as_deref().is_some_and(|v| !v.contains('{'));
                (Confidence::Strong, if single { Confidence::Strong } else { Confidence::Likely })
            } else {
                (Confidence::Weak, Confidence::Weak)
            };
            evidence.push(ev("os", name.family.clone(), family_conf));
            if let Some(versions) = &name.versions {
                evidence.push(ev("versions", versions.clone(), versions_conf));
            }
        } else if let Some((family, distance)) = &answer.hint {
            // A near miss by the confidence rule: Weak, and never the answer.
            evidence.push(ev("hint", family.clone(), Confidence::Weak));
            // How near: the limit was calibrated on real stacks only, so a
            // crafted SYN can fall inside it (thesis lessons E34).
            evidence.push(ev("hint-distance", format!("{distance:.3}"), Confidence::Weak));
        }

        Ok(if evidence.is_empty() {
            Outcome::NoMatch
        } else {
            Outcome::Complete(evidence)
        })
    }
}

#[cfg(test)]
mod tests;
