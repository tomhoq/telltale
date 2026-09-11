//! p0f-style stack fingerprinting from a TCP SYN: initial TTL, window size and
//! the order of TCP options. Cheapest method there is — it needs only the
//! first packet, which is often all a scanner ever sends.
//!
//! Until the p0f signature database is loaded, the OS family comes from the
//! initial TTL alone. That separates the big families and nothing finer.

use std::path::Path;

use pf_core::{Context, FieldValue, Fields, Method, MethodManifest, Result};

pub struct TcpSyn {
    manifest: MethodManifest,
    /// Signature database, if the manifest declared one.
    ///
    /// TODO: type this as a real `p0f::Db` once the loader exists.
    _db: Option<String>,
    /// How close a signature match must be; unused until the database is.
    _min_score: f64,
}

pub fn build(manifest: MethodManifest, _manifest_dir: &Path) -> Result<Box<dyn Method>> {
    let min_score = manifest.param("min-score", 0.8);
    // TODO: let db = manifest.database.as_ref().map(|spec|
    //     db::load::<p0f::Db>(&manifest.name, spec, manifest_dir)).transpose()?;
    Ok(Box::new(TcpSyn {
        manifest,
        _db: None,
        _min_score: min_score,
    }))
}

impl Method for TcpSyn {
    fn manifest(&self) -> &MethodManifest {
        &self.manifest
    }

    fn extract(&self, ctx: &Context<'_>) -> Result<Vec<Fields>> {
        let Some(packet) = ctx.packet else {
            return Ok(Vec::new());
        };
        let (Some(tcp), Some(ttl)) = (&packet.tcp, packet.ttl) else {
            return Ok(Vec::new());
        };

        let initial = initial_ttl(ttl);
        let signature = format!("{initial}:{}:{}", tcp.window, option_layout(&tcp.options));

        Ok(vec![Fields::from([
            ("signature".to_string(), FieldValue::from(signature)),
            (
                "distance".to_string(),
                FieldValue::from(i64::from(initial - ttl)),
            ),
            ("os-family".to_string(), FieldValue::from(os_family(initial))),
        ])])
    }
}

/// The TTL the sender most likely started from: the smallest common default
/// at or above what arrived. Every hop decrements it by one.
fn initial_ttl(observed: u8) -> u8 {
    [32, 64, 128, 255]
        .into_iter()
        .find(|&initial| observed <= initial)
        .unwrap_or(255)
}

/// Default initial TTLs by stack family — a coarse split that the p0f
/// database will replace.
fn os_family(initial_ttl: u8) -> &'static str {
    match initial_ttl {
        64 => "linux/unix",
        128 => "windows",
        255 => "network-device/solaris",
        _ => "unknown",
    }
}

/// Option kinds in the order they were sent, p0f-style: `mss,sok,ts,nop,ws`.
/// A malformed length ends the walk rather than reading past the block.
fn option_layout(options: &[u8]) -> String {
    let mut kinds = Vec::new();
    let mut rest = options;
    while let Some(&kind) = rest.first() {
        let name = match kind {
            0 => {
                kinds.push("eol".to_string());
                break;
            }
            1 => {
                kinds.push("nop".to_string());
                rest = &rest[1..];
                continue;
            }
            2 => "mss".to_string(),
            3 => "ws".to_string(),
            4 => "sok".to_string(),
            5 => "sack".to_string(),
            8 => "ts".to_string(),
            other => format!("?{other}"),
        };
        let Some(&len) = rest.get(1) else { break };
        let len = len as usize;
        if len < 2 || len > rest.len() {
            break;
        }
        kinds.push(name);
        rest = &rest[len..];
    }
    kinds.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_ttl_rounds_up_to_a_common_default() {
        assert_eq!(initial_ttl(64), 64);
        assert_eq!(initial_ttl(57), 64);
        assert_eq!(initial_ttl(113), 128);
        assert_eq!(initial_ttl(250), 255);
    }

    #[test]
    fn option_layout_names_options_in_wire_order() {
        // MSS 1460, SACK permitted, timestamps, NOP, window scale 7.
        let options = [
            2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7,
        ];
        assert_eq!(option_layout(&options), "mss,sok,ts,nop,ws");
    }

    #[test]
    fn a_lying_option_length_stops_the_walk() {
        assert_eq!(option_layout(&[2, 40, 5, 180]), "");
    }
}
