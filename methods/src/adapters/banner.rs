//! Identifies client software from plaintext banners and request headers —
//! SSH identification strings and HTTP User-Agents.

use std::path::Path;

use pf_core::{Context, Direction, FieldValue, Fields, Method, MethodManifest, Result, TriggerEvent};

pub struct Banner {
    manifest: MethodManifest,
    /// Cap on how many bytes to scan, so a large request cannot make this
    /// method expensive.
    max_bytes: usize,
}

pub fn build(manifest: MethodManifest, _manifest_dir: &Path) -> Result<Box<dyn Method>> {
    let max_bytes = manifest.param("max-bytes", 4096);
    Ok(Box::new(Banner {
        manifest,
        max_bytes,
    }))
}

impl Method for Banner {
    fn manifest(&self) -> &MethodManifest {
        &self.manifest
    }

    fn extract(&self, ctx: &Context<'_>) -> Result<Vec<Fields>> {
        let Some(packet) = ctx.packet else {
            return Ok(Vec::new());
        };
        // The client is what is being fingerprinted; the honeypot's own
        // banner says nothing about the attacker.
        if ctx.session.direction_of(packet) != Direction::ToResponder {
            return Ok(Vec::new());
        }

        let text = String::from_utf8_lossy(&packet.payload[..packet.payload.len().min(self.max_bytes)]);
        let found = match ctx.trigger {
            TriggerEvent::SshBanner => ssh_software(&text).map(|software| ("ssh", software)),
            TriggerEvent::HttpRequest => user_agent(&text).map(|agent| ("http", agent)),
            _ => None,
        };
        let Some((protocol, client)) = found else {
            return Ok(Vec::new());
        };

        Ok(vec![Fields::from([
            ("protocol".to_string(), FieldValue::from(protocol)),
            ("client".to_string(), FieldValue::from(client)),
        ])])
    }
}

/// `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3` -> `OpenSSH_8.9p1 Ubuntu-3`.
fn ssh_software(text: &str) -> Option<&str> {
    let line = text.lines().next()?.trim_end();
    let rest = line.strip_prefix("SSH-")?;
    let (_protocol_version, software) = rest.split_once('-')?;
    (!software.is_empty()).then_some(software)
}

/// The `User-Agent` header's value, header names compared case-insensitively.
fn user_agent(text: &str) -> Option<&str> {
    text.lines()
        .skip(1) // request line
        .take_while(|line| !line.is_empty() && *line != "\r")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("user-agent")
                .then(|| value.trim())
        })
        .filter(|agent| !agent.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_software_from_an_ssh_identification_string() {
        assert_eq!(
            ssh_software("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"),
            Some("OpenSSH_8.9p1 Ubuntu-3")
        );
        assert_eq!(ssh_software("SSH-2.0-\r\n"), None);
        assert_eq!(ssh_software("HTTP/1.1 200 OK\r\n"), None);
    }

    #[test]
    fn finds_the_user_agent_in_any_case() {
        let request = "GET / HTTP/1.1\r\nHost: x\r\nuser-agent: Mozilla/5.0 zgrab/0.x\r\n\r\n";
        assert_eq!(user_agent(request), Some("Mozilla/5.0 zgrab/0.x"));
    }

    #[test]
    fn stops_at_the_end_of_the_headers() {
        let request = "POST / HTTP/1.1\r\nHost: x\r\n\r\nUser-Agent: in-the-body\r\n";
        assert_eq!(user_agent(request), None);
    }
}
