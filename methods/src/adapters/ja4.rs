//! TLS ClientHello fingerprinting. Strong scanner signal: mass scanners use a
//! handful of TLS stacks, and their hashes are well catalogued.

use std::path::Path;

use pf_core::{Context, Fields, Method, MethodManifest, Result};

pub struct Ja4 {
    manifest: MethodManifest,
    /// TODO: a hash -> label map loaded from the manifest's database.
    _known_hashes: Option<String>,
}

pub fn build(manifest: MethodManifest, _manifest_dir: &Path) -> Result<Box<dyn Method>> {
    Ok(Box::new(Ja4 {
        manifest,
        _known_hashes: None,
    }))
}

impl Method for Ja4 {
    fn manifest(&self) -> &MethodManifest {
        &self.manifest
    }

    fn extract(&self, ctx: &Context<'_>) -> Result<Vec<Fields>> {
        // Fired by `tls-client-hello`, so this packet starts with the hello.
        let Some(_hello) = ctx.packet.map(|packet| &packet.payload) else {
            return Ok(Vec::new());
        };

        // TODO: parse the ClientHello, compute the ja4 hash, look it up. A
        // hello split across TCP segments needs the segments reassembled first.
        Ok(Vec::new())
    }
}
