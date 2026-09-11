//! TLS ClientHello fingerprinting. Strong scanner signal: mass scanners use a
//! handful of TLS stacks, and their hashes are well catalogued.

use std::path::Path;

use pf_core::{Context, Method, MethodManifest, Outcome, Result};

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

    fn extract(&self, ctx: &Context<'_>) -> Result<Outcome> {
        let session = ctx.session;
        // The registry guarantees the session reached `tls-client-hello`, so the
        // hello is somewhere in here.
        let Some(_hello) = session.from_initiator().find(|o| !o.payload.is_empty()) else {
            return Ok(Outcome::NotApplicable);
        };

        // TODO: parse the ClientHello, compute the hash, look it up.
        Ok(Outcome::NoMatch)
    }
}
