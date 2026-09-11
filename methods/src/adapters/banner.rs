//! Identifies client software from plaintext protocol banners and request
//! headers — User-Agent strings, SSH version strings, and the like.

use std::path::Path;

use pf_core::{Context, Method, MethodManifest, Outcome, Result};

pub struct Banner {
    manifest: MethodManifest,
    /// Cap on how many bytes to scan, so a large transfer cannot make this
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

    fn extract(&self, ctx: &Context<'_>) -> Result<Outcome> {
        let session = ctx.session;
        let scanned: usize = session
            .from_initiator()
            .map(|o| o.payload.len())
            .take_while(|len| *len <= self.max_bytes)
            .sum();

        if scanned == 0 {
            return Ok(Outcome::NotApplicable);
        }

        // TODO: match known banner patterns and emit client/vendor/version.
        Ok(Outcome::NoMatch)
    }
}
