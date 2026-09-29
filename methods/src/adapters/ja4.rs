//! TLS ClientHello fingerprinting. Strong scanner signal: mass scanners use a
//! handful of TLS stacks, and their hashes are well catalogued.

use std::path::Path;

use pf_core::{Context, Method, MethodManifest, Outcome, Result};

use super::ja4_common::{match_sections, Ja4Db};
use crate::db;

pub struct Ja4 {
    manifest: MethodManifest,
    /// Labelled rows of `ja4_fingerprint.csv`, ready for when the hash is.
    _db: Ja4Db,
    /// All three JA4 sections by default; none varies per visitor.
    _sections: usize,
}

pub fn build(manifest: MethodManifest, manifest_dir: &Path) -> Result<Box<dyn Method>> {
    let db = manifest
        .database
        .as_ref()
        .map(|spec| db::load::<Ja4Db>(&manifest.name, spec, manifest_dir))
        .transpose()?
        .unwrap_or_default();
    let sections = match_sections(&manifest, 3);
    Ok(Box::new(Ja4 {
        manifest,
        _db: db,
        _sections: sections,
    }))
}

impl Method for Ja4 {
    fn manifest(&self) -> &MethodManifest {
        &self.manifest
    }

    fn extract(&self, ctx: &Context<'_>) -> Result<Outcome> {
        // The registry guarantees the session reached `tls-client-hello`, so the
        // hello is somewhere in here.
        let Some(_hello) = ctx.observations().find(|o| !o.payload.is_empty()) else {
            return Ok(Outcome::NotApplicable);
        };

        // TODO: parse the ClientHello, compute the hash, look it up in `_db`
        // (then `label_evidence`, as `ja4h` and `ja4t` do).
        Ok(Outcome::NoMatch)
    }
}
