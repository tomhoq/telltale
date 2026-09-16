//! p0f-style fingerprinting from TCP SYN characteristics: window size, options
//! order, TTL, MSS. Cheapest method there is — it needs only the first packet,
//! which is often all a scanner ever sends.

use std::path::Path;

use pf_core::{Confidence, Context, Evidence, Method, MethodManifest, Outcome, Result, Transport};

pub struct TcpSyn {
    manifest: MethodManifest,
    /// Signature database, if the manifest declared one.
    ///
    /// TODO: type this as a real `p0f::Db` once the loader exists.
    _db: Option<String>,
    /// Example of a manifest-driven knob: how close a signature match must be.
    min_score: f64,
}

pub fn build(manifest: MethodManifest, _manifest_dir: &Path) -> Result<Box<dyn Method>> {
    let min_score = manifest.param("min-score", 0.8);
    // TODO: let db = manifest.database.as_ref().map(|spec|
    //     db::load::<p0f::Db>(&manifest.name, spec, manifest_dir)).transpose()?;
    Ok(Box::new(TcpSyn {
        manifest,
        _db: None,
        min_score,
    }))
}

impl Method for TcpSyn {
    fn manifest(&self) -> &MethodManifest {
        &self.manifest
    }

    fn extract(&self, ctx: &Context<'_>) -> Result<Outcome> {
        let session = ctx.session;
        if session.key.transport != Transport::Tcp {
            return Ok(Outcome::NotApplicable);
        }

        let Some(_syn) = ctx.observations().next() else {
            return Ok(Outcome::NotApplicable);
        };

        // TODO: build the signature from the SYN and match it against the
        // database, rejecting matches below `self.min_score`.
        let _ = self.min_score;

        let _example = Evidence::new(
            self.name(),
            session.initiator,
            "os",
            "unknown",
            Confidence::Weak,
        );

        Ok(Outcome::NoMatch)
    }
}

#[cfg(test)]
mod tests {
    // TODO: a fixture helper (a Session built from N synthetic observations)
    // belongs in pf-core behind #[cfg(feature = "test-support")] — every adapter
    // will want it.
}
