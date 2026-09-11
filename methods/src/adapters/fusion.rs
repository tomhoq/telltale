//! Combines the other methods into the verdict the tool exists to produce:
//! is this endpoint an automated scanner?
//!
//! Its "database" is combination logic, not a lookup table — which is exactly
//! why every method owning its own database is the right shape. Runs at the
//! lowest priority so the evidence it reads is already in the [`Context`].

use std::path::Path;

use pf_core::{Confidence, Context, Evidence, Method, MethodManifest, Outcome, Result, Verdict};

pub struct Fusion {
    manifest: MethodManifest,
    /// Score at or above which the endpoint is called a scanner. Lives in the
    /// manifest so the threshold can be swept without recompiling.
    threshold: f64,
    /// Per-method weights, also from the manifest.
    ///
    /// TODO: read these from `params["weights"]` as a map rather than hardcoding
    /// a single number.
    _weights: (),
}

pub fn build(manifest: MethodManifest, _manifest_dir: &Path) -> Result<Box<dyn Method>> {
    let threshold = manifest.param("threshold", 0.7);
    Ok(Box::new(Fusion {
        manifest,
        threshold,
        _weights: (),
    }))
}

impl Method for Fusion {
    fn manifest(&self) -> &MethodManifest {
        &self.manifest
    }

    fn extract(&self, ctx: &Context<'_>) -> Result<Outcome> {
        if ctx.evidence.is_empty() {
            return Ok(Outcome::NoMatch);
        }

        // TODO: the actual scoring. Signals worth weighing, roughly in order of
        // how much they distinguish a scanner from a browser:
        //   - a ja4 hash on the known-scanner list
        //   - a banner naming a scanning tool
        //   - an OS/stack fingerprint inconsistent with the claimed client
        //   - session shape: connect-then-abandon, no app data, very short life
        //   - across sessions: many destinations from one source (needs state
        //     the ProfileStore holds, not this session — decide where that lives)
        let score = 0.0_f64;

        let verdict = if score >= self.threshold {
            Verdict::Scanner
        } else {
            Verdict::Unknown
        };

        let evidence = Evidence::new(
            self.name(),
            ctx.session.initiator,
            "verdict",
            format!("{verdict:?}").to_lowercase(),
            Confidence::Weak,
        );

        // Not final until the session is: more traffic can change the verdict.
        Ok(if ctx.is_final {
            Outcome::Complete(vec![evidence])
        } else {
            Outcome::Partial(vec![evidence])
        })
    }
}
