//! Combines the other methods' results into one verdict.
//!
//! Just another method: it fires on `session-end`, when every other method
//! the session triggered has already reported, and reads `session.results`
//! instead of packet bytes. What it concludes is appended as its own entry,
//! beside the entries it read — nothing is merged in storage.
//!
//! Its "database" is combination logic, not a lookup table — which is exactly
//! why every method owning its own database is the right shape.

use std::collections::BTreeSet;
use std::path::Path;

use pf_core::{Context, FieldValue, Fields, Method, MethodManifest, Result};

pub struct Fusion {
    manifest: MethodManifest,
    /// Score at or above which the endpoint is called a scanner. Lives in the
    /// manifest so the threshold can be swept without recompiling.
    threshold: f64,
    /// Per-signal weights, also from the manifest.
    ///
    /// TODO: read these from `params["weights"]` as a map.
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

    fn extract(&self, ctx: &Context<'_>) -> Result<Vec<Fields>> {
        let reporting: BTreeSet<&str> = ctx
            .session
            .results
            .iter()
            .map(|entry| entry.method.as_str())
            .collect();
        if reporting.is_empty() {
            return Ok(Vec::new());
        }

        // TODO: the actual scoring. Signals worth weighing, roughly in order of
        // how much they distinguish a scanner from a browser:
        //   - a ja4 hash on the known-scanner list
        //   - a banner naming a scanning tool
        //   - an OS/stack fingerprint inconsistent with the claimed client
        //   - session shape: connect-then-abandon, no app data, very short life
        // Cross-session patterns (one source, many destinations) belong to the
        // separate scanner-detection layer above sessions, not here.
        let score = 0.0_f64;
        let verdict = if score >= self.threshold {
            "scanner"
        } else {
            "unknown"
        };

        Ok(vec![Fields::from([
            ("verdict".to_string(), FieldValue::from(verdict)),
            ("score".to_string(), FieldValue::from(score)),
            (
                "methods".to_string(),
                FieldValue::from(reporting.len() as i64),
            ),
        ])])
    }
}
