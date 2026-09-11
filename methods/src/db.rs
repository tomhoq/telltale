//! Per-method reference data.
//!
//! Each method owns its own database rather than sharing one. p0f signatures,
//! ja4 hash lists and the fusion method's combination rules have no useful
//! common schema, and forcing one would couple every method to every other.
//! What they do share is the loading contract below.

use std::path::{Path, PathBuf};

use pf_core::{DatabaseSpec, Error, Result};

/// A method's reference data, loaded once at startup.
pub trait Database: Send + Sync + Sized {
    /// Formats this implementation accepts, matched against `DatabaseSpec::format`.
    const FORMATS: &'static [&'static str];

    fn load(text: &str, spec: &DatabaseSpec) -> Result<Self>;
}

/// Resolve a manifest's `database.path` relative to the manifest directory and
/// read it.
pub fn load<D: Database>(method: &str, spec: &DatabaseSpec, manifest_dir: &Path) -> Result<D> {
    if !D::FORMATS.contains(&spec.format.as_str()) {
        return Err(Error::Database {
            method: method.to_string(),
            reason: format!(
                "format `{}` not supported (expected one of {:?})",
                spec.format,
                D::FORMATS
            ),
        });
    }

    let path: PathBuf = manifest_dir.join(&spec.path);
    let text = std::fs::read_to_string(&path).map_err(|source| Error::Database {
        method: method.to_string(),
        reason: format!("{}: {source}", path.display()),
    })?;

    D::load(&text, spec)
}
