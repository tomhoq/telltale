use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("capture source failed: {0}")]
    Capture(String),

    #[error("could not parse {layer}: {reason}")]
    Parse { layer: &'static str, reason: String },

    /// A method's reference database could not be loaded or is malformed.
    #[error("method `{method}` database: {reason}")]
    Database { method: String, reason: String },

    #[error("manifest `{path}`: {reason}")]
    Manifest { path: String, reason: String },

    /// The registry knows a manifest by this name but no adapter implements it.
    #[error("no adapter registered for method `{0}`")]
    UnknownMethod(String),

    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
