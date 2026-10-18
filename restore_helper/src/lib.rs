use std::error::Error;
use std::path;

use checksum_helper::ChecksumHelperError;

mod execute;
mod plan;

pub use execute::{ExistingFilePolicy, RestoreState};
pub use plan::Plan;

#[derive(Debug)]
pub enum RestoreHelperError {
    ManifestIdEmpty,
    ManifestDoesNotExist(path::PathBuf),
    ManifestIdDoesNotExist(String),
    ChecksumHelperError(ChecksumHelperError),
    IoError(std::io::ErrorKind),
    JsonError(serde_json::Error),
}

impl Error for RestoreHelperError {}

impl std::fmt::Display for RestoreHelperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ManifestIdEmpty => write!(f, "manifest ID must not be empty"),
            Self::ManifestDoesNotExist(path) => {
                write!(f, "manifest does not exist: {}", path.display())
            }
            Self::ManifestIdDoesNotExist(id) => {
                write!(f, "manifest with ID '{}' does not exist", id)
            }
            Self::ChecksumHelperError(error) => write!(f, "{error}"),
            Self::IoError(kind) => write!(f, "I/O error: {kind}"),
            Self::JsonError(error) => write!(f, "plan JSON error: {error}"),
        }
    }
}

impl From<std::io::Error> for RestoreHelperError {
    fn from(value: std::io::Error) -> Self {
        RestoreHelperError::IoError(value.kind())
    }
}

impl From<ChecksumHelperError> for RestoreHelperError {
    fn from(value: ChecksumHelperError) -> Self {
        RestoreHelperError::ChecksumHelperError(value)
    }
}

impl From<serde_json::Error> for RestoreHelperError {
    fn from(value: serde_json::Error) -> Self {
        Self::JsonError(value)
    }
}

#[derive(Debug, Clone)]
pub struct Source {
    id: String,
    manifest: path::PathBuf,
}

impl Source {
    pub fn new(
        id: impl AsRef<str>,
        manifest: impl AsRef<path::Path>,
    ) -> Result<Source, RestoreHelperError> {
        let id = id.as_ref();
        if id.is_empty() {
            return Err(RestoreHelperError::ManifestIdEmpty);
        }

        Ok(Source {
            id: id.to_string(),
            manifest: manifest.as_ref().to_path_buf(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Mount {
    id: String,
    mount: path::PathBuf,
}

impl Mount {
    pub fn new(
        id: impl AsRef<str>,
        mount: impl AsRef<path::Path>,
    ) -> Result<Mount, RestoreHelperError> {
        let id = id.as_ref();
        if id.is_empty() {
            return Err(RestoreHelperError::ManifestIdEmpty);
        }

        Ok(Mount {
            id: id.to_string(),
            mount: mount.as_ref().to_path_buf(),
        })
    }
}
