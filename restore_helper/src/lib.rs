use std::error::Error;
use std::path;

use checksum_helper::ChecksumHelperError;

mod check;
mod execute;
mod paths;
mod plan;

pub use check::{CheckOutcome, CheckProgress, CheckSummary};
pub use execute::{ExecuteProgress, ExistingFilePolicy, RestoreState, SkipReason};
pub use plan::Plan;

#[derive(Debug)]
pub enum RestoreHelperError {
    InvalidPlan(String),
    ManifestIdEmpty,
    ManifestDoesNotExist(path::PathBuf),
    ManifestIdDoesNotExist(String),
    TargetIsDirectory(path::PathBuf),
    ChecksumHelperError(ChecksumHelperError),
    CopyError(copy_helper::CopyError),
    IoError(std::io::Error),
    PathIoError {
        operation: &'static str,
        path: path::PathBuf,
        source: std::io::Error,
    },
    JsonError(serde_json::Error),
    CheckFailed,
}

impl Error for RestoreHelperError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::IoError(error) | Self::PathIoError { source: error, .. } => Some(error),
            Self::ChecksumHelperError(error) => Some(error),
            Self::CopyError(error) => Some(error),
            Self::JsonError(error) => Some(error),
            _ => None,
        }
    }
}

impl RestoreHelperError {
    pub(crate) fn path_io(
        operation: &'static str,
        path: impl AsRef<path::Path>,
        source: std::io::Error,
    ) -> Self {
        Self::PathIoError {
            operation,
            path: path.as_ref().to_path_buf(),
            source,
        }
    }
}

impl std::fmt::Display for RestoreHelperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPlan(message) => write!(f, "invalid restore plan: {message}"),
            Self::ManifestIdEmpty => write!(f, "manifest ID must not be empty"),
            Self::ManifestDoesNotExist(path) => {
                write!(f, "manifest does not exist: {}", path.display())
            }
            Self::ManifestIdDoesNotExist(id) => {
                write!(f, "manifest with ID '{}' does not exist", id)
            }
            Self::TargetIsDirectory(path) => {
                write!(f, "restore target is a directory: {}", path.display())
            }
            Self::ChecksumHelperError(error) => write!(f, "{error}"),
            Self::CopyError(error) => write!(f, "{error}"),
            Self::IoError(error) => write!(f, "I/O error: {error}"),
            Self::PathIoError {
                operation,
                path,
                source,
            } => write!(f, "failed to {operation} {}: {source}", path.display()),
            Self::JsonError(error) => write!(f, "plan JSON error: {error}"),
            Self::CheckFailed => write!(f, "destination check found problems"),
        }
    }
}

impl From<std::io::Error> for RestoreHelperError {
    fn from(value: std::io::Error) -> Self {
        RestoreHelperError::IoError(value)
    }
}

impl From<copy_helper::CopyError> for RestoreHelperError {
    fn from(value: copy_helper::CopyError) -> Self {
        Self::CopyError(value)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_errors_preserve_details_and_error_chain() {
        let original = std::io::Error::from_raw_os_error(2);
        let expected = original.to_string();
        let error =
            RestoreHelperError::path_io("read source metadata", "/archive/missing", original);
        let message = error.to_string();
        assert!(message.contains("read source metadata /archive/missing"));
        assert!(message.contains(&expected));
        let source = error
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(source.raw_os_error(), Some(2));

        let error = RestoreHelperError::from(std::io::Error::other("original detail"));
        assert!(error.to_string().contains("original detail"));
        assert!(error.source().is_some());
    }
}
