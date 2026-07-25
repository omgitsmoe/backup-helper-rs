use serde::{Deserialize, Serialize};
use std::path;

use crate::{backup_helper::DiskHandle, disks::Disk, reconcile::Reconcile};

type Result<T> = std::result::Result<T, crate::BackupHelperError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedInfo {
    checked: u64,
    errors: u64,
    missing: u64,
    crc_errors: u64,
    log_file: path::PathBuf,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TransferMode {
    Copy,
    // TODO settings?
    Sync,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    path: path::PathBuf,
    transfer_mode: TransferMode,
    transfered: bool,
    verify: bool,
    verified: Option<VerifiedInfo>,
    disk: Option<DiskHandle>,
}

impl Target {
    pub fn new(path: impl AsRef<path::Path>, transfer_mode: TransferMode, verify: bool) -> Target {
        Target {
            path: path.as_ref().to_path_buf(),
            transfer_mode,
            transfered: false,
            verify,
            verified: None,
            disk: None,
        }
    }

    pub fn path(&self) -> &path::PathBuf {
        &self.path
    }

    pub fn assign_disk(&mut self, disks: &[Disk]) -> Result<()> {
        self.disk = Some(Disk::matching_disk(&self.path, disks)?);

        Ok(())
    }

    pub fn is_transferred(&self) -> bool {
        self.transfered
    }
}

impl Reconcile for Target {
    fn reconcile(&mut self, other: Self) -> std::result::Result<(), crate::BackupHelperError> {
        debug_assert!(
            self.path == other.path,
            "paths must match, since it's the identity used to do the reconcile step"
        );
        debug_assert!(
            !other.transfered && other.verified.is_none() && other.disk.is_none(),
            "these fields must not come from a config reconciliation"
        );

        if self.transfered && self.transfered != other.transfered {
            return Err(crate::BackupHelperError::ReconcileConflict(format!(
                "transferred target {:?} may not have its `transfer_mode` changed",
                self.path
            )));
        }
        self.transfer_mode = other.transfer_mode;

        if self.verified.is_some() && self.verify != other.verify {
            return Err(crate::BackupHelperError::ReconcileConflict(format!(
                "verified target {:?} may not have its `verify` option changed",
                self.path
            )));
        }
        self.verify = other.verify;

        Ok(())
    }
}
