use serde::{Deserialize, Serialize};
use std::path;

use crate::{backup_helper::DiskHandle, disks::Disk, reconcile::Reconcile};

type Result<T> = std::result::Result<T, crate::BackupHelperError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedInfo {
    pub(crate) checked: u64,
    pub(crate) errors: u64,
    pub(crate) missing: u64,
    pub(crate) crc_errors: u64,
    pub(crate) log_file: path::PathBuf,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransferMode {
    Copy,
    // TODO settings?
    Sync,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    path: path::PathBuf,
    transfer_mode: TransferMode,
    transferred: bool,
    verify: bool,
    verified: Option<VerifiedInfo>,
    disk: Option<DiskHandle>,
}

impl Target {
    pub fn new(path: impl AsRef<path::Path>, transfer_mode: TransferMode, verify: bool) -> Target {
        Target {
            path: path.as_ref().to_path_buf(),
            transfer_mode,
            transferred: false,
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

    pub fn disk(&self) -> &Option<DiskHandle> {
        &self.disk
    }

    pub fn is_transferred(&self) -> bool {
        self.transferred
    }

    pub fn transferred(&mut self) {
        self.transferred = true;
    }

    pub fn verify(&self) -> bool {
        self.verify
    }

    pub fn is_verified(&self) -> bool {
        self.verified.is_some()
    }

    pub fn verified(&mut self, info: VerifiedInfo) {
        self.verified = Some(info);
    }
}

impl Reconcile for Target {
    fn reconcile(&mut self, other: Self) -> std::result::Result<(), crate::BackupHelperError> {
        debug_assert!(
            self.path == other.path,
            "paths must match, since it's the identity used to do the reconcile step"
        );
        debug_assert!(
            !other.transferred && other.verified.is_none() && other.disk.is_none(),
            "these fields must not come from a config reconciliation"
        );

        if self.transferred && self.transfer_mode != other.transfer_mode {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disks::Disk;
    use crate::reconcile::Reconcile;
    use pretty_assertions::assert_eq;

    fn target(mode: TransferMode, verify: bool) -> Target {
        Target::new("/backup", mode, verify)
    }

    fn conflict(result: Result<()>, expected: &str) {
        match result {
            Err(crate::BackupHelperError::ReconcileConflict(message)) => {
                assert!(message.contains(expected), "{message}");
            }
            other => panic!("expected reconciliation conflict, got {other:?}"),
        }
    }

    #[test]
    fn transfer_mode_can_change_before_transfer() {
        let mut existing = target(TransferMode::Copy, true);
        existing
            .reconcile(target(TransferMode::Sync, true))
            .unwrap();

        let json = serde_json::to_value(&existing).unwrap();
        assert_eq!(json["transfer_mode"], "Sync");
    }

    #[test]
    fn transferred_target_cannot_change_transfer_mode() {
        let mut existing = target(TransferMode::Copy, true);
        existing.transferred();

        conflict(
            existing.reconcile(target(TransferMode::Sync, true)),
            "transfer_mode",
        );
    }

    #[test]
    fn verify_can_change_before_verification() {
        let mut existing = target(TransferMode::Copy, true);
        existing
            .reconcile(target(TransferMode::Copy, false))
            .unwrap();

        assert_eq!(existing.verify(), false);
    }

    #[test]
    fn verified_target_cannot_change_verify_option() {
        let mut existing = target(TransferMode::Copy, true);
        existing.verified(VerifiedInfo {
            checked: 1,
            errors: 0,
            missing: 0,
            crc_errors: 0,
            log_file: "/verify.log".into(),
        });

        conflict(
            existing.reconcile(target(TransferMode::Copy, false)),
            "`verify` option",
        );
    }

    #[test]
    fn assign_disk_assigns_matching_disk() {
        let disks = vec![Disk {
            name: "backup".into(),
            path: "/backup".into(),
        }];
        let mut target = target(TransferMode::Copy, true);

        target.assign_disk(&disks).unwrap();

        assert_eq!(target.disk(), &Some(DiskHandle(0)));
    }
}
