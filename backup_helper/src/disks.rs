use crate::{BackupHelperError, backup_helper::DiskHandle, reconcile::Reconcile};
use serde::{Serialize, Deserialize};
use std::path;

type Result<T> = std::result::Result<T, crate::BackupHelperError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disk {
    pub(crate) name: String,
    pub(crate) path: path::PathBuf,
}

impl Disk {
    pub fn matching_disk(path: &path::Path, disks: &[Self]) -> Result<DiskHandle> {
        let mut max_idx_components = (0, 0);
        for (i, disk) in disks.iter().enumerate() {
            if !path.starts_with(&disk.path) {
                continue;
            }

            let components = disk.path.components().count();
            if components > max_idx_components.1 {
                max_idx_components = (i, components);
            }
        }

        if max_idx_components.1 == 0 {
            return Err(BackupHelperError::ReconcileConflict(
                format!(
                    "no declared disk matching path '{:?}'",
                    path)
            ));
        }

        Ok(DiskHandle(max_idx_components.0))
    }
}

impl Reconcile for Disk {
    fn reconcile(&mut self, other: Self) -> std::result::Result<(), crate::BackupHelperError> {
        self.path = other.path;

        Ok(())
    }
}
