use serde::{Deserialize, Serialize};
use std::path;

use crate::{backup_helper::DiskHandle, disks::Disk, reconcile::Reconcile, target::Target};

type Result<T> = std::result::Result<T, crate::BackupHelperError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    path: path::PathBuf,
    hash_file: Option<path::PathBuf>,
    hash_log_file: Option<path::PathBuf>,
    checksums: ChecksumOptions,
    targets: Vec<Target>,
    disk: Option<DiskHandle>,
    // TODO glob filters, separate for hash/all?
}

impl Source {
    pub fn new(path: impl AsRef<path::Path>, hash_file: Option<impl AsRef<path::Path>>) -> Source {
        Source {
            path: path.as_ref().to_path_buf(),
            hash_file: hash_file.map(|p| path::PathBuf::from(p.as_ref())),
            hash_log_file: None,
            checksums: ChecksumOptions{
                checksum_files: Default::default(),
                all_files: Default::default(),
            },
            targets: vec![],
            disk: None,
        }
    }

    pub fn set_hash_file(&mut self, path: impl AsRef<path::Path>) {
        self.hash_file = Some(path.as_ref().to_path_buf());
    }

    pub fn add_target(&mut self, target: Target) {
        self.targets.push(target);
    }

    pub fn assign_disk(&mut self, disks: &[Disk]) -> Result<()> {
        self.disk = Some(Disk::matching_disk(&self.path, disks)?);

        for target in &mut self.targets {
            target.assign_disk(disks)?;
        }

        Ok(())
    }

    pub fn path(&self) -> &path::PathBuf {
        &self.path
    }

    pub fn has_transferred_target(&self) -> bool {
        self.targets.iter().any(|t| t.is_transferred())
    }

    fn get_target_mut(&mut self, target_path: impl AsRef<path::Path>) -> Option<&mut Target> {
        let target_path = target_path.as_ref();
        self.targets
            .iter_mut()
            .find(|target| target.path() == target_path)
            .map(|v| v as _)
    }

    pub(crate) fn checksum_options_mut(&mut self) -> &mut ChecksumOptions {
        &mut self.checksums
    }

    pub fn checksum_options(&self) -> &ChecksumOptions {
        &self.checksums
    }
}

impl Reconcile for Source {
    fn reconcile(&mut self, other: Self) -> std::result::Result<(), crate::BackupHelperError> {
        debug_assert!(
            self.path == other.path,
            "paths must match, since it's the identity used to do the reconcile step"
        );
        debug_assert!(
            other.disk.is_none(),
            "these fields must not come from a config reconciliation"
        );

        if self.hash_file.is_some() && other.checksums.has_globs()
            && self.checksums != other.checksums {
            return Err(crate::BackupHelperError::ReconcileConflict(format!(
                "can't change source {:?} checksum options, since it already has a `hash_file`",
                other.path
            )));
        }

        self.checksums = other.checksums;

        // prefer other if set, otherwise self
        self.hash_file = other.hash_file.or(self.hash_file.take());
        self.hash_log_file = other.hash_log_file.or(self.hash_log_file.take());

        if self.targets.is_empty() {
            self.targets = other.targets;
            return Ok(());
        }

        let mut seen = vec![];
        for incoming_target in other.targets {
            seen.push(incoming_target.path().to_path_buf());
            if let Some(existing_target) = self.get_target_mut(incoming_target.path()) {
                existing_target.reconcile(incoming_target)?;
            } else {
                self.targets.push(incoming_target);
            }
        }

        for existing_target in &self.targets {
            if !seen.contains(existing_target.path()) && existing_target.is_transferred()
            {
                return Err(crate::BackupHelperError::ReconcileConflict(format!(
                    "reconciliation would drop transfered target {:?}",
                    existing_target.path()
                )));
            }
        }

        self.targets.retain(|t| seen.contains(t.path()));

        Ok(())
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChecksumOptions {
    pub(crate) checksum_files: GlobFilter,
    pub(crate) all_files: GlobFilter,
}

impl ChecksumOptions {
    pub fn has_globs(&self) -> bool {
        !self.checksum_files.allow.is_empty()
            || !self.checksum_files.block.is_empty()
            || !self.all_files.allow.is_empty()
            || !self.all_files.block.is_empty()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobFilter {
    pub(crate) allow: Vec<String>,
    pub(crate) block: Vec<String>,
}
