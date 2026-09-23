use crate::{BackupHelperError, backup_helper::DiskHandle, reconcile::Reconcile};
use serde::{Deserialize, Serialize};
use std::path;

type Result<T> = std::result::Result<T, crate::BackupHelperError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disk {
    pub(crate) name: String,
    pub(crate) path: path::PathBuf,
    #[serde(default)]
    pub(crate) mounted: bool,
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
            return Err(BackupHelperError::ReconcileConflict(format!(
                "no declared disk matching path '{:?}'",
                path
            )));
        }

        Ok(DiskHandle(max_idx_components.0))
    }

    pub fn is_mounted(&self) -> std::io::Result<bool> {
        if !self.mounted {
            return Ok(false);
        }

        match std::fs::metadata(&self.path) {
            Ok(metadata) => Ok(metadata.is_dir()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
}

impl Reconcile for Disk {
    fn reconcile(&mut self, other: Self) -> std::result::Result<(), crate::BackupHelperError> {
        self.path = other.path;
        self.mounted = other.mounted;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use testdir::testdir;

    fn disk(path: &str) -> Disk {
        Disk {
            name: path.to_string(),
            path: path.into(),
            mounted: false,
        }
    }

    #[test]
    fn matching_disk_accepts_an_exact_path() {
        let disks = vec![disk("/mnt/data"), disk("/mnt/backup")];

        assert_eq!(
            Disk::matching_disk(Path::new("/mnt/data"), &disks).unwrap(),
            DiskHandle(0)
        );
    }

    #[test]
    fn matching_disk_prefers_the_longest_matching_prefix() {
        let disks = vec![disk("/mnt"), disk("/mnt/data"), disk("/mnt/data/photos")];

        assert_eq!(
            Disk::matching_disk(Path::new("/mnt/data/photos/raw"), &disks).unwrap(),
            DiskHandle(2)
        );
    }

    #[test]
    fn matching_disk_does_not_match_a_similar_textual_prefix() {
        let disks = vec![disk("/mnt/a")];

        let result = Disk::matching_disk(Path::new("/mnt/abc/file"), &disks);

        assert!(matches!(
            result,
            Err(BackupHelperError::ReconcileConflict(message))
                if message.contains("no declared disk matching path")
        ));
    }

    #[test]
    fn matching_disk_reports_a_reconcile_conflict_when_no_disk_matches() {
        let disks = vec![disk("/mnt/data")];

        let result = Disk::matching_disk(Path::new("/archive/file"), &disks);

        assert!(matches!(
            result,
            Err(BackupHelperError::ReconcileConflict(message))
                if message.contains("no declared disk matching path")
        ));
    }

    #[test]
    fn missing_declared_mounted_disk_path_is_not_mounted() {
        let root = testdir!();
        let disk = Disk {
            name: "missing".into(),
            path: root.join("missing-disk"),
            mounted: true,
        };

        assert!(!disk.is_mounted().unwrap());
    }

    #[test]
    fn declared_mounted_directory_is_mounted() {
        let root = testdir!();
        let path = root.join("disk");
        std::fs::create_dir(&path).unwrap();
        let disk = Disk {
            name: "directory".into(),
            path,
            mounted: true,
        };

        assert!(disk.is_mounted().unwrap());
    }

    #[test]
    fn declared_mounted_file_is_not_mounted() {
        let root = testdir!();
        let path = root.join("disk");
        std::fs::write(&path, b"not a directory").unwrap();
        let disk = Disk {
            name: "file".into(),
            path,
            mounted: true,
        };

        assert!(!disk.is_mounted().unwrap());
    }

    #[test]
    fn undeclared_disk_is_not_mounted_even_when_the_path_exists() {
        let root = testdir!();
        let path = root.join("disk");
        std::fs::create_dir(&path).unwrap();
        let disk = Disk {
            name: "undeclared".into(),
            path,
            mounted: false,
        };

        assert!(!disk.is_mounted().unwrap());
    }
}
