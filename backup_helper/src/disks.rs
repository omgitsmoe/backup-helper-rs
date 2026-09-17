use crate::{BackupHelperError, backup_helper::DiskHandle, reconcile::Reconcile};
use serde::{Deserialize, Serialize};
use std::path;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

type Result<T> = std::result::Result<T, crate::BackupHelperError>;

pub(crate) trait DiskMountChecker: Send + Sync {
    fn is_mounted(&self, disk: &Disk) -> std::io::Result<bool>;
}

pub(crate) struct SystemDiskMountChecker;

impl DiskMountChecker for SystemDiskMountChecker {
    fn is_mounted(&self, disk: &Disk) -> std::io::Result<bool> {
        disk.is_mounted()
    }
}

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
            return Err(BackupHelperError::ReconcileConflict(format!(
                "no declared disk matching path '{:?}'",
                path
            )));
        }

        Ok(DiskHandle(max_idx_components.0))
    }

    #[cfg(unix)]
    pub fn is_mounted(&self) -> std::io::Result<bool> {
        let metadata = match std::fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };

        let parent = self.path.parent().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "disk has no parent")
        })?;

        let parent_metadata = match std::fs::metadata(parent) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };

        Ok(metadata.dev() != parent_metadata.dev())
    }

    #[cfg(windows)]
    fn volume_path(path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        use windows_sys::Win32::Storage::FileSystem::GetVolumePathNameW;

        let input: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut output = vec![0u16; 32_768];

        let result =
            unsafe { GetVolumePathNameW(input.as_ptr(), output.as_mut_ptr(), output.len() as u32) };

        if result == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let length = output.iter().position(|character| *character == 0).unwrap();

        Ok(std::ffi::OsString::from_wide(&output[..length]).into())
    }

    #[cfg(windows)]
    fn existing(path: &std::path::Path) -> std::io::Result<bool> {
        match std::fs::metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    #[cfg(windows)]
    pub fn is_mounted(&self) -> std::io::Result<bool> {
        if !Self::existing(&self.path)? {
            return Ok(false);
        }

        let Some(parent) = self.path.parent() else {
            return Ok(true);
        };

        if !Self::existing(parent)? {
            return Ok(false);
        }

        let path_volume = Self::volume_path(&self.path)?;
        let parent_volume = Self::volume_path(parent)?;

        let path_volume = path_volume.to_string_lossy();
        let parent_volume = parent_volume.to_string_lossy();

        let path_volume = path_volume.trim_end_matches(['\\', '/']);
        let parent_volume = parent_volume.trim_end_matches(['\\', '/']);

        Ok(!path_volume.eq_ignore_ascii_case(parent_volume))
    }
}

impl Reconcile for Disk {
    fn reconcile(&mut self, other: Self) -> std::result::Result<(), crate::BackupHelperError> {
        self.path = other.path;

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
    fn missing_disk_path_is_not_mounted() {
        let root = testdir!();
        let disk = Disk {
            name: "missing".into(),
            path: root.join("missing-disk"),
        };

        assert!(!disk.is_mounted().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn unix_directory_on_the_same_device_is_not_mounted() {
        let root = testdir!();
        let path = root.join("disk");
        std::fs::create_dir(&path).unwrap();
        let disk = Disk {
            name: "same-device".into(),
            path,
        };

        assert!(!disk.is_mounted().unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn windows_directory_on_the_same_volume_is_not_mounted() {
        let root = testdir!();
        let path = root.join("disk");
        std::fs::create_dir(&path).unwrap();
        let disk = Disk {
            name: "same-volume".into(),
            path,
        };

        assert!(!disk.is_mounted().unwrap());
    }
}
