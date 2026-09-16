use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::path;

use checksum_helper::{
    hash_type,
    pathmatcher::{PathMatcher, PathMatcherBuilder},
};

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
}

impl Source {
    pub fn new(path: impl AsRef<path::Path>, hash_file: Option<impl AsRef<path::Path>>) -> Source {
        Source {
            path: path.as_ref().to_path_buf(),
            hash_file: hash_file.map(|p| path::PathBuf::from(p.as_ref())),
            hash_log_file: None,
            checksums: ChecksumOptions {
                hash_type: HashType(hash_type::HashType::Sha512),
                checksum_files: Default::default(),
                all_files: Default::default(),
            },
            targets: vec![],
            disk: None,
        }
    }

    pub fn hash_file(&self) -> &Option<path::PathBuf> {
        &self.hash_file
    }

    pub fn set_hash_file(&mut self, path: impl AsRef<path::Path>) {
        self.hash_file = Some(path.as_ref().to_path_buf());
    }

    #[allow(dead_code)]
    pub fn hash_log_file(&self) -> &Option<path::PathBuf> {
        &self.hash_log_file
    }

    pub fn set_hash_log_file(&mut self, path: impl AsRef<path::Path>) {
        self.hash_log_file = Some(path.as_ref().to_path_buf());
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

    pub fn disk(&self) -> &Option<DiskHandle> {
        &self.disk
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

    pub fn targets(&self) -> &Vec<Target> {
        &self.targets
    }

    pub fn target_mut(&mut self, idx: usize) -> &mut Target {
        &mut self.targets[idx]
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

        if self.hash_file.is_some() {
            if self.checksums.hash_type != other.checksums.hash_type {
                return Err(crate::BackupHelperError::ReconcileConflict(format!(
                    "can't change source {:?} `hash_type`, since it already has a `hash_file`",
                    other.path
                )));
            }

            if other.checksums.has_globs() && self.checksums != other.checksums {
                return Err(crate::BackupHelperError::ReconcileConflict(format!(
                    "can't change source {:?} checksum options, since it already has a `hash_file`",
                    other.path
                )));
            }
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
            if !seen.contains(existing_target.path()) && existing_target.is_transferred() {
                return Err(crate::BackupHelperError::ReconcileConflict(format!(
                    "reconciliation would drop transferred target {:?}",
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
    pub(crate) hash_type: HashType,
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

impl TryInto<PathMatcher> for GlobFilter {
    type Error = checksum_helper::pathmatcher::PathMatcherError;

    fn try_into(self) -> std::result::Result<PathMatcher, Self::Error> {
        let mut matcher = PathMatcherBuilder::new();
        for allow in self.allow {
            matcher = matcher.allow(allow)?;
        }
        for block in self.block {
            matcher = matcher.block(block)?;
        }

        matcher.build()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashType(pub hash_type::HashType);

impl Default for HashType {
    fn default() -> Self {
        Self(hash_type::HashType::Sha512)
    }
}

impl Serialize for HashType {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.to_str())
    }
}

impl<'de> Deserialize<'de> for HashType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        hash_type::HashType::try_from(s.as_str())
            .map(HashType)
            .map_err(serde::de::Error::custom)
    }
}

impl TryFrom<&str> for HashType {
    type Error = String;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Ok(HashType(hash_type::HashType::try_from(value)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disks::Disk;
    use crate::reconcile::Reconcile;
    use crate::target::TransferMode;
    use pretty_assertions::assert_eq;

    fn target(path: &str) -> Target {
        Target::new(path, TransferMode::Copy, true)
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
    fn hash_type_cannot_change_after_hash_file_is_set() {
        let mut existing = Source::new("/data", Some("/data.sha512"));
        let mut incoming = Source::new("/data", None::<&str>);
        incoming.checksum_options_mut().hash_type = HashType::try_from("sha256").unwrap();

        conflict(existing.reconcile(incoming), "hash_type");
    }

    #[test]
    fn checksum_globs_cannot_change_after_hash_file_is_set() {
        let mut existing = Source::new("/data", Some("/data.sha512"));
        let mut incoming = Source::new("/data", None::<&str>);
        incoming.checksum_options_mut().all_files.allow = vec!["*.jpg".into()];

        conflict(existing.reconcile(incoming), "checksum options");
    }

    #[test]
    fn source_reconcile_adds_and_removes_untransferred_targets() {
        let mut existing = Source::new("/data", None::<&str>);
        existing.add_target(target("/old"));

        let mut incoming = Source::new("/data", None::<&str>);
        incoming.add_target(target("/new"));

        existing.reconcile(incoming).unwrap();

        assert_eq!(existing.targets().len(), 1);
        assert_eq!(
            existing.targets()[0].path(),
            &std::path::PathBuf::from("/new")
        );
    }

    #[test]
    fn transferred_target_cannot_be_removed() {
        let mut existing = Source::new("/data", None::<&str>);
        existing.add_target(target("/backup"));
        existing.target_mut(0).transferred();

        let incoming = Source::new("/data", None::<&str>);
        conflict(existing.reconcile(incoming), "drop transferred target");
    }

    #[test]
    fn source_reconcile_preserves_hash_paths_when_config_omits_them() {
        let mut existing = Source::new("/data", Some("/data.sha512"));
        existing.set_hash_log_file("/data.log");

        let incoming = Source::new("/data", None::<&str>);
        existing.reconcile(incoming).unwrap();

        assert_eq!(
            existing.hash_file(),
            &Some(std::path::PathBuf::from("/data.sha512"))
        );
        assert_eq!(
            existing.hash_log_file(),
            &Some(std::path::PathBuf::from("/data.log"))
        );
    }

    #[test]
    fn assign_disk_assigns_source_and_target_disks() {
        let disks = vec![
            Disk {
                name: "source".into(),
                path: "/data".into(),
            },
            Disk {
                name: "backup".into(),
                path: "/backup".into(),
            },
        ];
        let mut source = Source::new("/data/files", None::<&str>);
        source.add_target(target("/backup/files"));

        source.assign_disk(&disks).unwrap();

        assert_eq!(source.disk(), &Some(DiskHandle(0)));
        assert_eq!(source.targets()[0].disk(), &Some(DiskHandle(1)));
    }
}
