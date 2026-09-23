use serde::{Deserialize, Serialize};
use std::path;

use crate::{BackupHelperError, disks::Disk, parse::Parsed, reconcile::Reconcile, source::Source};

type Result<T> = std::result::Result<T, crate::BackupHelperError>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DiskHandle(pub(crate) usize);

#[derive(Default, Debug, Clone)]
pub struct BackupHelper {
    disks: Vec<Disk>,
    sources: Vec<Source>,
}

impl BackupHelper {
    pub fn from_file(path: impl AsRef<path::Path>) -> Result<Self> {
        let path = path.as_ref();
        if !std::fs::exists(path)? {
            return Ok(Self::default());
        }

        let json = std::fs::read_to_string(path)?;
        Self::from_state(&json)
    }

    pub fn from_state(json: &str) -> Result<Self> {
        let header: BackupHeader = serde_json::from_str(json)?;

        match header.version {
            1 => {
                let state: BackupStateV1Owned = serde_json::from_str(json)?;
                Ok(Self {
                    disks: state.disks,
                    sources: state.sources,
                })
            }
            v => Err(BackupHelperError::InvalidState(format!(
                "unsupported version {v}"
            ))),
        }
    }

    pub fn serialize(&self) -> Result<String> {
        let state = BackupStateV1Ref {
            version: 1,
            disks: &self.disks,
            sources: &self.sources,
        };

        Ok(serde_json::to_string_pretty(&state)?)
    }

    pub fn persist(&self, path: impl AsRef<path::Path>) -> Result<()> {
        Ok(std::fs::write(path, self.serialize()?)?)
    }

    pub fn reconcile(&mut self, config: Parsed) -> Result<()> {
        if self.disks.is_empty() {
            self.disks = config.disks;
        } else {
            let mut seen = vec![];
            for incoming_disk in config.disks {
                seen.push(incoming_disk.name.clone());
                if !self.has_disk(&incoming_disk.name) {
                    self.disks.push(incoming_disk);
                    continue;
                }

                let existing_disk = self
                    .get_disk_mut(&incoming_disk.name)
                    .expect("checked above");
                existing_disk.reconcile(incoming_disk)?;
            }

            self.disks = std::mem::take(&mut self.disks)
                .into_iter()
                .filter(|d| seen.contains(&d.name))
                .collect();
        }

        if self.sources.is_empty() {
            self.sources = config.sources;
        } else {
            let mut seen = vec![];
            for incoming_source in config.sources {
                seen.push(incoming_source.path().clone());
                if let Some(existing_source) = self.get_source_mut(&incoming_source.path()) {
                    existing_source.reconcile(incoming_source)?;
                } else {
                    self.sources.push(incoming_source);
                }
            }

            for existing_source in &self.sources {
                if !seen.contains(existing_source.path()) && existing_source.hash_file().is_some() {
                    return Err(BackupHelperError::ReconcileConflict(format!(
                        "reconciliation would drop hashed source {:?}",
                        existing_source.path()
                    )));
                }

                if !seen.contains(existing_source.path())
                    && existing_source.has_transferred_target()
                {
                    return Err(BackupHelperError::ReconcileConflict(format!(
                        "reconciliation would drop source {:?} with transferred targets",
                        existing_source.path()
                    )));
                }
            }

            self.sources.retain(|s| seen.contains(s.path()));
        }

        self.assign_disks()?;

        Ok(())
    }

    fn has_disk(&self, name: &str) -> bool {
        self.disks.iter().any(|d| d.name == name)
    }

    fn get_disk_mut(&mut self, name: &str) -> Option<&mut Disk> {
        self.disks.iter_mut().find(|d| d.name == name)
    }

    fn get_source_mut(&mut self, source_path: &path::Path) -> Option<&mut Source> {
        self.sources.iter_mut().find(|s| s.path() == source_path)
    }

    fn assign_disks(&mut self) -> Result<()> {
        for source in &mut self.sources {
            source.assign_disk(&self.disks)?;
        }

        Ok(())
    }

    pub fn disks(&self) -> &[Disk] {
        &self.disks[..]
    }

    pub fn sources(&self) -> &Vec<Source> {
        &self.sources
    }

    pub fn source_mut(&mut self, idx: usize) -> &mut Source {
        &mut self.sources[idx]
    }
}

#[derive(Deserialize)]
struct BackupHeader {
    version: u32,
}

#[derive(Serialize)]
struct BackupStateV1Ref<'a> {
    version: u32,
    disks: &'a [Disk],
    sources: &'a [Source],
}

#[derive(Deserialize)]
struct BackupStateV1Owned {
    disks: Vec<Disk>,
    sources: Vec<Source>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;
    use crate::target::VerifiedInfo;
    use pretty_assertions::assert_eq;
    use serde_json::Value;
    use testdir::testdir;

    fn reconcile_state(state: &str, config: &str) -> Result<Value> {
        let mut helper =
            BackupHelper::from_state(&crate::test_utils::config_with_absolute_paths(state))?;
        helper.reconcile(parse::parse(
            &crate::test_utils::config_with_absolute_paths(config),
        )?)?;
        Ok(serde_json::from_str(&helper.serialize()?)?)
    }

    fn json_state(state: &str) -> Value {
        serde_json::from_str(&crate::test_utils::config_with_absolute_paths(state)).unwrap()
    }

    fn parsed_target(transfer_mode: crate::target::TransferMode, verify: bool) -> parse::Parsed {
        let mut source = crate::source::Source::new("/mnt/source", None::<&str>);
        source.add_target(crate::target::Target::new(
            "/mnt/backup",
            transfer_mode,
            verify,
        ));

        parse::Parsed {
            disks: vec![crate::disks::Disk {
                name: "main".into(),
                path: "/mnt".into(),
                mounted: false,
            }],
            sources: vec![source],
        }
    }

    fn conflict(result: Result<Value>, expected: &str) {
        match result {
            Err(BackupHelperError::ReconcileConflict(message)) => {
                assert!(message.contains(expected), "{message}");
            }
            other => panic!("expected reconciliation conflict, got {other:?}"),
        }
    }

    const EMPTY_STATE: &str = r#"{
        "version": 1,
        "disks": [],
        "sources": []
    }"#;

    #[test]
    fn reconcile_from_empty_state_assigns_nested_disks_and_updates_state() {
        let config = r#"
            disks {
                disk "main" {
                    path "/mnt"
                    mounted #false
                }
                disk "photos" {
                    path "/mnt/photos"
                    mounted #false
                }
            }
            source "/mnt/photos/raw" {
                hash_file "/mnt/photos/raw.sha512"
                target "/mnt/backup/photos" { transfer_mode copy verify #true }
            }
        "#;

        let actual = reconcile_state(EMPTY_STATE, config).unwrap();
        let expected = json_state(
            r#"{
                "version": 1,
                "disks": [
                    {"name": "main", "path": "/mnt", "mounted": false},
                    {"name": "photos", "path": "/mnt/photos", "mounted": false}
                ],
                "sources": [{
                    "path": "/mnt/photos/raw",
                    "hash_file": "/mnt/photos/raw.sha512",
                    "hash_log_file": null,
                    "checksums": {
                        "hash_type": "sha512",
                        "checksum_files": {"allow": [], "block": []},
                        "all_files": {"allow": [], "block": []}
                    },
                    "targets": [{
                        "path": "/mnt/backup/photos",
                        "transfer_mode": "Copy",
                        "transferred": false,
                        "verify": true,
                        "verified": null,
                        "disk": 0
                    }],
                    "disk": 1
                }]
            }"#,
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn reconcile_updates_existing_entries_adds_new_entries_and_removes_stale_entries() {
        let state = r#"
            {
                "version": 1,
                "disks": [
                    {"name": "main", "path": "/mnt/old"},
                    {"name": "stale", "path": "/mnt/stale"}
                ],
                "sources": [{
                    "path": "/mnt/new/source",
                    "hash_file": null,
                    "hash_log_file": null,
                    "checksums": {
                        "hash_type": "sha512",
                        "checksum_files": {"allow": [], "block": []},
                        "all_files": {"allow": [], "block": []}
                    },
                    "targets": [{
                        "path": "/archive/old-target",
                        "transfer_mode": "Copy",
                        "transferred": false,
                        "verify": true,
                        "verified": null,
                        "disk": 1
                    }],
                    "disk": 0
                }]
            }
        "#;
        let config = r#"
            disks {
                disk "main" {
                    path "/mnt/new"
                    mounted #false
                }
                disk "archive" {
                    path "/archive"
                    mounted #false
                }
            }
            source "/mnt/new/source" {
                target "/archive/old-target" {
                    transfer_mode sync
                    verify #false
                }
                target "/archive/new-target" { transfer_mode copy }
            }
            source "/archive/source" {
                target "/archive/second-target" { transfer_mode copy }
            }
        "#;

        let actual = reconcile_state(state, config).unwrap();
        let expected = json_state(
            r#"{
                "version": 1,
                "disks": [
                    {"name": "main", "path": "/mnt/new", "mounted": false},
                    {"name": "archive", "path": "/archive", "mounted": false}
                ],
                "sources": [{
                    "path": "/mnt/new/source",
                    "hash_file": null,
                    "hash_log_file": null,
                    "checksums": {
                        "hash_type": "sha512",
                        "checksum_files": {"allow": [], "block": []},
                        "all_files": {"allow": [], "block": []}
                    },
                    "targets": [
                        {
                            "path": "/archive/old-target",
                            "transfer_mode": "Sync",
                            "transferred": false,
                            "verify": false,
                            "verified": null,
                            "disk": 1
                        },
                        {
                            "path": "/archive/new-target",
                            "transfer_mode": "Copy",
                            "transferred": false,
                            "verify": true,
                            "verified": null,
                            "disk": 1
                        }
                    ],
                    "disk": 0
                }, {
                    "path": "/archive/source",
                    "hash_file": null,
                    "hash_log_file": null,
                    "checksums": {
                        "hash_type": "sha512",
                        "checksum_files": {"allow": [], "block": []},
                        "all_files": {"allow": [], "block": []}
                    },
                    "targets": [{
                        "path": "/archive/second-target",
                        "transfer_mode": "Copy",
                        "transferred": false,
                        "verify": true,
                        "verified": null,
                        "disk": 1
                    }],
                    "disk": 1
                }]
            }"#,
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn missing_source_or_target_disk_is_a_reconcile_conflict() {
        let config = r#"
            disks {
                disk "main" {
                    path "/mnt/source"
                    mounted #false
                }
            }
            source "/outside/source" {
                target "/mnt/target" { transfer_mode copy }
            }
        "#;

        conflict(
            reconcile_state(EMPTY_STATE, config),
            "no declared disk matching path",
        );
    }

    #[test]
    fn removed_source_with_transferred_target_is_rejected() {
        let state = r#"
            {
                "version": 1,
                "disks": [{"name":"main","path":"/mnt"}],
                "sources": [{
                    "path":"/mnt/source", "hash_file":null, "hash_log_file":null,
                    "checksums":{"hash_type":"sha512","checksum_files":{"allow":[],"block":[]},"all_files":{"allow":[],"block":[]}},
                    "targets":[{"path":"/mnt/backup","transfer_mode":"Copy","transferred":true,"verify":true,"verified":null,"disk":0}],
                    "disk":0
                }]
            }
        "#;

        conflict(
            reconcile_state(
                state,
                "disks {\n disk \"main\" {\n path \"/mnt\"\n mounted #false\n }\n}",
            ),
            "drop source",
        );
    }

    #[test]
    fn changing_path_of_hashed_source_is_rejected() {
        let state = r#"
            {
                "version": 1,
                "disks": [{"name":"main","path":"/mnt"}],
                "sources": [{
                    "path":"/mnt/old-source", "hash_file":"/mnt/old-source.sha512", "hash_log_file":null,
                    "checksums":{"hash_type":"sha512","checksum_files":{"allow":[],"block":[]},"all_files":{"allow":[],"block":[]}},
                    "targets":[], "disk":0
                }]
            }
        "#;
        let config = r#"
            disks {
                disk "main" {
                    path "/mnt"
                    mounted #false
                }
            }
            source "/mnt/new-source" { target "/mnt/backup" { transfer_mode copy } }
        "#;

        conflict(reconcile_state(state, config), "drop hashed source");
    }

    #[test]
    fn removed_untransferred_source_is_dropped() {
        let state = r#"
            {
                "version": 1,
                "disks": [{"name":"main","path":"/mnt"}],
                "sources": [{
                    "path":"/mnt/source", "hash_file":null, "hash_log_file":null,
                    "checksums":{"hash_type":"sha512","checksum_files":{"allow":[],"block":[]},"all_files":{"allow":[],"block":[]}},
                    "targets":[], "disk":0
                }]
            }
        "#;

        let actual = reconcile_state(
            state,
            "disks {\n disk \"main\" {\n path \"/mnt\"\n mounted #false\n }\n}",
        )
        .unwrap();
        let expected = json_state(
            r#"{
                "version": 1,
                "disks": [{"name": "main", "path": "/mnt", "mounted": false}],
                "sources": []
            }"#,
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn reconcile_allows_target_changes_before_transfer() {
        let mut helper = BackupHelper::default();
        helper
            .reconcile(parsed_target(crate::target::TransferMode::Copy, true))
            .unwrap();

        helper
            .reconcile(parsed_target(crate::target::TransferMode::Sync, false))
            .unwrap();

        let json: Value = serde_json::from_str(&helper.serialize().unwrap()).unwrap();
        assert_eq!(json["sources"][0]["targets"][0]["transfer_mode"], "Sync");
        assert_eq!(json["sources"][0]["targets"][0]["verify"], false);
    }

    #[test]
    fn reconcile_rejects_transfer_mode_change_after_transfer() {
        let mut helper = BackupHelper::default();
        helper
            .reconcile(parsed_target(crate::target::TransferMode::Copy, true))
            .unwrap();
        helper.source_mut(0).target_mut(0).transferred();

        conflict(
            helper
                .reconcile(parsed_target(crate::target::TransferMode::Sync, true))
                .map(|_| serde_json::json!(null)),
            "transfer_mode",
        );
    }

    #[test]
    fn reconcile_rejects_verify_change_after_verification() {
        let mut helper = BackupHelper::default();
        helper
            .reconcile(parsed_target(crate::target::TransferMode::Copy, true))
            .unwrap();
        helper.source_mut(0).target_mut(0).verified(VerifiedInfo {
            checked: 1,
            errors: 0,
            missing: 0,
            crc_errors: 0,
            log_file: "/mnt/verify.log".into(),
        });

        conflict(
            helper
                .reconcile(parsed_target(crate::target::TransferMode::Copy, false))
                .map(|_| serde_json::json!(null)),
            "`verify` option",
        );
    }

    #[test]
    fn unknown_json_properties_are_ignored() {
        let state = r#"{
            "version": 1,
            "future_property": true,
            "disks": [],
            "sources": [],
            "another_future_property": {"value": 42}
        }"#;

        let helper = BackupHelper::from_state(state).unwrap();
        let actual = json_state(&helper.serialize().unwrap());
        let expected = json_state(EMPTY_STATE);

        assert_eq!(actual, expected);
    }

    #[test]
    fn unsupported_state_version_is_rejected() {
        match BackupHelper::from_state(r#"{"version":2,"disks":[],"sources":[]}"#) {
            Err(BackupHelperError::InvalidState(message)) => {
                assert_eq!(message, "unsupported version 2");
            }
            other => panic!("expected unsupported version error, got {other:?}"),
        }
    }

    #[test]
    fn from_file_loads_existing_state() {
        let testdir = testdir!();
        let path = testdir.join("state.json");
        let state = r#"{"version":1,"disks":[],"sources":[]}"#;
        std::fs::write(&path, state).unwrap();

        let helper = BackupHelper::from_file(&path).unwrap();

        assert_eq!(
            json_state(&helper.serialize().unwrap()),
            json_state(EMPTY_STATE)
        );
    }

    #[test]
    fn from_file_rejects_invalid_state_json() {
        let testdir = testdir!();
        let path = testdir.join("invalid-state.json");
        std::fs::write(&path, "not json").unwrap();

        assert!(matches!(
            BackupHelper::from_file(&path),
            Err(BackupHelperError::InvalidState(_))
        ));
    }
}
