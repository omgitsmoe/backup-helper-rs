use crate::BackupHelperError;
use crate::ReconcileArgs;
use crate::backup_helper::BackupHelper;
use crate::parse;

use std::fs;

type Result<T> = std::result::Result<T, BackupHelperError>;

pub fn reconcile(args: ReconcileArgs) -> Result<()> {
    let contents = fs::read_to_string(&args.config)?;
    let parsed = parse::parse(&contents)?;

    let mut bh = BackupHelper::from_file(&args.common.state)?;
    bh.reconcile(parsed)?;
    bh.persist(&args.common.state)?;

    println!("after reconcile:\n{}", bh.serialize()?);

    Ok(())
}

pub(crate) trait Reconcile {
    fn reconcile(&mut self, other: Self) -> std::result::Result<(), BackupHelperError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommonArgs, ReconcileArgs};
    use pretty_assertions::assert_eq;
    use testdir::testdir;

    #[test]
    fn reconcile_reads_config_and_persists_state() {
        let testdir = testdir!();
        let state_path = testdir.join("state.json");
        let config_path = testdir.join("config.kdl");
        std::fs::write(
            &config_path,
            crate::test_utils::config_with_absolute_paths(
                r#"
                disks { disk "main" { path "/mnt" } }
                source "/mnt/source" {
                    target "/mnt/backup" { transfer_mode copy }
                }
            "#,
            ),
        )
        .unwrap();

        reconcile(ReconcileArgs {
            common: CommonArgs {
                state: state_path.clone(),
            },
            config: config_path.clone(),
        })
        .unwrap();

        let actual: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
        let expected: serde_json::Value =
            serde_json::from_str(&crate::test_utils::config_with_absolute_paths(
                r#"{
                "version": 1,
                "disks": [{"name": "main", "path": "/mnt"}],
                "sources": [{
                    "path": "/mnt/source",
                    "hash_file": null,
                    "hash_log_file": null,
                    "checksums": {
                        "hash_type": "sha512",
                        "checksum_files": {"allow": [], "block": []},
                        "all_files": {"allow": [], "block": []}
                    },
                    "targets": [{
                        "path": "/mnt/backup",
                        "transfer_mode": "Copy",
                        "transferred": false,
                        "verify": true,
                        "verified": null,
                        "disk": 0
                    }],
                    "disk": 0
                }]
            }"#,
            ))
            .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn reconcile_returns_io_error_for_missing_config() {
        let testdir = testdir!();
        let result = reconcile(ReconcileArgs {
            common: CommonArgs {
                state: testdir.join("missing-state.json"),
            },
            config: testdir.join("missing-config.kdl"),
        });

        assert!(matches!(result, Err(BackupHelperError::IoError(_))));
    }
}
