use std::path;

use checksum_helper::{ChecksumHelper, collection, hashed_file::VerifyResult};

use crate::{
    BackupHelperError, backup_helper::DiskHandle, source::ChecksumOptions, target::VerifiedInfo,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Task {
    SourceHash(SourceHash),
    SourceToTargetCopy(SourceToTargetCopy),
    SourceToTargetSync(SourceToTargetSync),
    TargetVerify(TargetVerify),
}

impl Task {
    pub fn involved_disks(&self) -> &[DiskHandle] {
        match self {
            Task::SourceHash(t) => &t.common.involved_disks[..],
            Task::SourceToTargetCopy(t) => &t.common.involved_disks[..],
            Task::SourceToTargetSync(t) => &t.common.involved_disks[..],
            Task::TargetVerify(t) => &t.common.involved_disks[..],
        }
    }

    pub fn execute(&self, ctx: &TaskContext) -> Result<TaskOutcome, BackupHelperError> {
        match self {
            Task::SourceHash(t) => t.execute(ctx),
            Task::SourceToTargetCopy(t) => t.execute(ctx),
            Task::SourceToTargetSync(t) => t.execute(ctx),
            Task::TargetVerify(t) => t.execute(ctx),
        }
    }
}

pub(crate) trait TaskExecutor {
    fn execute(&self, ctx: &TaskContext) -> Result<TaskOutcome, BackupHelperError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommonData {
    pub(crate) involved_disks: Box<[DiskHandle]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceHash{
    pub(crate) common: CommonData,
    pub(crate) source_idx: usize,
    pub(crate) options: ChecksumOptions,
}

impl TaskExecutor for SourceHash {
    fn execute(&self, ctx: &TaskContext) -> Result<TaskOutcome, BackupHelperError> {
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("<unnamed>");
        println!("{name}: Executing SourceHash");

        let source_path = ctx.source_path
            .as_ref()
            .expect("ctx must have a source path for SourceHash task");
        if !source_path.is_dir() {
            return Err(BackupHelperError::TaskError(String::from(
                "SourceHash task requires the source path to be a directory!",
            )));
        }

        let mut ch = ChecksumHelper::new(source_path)?;
        // TODO progress
        let collection = ch.incremental(|_p| {})?;
        ch.write_collection(&collection)?;

        Ok(TaskOutcome::SourceHash {
            hash_file: collection.full_path()?,
            hash_log_file: path::PathBuf::from("/todo.log"),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceToTargetCopy {
    pub(crate) common: CommonData,
    pub(crate) source_idx: usize,
    pub(crate) target_idx: usize,
}

impl TaskExecutor for SourceToTargetCopy {
    fn execute(&self, ctx: &TaskContext) -> Result<TaskOutcome, BackupHelperError> {
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("<unnamed>");
        println!("{name}: Executing SourceToTargetCopy");

        let source_path = ctx
            .source_path
            .as_ref()
            .expect("ctx must have a source_path for SourceToTargetCopy task");
        let target_path = ctx
            .target_path
            .as_ref()
            .expect("ctx must have a target_path for SourceToTargetCopy task");

        if !source_path.is_dir() {
            return Err(BackupHelperError::TaskError(String::from(
                "SourceToTargetCopy task requires the source path to be a directory!",
            )));
        }

        if let Some(p) = target_path.parent() {
            std::fs::create_dir_all(p)?;
        }
        // TODO implement this properly
        let output = std::process::Command::new("cp")
            .args([
                "-r",
                &source_path.join(".").to_string_lossy(),
                &target_path.to_string_lossy(),
            ])
            .output()?;

        if output.status.success() {
            Ok(TaskOutcome::SourceToTargetCopy)
        } else {
            Err(BackupHelperError::CopyError(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceToTargetSync {
    pub(crate) common: CommonData,
    pub(crate) source_idx: usize,
    pub(crate) target_idx: usize,
}

impl TaskExecutor for SourceToTargetSync {
    fn execute(&self, _ctx: &TaskContext) -> Result<TaskOutcome, BackupHelperError> {
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("<unnamed>");
        println!("{name}: Executing SourceToTargetSync");

        todo!("implement sync")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetVerify {
    pub(crate) common: CommonData,
    pub(crate) source_idx: usize,
    pub(crate) target_idx: usize,
}

impl TaskExecutor for TargetVerify {
    fn execute(&self, ctx: &TaskContext) -> Result<TaskOutcome, BackupHelperError> {
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("<unnamed>");
        println!("{name}: Executing TargetVerify");

        let source_hash_file = ctx
            .hash_file
            .as_ref()
            .expect("ctx must have a hash_file for TargetVerify task");
        let target_path = ctx
            .target_path
            .as_ref()
            .expect("ctx must have a target_path for SourceToTargetCopy task");
        let mut ch = ChecksumHelper::new(target_path)?;

        let collection_file_name = source_hash_file
            .file_name()
            .expect("hash_file must have a file_name");
        let target_collection_path = target_path.join(collection_file_name);

        let collection = ch.read_collection(&target_collection_path)?;
        // TODO progress
        let mut verified = VerifiedInfo {
            checked: 0,
            errors: 0,
            missing: 0,
            crc_errors: 0,
            log_file: path::PathBuf::new(),
        };
        ch.verify(
            &collection,
            |_| true,
            |p| match p {
                collection::VerifyProgress::Pre(_verify_progress_common) => {}
                collection::VerifyProgress::During(_hash_progress) => {}
                collection::VerifyProgress::Post(verify_progress_post) => {
                    verified.checked += 1;
                    println!("verified {:?}", verify_progress_post.progress.relative_path);

                    match verify_progress_post.result {
                        VerifyResult::Ok => {}
                        VerifyResult::FileMissing(_error_kind) => {
                            verified.errors += 1;
                            verified.missing += 1;
                        }
                        VerifyResult::Mismatch
                        | VerifyResult::MismatchSize
                        | VerifyResult::MismatchCorrupted
                        | VerifyResult::MismatchOutdatedHash => {
                            verified.errors += 1;
                            verified.crc_errors += 1;
                        }
                    }
                }
            },
        )?;

        Ok(TaskOutcome::TargetVerify(verified))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskContext {
    pub(crate) source_path: Option<path::PathBuf>,
    pub(crate) target_path: Option<path::PathBuf>,
    pub(crate) hash_file: Option<path::PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TaskOutcome {
    SourceHash {
        hash_file: path::PathBuf,
        hash_log_file: path::PathBuf,
    },
    SourceToTargetCopy,
    SourceToTargetSync,
    TargetVerify(VerifiedInfo),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use testdir::testdir;

    fn common(disks: &[usize]) -> CommonData {
        CommonData {
            involved_disks: disks
                .iter()
                .copied()
                .map(DiskHandle)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    #[test]
    fn involved_disks_returns_disks_for_each_task_variant() {
        let tasks = [
            Task::SourceHash(SourceHash {
                common: common(&[1]),
                source_idx: 0,
                options: ChecksumOptions::default(),
            }),
            Task::SourceToTargetCopy(SourceToTargetCopy {
                common: common(&[2, 3]),
                source_idx: 0,
                target_idx: 0,
            }),
            Task::SourceToTargetSync(SourceToTargetSync {
                common: common(&[4, 5]),
                source_idx: 0,
                target_idx: 0,
            }),
            Task::TargetVerify(TargetVerify {
                common: common(&[6]),
                source_idx: 0,
                target_idx: 0,
            }),
        ];

        assert_eq!(tasks[0].involved_disks(), &[DiskHandle(1)]);
        assert_eq!(tasks[1].involved_disks(), &[DiskHandle(2), DiskHandle(3)]);
        assert_eq!(tasks[2].involved_disks(), &[DiskHandle(4), DiskHandle(5)]);
        assert_eq!(tasks[3].involved_disks(), &[DiskHandle(6)]);
    }

    #[test]
    fn execute_source_hash_writes_hash_collection() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        fs::create_dir(&source_path).unwrap();
        fs::write(source_path.join("file.txt"), "content").unwrap();

        let task = Task::SourceHash(SourceHash {
            common: common(&[0]),
            source_idx: 0,
            options: ChecksumOptions::default(),
        });
        let outcome = task
            .execute(&TaskContext {
                source_path: Some(source_path),
                target_path: None,
                hash_file: None,
            })
            .unwrap();

        let TaskOutcome::SourceHash { hash_file, .. } = outcome else {
            panic!("SourceHash task returned the wrong outcome");
        };
        assert!(hash_file.is_file());
    }

    #[test]
    fn execute_source_hash_rejects_file_source() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        fs::write(&source_path, "content").unwrap();

        let task = Task::SourceHash(SourceHash {
            common: common(&[0]),
            source_idx: 0,
            options: ChecksumOptions::default(),
        });
        let outcome = task.execute(&TaskContext {
            source_path: Some(source_path),
            target_path: None,
            hash_file: None,
        });

        assert!(matches!(
            outcome,
            Err(BackupHelperError::TaskError(message))
                if message == "SourceHash task requires the source path to be a directory!"
        ));
    }

    #[test]
    fn execute_copy_puts_source_contents_in_existing_target() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        let target_path = testdir.join("target");
        fs::create_dir(&source_path).unwrap();
        fs::create_dir(&target_path).unwrap();
        fs::create_dir(source_path.join("nested")).unwrap();
        fs::write(source_path.join("file.txt"), "content").unwrap();
        fs::write(source_path.join(".hidden"), "hidden content").unwrap();
        fs::write(source_path.join("nested/file.txt"), "nested content").unwrap();

        let task = Task::SourceToTargetCopy(SourceToTargetCopy {
            common: common(&[0, 1]),
            source_idx: 0,
            target_idx: 0,
        });
        let outcome = task.execute(&TaskContext {
            source_path: Some(source_path),
            target_path: Some(target_path.clone()),
            hash_file: None,
        });
        assert!(matches!(outcome, Ok(TaskOutcome::SourceToTargetCopy)));

        assert_eq!(fs::read_to_string(target_path.join("file.txt")).unwrap(), "content");
        assert_eq!(
            fs::read_to_string(target_path.join(".hidden")).unwrap(),
            "hidden content"
        );
        assert_eq!(
            fs::read_to_string(target_path.join("nested/file.txt")).unwrap(),
            "nested content"
        );
        assert!(!target_path.join("source").exists());
    }

    #[test]
    fn execute_copy_rejects_file_source_before_creating_target() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        let target_path = testdir.join("target/nested/destination");
        fs::write(&source_path, "content").unwrap();

        let task = Task::SourceToTargetCopy(SourceToTargetCopy {
            common: common(&[0, 1]),
            source_idx: 0,
            target_idx: 0,
        });
        let outcome = task.execute(&TaskContext {
            source_path: Some(source_path),
            target_path: Some(target_path.clone()),
            hash_file: None,
        });

        assert!(matches!(
            outcome,
            Err(BackupHelperError::TaskError(message))
                if message == "SourceToTargetCopy task requires the source path to be a directory!"
        ));
        assert!(!target_path.parent().unwrap().exists());
    }

    #[test]
    fn execute_target_verify_reports_matching_files() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        let target_path = testdir.join("target");
        fs::create_dir(&source_path).unwrap();
        fs::create_dir(&target_path).unwrap();
        fs::write(source_path.join("file.txt"), "content").unwrap();

        let source_hash = Task::SourceHash(SourceHash {
            common: common(&[0]),
            source_idx: 0,
            options: ChecksumOptions::default(),
        })
        .execute(&TaskContext {
            source_path: Some(source_path.clone()),
            target_path: None,
            hash_file: None,
        })
        .unwrap();
        let TaskOutcome::SourceHash { hash_file, .. } = source_hash else {
            panic!("SourceHash task returned the wrong outcome");
        };

        fs::copy(source_path.join("file.txt"), target_path.join("file.txt")).unwrap();
        fs::copy(
            &hash_file,
            target_path.join(hash_file.file_name().unwrap()),
        )
        .unwrap();

        let outcome = Task::TargetVerify(TargetVerify {
            common: common(&[1]),
            source_idx: 0,
            target_idx: 0,
        })
        .execute(&TaskContext {
            source_path: None,
            target_path: Some(target_path),
            hash_file: Some(hash_file),
        })
        .unwrap();

        let TaskOutcome::TargetVerify(verified) = outcome else {
            panic!("TargetVerify task returned the wrong outcome");
        };
        assert_eq!(verified.checked, 1);
        assert_eq!(verified.errors, 0);
        assert_eq!(verified.missing, 0);
        assert_eq!(verified.crc_errors, 0);
    }
}
