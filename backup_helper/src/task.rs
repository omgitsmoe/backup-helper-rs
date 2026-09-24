use std::{path, sync::mpsc::Sender};

use checksum_helper::{
    ChecksumHelper, ChecksumHelperOptions, checksum_helper::IncrementalProgress, collection,
    hashed_file::VerifyResult,
};

use crate::{
    BackupHelperError,
    backup_helper::DiskHandle,
    copy,
    progress::{self, ProgressEvent},
    source::ChecksumOptions,
    target::VerifiedInfo,
    task_log::{TaskLog, TaskLogType},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Task {
    SourceHash(SourceHash),
    SourceToTargetCopy(SourceToTargetCopy),
    #[allow(dead_code)]
    SourceToTargetSync(SourceToTargetSync),
    TargetVerify(TargetVerify),
}

impl Task {
    pub fn description(&self, ctx: &TaskContext) -> String {
        match self {
            Task::SourceHash(_) => {
                format!("hash {}", ctx.source_path.as_deref().unwrap().display())
            }
            Task::SourceToTargetCopy(_) => format!(
                "copy {} -> {}",
                ctx.source_path.as_deref().unwrap().display(),
                ctx.target_path.as_deref().unwrap().display()
            ),
            Task::SourceToTargetSync(_) => format!(
                "sync {} -> {}",
                ctx.source_path.as_deref().unwrap().display(),
                ctx.target_path.as_deref().unwrap().display()
            ),
            Task::TargetVerify(_) => {
                format!("verify {}", ctx.target_path.as_deref().unwrap().display())
            }
        }
    }

    pub fn involved_disks(&self) -> &[DiskHandle] {
        match self {
            Task::SourceHash(t) => &t.common.involved_disks[..],
            Task::SourceToTargetCopy(t) => &t.common.involved_disks[..],
            Task::SourceToTargetSync(t) => &t.common.involved_disks[..],
            Task::TargetVerify(t) => &t.common.involved_disks[..],
        }
    }

    pub fn execute(
        &self,
        ctx: &TaskContext,
        progress: &Sender<ProgressEvent>,
    ) -> Result<TaskOutcome, BackupHelperError> {
        progress::report(
            progress,
            ProgressEvent::Started {
                task_id: ctx.task_id,
                description: self.description(ctx),
            },
        );

        let outcome = match self {
            Task::SourceHash(t) => t.execute(ctx, progress),
            Task::SourceToTargetCopy(t) => t.execute(ctx, progress),
            Task::SourceToTargetSync(t) => t.execute(ctx, progress),
            Task::TargetVerify(t) => t.execute(ctx, progress),
        };

        match &outcome {
            Ok(_) => progress::report(
                progress,
                ProgressEvent::Finished {
                    task_id: ctx.task_id,
                },
            ),
            Err(error) => progress::report(
                progress,
                ProgressEvent::Failed {
                    task_id: ctx.task_id,
                    message: error.to_string(),
                },
            ),
        }

        outcome
    }
}

pub(crate) trait TaskExecutor {
    fn execute(
        &self,
        ctx: &TaskContext,
        progress: &Sender<ProgressEvent>,
    ) -> Result<TaskOutcome, BackupHelperError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommonData {
    pub(crate) involved_disks: Box<[DiskHandle]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceHash {
    pub(crate) common: CommonData,
    pub(crate) source_idx: usize,
    pub(crate) options: ChecksumOptions,
}

impl TaskExecutor for SourceHash {
    fn execute(
        &self,
        ctx: &TaskContext,
        progress_tx: &Sender<ProgressEvent>,
    ) -> Result<TaskOutcome, BackupHelperError> {
        let source_path = ctx
            .source_path
            .as_ref()
            .expect("ctx must have a source path for SourceHash task");
        if !source_path.is_dir() {
            return Err(BackupHelperError::TaskError(String::from(
                "SourceHash task requires the source path to be a directory!",
            )));
        }

        let checksum_options = ctx
            .checksum_options
            .as_ref()
            .expect("ctx must have checksum_options for SourceHash task");
        let options = ChecksumHelperOptions::default()
            .incremental_skip_unchanged(true)
            .incremental_include_unchanged_files(true)
            .hash_type(checksum_options.hash_type.0)
            .hash_files_matcher(checksum_options.checksum_files.clone().try_into()?)
            .all_files_matcher(checksum_options.all_files.clone().try_into()?);
        let mut ch = ChecksumHelper::with_options(source_path, options)?;
        let mut log = TaskLog::new(
            TaskLogType::SourceHash { root: source_path },
            ctx.log_directory.as_deref(),
        )?;
        let mut log_error = None;
        let collection = ch.incremental(|progress| {
            if let Some(message) = incremental_progress_message(&progress) {
                progress::report(
                    progress_tx,
                    ProgressEvent::Updated {
                        task_id: ctx.task_id,
                        message,
                    },
                );
            }

            if log_error.is_none()
                && let Err(error) = log.report_incremental(&progress)
            {
                log_error = Some(error);
            }
        })?;

        if let Some(error) = log_error {
            return Err(error.into());
        }

        log.finish_incremental()?;
        // With a periodic write interval, `incremental` already wrote the
        // collection to disk; `write_collection` is then a no-op.
        ch.write_collection(&collection)?;

        Ok(TaskOutcome::SourceHash {
            hash_file: collection.full_path()?,
            hash_log_file: log.path().to_path_buf(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceToTargetCopy {
    pub(crate) common: CommonData,
    pub(crate) source_idx: usize,
    pub(crate) target_idx: usize,
    pub(crate) copy_policy: copy::CopyPolicy,
}

impl TaskExecutor for SourceToTargetCopy {
    fn execute(
        &self,
        ctx: &TaskContext,
        progress_tx: &Sender<ProgressEvent>,
    ) -> Result<TaskOutcome, BackupHelperError> {
        let source_path = ctx
            .source_path
            .as_ref()
            .expect("ctx must have a source_path for SourceToTargetCopy task");
        let target_path = ctx
            .target_path
            .as_ref()
            .expect("ctx must have a target_path for SourceToTargetCopy task");

        match copy::is_directory(source_path) {
            Ok(true) => {}
            Ok(false) => {
                return Err(BackupHelperError::TaskError(String::from(
                    "SourceToTargetCopy task requires the source path to be a directory!",
                )));
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && !copy::is_retryable_io_error(&error) =>
            {
                return Err(BackupHelperError::TaskError(String::from(
                    "SourceToTargetCopy task requires the source path to be a directory!",
                )));
            }
            Err(error) => {
                return Err(BackupHelperError::CopyError(format!(
                    "Failed to get source path metadata: {error}"
                )));
            }
        }

        copy::copy_tree(source_path, target_path, self.copy_policy, |progress| {
            let action = match progress.action {
                copy::CopyAction::Copied => "copied",
                copy::CopyAction::SkippedUnchanged => "skipped unchanged",
                copy::CopyAction::Directory => "directory ready",
                copy::CopyAction::Ignored => "ignored",
            };
            progress::report(
                progress_tx,
                ProgressEvent::Updated {
                    task_id: ctx.task_id,
                    message: format!("{} {:?}", action, progress.relative_path),
                },
            );
        })?;

        Ok(TaskOutcome::SourceToTargetCopy)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceToTargetSync {
    pub(crate) common: CommonData,
    pub(crate) source_idx: usize,
    pub(crate) target_idx: usize,
}

impl TaskExecutor for SourceToTargetSync {
    fn execute(
        &self,
        _ctx: &TaskContext,
        _progress_tx: &Sender<ProgressEvent>,
    ) -> Result<TaskOutcome, BackupHelperError> {
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
    fn execute(
        &self,
        ctx: &TaskContext,
        progress_tx: &Sender<ProgressEvent>,
    ) -> Result<TaskOutcome, BackupHelperError> {
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
        let mut log = TaskLog::new(
            TaskLogType::TargetVerify {
                root: target_path,
                checksum_file: &target_collection_path,
            },
            ctx.log_directory.as_deref(),
        )?;
        let mut log_error = None;
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
                    let path = verify_progress_post
                        .progress
                        .tree_root
                        .join(verify_progress_post.progress.relative_path);

                    progress::report(
                        progress_tx,
                        ProgressEvent::Updated {
                            task_id: ctx.task_id,
                            message: verify_progress_message(&path, verify_progress_post.result),
                        },
                    );

                    if log_error.is_none()
                        && let Err(error) = log.report_verify(&path, verify_progress_post.result)
                    {
                        log_error = Some(error);
                    }

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

        if let Some(error) = log_error {
            return Err(error.into());
        }

        log.finish_verify()?;
        verified.log_file = log.path().to_path_buf();

        Ok(TaskOutcome::TargetVerify(verified))
    }
}

fn incremental_progress_message(progress: &IncrementalProgress) -> Option<String> {
    match progress {
        IncrementalProgress::FileMatch(path) => Some(format!("[OK   ] {:?} unchanged", path)),
        IncrementalProgress::FileUnchangedSkipped(path) => {
            Some(format!("[SKIP ] {:?} (unchanged, skipped)", path))
        }
        IncrementalProgress::FileChanged(path) => Some(format!("[CHG  ] {:?} modified", path)),
        IncrementalProgress::FileChangedCorrupted(path) => {
            Some(format!("[CORR ] {:?} corrupted", path))
        }
        IncrementalProgress::FileChangedOlder(path) => {
            Some(format!("[OLD  ] {:?} local newer than hash", path))
        }
        IncrementalProgress::FileNew(path) => Some(format!("[NEW  ] {:?}", path)),
        IncrementalProgress::FileRemoved(path) => Some(format!("[DEL  ] {:?}", path)),
        _ => None,
    }
}

fn verify_progress_message(path: &path::Path, result: VerifyResult) -> String {
    let status = match result {
        VerifyResult::Ok => "[OK        ]",
        VerifyResult::FileMissing(_) => "[ERR MISS  ]",
        VerifyResult::Mismatch => "[ERR HASH  ]",
        VerifyResult::MismatchSize => "[ERR SIZE  ]",
        VerifyResult::MismatchCorrupted => "[ERR CORR  ]",
        VerifyResult::MismatchOutdatedHash => "[WARN STALE]",
    };

    format!("{status} {:?}", path)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskContext {
    pub(crate) task_id: usize,
    pub(crate) source_path: Option<path::PathBuf>,
    pub(crate) target_path: Option<path::PathBuf>,
    pub(crate) hash_file: Option<path::PathBuf>,
    pub(crate) checksum_options: Option<ChecksumOptions>,
    pub(crate) log_directory: Option<path::PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TaskOutcome {
    SourceHash {
        hash_file: path::PathBuf,
        hash_log_file: path::PathBuf,
    },
    SourceToTargetCopy,
    #[allow(dead_code)]
    SourceToTargetSync,
    TargetVerify(VerifiedInfo),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::HashType;
    use std::fs;
    use std::panic::AssertUnwindSafe;
    use std::path::Path;
    use std::sync::mpsc;
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

    fn hash_source(source_path: &Path) -> path::PathBuf {
        hash_source_with_options(source_path, ChecksumOptions::default())
    }

    fn hash_source_with_options(
        source_path: &Path,
        checksum_options: ChecksumOptions,
    ) -> path::PathBuf {
        let progress = progress_sender();
        let outcome = Task::SourceHash(SourceHash {
            common: common(&[0]),
            source_idx: 0,
            options: checksum_options.clone(),
        })
        .execute(
            &TaskContext {
                task_id: 0,
                source_path: Some(source_path.to_path_buf()),
                target_path: None,
                hash_file: None,
                checksum_options: Some(checksum_options),
                log_directory: source_path.parent().map(path::Path::to_path_buf),
            },
            &progress,
        )
        .unwrap();

        let TaskOutcome::SourceHash {
            hash_file,
            hash_log_file,
        } = outcome
        else {
            panic!("SourceHash task returned the wrong outcome");
        };

        assert_log_contains(
            &hash_log_file,
            &[
                &format!("Root: {:?}", source_path),
                "[NEW  ]",
                "Summary:",
                "Done.",
            ],
        );

        hash_file
    }

    fn verify_target(target_path: &Path, hash_file: &Path) -> VerifiedInfo {
        let progress = progress_sender();
        let outcome = Task::TargetVerify(TargetVerify {
            common: common(&[1]),
            source_idx: 0,
            target_idx: 0,
        })
        .execute(
            &TaskContext {
                task_id: 0,
                source_path: None,
                target_path: Some(target_path.to_path_buf()),
                hash_file: Some(hash_file.to_path_buf()),
                checksum_options: None,
                log_directory: target_path.parent().map(path::Path::to_path_buf),
            },
            &progress,
        )
        .unwrap();

        let TaskOutcome::TargetVerify(verified) = outcome else {
            panic!("TargetVerify task returned the wrong outcome");
        };
        assert_log_contains(
            &verified.log_file,
            &[
                &format!(
                    "Checksum file: {:?}",
                    target_path.join(hash_file.file_name().unwrap())
                ),
                "Summary:",
                "Done.",
            ],
        );
        verified
    }

    fn copy_collection(hash_file: &Path, target_path: &Path) {
        fs::copy(hash_file, target_path.join(hash_file.file_name().unwrap())).unwrap();
    }

    fn assert_log_contains(log_file: &Path, expected: &[&str]) {
        assert!(log_file.is_file(), "log file does not exist: {log_file:?}");
        let contents = fs::read_to_string(log_file).unwrap();

        for expected in expected {
            assert!(
                contents.contains(expected),
                "log file {log_file:?} did not contain {expected:?}:\n{contents}"
            );
        }
    }

    fn progress_sender() -> Sender<ProgressEvent> {
        let (sender, _receiver) = mpsc::channel();
        sender
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
                copy_policy: copy::CopyPolicy::SkipUnchanged,
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
        let progress = progress_sender();
        let outcome = task
            .execute(
                &TaskContext {
                    task_id: 0,
                    source_path: Some(source_path.clone()),
                    target_path: None,
                    hash_file: None,
                    checksum_options: Some(ChecksumOptions::default()),
                    log_directory: Some(testdir.clone()),
                },
                &progress,
            )
            .unwrap();

        let TaskOutcome::SourceHash {
            hash_file,
            hash_log_file,
        } = outcome
        else {
            panic!("SourceHash task returned the wrong outcome");
        };
        assert!(hash_file.is_file());
        assert_log_contains(
            &hash_log_file,
            &[
                &format!("Root: {:?}", source_path),
                "[NEW  ]",
                "file.txt",
                "Summary:",
                "  new: 1",
                "Done.",
            ],
        );
    }

    #[test]
    fn execute_source_hash_reports_progress_lifecycle() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        fs::create_dir(&source_path).unwrap();
        fs::write(source_path.join("file.txt"), "content").unwrap();

        let task = Task::SourceHash(SourceHash {
            common: common(&[0]),
            source_idx: 0,
            options: ChecksumOptions::default(),
        });
        let (progress, events) = mpsc::channel();

        task.execute(
            &TaskContext {
                task_id: 10,
                source_path: Some(source_path.clone()),
                target_path: None,
                hash_file: None,
                checksum_options: Some(ChecksumOptions::default()),
                log_directory: Some(testdir),
            },
            &progress,
        )
        .unwrap();

        let events: Vec<_> = events.try_iter().collect();
        assert!(matches!(
            events.first(),
            Some(ProgressEvent::Started { task_id: 10, description })
                if description.contains("hash") && description.contains("source")
        ));
        assert!(events.iter().any(|event| matches!(
            event,
            ProgressEvent::Updated { task_id: 10, message }
                if message.contains("[NEW  ]") && message.contains("file.txt")
        )));
        assert!(matches!(
            events.last(),
            Some(ProgressEvent::Finished { task_id: 10 })
        ));
    }

    #[test]
    fn execute_source_hash_uses_configured_hash_type() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        fs::create_dir(&source_path).unwrap();
        fs::write(source_path.join("file.txt"), "content").unwrap();

        let mut checksum_options = ChecksumOptions::default();
        checksum_options.hash_type = HashType::try_from("sha256").unwrap();
        let hash_file = hash_source_with_options(&source_path, checksum_options);
        let collection = fs::read_to_string(hash_file).unwrap();

        assert!(collection.lines().any(|line| line.contains(",sha256,")));
    }

    #[test]
    fn execute_source_hash_uses_configured_file_globs() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        fs::create_dir(&source_path).unwrap();
        fs::write(source_path.join("included.txt"), "included").unwrap();
        fs::write(source_path.join("excluded.bin"), "excluded").unwrap();

        let mut checksum_options = ChecksumOptions::default();
        checksum_options.all_files.block = vec!["*.bin".into()];
        let hash_file = hash_source_with_options(&source_path, checksum_options);
        let collection = fs::read_to_string(hash_file).unwrap();
        let entries: Vec<_> = collection
            .lines()
            .filter(|line| !line.starts_with('#'))
            .collect();

        assert_eq!(entries.len(), 1);
        assert!(entries[0].ends_with(" included.txt"));
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
        let progress = progress_sender();
        let outcome = task.execute(
            &TaskContext {
                task_id: 0,
                source_path: Some(source_path),
                target_path: None,
                hash_file: None,
                checksum_options: Some(ChecksumOptions::default()),
                log_directory: None,
            },
            &progress,
        );

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
        fs::write(target_path.join("existing.txt"), "existing content").unwrap();
        fs::create_dir(source_path.join("nested")).unwrap();
        fs::write(source_path.join("file.txt"), "content").unwrap();
        fs::write(source_path.join(".hidden"), "hidden content").unwrap();
        fs::write(source_path.join("nested/file.txt"), "nested content").unwrap();

        let task = Task::SourceToTargetCopy(SourceToTargetCopy {
            common: common(&[0, 1]),
            source_idx: 0,
            target_idx: 0,
            copy_policy: copy::CopyPolicy::SkipUnchanged,
        });
        let (progress, progress_events) = mpsc::channel();
        let outcome = task.execute(
            &TaskContext {
                task_id: 0,
                source_path: Some(source_path),
                target_path: Some(target_path.clone()),
                hash_file: None,
                checksum_options: None,
                log_directory: None,
            },
            &progress,
        );
        assert!(matches!(outcome, Ok(TaskOutcome::SourceToTargetCopy)));

        let events: Vec<_> = progress_events.try_iter().collect();
        assert!(events.iter().any(|event| matches!(
            event,
            ProgressEvent::Updated { task_id: 0, message } if message.contains("file.txt")
        )));

        assert_eq!(
            fs::read_to_string(target_path.join("file.txt")).unwrap(),
            "content"
        );
        assert_eq!(
            fs::read_to_string(target_path.join(".hidden")).unwrap(),
            "hidden content"
        );
        assert_eq!(
            fs::read_to_string(target_path.join("nested/file.txt")).unwrap(),
            "nested content"
        );
        assert_eq!(
            fs::read_to_string(target_path.join("existing.txt")).unwrap(),
            "existing content"
        );
        assert!(!target_path.join("source").exists());
    }

    #[test]
    fn execute_copy_creates_missing_destination_parent() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        let target_path = testdir.join("missing/parents/target");
        fs::create_dir(&source_path).unwrap();
        fs::write(source_path.join("file.txt"), "content").unwrap();

        let task = Task::SourceToTargetCopy(SourceToTargetCopy {
            common: common(&[0, 1]),
            source_idx: 0,
            target_idx: 0,
            copy_policy: copy::CopyPolicy::SkipUnchanged,
        });
        let progress = progress_sender();
        let outcome = task.execute(
            &TaskContext {
                task_id: 0,
                source_path: Some(source_path),
                target_path: Some(target_path.clone()),
                hash_file: None,
                checksum_options: None,
                log_directory: None,
            },
            &progress,
        );

        assert!(matches!(outcome, Ok(TaskOutcome::SourceToTargetCopy)));
        assert_eq!(
            fs::read_to_string(target_path.join("file.txt")).unwrap(),
            "content"
        );
    }

    #[test]
    fn execute_copy_reports_progress_lifecycle() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        let target_path = testdir.join("target");
        fs::create_dir(&source_path).unwrap();
        fs::write(source_path.join("file.txt"), "content").unwrap();

        let task = Task::SourceToTargetCopy(SourceToTargetCopy {
            common: common(&[0, 1]),
            source_idx: 0,
            target_idx: 0,
            copy_policy: copy::CopyPolicy::SkipUnchanged,
        });
        let (progress, events) = mpsc::channel();

        task.execute(
            &TaskContext {
                task_id: 11,
                source_path: Some(source_path.clone()),
                target_path: Some(target_path.clone()),
                hash_file: None,
                checksum_options: None,
                log_directory: None,
            },
            &progress,
        )
        .unwrap();

        let events: Vec<_> = events.try_iter().collect();
        assert!(matches!(
            events.first(),
            Some(ProgressEvent::Started { task_id: 11, description })
                if description.contains("copy")
                    && description.contains(&*source_path.to_string_lossy())
                    && description.contains(&*target_path.to_string_lossy())
        ));
        assert!(events.iter().any(|event| matches!(
            event,
            ProgressEvent::Updated { task_id: 11, message }
                if message.contains("copied") && message.contains("file.txt")
        )));
        assert!(matches!(
            events.last(),
            Some(ProgressEvent::Finished { task_id: 11 })
        ));
    }

    #[test]
    fn execute_copy_returns_copy_error_for_destination_file() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        let target_path = testdir.join("target");
        fs::create_dir(&source_path).unwrap();
        fs::write(source_path.join("file.txt"), "content").unwrap();
        fs::write(&target_path, "not a directory").unwrap();

        let task = Task::SourceToTargetCopy(SourceToTargetCopy {
            common: common(&[0, 1]),
            source_idx: 0,
            target_idx: 0,
            copy_policy: copy::CopyPolicy::SkipUnchanged,
        });
        let progress = progress_sender();
        let outcome = task.execute(
            &TaskContext {
                task_id: 0,
                source_path: Some(source_path),
                target_path: Some(target_path),
                hash_file: None,
                checksum_options: None,
                log_directory: None,
            },
            &progress,
        );

        assert!(matches!(outcome, Err(BackupHelperError::CopyError(_))));
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
            copy_policy: copy::CopyPolicy::SkipUnchanged,
        });
        let progress = progress_sender();
        let outcome = task.execute(
            &TaskContext {
                task_id: 0,
                source_path: Some(source_path),
                target_path: Some(target_path.clone()),
                hash_file: None,
                checksum_options: None,
                log_directory: None,
            },
            &progress,
        );

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

        let hash_file = hash_source(&source_path);

        fs::copy(source_path.join("file.txt"), target_path.join("file.txt")).unwrap();
        copy_collection(&hash_file, &target_path);

        let verified = verify_target(&target_path, &hash_file);
        assert_eq!(verified.checked, 1);
        assert_eq!(verified.errors, 0);
        assert_eq!(verified.missing, 0);
        assert_eq!(verified.crc_errors, 0);
        assert_log_contains(
            &verified.log_file,
            &[
                &format!(
                    "Checksum file: {:?}",
                    target_path.join(hash_file.file_name().unwrap())
                ),
                "[OK        ]",
                "file.txt",
                "checked: 1",
                "errors: 0",
                "Total: 1 | OK: 1 | ERR: 0 | WARN: 0",
                "✅ ALL FILES VERIFIED SUCCESSFULLY",
            ],
        );
    }

    #[test]
    fn execute_target_verify_reports_progress_lifecycle() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        let target_path = testdir.join("target");
        fs::create_dir(&source_path).unwrap();
        fs::create_dir(&target_path).unwrap();
        fs::write(source_path.join("file.txt"), "content").unwrap();

        let hash_file = hash_source(&source_path);
        fs::copy(source_path.join("file.txt"), target_path.join("file.txt")).unwrap();
        copy_collection(&hash_file, &target_path);

        let task = Task::TargetVerify(TargetVerify {
            common: common(&[1]),
            source_idx: 0,
            target_idx: 0,
        });
        let (progress, events) = mpsc::channel();

        task.execute(
            &TaskContext {
                task_id: 12,
                source_path: Some(source_path),
                target_path: Some(target_path.clone()),
                hash_file: Some(hash_file),
                checksum_options: None,
                log_directory: Some(testdir),
            },
            &progress,
        )
        .unwrap();

        let events: Vec<_> = events.try_iter().collect();
        assert!(matches!(
            events.first(),
            Some(ProgressEvent::Started { task_id: 12, description })
                if description.contains("verify") && description.contains("target")
        ));
        assert!(events.iter().any(|event| matches!(
            event,
            ProgressEvent::Updated { task_id: 12, message }
                if message.contains("[OK        ]") && message.contains("file.txt")
        )));
        assert!(matches!(
            events.last(),
            Some(ProgressEvent::Finished { task_id: 12 })
        ));
    }

    #[test]
    fn execute_sync_reports_started_before_not_implemented_panic() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        let target_path = testdir.join("target");
        fs::create_dir(&source_path).unwrap();
        fs::create_dir(&target_path).unwrap();

        let task = Task::SourceToTargetSync(SourceToTargetSync {
            common: common(&[0, 1]),
            source_idx: 0,
            target_idx: 0,
        });
        let (progress, events) = mpsc::channel();

        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            task.execute(
                &TaskContext {
                    task_id: 13,
                    source_path: Some(source_path),
                    target_path: Some(target_path),
                    hash_file: None,
                    checksum_options: None,
                    log_directory: None,
                },
                &progress,
            )
        }));

        assert!(result.is_err());
        assert!(matches!(
            events.try_iter().next(),
            Some(ProgressEvent::Started { task_id: 13, description })
                if description.contains("sync")
        ));
    }

    #[test]
    fn execute_target_verify_reports_missing_file() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        let target_path = testdir.join("target");
        fs::create_dir(&source_path).unwrap();
        fs::create_dir(&target_path).unwrap();
        fs::write(source_path.join("present.txt"), "present").unwrap();
        fs::write(source_path.join("missing.txt"), "missing").unwrap();

        let hash_file = hash_source(&source_path);
        fs::copy(
            source_path.join("present.txt"),
            target_path.join("present.txt"),
        )
        .unwrap();
        copy_collection(&hash_file, &target_path);

        let verified = verify_target(&target_path, &hash_file);
        assert_eq!(verified.checked, 2);
        assert_eq!(verified.errors, 1);
        assert_eq!(verified.missing, 1);
        assert_eq!(verified.crc_errors, 0);
        assert_log_contains(
            &verified.log_file,
            &["[ERR MISS  ]", "missing.txt", "checked: 2", "missing: 1"],
        );
    }

    #[test]
    fn execute_target_verify_reports_size_mismatch() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        let target_path = testdir.join("target");
        fs::create_dir(&source_path).unwrap();
        fs::create_dir(&target_path).unwrap();
        fs::write(source_path.join("file.txt"), "source content").unwrap();

        let hash_file = hash_source(&source_path);
        fs::write(target_path.join("file.txt"), "different").unwrap();
        copy_collection(&hash_file, &target_path);

        let verified = verify_target(&target_path, &hash_file);
        assert_eq!(verified.checked, 1);
        assert_eq!(verified.errors, 1);
        assert_eq!(verified.missing, 0);
        assert_eq!(verified.crc_errors, 1);
        assert_log_contains(
            &verified.log_file,
            &[
                "[ERR SIZE  ]",
                "file.txt",
                "errors: 1",
                "checksum errors: 1",
            ],
        );
    }

    #[test]
    fn execute_target_verify_reports_hash_mismatch() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        let target_path = testdir.join("target");
        fs::create_dir(&source_path).unwrap();
        fs::create_dir(&target_path).unwrap();
        fs::write(source_path.join("file.txt"), "source content").unwrap();

        let hash_file = hash_source(&source_path);
        fs::write(target_path.join("file.txt"), "target content").unwrap();
        filetime::set_file_mtime(
            target_path.join("file.txt"),
            filetime::FileTime::from_unix_time(1, 0),
        )
        .unwrap();
        copy_collection(&hash_file, &target_path);

        let verified = verify_target(&target_path, &hash_file);
        assert_eq!(verified.checked, 1);
        assert_eq!(verified.errors, 1);
        assert_eq!(verified.missing, 0);
        assert_eq!(verified.crc_errors, 1);
        assert_log_contains(
            &verified.log_file,
            &[
                "[WARN STALE]",
                "file.txt",
                "errors: 1",
                "checksum errors: 1",
            ],
        );
    }

    #[test]
    fn execute_target_verify_aggregates_multiple_failures() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        let target_path = testdir.join("target");
        fs::create_dir(&source_path).unwrap();
        fs::create_dir(&target_path).unwrap();
        fs::write(source_path.join("matching.txt"), "matching").unwrap();
        fs::write(source_path.join("missing.txt"), "missing").unwrap();
        fs::write(source_path.join("size.txt"), "source size").unwrap();
        fs::write(source_path.join("hash.txt"), "source hash").unwrap();

        let hash_file = hash_source(&source_path);
        fs::write(target_path.join("matching.txt"), "matching").unwrap();
        fs::write(target_path.join("size.txt"), "different size").unwrap();
        fs::write(target_path.join("hash.txt"), "target hash").unwrap();
        copy_collection(&hash_file, &target_path);

        let verified = verify_target(&target_path, &hash_file);
        assert_eq!(verified.checked, 4);
        assert_eq!(verified.errors, 3);
        assert_eq!(verified.missing, 1);
        assert_eq!(verified.crc_errors, 2);
        assert_log_contains(
            &verified.log_file,
            &[
                "[OK        ]",
                "[ERR MISS  ]",
                "[ERR SIZE  ]",
                "[WARN STALE]",
                "checked: 4",
                "errors: 3",
                "missing: 1",
                "checksum errors: 2",
                "Total: 4 | OK: 1 | ERR: 2 | WARN: 1",
                "❌ VERIFICATION FAILED",
                "--- Missing files (1) ---",
                "--- Size mismatches (1) ---",
                "--- Outdated hashes (1) ---",
            ],
        );
    }

    #[test]
    fn execute_target_verify_uses_source_hash_filename_on_target() {
        let testdir = testdir!();
        let source_path = testdir.join("source");
        let target_path = testdir.join("target");
        fs::create_dir(&source_path).unwrap();
        fs::create_dir(&target_path).unwrap();
        fs::write(source_path.join("file.txt"), "content").unwrap();

        let generated_hash_file = hash_source(&source_path);
        fs::copy(source_path.join("file.txt"), target_path.join("file.txt")).unwrap();
        let source_hash_file = testdir.join("manifest.cshd");
        fs::copy(
            &generated_hash_file,
            target_path.join(source_hash_file.file_name().unwrap()),
        )
        .unwrap();

        let verified = verify_target(&target_path, &source_hash_file);
        assert_eq!(verified.checked, 1);
        assert_eq!(verified.errors, 0);
        assert_eq!(verified.missing, 0);
        assert_eq!(verified.crc_errors, 0);
    }
}
