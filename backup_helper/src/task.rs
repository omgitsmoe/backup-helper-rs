use std::path;

use checksum_helper::{ChecksumHelper, collection, hashed_file::{self, VerifyResult}};

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

        let mut ch = ChecksumHelper::new(
            ctx.source_path
                .as_ref()
                .expect("ctx must have a source path for SourceHash task")
        )?;
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

        if let Some(p) = target_path.parent() {
            std::fs::create_dir_all(p)?;
        }
        // TODO implement this properly
        let output = std::process::Command::new("cp")
            .args([
                "-r",
                &source_path.to_string_lossy(),
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
