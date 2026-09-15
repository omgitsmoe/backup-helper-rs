use std::sync::atomic::{AtomicUsize, Ordering};
use std::{path, sync::Arc};
use std::error::Error;

use checksum_helper::pathmatcher::PathMatcherError;
use checksum_helper::{ChecksumHelperError, collection::HashCollectionError};
use clap::{Args, Parser, Subcommand};

use crate::{backup_helper::BackupHelper, scheduler::{Scheduler, SchedulerShared}};

mod reconcile;
mod source;
mod target;
mod parse;
mod disks;
mod backup_helper;
mod task;
mod scheduler;
mod copy;

#[cfg(test)]
mod test_utils;

#[derive(Debug)]
enum BackupHelperError {
    IoError(String),
    InvalidConfig(String),
    InvalidState(String),
    ReconcileConflict(String),
    SchedulerError(String),
    ChecksumHelperError(ChecksumHelperError),
    CopyError(String),
    TaskError(String),
    Interrupted,
}

impl Error for BackupHelperError {
}

impl std::fmt::Display for BackupHelperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            BackupHelperError::IoError(e) => {
                write!(f, "IoError: {}", e)
            },
            BackupHelperError::InvalidConfig(e) => {
                write!(f, "InvalidConfig: {}", e)
            },
            BackupHelperError::InvalidState(e) => {
                write!(f, "InvalidState: {}", e)
            },
            BackupHelperError::ReconcileConflict(e) => {
                write!(f, "ReconcileConflict: {}", e)
            },
            BackupHelperError::SchedulerError(e) => {
                write!(f, "Scheduler: {}", e)
            },
            BackupHelperError::ChecksumHelperError(e) => {
                write!(f, "ChecksumHelper: {}", e)
            },
            BackupHelperError::CopyError(e) => {
                write!(f, "CopyError: {}", e)
            },
            BackupHelperError::TaskError(e) => {
                write!(f, "TaskError: {}", e)
            },
            BackupHelperError::Interrupted => {
                write!(f, "UserInterrupt")
            },
        }
    }
}

impl From<ChecksumHelperError> for BackupHelperError {
    fn from(value: ChecksumHelperError) -> Self {
        BackupHelperError::ChecksumHelperError(value)
    }
}

impl From<HashCollectionError> for BackupHelperError {
    fn from(value: HashCollectionError) -> Self {
        BackupHelperError::ChecksumHelperError(ChecksumHelperError::HashCollectionError(Box::new(
            value,
        )))
    }
}

impl From<PathMatcherError> for BackupHelperError {
    fn from(value: PathMatcherError) -> Self {
        BackupHelperError::InvalidConfig(value.to_string())
    }
}

impl From<std::io::Error> for BackupHelperError {
    fn from(value: std::io::Error) -> Self {
        BackupHelperError::IoError(value.to_string())
    }
}

impl From<kdl::KdlError> for BackupHelperError {
    fn from(value: kdl::KdlError) -> Self {
        let mut result = String::new();
        let mut first = true;
        for diag in value.diagnostics {
            if !first {
                result.push_str(". ");
            }
            result.push_str(&format!("{}", diag));
            first = false;
        }

        BackupHelperError::InvalidConfig(result)
    }
}

impl From<serde_json::Error> for BackupHelperError {
    fn from(value: serde_json::Error) -> Self {
        BackupHelperError::InvalidState(value.to_string())
    }
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Args)]
struct CommonArgs {
    #[arg(long, default_value = "state.json")]
    state: path::PathBuf,
}

#[derive(Args)]
struct ReconcileArgs {
    #[command(flatten)]
    common: CommonArgs,

    config: path::PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    Reconcile(ReconcileArgs),

    Start(CommonArgs),
}

fn main() -> std::result::Result<(), BackupHelperError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Reconcile(reconcile_args) => reconcile::reconcile(reconcile_args),
        Commands::Start(common_args) => start(common_args),
    }
}

fn start(args: CommonArgs) -> std::result::Result<(), BackupHelperError> {
    if !std::fs::exists(&args.state)? {
        return Err(BackupHelperError::IoError(format!(
            "state file does not exist: {:?}",
            args.state
        )));
    }

    let bh = BackupHelper::from_file(&args.state)?;
    let scheduler = Scheduler::new(SchedulerShared::new(bh)?);

    let cancellation_request_count = Arc::new(AtomicUsize::new(0));
    const EXIT_AFTER_COUNT_CANCEL_REQUESTS: usize = 3;
    let signal_scheduler = Arc::downgrade(&scheduler);
    ctrlc::set_handler(move || {
        let count = cancellation_request_count.fetch_add(1, Ordering::Relaxed) + 1;

        if count >= EXIT_AFTER_COUNT_CANCEL_REQUESTS {
            eprintln!("Forced exit...");
            std::process::exit(130);
        }

        if count == 1 {
            eprintln!("Cancellation requested; waiting for in-progress tasks...");
            if let Some(scheduler) = signal_scheduler.upgrade() {
                scheduler.request_cancel();
            }
        } else {
            eprintln!("Cancellation already requested; press Ctrl-C once more to force exit.");
        }
    })
    .expect("Error setting Ctrl-C handler");

    let result = scheduler::run(&scheduler);

    let bh = scheduler.close()?;
    bh.persist(&args.state)?;

    result
}
