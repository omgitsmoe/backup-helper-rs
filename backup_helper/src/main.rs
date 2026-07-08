use std::path;
use std::error::Error;

use clap::{Args, Parser, Subcommand};

mod reconcile;

#[derive(Debug)]
enum BackupHelperError {
    IoError(String),
    InvalidConfig(String),
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
        }
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

    Start,
}

fn main() -> std::result::Result<(), BackupHelperError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Reconcile(reconcile_args) => reconcile::reconcile(reconcile_args),
        Commands::Start => todo!(),
    }
}
