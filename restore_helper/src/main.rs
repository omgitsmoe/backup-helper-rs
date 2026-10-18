use std::{
    fs::File,
    io::{self, BufWriter, IsTerminal, Write},
    path,
};

use clap::{Args, Parser, Subcommand};

use restore_helper::{ExistingFilePolicy, Mount, RestoreHelperError, RestoreState, Source};

mod progress;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,
}

fn parse_source(value: &str) -> Result<Source, String> {
    let (id, path) = value.split_once('=').ok_or("expected NAME=PATH")?;

    if id.is_empty() || path.is_empty() {
        return Err("source name and manifest path must not be empty".into());
    }

    let manifest = path::absolute(path).map_err(|e| e.to_string())?;
    Source::new(id, manifest).map_err(|e| e.to_string())
}

#[derive(Args)]
struct PlanArgs {
    /// Path to the manifest of the file tree to restore (in .cshd format).
    restore_manifest: path::PathBuf,

    /// Pairs of `name=path`, which assigns a name to a source manifest file.
    #[arg(
        long = "source",
        value_name = "NAME=PATH",
        value_parser = parse_source,
        required = true,
    )]
    sources: Vec<Source>,

    // Path to the output file, which contains the restore plan.
    #[arg(long = "output", default_value = "plan.json")]
    output: path::PathBuf,
}

fn parse_mount(value: &str) -> Result<Mount, String> {
    let (id, path) = value.split_once('=').ok_or("expected NAME=PATH")?;

    if id.is_empty() || path.is_empty() {
        return Err("source name and mount path must not be empty".into());
    }

    Mount::new(id, path::PathBuf::from(path)).map_err(|e| e.to_string())
}

#[derive(Args)]
struct ExecuteArgs {
    plan: path::PathBuf,

    #[arg(
        long,
        value_enum,
        help = "How to handle files that already exist at the target"
    )]
    existing_file_policy: ExistingFilePolicy,

    #[arg(required = true, long = "target")]
    target: path::PathBuf,

    /// Pairs of `name=mount-path`, which assigns a mount path
    /// to a source manifest file name.
    #[arg(
        long = "mount",
        value_name = "NAME=PATH",
        value_parser = parse_mount,
        required = true,
    )]
    sources: Vec<Mount>,
}

#[derive(Subcommand)]
enum Commands {
    Plan(PlanArgs),
    Execute(ExecuteArgs),
    /// Check destination file existence and available planned metadata (not checksums).
    Check(CheckArgs),
}

#[derive(Args)]
struct CheckArgs {
    plan: path::PathBuf,
    #[arg(long)]
    target: path::PathBuf,
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> std::result::Result<(), RestoreHelperError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Plan(plan_args) => plan(plan_args, cli.verbose),
        Commands::Execute(execute_args) => execute(execute_args),
        Commands::Check(args) => check(args),
    }
}

fn check(args: CheckArgs) -> Result<(), RestoreHelperError> {
    use restore_helper::CheckOutcome;

    let plan = restore_helper::Plan::from_json(args.plan)?;
    let mut out = BufWriter::new(io::stdout().lock());
    let summary = plan.check_with_progress(args.target, |event| {
        match event.outcome {
            CheckOutcome::Matching => {}
            CheckOutcome::Missing => writeln!(out, "MISSING {}", event.target.display())?,
            CheckOutcome::NotRegularFile => {
                writeln!(out, "NOT A REGULAR FILE {}", event.target.display())?
            }
            CheckOutcome::IoError(error) => {
                writeln!(out, "ERROR {}: {error}", event.target.display())?
            }
            CheckOutcome::MetadataMismatch { size, mtime } => {
                write!(out, "MISMATCH {}", event.target.display())?;
                if let Some((expected, actual)) = size {
                    write!(out, " size: expected {expected}, actual {actual}")?;
                }
                if let Some((expected, actual)) = mtime {
                    write!(
                        out,
                        " mtime: expected {}.{:09}, actual {}.{:09}",
                        expected.unix_seconds(),
                        expected.nanoseconds(),
                        actual.unix_seconds(),
                        actual.nanoseconds()
                    )?;
                }
                writeln!(out)?;
            }
        }
        Ok(())
    })?;
    writeln!(
        out,
        "Matching: {}, missing: {}, mismatched: {}, not regular: {}, errors: {}",
        summary.matching, summary.missing, summary.mismatched, summary.not_regular, summary.errors
    )?;
    out.flush()?;
    if summary.has_problems() {
        return Err(RestoreHelperError::CheckFailed);
    }
    Ok(())
}

fn execute(args: ExecuteArgs) -> Result<(), RestoreHelperError> {
    let mut state = RestoreState::from_json(args.plan, args.sources, args.target)?;
    let stdout = io::stdout();
    let interactive = stdout.is_terminal();
    let width = if interactive {
        crossterm::terminal::size()?.0 as usize
    } else {
        0
    };
    let mut reporter = progress::ProgressReporter::new(stdout.lock(), interactive, width);
    let result =
        state.execute_with_progress(args.existing_file_policy, |event| reporter.report(event));
    let summary = reporter.finish(result.is_err());
    result?;
    summary?;
    Ok(())
}

fn plan(args: PlanArgs, verbosity: u8) -> Result<(), RestoreHelperError> {
    let plan = restore_helper::Plan::build(path::absolute(args.restore_manifest)?, args.sources)?;
    let mut writer = BufWriter::new(File::create_new(&args.output).map_err(|source| {
        RestoreHelperError::PathIoError {
            operation: "create restore plan",
            path: args.output.clone(),
            source,
        }
    })?);
    serde_json::to_writer_pretty(&mut writer, &plan)?;
    writeln!(writer)?;
    writer.flush()?;

    let no_source = plan.content_without_source();
    eprintln!(
        "WARN: Files without matching content source: {}",
        no_source.len()
    );

    if verbosity > 0 && !no_source.is_empty() {
        let stderr = io::stderr();
        let mut out = io::BufWriter::new(stderr.lock());

        for path in &no_source {
            writeln!(out, "  {}", path.display()).unwrap();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_parses_existing_file_policies() {
        for (value, expected) in [
            ("skip-always", ExistingFilePolicy::SkipAlways),
            ("skip-same-metadata", ExistingFilePolicy::SkipSameMetadata),
            ("overwrite", ExistingFilePolicy::Overwrite),
        ] {
            let cli = Cli::try_parse_from([
                "restore_helper",
                "execute",
                "plan.json",
                "--target",
                "restored",
                "--mount",
                "archive=/mnt/archive",
                "--existing-file-policy",
                value,
            ])
            .unwrap();
            let Commands::Execute(args) = cli.command else {
                panic!("expected execute command");
            };
            assert_eq!(args.existing_file_policy, expected);
        }
    }

    #[test]
    fn execute_requires_existing_file_policy() {
        let error = Cli::try_parse_from([
            "restore_helper",
            "execute",
            "plan.json",
            "--target",
            "restored",
            "--mount",
            "archive=/mnt/archive",
        ])
        .err()
        .unwrap();

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        assert!(error.to_string().contains("--existing-file-policy"));
    }

    #[test]
    fn execute_rejects_invalid_existing_file_policy() {
        let error = Cli::try_parse_from([
            "restore_helper",
            "execute",
            "plan.json",
            "--target",
            "restored",
            "--mount",
            "archive=/mnt/archive",
            "--existing-file-policy",
            "invalid",
        ])
        .err()
        .unwrap();

        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
    }
}
