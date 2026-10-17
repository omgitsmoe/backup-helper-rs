use std::{
    fs::File,
    io::{BufWriter, Write},
    path,
};

use clap::{Args, Parser, Subcommand};

use restore_helper::{Mount, RestoreHelperError, Source};

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
    #[arg(default_value = "plan.json")]
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
}

fn main() -> std::result::Result<(), RestoreHelperError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Plan(plan_args) => plan(plan_args),
        Commands::Execute(execute_args) => Ok(()),
    }
}

fn plan(args: PlanArgs) -> Result<(), RestoreHelperError> {
    let plan = restore_helper::Plan::build(path::absolute(args.restore_manifest)?, args.sources)?;
    let mut writer = BufWriter::new(File::create_new(args.output)?);
    serde_json::to_writer_pretty(&mut writer, &plan)?;
    writeln!(writer)?;
    writer.flush()?;
    Ok(())
}
