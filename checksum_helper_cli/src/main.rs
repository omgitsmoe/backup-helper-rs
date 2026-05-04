// TODO remove
#![allow(dead_code)]

use checksum_helper::pathmatcher::PathMatcherBuilder;
use checksum_helper::ChecksumHelperOptions;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

use std::io::prelude::*;

use checksum_helper::hash_type::HashType as HashTypeLib;

mod build;
mod incremental;
mod modify;
mod verify;

fn pause() {
    let mut stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    // We want the cursor to stay at the end of the line, so we print without a newline and flush manually.
    write!(stdout, "Press any key to continue...").unwrap();
    stdout.flush().unwrap();

    // Read a single byte and discard
    let _ = stdin.read(&mut [0u8]).unwrap();
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum HashType {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl From<HashType> for HashTypeLib {
    fn from(v: HashType) -> Self {
        match v {
            HashType::Md5 => HashTypeLib::Md5,
            HashType::Sha1 => HashTypeLib::Sha1,
            HashType::Sha256 => HashTypeLib::Sha256,
            HashType::Sha224 => HashTypeLib::Sha224,
            HashType::Sha384 => HashTypeLib::Sha384,
            HashType::Sha512 => HashTypeLib::Sha512,
            HashType::Sha3_224 => HashTypeLib::Sha3_224,
            HashType::Sha3_256 => HashTypeLib::Sha3_256,
            HashType::Sha3_384 => HashTypeLib::Sha3_384,
            HashType::Sha3_512 => HashTypeLib::Sha3_512,
        }
    }
}

#[derive(Args, Debug)]
pub struct HashMatcherArgs {
    /// Glob patterns for files that are allowed as checksum sources.
    ///
    /// If empty, all checksum files are included by default.
    #[arg(long, num_args = 1..)]
    hash_allow: Vec<String>,

    /// Glob patterns for checksum files that should be excluded.
    ///
    /// Block patterns always take precedence over allow patterns.
    #[arg(long, num_args = 1..)]
    hash_block: Vec<String>,
}

#[derive(Args, Debug)]
pub struct AllMatcherArgs {
    /// Glob patterns for files included in all file discovery operations.
    ///
    /// If empty, all files are included by default.
    #[arg(long, num_args = 1..)]
    all_allow: Vec<String>,

    /// Glob patterns for files excluded from all file discovery operations.
    ///
    /// Block patterns always take precedence over allow patterns.
    #[arg(long, num_args = 1..)]
    all_block: Vec<String>,
}

#[derive(Args)]
struct MostCurrentArgs {
    /// Maximum directory depth for discovering checksum files recursively.
    ///
    /// If not set, all subdirectories are searched.
    #[arg(long)]
    discover_hash_files_depth: Option<u32>,

    /// Whether files that do not exist on disk at the time of collection
    /// should be kept as part of the most current checksum file.
    ///
    /// By default: files that are missing will be removed.
    #[arg(long)]
    keep_deleted: bool,

    #[command(flatten)]
    hash_files_matcher: HashMatcherArgs,
}

impl MostCurrentArgs {
    fn apply(
        self,
        options: ChecksumHelperOptions,
    ) -> Result<ChecksumHelperOptions, Box<dyn std::error::Error>> {
        let mut matcher = PathMatcherBuilder::new();
        for allow in self.hash_files_matcher.hash_allow {
            matcher = matcher.allow(allow)?;
        }
        for block in self.hash_files_matcher.hash_block {
            matcher = matcher.block(block)?;
        }

        Ok(options
            .discover_hash_files_depth(self.discover_hash_files_depth)
            .most_current_filter_deleted(!self.keep_deleted)
            .hash_files_matcher(matcher.build()?))
    }

}

#[derive(Args, Debug)]
pub struct VerifyMatcherArgs {
    /// Glob patterns for files included in verify operations.
    ///
    /// If empty, all files are included by default.
    #[arg(long, num_args = 1..)]
    verify_allow: Vec<String>,

    /// Glob patterns for files excluded from verify operations.
    ///
    /// Block patterns always take precedence over allow patterns.
    #[arg(long, num_args = 1..)]
    verify_block: Vec<String>,
}

#[derive(Args)]
struct IncrementalArgs {
    /// Root directory that serves as the entry point for checksum generation.
    /// All files under this directory (recursively) will be included unless filtered.
    root: PathBuf,

    /// Which hash type will be used for generating new hashes.
    #[arg(long, default_value = "sha512")]
    hash_type: HashType,

    /// Whether to include unchanged files in the incremental checksum output file.
    #[arg(short, long)]
    include_unchanged: bool,

    /// Whether to skip a file based on the recorded modification time, if the
    /// modification time matches that of the file on disk.
    #[arg(short, long)]
    skip_unchanged: bool,

    /// If specified: the current checksum entries will be flushed to disk
    /// every `periodic_write_interval_seconds` seconds.
    /// Otherwise, the file will only be written after all entries have
    /// been processed.
    #[arg(long, value_name = "SECONDS")]
    periodic_write_interval_seconds: Option<u64>,

    #[command(flatten)]
    most_current: MostCurrentArgs,

    #[command(flatten)]
    all_files_matcher: AllMatcherArgs,
}

impl IncrementalArgs {
    fn apply(
        self,
        options: ChecksumHelperOptions,
    ) -> Result<ChecksumHelperOptions, Box<dyn std::error::Error>> {
        let mut matcher = PathMatcherBuilder::new();
        for allow in self.all_files_matcher.all_allow {
            matcher = matcher.allow(allow)?;
        }
        for block in self.all_files_matcher.all_block {
            matcher = matcher.block(block)?;
        }

        Ok(self.most_current.apply(options)?
            .hash_type(self.hash_type.into())
            .incremental_include_unchanged_files(self.include_unchanged)
            .incremental_skip_unchanged(self.skip_unchanged)
            .incremental_periodic_write_interval(
                self.periodic_write_interval_seconds
                    .map(std::time::Duration::from_secs),
            )
            .all_files_matcher(matcher.build()?))
    }

}

#[derive(Subcommand)]
enum VerifyCommand {
    /// Verify a single hash file
    File {
        /// Path to the checksum file to verify
        path: PathBuf,

        #[command(flatten)]
        verify_matcher: VerifyMatcherArgs,
    },

    /// Verify hashes in a directory
    Root {
        /// Root directory that serves as the entry point for checksum file discovery.
        ///
        /// All matched checksum files will be merged into one checksum file for
        /// the entire root directory.
        /// Then all found checksums will be verified.
        root: PathBuf,

        #[command(flatten)]
        most_current: MostCurrentArgs,

        #[command(flatten)]
        verify_matcher: VerifyMatcherArgs,
    },
}

#[derive(Subcommand)]
enum Commands {
    /// Creates an incremental checksum file.
    Incremental(IncrementalArgs),

    /// Creates one checksum file for the given root directory where all
    /// contained checksums are the most current hashes found in
    /// matched checksum files.
    Build {
        /// Root directory that serves as the entry point for checksum file discovery.
        ///
        /// All matched checksum files will be merged into one checksum file for
        /// the entire root directory.
        root: PathBuf,

        #[command(flatten)]
        most_current: MostCurrentArgs,
    },

    /// Check for files that don't have a checksum yet.
    Missing {
        /// Root directory that serves as the entry point for finding missing
        /// checksums for files.
        ///
        /// All matched checksum files will be merged into one checksum file for
        /// the entire root directory.
        /// Then this list will be compared to all files in the directory
        /// to determine the missing files that don't have a checksum.
        root: PathBuf,

        #[command(flatten)]
        most_current: MostCurrentArgs,
    },

    /// Generate checksums for files that don't have one yet.
    ///
    /// The root directory here serves as the entry point for generating missing
    /// checksums for files.
    ///
    /// All matched checksum files will be merged into one checksum file for
    /// the entire root directory.
    /// Then this list will be compared to all files in the directory
    /// to determine the missing files that don't have a checksum.
    Fill(IncrementalArgs),

    /// Move a hash file modifying the relative paths inside accordingly.
    Move {
        /// Path to the source checksum file.
        src: PathBuf,

        /// Path to the destination.
        dst: PathBuf,
    },

    /// Subcommands for all verify operations.
    #[command(subcommand)]
    Verify(VerifyCommand),
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Incremental(incremental_args) => incremental::incremental(incremental_args),
        Commands::Fill(incremental_args) => incremental::fill(incremental_args),
        Commands::Build { root, most_current } => build::build(&root, most_current),
        Commands::Missing { root, most_current } => build::missing(&root, most_current),
        Commands::Move { src, dst } => modify::move_hash_file(src, dst),
        Commands::Verify(verify_command) => match verify_command {
            VerifyCommand::File {
                path,
                verify_matcher,
            } => verify::verify_file(&path, verify_matcher),
            VerifyCommand::Root {
                root,
                most_current,
                verify_matcher,
            } => verify::verify_root(&root, most_current, verify_matcher),
        },
    };

    if let Err(err) = result {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
