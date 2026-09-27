use checksum_helper::{
    checksum_helper::VerifyRootProgress, collection::VerifyProgress, hashed_file::VerifyResult,
    ChecksumHelperOptions,
};

use crate::{progress::ProgressReporter, MostCurrentArgs, VerifyMatcherArgs};

use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct VerifySummary {
    pub ok: u64,
    pub missing: Vec<PathBuf>,
    pub mismatch: Vec<PathBuf>,
    pub mismatch_size: Vec<PathBuf>,
    pub corrupted: Vec<PathBuf>,
    pub outdated: Vec<PathBuf>,
}

#[derive(Debug, PartialEq)]
pub enum VerifySummaryResult {
    Success,
    WithWarnings,
    WithErrors,
}

impl std::fmt::Display for VerifySummaryResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifySummaryResult::Success => {
                write!(f, "Success! Verified all files!")
            }

            VerifySummaryResult::WithWarnings => {
                write!(f, "Warning: Verified all files with warnings!")
            }

            VerifySummaryResult::WithErrors => {
                write!(f, "Failure: There were verification failures!")
            }
        }
    }
}

impl VerifySummaryResult {
    pub fn as_result(&self) -> Result<(), String> {
        if *self == Self::Success {
            Ok(())
        } else {
            Err(format!("{}", self))
        }
    }
}

impl VerifySummary {
    pub fn record(&mut self, result: &VerifyResult, path: impl AsRef<Path>) {
        match result {
            VerifyResult::Ok => self.ok += 1,
            VerifyResult::FileMissing(_) => self.missing.push(path.as_ref().to_path_buf()),
            VerifyResult::Mismatch => self.mismatch.push(path.as_ref().to_path_buf()),
            VerifyResult::MismatchSize => self.mismatch_size.push(path.as_ref().to_path_buf()),
            VerifyResult::MismatchCorrupted => self.corrupted.push(path.as_ref().to_path_buf()),
            VerifyResult::MismatchOutdatedHash => self.outdated.push(path.as_ref().to_path_buf()),
        }
    }

    pub fn report(&self) -> VerifySummaryResult {
        println!("\n========== VERIFY SUMMARY ==========");

        let total = self.ok as usize
            + self.missing.len()
            + self.mismatch.len()
            + self.mismatch_size.len()
            + self.corrupted.len()
            + self.outdated.len();

        println!(
            "Total: {} | OK: {} | ERR: {} | WARN: {}",
            total,
            self.ok,
            self.missing.len()
                + self.mismatch.len()
                + self.mismatch_size.len()
                + self.corrupted.len(),
            self.outdated.len()
        );

        let has_errors = !self.missing.is_empty()
            || !self.mismatch.is_empty()
            || !self.mismatch_size.is_empty()
            || !self.corrupted.is_empty();
        let has_warnings = !self.outdated.is_empty();

        if !has_errors {
            println!("✅ ALL FILES VERIFIED SUCCESSFULLY");
        } else {
            println!("❌ VERIFICATION FAILED\n");

            if !self.missing.is_empty() {
                println!("--- Missing files ({}) ---", self.missing.len());
                for p in &self.missing {
                    println!("[ERR MISS  ] {:?}", p);
                }
                println!();
            }

            if !self.mismatch.is_empty() {
                println!("--- Hash mismatches ({}) ---", self.mismatch.len());
                for p in &self.mismatch {
                    println!("[ERR HASH  ] {:?}", p);
                }
                println!();
            }

            if !self.mismatch_size.is_empty() {
                println!("--- Size mismatches ({}) ---", self.mismatch_size.len());
                for p in &self.mismatch_size {
                    println!("[ERR SIZE  ] {:?}", p);
                }
                println!();
            }

            if !self.corrupted.is_empty() {
                println!("--- Corrupted files ({}) ---", self.corrupted.len());
                for p in &self.corrupted {
                    println!("[ERR CORR  ] {:?}", p);
                }
                println!();
            }
        }

        // Warnings separately (less alarming)
        if has_warnings {
            println!("--- Outdated hashes ({}) ---", self.outdated.len());
            for p in &self.outdated {
                println!("[WARN STALE] {:?}", p);
            }
        }

        match (has_errors, has_warnings) {
            (true, _) => VerifySummaryResult::WithErrors,
            (false, true) => VerifySummaryResult::WithWarnings,
            (false, false) => VerifySummaryResult::Success,
        }
    }
}

pub fn verify_root(
    root: impl AsRef<Path>,
    most_current_args: MostCurrentArgs,
    matcher: VerifyMatcherArgs,
    verbose: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::absolute(root)?;
    println!("Verifying root: {:?}", root);
    let options = most_current_args.apply(ChecksumHelperOptions::default())?;
    let mut ch = checksum_helper::ChecksumHelper::with_options(&root, options)?;
    let matcher = matcher.to_path_matcher()?;

    let mut reporter = ProgressReporter::new();
    reporter.set_verbose(verbose);
    let mut summary = VerifySummary::default();
    let verify_root = ch.verify_root(
        |path| matcher.is_match(path) && !matcher.is_excluded(path),
        |p| {
            if let VerifyRootProgress::Verify(VerifyProgress::Post(post)) = p {
                summary.record(&post.result, post.progress.relative_path);
            }
            reporter.report_verify_root(p);
        },
    );
    // The most current totals were already reported when verification started.
    reporter.finish();
    verify_root?;

    let result = summary.report();
    result.as_result()?;

    Ok(())
}

pub fn verify_file(
    path: impl AsRef<Path>,
    matcher: VerifyMatcherArgs,
    verbose: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = path.as_ref();

    if !std::fs::metadata(path)?.is_file() {
        return Err(format!("Expected a path to a hash file, got: {:?}", path).into());
    }

    // `verify latest` delegates here, so this is where the hash file it picked
    // is named, after the pick and before anything is verified.
    println!("Verifying hash file: {:?}", std::path::absolute(path)?);

    let root = if path.is_relative() {
        std::env::current_dir()?.join(path.parent().expect("checked above"))
    } else {
        path.parent().expect("checked above").to_path_buf()
    };

    let options = ChecksumHelperOptions::default();
    let mut ch = checksum_helper::ChecksumHelper::with_options(&root, options)?;
    let matcher = matcher.to_path_matcher()?;

    let mut reporter = ProgressReporter::new();
    reporter.set_verbose(verbose);
    let mut summary = VerifySummary::default();

    let hc = ch.read_collection(path)?;
    let verify = ch.verify(
        &hc,
        |path| matcher.is_match(path) && !matcher.is_excluded(path),
        |p| {
            if let VerifyProgress::Post(post) = p {
                summary.record(&post.result, post.progress.relative_path);
            }
            reporter.report_verify(p);
        },
    );
    reporter.finish();
    verify?;

    let result = summary.report();
    result.as_result()?;

    Ok(())
}

fn latest_hash_file(root_path: impl AsRef<Path>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    struct FileWithMTime {
        path: PathBuf,
        mtime: std::time::SystemTime,
    }
    let root_path = root_path.as_ref();
    let mut hash_files = vec![];
    for entry in std::fs::read_dir(root_path)? {
        let entry = entry.map_err(|e| {
            std::io::Error::new(e.kind(), format!("Error getting latest hash file: {}", e))
        })?;

        if !entry.file_type()?.is_file() {
            continue;
        }

        let path = entry.path();
        if !checksum_helper::is_hash_file_by_ext(&path) {
            continue;
        }

        hash_files.push(FileWithMTime {
            path,
            mtime: entry.metadata()?.modified()?,
        });
    }

    if hash_files.is_empty() {
        return Err(format!(
            "Expected at least one hash file, but found none in {:?}",
            root_path
        )
        .into());
    }

    // sort by descending mtime
    hash_files.sort_by(|a, b| b.mtime.cmp(&a.mtime));

    Ok(hash_files.first().expect("checked above").path.clone())
}

pub fn verify_latest(
    root_path: impl AsRef<Path>,
    matcher: VerifyMatcherArgs,
    verbose: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let root_path = root_path.as_ref();

    if !std::fs::metadata(root_path)?.is_dir() {
        return Err(format!("Expected a path to a directory, got: {:?}", root_path).into());
    }

    let latest_hash_file = latest_hash_file(root_path)?;
    verify_file(latest_hash_file, matcher, verbose)
}
