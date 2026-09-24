use checksum_helper::{checksum_helper::IncrementalProgress, hashed_file::VerifyResult};
use chrono::Local;
use std::fmt;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

const MAX_PATH_PREFIX_LENGTH: usize = 120;

pub(crate) struct TaskLog {
    path: PathBuf,
    writer: BufWriter<File>,
    incremental: IncrementalCounts,
    verify: VerifySummary,
}

pub(crate) enum TaskLogType<'a> {
    SourceHash {
        root: &'a Path,
    },
    TargetVerify {
        root: &'a Path,
        checksum_file: &'a Path,
    },
}

#[derive(Default)]
struct IncrementalCounts {
    unchanged: u64,
    skipped: u64,
    changed: u64,
    corrupted: u64,
    older: u64,
    new: u64,
    removed: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct VerifySummary {
    ok: u64,
    missing: Vec<PathBuf>,
    mismatch: Vec<PathBuf>,
    mismatch_size: Vec<PathBuf>,
    corrupted: Vec<PathBuf>,
    outdated: Vec<PathBuf>,
}

impl VerifySummary {
    fn record(&mut self, path: &Path, result: VerifyResult) {
        match result {
            VerifyResult::Ok => self.ok += 1,
            VerifyResult::FileMissing(_) => self.missing.push(path.to_path_buf()),
            VerifyResult::Mismatch => self.mismatch.push(path.to_path_buf()),
            VerifyResult::MismatchSize => self.mismatch_size.push(path.to_path_buf()),
            VerifyResult::MismatchCorrupted => self.corrupted.push(path.to_path_buf()),
            VerifyResult::MismatchOutdatedHash => self.outdated.push(path.to_path_buf()),
        }
    }

    fn total(&self) -> u64 {
        self.ok
            + self.missing.len() as u64
            + self.mismatch.len() as u64
            + self.mismatch_size.len() as u64
            + self.corrupted.len() as u64
            + self.outdated.len() as u64
    }

    fn error_count(&self) -> u64 {
        self.missing.len() as u64
            + self.mismatch.len() as u64
            + self.mismatch_size.len() as u64
            + self.corrupted.len() as u64
    }

    fn all_error_count(&self) -> u64 {
        self.error_count() + self.outdated.len() as u64
    }

    fn checksum_error_count(&self) -> u64 {
        self.mismatch.len() as u64
            + self.mismatch_size.len() as u64
            + self.corrupted.len() as u64
            + self.outdated.len() as u64
    }

    fn has_errors(&self) -> bool {
        self.error_count() > 0
    }

    fn has_warnings(&self) -> bool {
        !self.outdated.is_empty()
    }
}

impl fmt::Display for VerifySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "\n========== VERIFY SUMMARY ==========")?;
        writeln!(
            f,
            "Total: {} | OK: {} | ERR: {} | WARN: {}",
            self.total(),
            self.ok,
            self.error_count(),
            self.outdated.len()
        )?;

        if self.has_errors() {
            writeln!(f, "❌ VERIFICATION FAILED\n")?;
            write_result_paths(f, "Missing files", "[ERR MISS  ]", &self.missing)?;
            write_result_paths(f, "Hash mismatches", "[ERR HASH  ]", &self.mismatch)?;
            write_result_paths(f, "Size mismatches", "[ERR SIZE  ]", &self.mismatch_size)?;
            write_result_paths(f, "Corrupted files", "[ERR CORR  ]", &self.corrupted)?;
        } else {
            writeln!(f, "✅ ALL FILES VERIFIED SUCCESSFULLY")?;
        }

        if self.has_warnings() {
            write_result_paths(f, "Outdated hashes", "[WARN STALE]", &self.outdated)?;
        }

        Ok(())
    }
}

fn write_result_paths<W: fmt::Write>(
    writer: &mut W,
    title: &str,
    status: &str,
    paths: &[PathBuf],
) -> fmt::Result {
    if paths.is_empty() {
        return Ok(());
    }

    writeln!(writer, "--- {title} ({}) ---", paths.len())?;
    for path in paths {
        writeln!(writer, "{status} {path:?}")?;
    }
    writeln!(writer)
}

impl TaskLog {
    pub(crate) fn new(
        log_type: TaskLogType<'_>,
        output_directory: Option<&Path>,
    ) -> io::Result<Self> {
        let (subject, task, header_label, header_path) = match log_type {
            TaskLogType::SourceHash { root } => (root, "SourceHash", "Root", root),
            TaskLogType::TargetVerify {
                root,
                checksum_file,
            } => (root, "TargetVerify", "Checksum file", checksum_file),
        };
        let prefix = sanitized_path_prefix(subject);
        let timestamp = Local::now().format("%Y-%m-%dT%H-%M-%S");
        let filename = format!("{prefix}_{task}_{timestamp}.log");
        let directory = match output_directory {
            Some(directory) => directory.to_path_buf(),
            None => std::env::current_dir()?,
        };
        let path = directory.join(filename);
        let writer = BufWriter::new(File::create(&path)?);

        let mut log = Self {
            path,
            writer,
            incremental: IncrementalCounts::default(),
            verify: VerifySummary::default(),
        };
        log.write_path_header(header_label, header_path)?;
        Ok(log)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn write_path_header(&mut self, label: &str, path: &Path) -> io::Result<()> {
        writeln!(self.writer, "{label}: {:?}", absolute_path(path)?)
    }

    pub(crate) fn report_incremental(&mut self, progress: &IncrementalProgress) -> io::Result<()> {
        let line = match progress {
            IncrementalProgress::FileMatch(path) => {
                self.incremental.unchanged += 1;
                format!("[OK   ] {:?} unchanged", path)
            }
            IncrementalProgress::FileUnchangedSkipped(path) => {
                self.incremental.skipped += 1;
                format!("[SKIP ] {:?} (unchanged, skipped)", path)
            }
            IncrementalProgress::FileChanged(path) => {
                self.incremental.changed += 1;
                format!("[CHG  ] {:?} modified", path)
            }
            IncrementalProgress::FileChangedCorrupted(path) => {
                self.incremental.corrupted += 1;
                format!("[CORR ] {:?} corrupted", path)
            }
            IncrementalProgress::FileChangedOlder(path) => {
                self.incremental.older += 1;
                format!("[OLD  ] {:?} local newer than hash", path)
            }
            IncrementalProgress::FileNew(path) => {
                self.incremental.new += 1;
                format!("[NEW  ] {:?}", path)
            }
            IncrementalProgress::FileRemoved(path) => {
                self.incremental.removed += 1;
                format!("[DEL  ] {:?}", path)
            }
            _ => return Ok(()),
        };

        writeln!(self.writer, "{line}")
    }

    pub(crate) fn report_verify(&mut self, path: &Path, result: VerifyResult) -> io::Result<()> {
        self.verify.record(path, result);
        let status = match result {
            VerifyResult::Ok => "[OK        ]",
            VerifyResult::FileMissing(_) => "[ERR MISS  ]",
            VerifyResult::Mismatch => "[ERR HASH  ]",
            VerifyResult::MismatchSize => "[ERR SIZE  ]",
            VerifyResult::MismatchCorrupted => "[ERR CORR  ]",
            VerifyResult::MismatchOutdatedHash => "[WARN STALE]",
        };

        writeln!(self.writer, "{status} {:?}", path)
    }

    pub(crate) fn finish_incremental(&mut self) -> io::Result<()> {
        writeln!(self.writer)?;
        writeln!(self.writer, "Summary:")?;
        writeln!(self.writer, "  unchanged: {}", self.incremental.unchanged)?;
        writeln!(self.writer, "  skipped: {}", self.incremental.skipped)?;
        writeln!(self.writer, "  changed: {}", self.incremental.changed)?;
        writeln!(self.writer, "  corrupted: {}", self.incremental.corrupted)?;
        writeln!(
            self.writer,
            "  local newer than hash: {}",
            self.incremental.older
        )?;
        writeln!(self.writer, "  new: {}", self.incremental.new)?;
        writeln!(self.writer, "  removed: {}", self.incremental.removed)?;
        writeln!(self.writer, "\nDone.")?;
        self.writer.flush()
    }

    pub(crate) fn finish_verify(&mut self) -> io::Result<()> {
        writeln!(self.writer)?;
        writeln!(self.writer, "Summary:")?;
        writeln!(self.writer, "  checked: {}", self.verify.total())?;
        writeln!(self.writer, "  errors: {}", self.verify.all_error_count())?;
        writeln!(self.writer, "  missing: {}", self.verify.missing.len())?;
        writeln!(
            self.writer,
            "  checksum errors: {}",
            self.verify.checksum_error_count()
        )?;
        writeln!(
            self.writer,
            "  outdated hashes: {}",
            self.verify.outdated.len()
        )?;
        // Keep the compact counts above while adding the detailed CLI-style report.
        write!(self.writer, "{}", self.verify)?;
        writeln!(self.writer, "\nDone.")?;
        self.writer.flush()
    }

    pub(crate) fn into_verify_summary(self) -> VerifySummary {
        self.verify
    }
}

fn sanitized_path_prefix(path: &Path) -> String {
    let mut result = String::new();
    let mut previous_was_separator = false;

    for character in path.to_string_lossy().chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '-') {
            result.push(character);
            previous_was_separator = false;
        } else if !previous_was_separator {
            result.push('_');
            previous_was_separator = true;
        }
    }

    let result = result.trim_matches('_');
    let start = result.len().saturating_sub(MAX_PATH_PREFIX_LENGTH);
    result[start..].to_owned()
}

fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

#[cfg(test)]
mod tests {
    use super::{TaskLog, TaskLogType, sanitized_path_prefix};
    use checksum_helper::{checksum_helper::IncrementalProgress, hashed_file::VerifyResult};
    use std::path::Path;
    use testdir::testdir;

    #[test]
    fn sanitizes_full_path_and_keeps_rightmost_characters() {
        let prefix = sanitized_path_prefix(Path::new("/mnt/backup source/source"));

        assert_eq!(prefix, "mnt_backup_source_source");
    }

    #[test]
    fn truncates_long_prefix_from_the_left() {
        let path = format!("/{}", "a".repeat(140));
        let prefix = sanitized_path_prefix(Path::new(&path));

        assert_eq!(prefix.len(), 120);
        assert!(prefix.chars().all(|character| character == 'a'));
    }

    #[test]
    fn reports_all_incremental_statuses_and_summary_counts() {
        let root = testdir!();
        let subject = root.join("source");
        let mut log =
            TaskLog::new(TaskLogType::SourceHash { root: &subject }, Some(&root)).unwrap();

        let statuses = [
            IncrementalProgress::FileMatch("unchanged.txt".into()),
            IncrementalProgress::FileUnchangedSkipped("skipped.txt".into()),
            IncrementalProgress::FileChanged("changed.txt".into()),
            IncrementalProgress::FileChangedCorrupted("corrupted.txt".into()),
            IncrementalProgress::FileChangedOlder("older.txt".into()),
            IncrementalProgress::FileNew("new.txt".into()),
            IncrementalProgress::FileRemoved("removed.txt".into()),
        ];
        for status in &statuses {
            log.report_incremental(status).unwrap();
        }
        log.report_incremental(&IncrementalProgress::Finished)
            .unwrap();
        log.finish_incremental().unwrap();

        let log_path = log.path().to_owned();
        drop(log);
        let contents = std::fs::read_to_string(log_path).unwrap();
        let expected_root = format!("Root: {:?}", subject);
        assert_eq!(contents.lines().next(), Some(expected_root.as_str()));

        for expected in [
            "[OK   ] \"unchanged.txt\" unchanged",
            "[SKIP ] \"skipped.txt\" (unchanged, skipped)",
            "[CHG  ] \"changed.txt\" modified",
            "[CORR ] \"corrupted.txt\" corrupted",
            "[OLD  ] \"older.txt\" local newer than hash",
            "[NEW  ] \"new.txt\"",
            "[DEL  ] \"removed.txt\"",
            "  unchanged: 1",
            "  skipped: 1",
            "  changed: 1",
            "  corrupted: 1",
            "  local newer than hash: 1",
            "  new: 1",
            "  removed: 1",
            "Done.",
        ] {
            assert!(
                contents.contains(expected),
                "missing {expected:?}:\n{contents}"
            );
        }
    }

    #[test]
    fn reports_all_verification_statuses_and_summary_counts() {
        let root = testdir!();
        let subject = root.join("target");
        let checksum_file = subject.join("checksums.cshd");
        let mut log = TaskLog::new(
            TaskLogType::TargetVerify {
                root: &subject,
                checksum_file: &checksum_file,
            },
            Some(&root),
        )
        .unwrap();

        for (path, result) in [
            ("ok.txt", VerifyResult::Ok),
            (
                "missing.txt",
                VerifyResult::FileMissing(std::io::ErrorKind::NotFound),
            ),
            ("hash.txt", VerifyResult::Mismatch),
            ("size.txt", VerifyResult::MismatchSize),
            ("corrupted.txt", VerifyResult::MismatchCorrupted),
            ("outdated.txt", VerifyResult::MismatchOutdatedHash),
        ] {
            log.report_verify(Path::new(path), result).unwrap();
        }
        log.finish_verify().unwrap();

        let log_path = log.path().to_owned();
        drop(log);
        let contents = std::fs::read_to_string(log_path).unwrap();
        let expected_checksum_file = format!("Checksum file: {:?}", checksum_file);
        assert_eq!(
            contents.lines().next(),
            Some(expected_checksum_file.as_str())
        );

        for expected in [
            "[OK        ] \"ok.txt\"",
            "[ERR MISS  ] \"missing.txt\"",
            "[ERR HASH  ] \"hash.txt\"",
            "[ERR SIZE  ] \"size.txt\"",
            "[ERR CORR  ] \"corrupted.txt\"",
            "[WARN STALE] \"outdated.txt\"",
            "  checked: 6",
            "  errors: 5",
            "  missing: 1",
            "  checksum errors: 4",
            "  outdated hashes: 1",
            "========== VERIFY SUMMARY ==========",
            "Total: 6 | OK: 1 | ERR: 4 | WARN: 1",
            "❌ VERIFICATION FAILED",
            "--- Missing files (1) ---",
            "--- Hash mismatches (1) ---",
            "--- Size mismatches (1) ---",
            "--- Corrupted files (1) ---",
            "--- Outdated hashes (1) ---",
            "Done.",
        ] {
            assert!(
                contents.contains(expected),
                "missing {expected:?}:\n{contents}"
            );
        }
    }

    #[test]
    fn reports_success_for_verification_without_errors() {
        let root = testdir!();
        let subject = root.join("target");
        let checksum_file = subject.join("checksums.cshd");
        let mut log = TaskLog::new(
            TaskLogType::TargetVerify {
                root: &subject,
                checksum_file: &checksum_file,
            },
            Some(&root),
        )
        .unwrap();

        log.report_verify(Path::new("ok.txt"), VerifyResult::Ok)
            .unwrap();
        log.finish_verify().unwrap();

        let log_path = log.path().to_owned();
        drop(log);
        let contents = std::fs::read_to_string(log_path).unwrap();
        assert!(contents.contains("Total: 1 | OK: 1 | ERR: 0 | WARN: 0"));
        assert!(contents.contains("✅ ALL FILES VERIFIED SUCCESSFULLY"));
        assert!(!contents.contains("❌ VERIFICATION FAILED"));
    }

    #[test]
    fn reports_outdated_hashes_as_warnings() {
        let root = testdir!();
        let subject = root.join("target");
        let checksum_file = subject.join("checksums.cshd");
        let mut log = TaskLog::new(
            TaskLogType::TargetVerify {
                root: &subject,
                checksum_file: &checksum_file,
            },
            Some(&root),
        )
        .unwrap();

        log.report_verify(
            Path::new("outdated.txt"),
            VerifyResult::MismatchOutdatedHash,
        )
        .unwrap();
        log.finish_verify().unwrap();

        let log_path = log.path().to_owned();
        drop(log);
        let contents = std::fs::read_to_string(log_path).unwrap();
        assert!(contents.contains("Total: 1 | OK: 0 | ERR: 0 | WARN: 1"));
        assert!(contents.contains("✅ ALL FILES VERIFIED SUCCESSFULLY"));
        assert!(contents.contains("--- Outdated hashes (1) ---"));
        assert!(contents.contains("[WARN STALE] \"outdated.txt\""));
    }
}
