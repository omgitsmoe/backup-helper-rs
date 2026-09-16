use checksum_helper::{checksum_helper::IncrementalProgress, hashed_file::VerifyResult};
use chrono::Local;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

const MAX_PATH_PREFIX_LENGTH: usize = 120;

pub(crate) struct TaskLog {
    path: PathBuf,
    writer: BufWriter<File>,
    incremental: IncrementalCounts,
    verify: VerifyCounts,
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

#[derive(Default)]
struct VerifyCounts {
    checked: u64,
    errors: u64,
    missing: u64,
    crc_errors: u64,
    stale: u64,
}

impl TaskLog {
    pub(crate) fn new(
        subject: &Path,
        task: &str,
        output_directory: Option<&Path>,
    ) -> io::Result<Self> {
        let prefix = sanitized_path_prefix(subject);
        let timestamp = Local::now().format("%Y-%m-%dT%H-%M-%S");
        let filename = format!("{prefix}_{task}_{timestamp}.log");
        let directory = match output_directory {
            Some(directory) => directory.to_path_buf(),
            None => std::env::current_dir()?,
        };
        let path = directory.join(filename);
        let writer = BufWriter::new(File::create(&path)?);

        Ok(Self {
            path,
            writer,
            incremental: IncrementalCounts::default(),
            verify: VerifyCounts::default(),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
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
        self.verify.checked += 1;
        let status = match result {
            VerifyResult::Ok => "[OK        ]",
            VerifyResult::FileMissing(_) => {
                self.verify.errors += 1;
                self.verify.missing += 1;
                "[ERR MISS  ]"
            }
            VerifyResult::Mismatch => {
                self.verify.errors += 1;
                self.verify.crc_errors += 1;
                "[ERR HASH  ]"
            }
            VerifyResult::MismatchSize => {
                self.verify.errors += 1;
                self.verify.crc_errors += 1;
                "[ERR SIZE  ]"
            }
            VerifyResult::MismatchCorrupted => {
                self.verify.errors += 1;
                self.verify.crc_errors += 1;
                "[ERR CORR  ]"
            }
            VerifyResult::MismatchOutdatedHash => {
                self.verify.errors += 1;
                self.verify.crc_errors += 1;
                self.verify.stale += 1;
                "[WARN STALE]"
            }
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
        writeln!(self.writer, "  checked: {}", self.verify.checked)?;
        writeln!(self.writer, "  errors: {}", self.verify.errors)?;
        writeln!(self.writer, "  missing: {}", self.verify.missing)?;
        writeln!(self.writer, "  checksum errors: {}", self.verify.crc_errors)?;
        writeln!(self.writer, "  outdated hashes: {}", self.verify.stale)?;
        writeln!(self.writer, "\nDone.")?;
        self.writer.flush()
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

#[cfg(test)]
mod tests {
    use super::{TaskLog, sanitized_path_prefix};
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
        let mut log = TaskLog::new(&subject, "SourceHash", Some(&root)).unwrap();

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
        let mut log = TaskLog::new(&subject, "TargetVerify", Some(&root)).unwrap();

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
            "Done.",
        ] {
            assert!(
                contents.contains(expected),
                "missing {expected:?}:\n{contents}"
            );
        }
    }
}
