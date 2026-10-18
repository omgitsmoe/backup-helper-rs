use std::{fs, io, path::Path};

use checksum_helper::hashed_file::mtimes_match;
use filetime::FileTime;

use crate::{Plan, RestoreHelperError, plan::RestoreFile};

#[derive(Debug)]
pub enum CheckOutcome {
    Matching,
    Missing,
    NotRegularFile,
    MetadataMismatch {
        size: Option<(u64, u64)>,
        mtime: Option<(FileTime, FileTime)>,
    },
    IoError(io::Error),
}

#[derive(Debug)]
pub struct CheckProgress<'a> {
    pub target: &'a Path,
    pub outcome: CheckOutcome,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CheckSummary {
    pub matching: usize,
    pub missing: usize,
    pub mismatched: usize,
    pub not_regular: usize,
    pub errors: usize,
}

impl CheckSummary {
    pub fn has_problems(&self) -> bool {
        self.missing + self.mismatched + self.not_regular + self.errors > 0
    }
}

impl Plan {
    pub fn check(&self, target: impl AsRef<Path>) -> Result<CheckSummary, RestoreHelperError> {
        self.check_with_progress(target, |_| Ok(()))
    }

    pub fn check_with_progress(
        &self,
        target: impl AsRef<Path>,
        mut progress: impl FnMut(CheckProgress<'_>) -> io::Result<()>,
    ) -> Result<CheckSummary, RestoreHelperError> {
        let mut summary = CheckSummary::default();
        for file in &self.files {
            let target = target.as_ref().join(&file.relative_path);
            let outcome = match check_file(&target, file) {
                Ok(outcome) => outcome,
                Err(error) => CheckOutcome::IoError(error),
            };
            match &outcome {
                CheckOutcome::Matching => summary.matching += 1,
                CheckOutcome::Missing => summary.missing += 1,
                CheckOutcome::NotRegularFile => summary.not_regular += 1,
                CheckOutcome::MetadataMismatch { .. } => summary.mismatched += 1,
                CheckOutcome::IoError(_) => summary.errors += 1,
            }
            progress(CheckProgress {
                target: &target,
                outcome,
            })?;
        }
        Ok(summary)
    }
}

fn check_file(target: &Path, file: &RestoreFile) -> io::Result<CheckOutcome> {
    let metadata = match fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(CheckOutcome::Missing),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() {
        return Ok(CheckOutcome::NotRegularFile);
    }
    let size = file
        .size
        .filter(|size| *size != metadata.len())
        .map(|size| (size, metadata.len()));
    let mtime = if let Some(expected) = file.mtime {
        let actual = FileTime::from(metadata.modified()?);
        (!mtimes_match(Some(expected), Some(actual))).then_some((expected, actual))
    } else {
        None
    };
    if size.is_some() || mtime.is_some() {
        Ok(CheckOutcome::MetadataMismatch { size, mtime })
    } else {
        Ok(CheckOutcome::Matching)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use testdir::testdir;

    fn file(name: &str, size: Option<u64>, mtime: Option<FileTime>) -> Value {
        json!({
            "hash_type": "sha256", "hash": "00", "content": 0,
            "relative_path": name, "size": size,
            "mtime": mtime.map(|time| json!({
                "seconds": time.unix_seconds(), "nanoseconds": time.nanoseconds()
            }))
        })
    }

    fn plan(files: Vec<Value>) -> Plan {
        serde_json::from_value(json!({
            "source_manifests": [],
            "contents": [{"key": {"hash_type": "sha256", "hash": "00"}, "sources": []}],
            "files": files
        }))
        .unwrap()
    }

    #[test]
    fn checks_all_files_without_sources_and_compares_optional_fields_independently() {
        let root = testdir!();
        for name in ["size-only", "mtime-only", "both", "no-metadata", "matching"] {
            fs::write(root.join(name), b"abc").unwrap();
        }
        let actual = FileTime::from_unix_time(100, 0);
        for name in ["mtime-only", "both", "matching"] {
            filetime::set_file_mtime(root.join(name), actual).unwrap();
        }
        fs::create_dir(root.join("directory")).unwrap();
        let expected = FileTime::from_unix_time(101, 0);
        let plan = plan(vec![
            file("missing", None, None),
            file("size-only", Some(4), None),
            file("mtime-only", None, Some(expected)),
            file("both", Some(5), Some(expected)),
            file("directory", None, None),
            file("no-metadata", None, None),
            file("matching", Some(3), Some(actual)),
        ]);
        let mut outcomes = vec![];
        let summary = plan
            .check_with_progress(&root, |event| {
                outcomes.push(event.outcome);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            summary,
            CheckSummary {
                matching: 2,
                missing: 1,
                mismatched: 3,
                not_regular: 1,
                errors: 0
            }
        );
        assert!(summary.has_problems());
        assert!(matches!(outcomes[0], CheckOutcome::Missing));
        assert!(matches!(
            outcomes[1],
            CheckOutcome::MetadataMismatch {
                size: Some((4, 3)),
                mtime: None
            }
        ));
        assert!(
            matches!(outcomes[2], CheckOutcome::MetadataMismatch { size: None, mtime: Some((e, a)) } if e == expected && a == actual)
        );
        assert!(matches!(
            outcomes[3],
            CheckOutcome::MetadataMismatch {
                size: Some((5, 3)),
                mtime: Some(_)
            }
        ));
        assert!(matches!(outcomes[4], CheckOutcome::NotRegularFile));
        assert_eq!(fs::read(root.join("both")).unwrap(), b"abc");
        assert!(!root.join("missing").exists());
    }

    #[test]
    fn mtime_tolerance_is_inclusive_and_symmetric_across_second_boundary() {
        let root = testdir!();
        fs::write(root.join("file"), b"abc").unwrap();
        let actual = FileTime::from_unix_time(100, 0);
        filetime::set_file_mtime(root.join("file"), actual).unwrap();
        for (seconds, nanos, matches) in [
            (100, 0, true),
            (100, 999, true),
            (100, 1000, true),
            (100, 1001, false),
            (99, 999_999_001, true),
            (99, 999_999_000, true),
            (99, 999_998_999, false),
        ] {
            let plan = plan(vec![file(
                "file",
                None,
                Some(FileTime::from_unix_time(seconds, nanos)),
            )]);
            let summary = plan.check(&root).unwrap();
            assert_eq!(summary.matching == 1, matches, "{seconds}.{nanos:09}");
            assert_eq!(summary.has_problems(), !matches);
        }
    }

    #[test]
    fn nonexistent_target_reports_every_file_without_creating_it() {
        let target = testdir!().join("absent");
        let summary = plan(vec![file("a", None, None), file("dir/b", None, None)])
            .check(&target)
            .unwrap();
        assert_eq!(summary.missing, 2);
        assert!(!target.exists());
    }

    #[test]
    fn callback_errors_stop_checking() {
        let error = plan(vec![file("missing", None, None)])
            .check_with_progress(testdir!(), |_| Err(io::ErrorKind::BrokenPipe.into()))
            .unwrap_err();
        assert!(matches!(
            error,
            RestoreHelperError::IoError(io::ErrorKind::BrokenPipe)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn reports_symlinks_and_continues_after_metadata_errors() {
        let root = testdir!();
        fs::write(root.join("regular"), b"abc").unwrap();
        std::os::unix::fs::symlink("regular", root.join("link")).unwrap();
        std::os::unix::fs::symlink("absent", root.join("dangling")).unwrap();
        let plan = plan(vec![
            file("regular/child", None, None),
            file("link", None, None),
            file("dangling", None, None),
            file("regular", Some(3), None),
        ]);
        let summary = plan.check(&root).unwrap();
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.not_regular, 2);
        assert_eq!(summary.matching, 1);
    }
}
