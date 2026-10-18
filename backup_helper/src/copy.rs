use std::{
    collections::BTreeSet,
    fmt, fs, io,
    path::{Path, PathBuf},
};

pub(crate) use copy_helper::is_retryable_io_error;
use copy_helper::{
    PreservedMetadata, preserved_metadata, retry_io, sweep_stale_temps, sync_parent_directory,
};
use filetime::FileTime;

use crate::BackupHelperError;

pub(crate) fn is_directory(path: &Path) -> io::Result<bool> {
    Ok(retry_io(|| fs::metadata(path))?.is_dir())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyPolicy {
    SkipUnchanged,
    ForceOverwrite,
}

pub fn copy_tree(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: CopyPolicy,
    mut on_progress: impl FnMut(CopyProgress),
) -> Result<CopyStats, BackupHelperError> {
    let source = source.as_ref();
    let destination = destination.as_ref();

    let source_meta = retry_io(|| fs::metadata(source)).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound && !is_retryable_io_error(&e) {
            BackupHelperError::CopyError(format!("Source at {:?} does not exist: {}", source, e))
        } else {
            BackupHelperError::CopyError(format!("Failed to get source path metadata: {}", e))
        }
    })?;

    if !source_meta.is_dir() {
        return Err(BackupHelperError::CopyError(format!(
            "Source at {:?} is not a directory!",
            source
        )));
    }

    reject_overlapping_paths(source, destination)?;
    retry_io(|| fs::create_dir_all(destination))
        .map_err(|error| copy_io_error("create destination directory", destination, error))?;
    reject_destination_symlink_components(destination, destination)?;
    sweep_stale_temps(destination);

    let iter =
        WalkTree::new(source).map_err(|error| copy_io_error("walk source", source, error))?;
    let mut published_directories = BTreeSet::new();
    let mut stats = CopyStats::default();
    copy_tree_entries(
        source,
        destination,
        iter,
        policy,
        &mut on_progress,
        &mut published_directories,
        &mut stats,
    )?;

    // A rename is only durable once its directory is flushed. Batched per
    // directory rather than per file: a whole-tree copy would otherwise pay one
    // extra round trip per file.
    for directory in &published_directories {
        sync_parent_directory(directory)
            .map_err(|error| copy_io_error("flush destination directory", directory, error))?;
    }

    Ok(stats)
}

const BYTE_UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];

/// A byte count in the largest unit that keeps it readable: exact below 1 KiB,
/// one decimal above it, because a status line has no room for more.
pub fn format_bytes(bytes: u64) -> String {
    const UNIT: f64 = 1024.0;

    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= UNIT && unit < BYTE_UNITS.len() - 1 {
        value /= UNIT;
        unit += 1;
    }

    if unit == 0 {
        format!("{bytes} {}", BYTE_UNITS[unit])
    } else {
        format!("{value:.1} {}", BYTE_UNITS[unit])
    }
}

/// Running totals of a copy, assembled from what the walk already knows.
///
/// Every number here is one the copy had anyway: the byte count `fs::copy`
/// returns, and the source length the skip test has already compared against the
/// destination. Counting therefore costs no extra metadata call, and there is no
/// pre-pass over the source to obtain a total up front.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CopyStats {
    pub entries: u64,
    pub directories: u64,
    pub ignored: u64,
    pub copied_files: u64,
    pub copied_bytes: u64,
    pub skipped_files: u64,
    pub skipped_bytes: u64,
}

impl CopyStats {
    fn record(&mut self, action: CopyAction, bytes: u64) {
        self.entries += 1;
        match action {
            CopyAction::Copied => {
                self.copied_files += 1;
                self.copied_bytes += bytes;
            }
            CopyAction::SkippedUnchanged => {
                self.skipped_files += 1;
                self.skipped_bytes += bytes;
            }
            CopyAction::Directory => self.directories += 1,
            CopyAction::Ignored => self.ignored += 1,
        }
    }

    /// The compact form for an in-place status line. Directories and ignored
    /// entries are left out: they say nothing about how much of the tree is
    /// left, and the width is better spent on the rate.
    pub fn progress_line(&self) -> String {
        format!(
            "{} copied ({}) | {} skipped",
            self.copied_files,
            format_bytes(self.copied_bytes),
            self.skipped_files
        )
    }

    pub fn totals(&self) -> String {
        format!(
            "{} entries | {} copied ({}) | {} skipped ({}) | {} directories | {} ignored",
            self.entries,
            self.copied_files,
            format_bytes(self.copied_bytes),
            self.skipped_files,
            format_bytes(self.skipped_bytes),
            self.directories,
            self.ignored,
        )
    }
}

impl fmt::Display for CopyStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Totals: {}", self.totals())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyAction {
    Copied,
    SkippedUnchanged,
    Directory,
    Ignored,
}

/// One walked entry together with the totals as they stand after it, so a
/// consumer never has to accumulate events it might not receive in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyProgress {
    pub relative_path: PathBuf,
    pub action: CopyAction,
    pub stats: CopyStats,
}

/// What a single file cost. The byte count is the one `fs::copy` returned, or
/// the source length the skip test already matched against the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileOutcome {
    action: CopyAction,
    bytes: u64,
}

/// Whether a destination file can be left alone. Size and mtime are only a
/// sufficient test because a copy is published by renaming a complete temp file
/// onto the final name, so a file that exists there is never a partial transfer.
fn metadata_matches(
    source: &PreservedMetadata,
    source_len: u64,
    destination: &fs::Metadata,
) -> bool {
    destination.is_file()
        && source_len == destination.len()
        && destination
            .modified()
            .map(FileTime::from)
            .is_ok_and(|modified| modified == source.modified)
}

fn reject_destination_symlink_components(
    destination: &Path,
    destination_path: &Path,
) -> Result<(), BackupHelperError> {
    let relative = destination_path
        .strip_prefix(destination)
        .expect("destination path is outside the destination root");
    let mut current = destination.to_path_buf();

    if !destination_component_exists(&current)? {
        return Ok(());
    }

    for component in relative.components() {
        if matches!(component, std::path::Component::CurDir) {
            continue;
        }

        current.push(component.as_os_str());
        if !destination_component_exists(&current)? {
            break;
        }
    }

    Ok(())
}

fn destination_component_exists(path: &Path) -> Result<bool, BackupHelperError> {
    match retry_io(|| fs::symlink_metadata(path)) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(BackupHelperError::CopyError(
            format!("Destination path {:?} contains a symbolic link", path),
        )),
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound && !is_retryable_io_error(&error) => {
            Ok(false)
        }
        Err(error) => Err(copy_io_error("read destination metadata", path, error)),
    }
}

fn copy_file(
    source: &Path,
    destination: &Path,
    source_metadata: &PreservedMetadata,
    source_len: u64,
    source_is_file: bool,
    operation: &str,
    policy: CopyPolicy,
) -> Result<FileOutcome, BackupHelperError> {
    if source_is_file && policy == CopyPolicy::SkipUnchanged {
        let destination_metadata = match retry_io(|| fs::symlink_metadata(destination)) {
            Ok(metadata) => Some(metadata),
            Err(error)
                if error.kind() == io::ErrorKind::NotFound && !is_retryable_io_error(&error) =>
            {
                None
            }
            Err(error) => {
                return Err(copy_io_error(
                    "read destination metadata",
                    destination,
                    error,
                ));
            }
        };

        if let Some(destination_metadata) = destination_metadata
            && metadata_matches(source_metadata, source_len, &destination_metadata)
        {
            return Ok(FileOutcome {
                action: CopyAction::SkippedUnchanged,
                bytes: source_len,
            });
        }
    }

    let copied = copy_helper::copy_file(
        source,
        destination,
        source_metadata,
        source_is_file.then_some(source_len),
        operation,
    )
    .map_err(|error| BackupHelperError::CopyError(error.to_string()))?;

    Ok(FileOutcome {
        action: CopyAction::Copied,
        bytes: copied,
    })
}

fn copy_tree_entries(
    source: &Path,
    destination: &Path,
    mut iter: WalkTree,
    policy: CopyPolicy,
    on_progress: &mut impl FnMut(CopyProgress),
    published_directories: &mut BTreeSet<PathBuf>,
    stats: &mut CopyStats,
) -> Result<(), BackupHelperError> {
    for entry in iter.by_ref() {
        let source_path = entry.entry.path();
        let meta = retry_io(|| fs::symlink_metadata(&source_path))
            .map_err(|error| copy_io_error("read source metadata", &source_path, error))?;
        let relative = source_path
            .strip_prefix(source)
            .expect("walker yielded a path outside its root");
        let destination_path = destination.join(relative);
        reject_destination_symlink_components(destination, &destination_path)?;

        let FileOutcome { action, bytes } = if meta.is_dir() {
            retry_io(|| fs::create_dir_all(&destination_path)).map_err(|error| {
                copy_io_error("create destination directory", &destination_path, error)
            })?;
            // The walker yields every directory exactly once, so each one is swept
            // exactly once and never while it holds a file of our own.
            sweep_stale_temps(&destination_path);
            FileOutcome {
                action: CopyAction::Directory,
                bytes: 0,
            }
        } else if meta.file_type().is_symlink() {
            let target_meta = retry_io(|| fs::metadata(&source_path)).map_err(|error| {
                copy_io_error("read symlink target metadata", &source_path, error)
            })?;
            // Copy linked files as regular files, but do not follow linked directories.
            if target_meta.is_file() {
                let metadata = preserved_metadata(&target_meta).map_err(|error| {
                    copy_io_error("read symlink target metadata", &source_path, error)
                })?;
                copy_file(
                    &source_path,
                    &destination_path,
                    &metadata,
                    target_meta.len(),
                    true,
                    "copy symlink target",
                    policy,
                )?
            } else {
                FileOutcome {
                    action: CopyAction::Ignored,
                    bytes: 0,
                }
            }
        } else {
            let metadata = preserved_metadata(&meta)
                .map_err(|error| copy_io_error("read source metadata", &source_path, error))?;
            copy_file(
                &source_path,
                &destination_path,
                &metadata,
                meta.len(),
                meta.is_file(),
                "copy source file",
                policy,
            )?
        };

        stats.record(action, bytes);

        if action == CopyAction::Copied
            && let Some(directory) = destination_path.parent()
        {
            published_directories.insert(directory.to_path_buf());
        }

        on_progress(CopyProgress {
            relative_path: relative.to_path_buf(),
            action,
            stats: *stats,
        });
    }

    if let Some(err) = iter.error() {
        return Err(BackupHelperError::CopyError(format!(
            "Iteration error: {err}"
        )));
    }

    Ok(())
}

fn copy_io_error(operation: &str, path: &Path, error: io::Error) -> BackupHelperError {
    BackupHelperError::CopyError(format!("Failed to {operation} {:?}: {error}", path))
}

fn reject_overlapping_paths(source: &Path, destination: &Path) -> Result<(), BackupHelperError> {
    let source_canonical = canonicalize_for_comparison(source).map_err(|error| {
        BackupHelperError::CopyError(format!("Failed to resolve source {:?}: {}", source, error))
    })?;
    let destination_canonical = canonicalize_for_comparison(destination).map_err(|error| {
        BackupHelperError::CopyError(format!(
            "Failed to resolve destination {:?}: {}",
            destination, error
        ))
    })?;

    if source_canonical == destination_canonical {
        return Err(BackupHelperError::CopyError(format!(
            "Source and destination refer to the same path: {:?}",
            source
        )));
    }

    if destination_canonical.starts_with(&source_canonical) {
        return Err(BackupHelperError::CopyError(format!(
            "Destination {:?} is inside source {:?}",
            destination, source
        )));
    }

    if source_canonical.starts_with(&destination_canonical) {
        return Err(BackupHelperError::CopyError(format!(
            "Source {:?} is inside destination {:?}",
            source, destination
        )));
    }

    Ok(())
}

fn canonicalize_for_comparison(path: &Path) -> io::Result<PathBuf> {
    match retry_io(|| fs::metadata(path)) {
        Ok(_) => retry_io(|| fs::canonicalize(path)),
        Err(error)
            if !is_retryable_io_error(&error)
                && matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
        {
            let file_name = path
                .file_name()
                .expect("a non-empty path must have a file name");
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            let mut result = canonicalize_for_comparison(parent)?;
            result.push(file_name);
            Ok(result)
        }
        Err(error) => Err(error),
    }
}

fn entry_file_type(entry: &fs::DirEntry, path: &Path) -> io::Result<fs::FileType> {
    match entry.file_type() {
        Ok(file_type) => Ok(file_type),
        Err(error) if is_retryable_io_error(&error) => {
            retry_io(|| fs::symlink_metadata(path).map(|metadata| metadata.file_type()))
        }
        Err(error) => Err(error),
    }
}

pub struct WalkTree {
    stack: Vec<fs::ReadDir>,
    error: Option<io::Error>,
}

pub struct DirItem {
    pub entry: fs::DirEntry,
}

impl Iterator for WalkTree {
    type Item = DirItem;

    fn next(&mut self) -> Option<Self::Item> {
        if self.error.is_some() {
            return None;
        }

        while let Some(dir) = self.stack.last_mut() {
            // ReadDir is terminal after an iteration error, so propagate it
            // instead of retrying the exhausted handle.
            match dir.next() {
                Some(Ok(entry)) => {
                    let path = entry.path();
                    let file_type = match entry_file_type(&entry, &path) {
                        Ok(file_type) => file_type,
                        Err(error) => {
                            self.error = Some(error);
                            return None;
                        }
                    };

                    if file_type.is_dir() {
                        match retry_io(|| fs::read_dir(&path)) {
                            Ok(children) => self.stack.push(children),
                            Err(error) => {
                                self.error = Some(error);
                                return None;
                            }
                        }
                    }

                    return Some(DirItem { entry });
                }
                Some(Err(error)) => {
                    self.error = Some(error);
                    return None;
                }
                None => {
                    self.stack.pop();
                }
            }
        }

        None
    }
}

impl WalkTree {
    pub fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref();
        let children = retry_io(|| fs::read_dir(root))?;
        Ok(Self {
            stack: vec![children],
            error: None,
        })
    }

    pub fn error(&self) -> Option<&io::Error> {
        self.error.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use testdir::testdir;

    /// The names in a directory, sorted, so a leftover temp file shows up as an
    /// unexpected entry rather than as a wrong file count.
    fn entry_names(directory: &Path) -> Vec<OsString> {
        let mut names: Vec<OsString> = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn walk_tree_yields_nested_entries_depth_first() {
        let root = testdir!();
        fs::create_dir(root.join("nested")).unwrap();
        fs::write(root.join("nested/file.txt"), "content").unwrap();
        fs::write(root.join("file.txt"), "content").unwrap();

        let mut tree = WalkTree::new(&root).unwrap();
        let mut paths = Vec::new();
        for item in tree.by_ref() {
            paths.push(item.entry.path());
        }

        assert!(tree.error().is_none());
        assert_eq!(paths.len(), 3);
        assert!(paths.contains(&root.join("nested")));
        assert!(paths.contains(&root.join("nested/file.txt")));
        assert!(paths.contains(&root.join("file.txt")));
    }

    #[cfg(unix)]
    #[test]
    fn walk_tree_yields_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let root = testdir!();
        fs::create_dir(root.join("target")).unwrap();
        fs::write(root.join("target/file.txt"), "content").unwrap();
        symlink(root.join("target"), root.join("link")).unwrap();

        let mut tree = WalkTree::new(&root).unwrap();
        let paths: Vec<_> = tree.by_ref().map(|item| item.entry.path()).collect();

        assert!(tree.error().is_none());
        assert!(paths.contains(&root.join("link")));
        assert!(!paths.contains(&root.join("link/file.txt")));
    }

    #[test]
    fn walk_tree_reports_missing_root_from_constructor() {
        let root = testdir!().join("missing");

        let result = WalkTree::new(root);

        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::NotFound));
    }

    #[test]
    fn copy_tree_rejects_same_source_and_destination() {
        let root = testdir!();

        let result = copy_tree(&root, &root, CopyPolicy::SkipUnchanged, |_| {});

        assert!(
            matches!(result, Err(BackupHelperError::CopyError(message)) if message.contains("same path"))
        );
    }

    #[test]
    fn copy_tree_rejects_missing_source() {
        let root = testdir!();
        let source = root.join("missing-source");

        let result = copy_tree(
            &source,
            root.join("destination"),
            CopyPolicy::SkipUnchanged,
            |_| {},
        );

        assert!(matches!(
            result,
            Err(BackupHelperError::CopyError(message))
                if message.contains("does not exist")
        ));
    }

    #[test]
    fn copy_tree_rejects_file_source() {
        let root = testdir!();
        let source = root.join("source");
        fs::write(&source, "not a directory").unwrap();

        let result = copy_tree(
            &source,
            root.join("destination"),
            CopyPolicy::SkipUnchanged,
            |_| {},
        );

        assert!(matches!(
            result,
            Err(BackupHelperError::CopyError(message))
                if message.contains("is not a directory")
        ));
    }

    #[test]
    fn copy_tree_rejects_file_destination() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        fs::write(&destination, "not a directory").unwrap();

        let result = copy_tree(&source, &destination, CopyPolicy::SkipUnchanged, |_| {});

        assert!(matches!(
            result,
            Err(BackupHelperError::CopyError(message))
                if message.contains("create destination directory")
        ));
    }

    #[test]
    fn copy_tree_rejects_destination_below_file_parent() {
        let root = testdir!();
        let source = root.join("source");
        let file_parent = root.join("file-parent");
        let destination = file_parent.join("destination");
        fs::create_dir(&source).unwrap();
        fs::write(&file_parent, "not a directory").unwrap();

        let result = copy_tree(&source, &destination, CopyPolicy::SkipUnchanged, |_| {});

        assert!(matches!(
            result,
            Err(BackupHelperError::CopyError(message))
                if message.contains("create destination directory")
        ));
    }

    #[test]
    fn copy_tree_rejects_destination_inside_source() {
        let root = testdir!();
        let destination = root.join("nested/destination");

        let result = copy_tree(&root, &destination, CopyPolicy::SkipUnchanged, |_| {});

        assert!(
            matches!(result, Err(BackupHelperError::CopyError(message)) if message.contains("inside source"))
        );
        assert!(!destination.exists());
    }

    #[test]
    fn copy_tree_rejects_source_inside_destination() {
        let root = testdir!();
        let source = root.join("source");
        fs::create_dir(&source).unwrap();

        let result = copy_tree(&source, &root, CopyPolicy::SkipUnchanged, |_| {});

        assert!(
            matches!(result, Err(BackupHelperError::CopyError(message)) if message.contains("inside destination"))
        );
    }

    #[test]
    fn copy_tree_allows_sibling_directories() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();

        let result = copy_tree(&source, &destination, CopyPolicy::SkipUnchanged, |_| {});

        assert!(result.is_ok());
    }

    #[test]
    fn copy_tree_allows_existing_nested_destination_directory() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        let nested_source = source.join("nested");
        let nested_destination = destination.join("nested");
        fs::create_dir_all(&nested_source).unwrap();
        fs::create_dir_all(&nested_destination).unwrap();
        fs::write(nested_source.join("file.txt"), "content").unwrap();

        let result = copy_tree(&source, &destination, CopyPolicy::SkipUnchanged, |_| {});

        assert!(result.is_ok());
        assert_eq!(
            fs::read_to_string(nested_destination.join("file.txt")).unwrap(),
            "content"
        );
    }

    #[cfg(unix)]
    #[test]
    fn copy_tree_rejects_destination_symlink_components() {
        use std::os::unix::fs::symlink;

        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        let outside = root.join("outside");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(source.join("nested/file.txt"), "source").unwrap();
        fs::write(outside.join("file.txt"), "outside").unwrap();
        symlink(&outside, destination.join("nested")).unwrap();

        let result = copy_tree(&source, &destination, CopyPolicy::SkipUnchanged, |_| {});

        assert!(matches!(
            result,
            Err(BackupHelperError::CopyError(message))
                if message.contains("symbolic link")
        ));
        assert_eq!(
            fs::read_to_string(outside.join("file.txt")).unwrap(),
            "outside"
        );
    }

    #[cfg(unix)]
    #[test]
    fn copy_tree_rejects_destination_file_symlink() {
        use std::os::unix::fs::symlink;

        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        let outside = root.join("outside.txt");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(source.join("file.txt"), "source").unwrap();
        fs::write(&outside, "outside").unwrap();
        symlink(&outside, destination.join("file.txt")).unwrap();

        let result = copy_tree(&source, &destination, CopyPolicy::ForceOverwrite, |_| {});

        assert!(matches!(
            result,
            Err(BackupHelperError::CopyError(message))
                if message.contains("symbolic link")
        ));
        assert_eq!(fs::read_to_string(outside).unwrap(), "outside");
    }

    #[test]
    fn copy_tree_counts_what_it_copied_and_what_it_left_alone() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(source.join("copied.txt"), "12345").unwrap();
        fs::write(source.join("nested/copied.txt"), "123").unwrap();
        fs::write(source.join("unchanged.txt"), "1234567").unwrap();
        fs::write(destination.join("unchanged.txt"), "1234567").unwrap();

        let mtime = FileTime::from_unix_time(1_700_000_000, 123_000_000);
        filetime::set_file_mtime(source.join("unchanged.txt"), mtime).unwrap();
        filetime::set_file_mtime(destination.join("unchanged.txt"), mtime).unwrap();

        let stats = copy_tree(&source, &destination, CopyPolicy::SkipUnchanged, |_| {}).unwrap();

        assert_eq!(stats.copied_files, 2);
        assert_eq!(stats.copied_bytes, 8);
        assert_eq!(stats.skipped_files, 1);
        assert_eq!(stats.skipped_bytes, 7);
        assert_eq!(stats.directories, 1);
        assert_eq!(stats.ignored, 0);
        assert_eq!(stats.entries, 4);
    }

    #[test]
    fn copy_tree_reports_the_running_totals_with_every_entry() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("a.txt"), "12").unwrap();
        fs::write(source.join("b.txt"), "345").unwrap();

        let mut progress = Vec::new();
        let stats = copy_tree(&source, &destination, CopyPolicy::SkipUnchanged, |entry| {
            progress.push(entry)
        })
        .unwrap();

        // Each event carries the totals as they stand, so a consumer never has to
        // accumulate them and cannot fall a step behind.
        assert!(
            progress
                .windows(2)
                .all(|pair| pair[0].stats.entries < pair[1].stats.entries)
        );
        assert_eq!(progress.last().unwrap().stats, stats);
    }

    #[cfg(unix)]
    #[test]
    fn copy_tree_counts_a_skipped_symlink_to_a_directory_as_ignored() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir_all(source.join("directory")).unwrap();
        fs::create_dir(&destination).unwrap();
        std::os::unix::fs::symlink(source.join("directory"), source.join("link")).unwrap();

        let stats = copy_tree(&source, &destination, CopyPolicy::SkipUnchanged, |_| {}).unwrap();

        assert_eq!(stats.ignored, 1);
        assert_eq!(stats.copied_files, 0);
        assert_eq!(stats.directories, 1);
    }

    #[test]
    fn byte_counts_are_rendered_in_the_largest_readable_unit() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
        assert_eq!(format_bytes(2 * 1024u64.pow(4)), "2.0 TiB");
        // Past the largest unit the count keeps growing rather than wrapping.
        assert_eq!(format_bytes(1024 * 1024u64.pow(4)), "1024.0 TiB");
    }

    #[test]
    fn copy_tree_skips_file_when_size_and_mtime_match() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(source.join("file.txt"), "source").unwrap();
        fs::write(destination.join("file.txt"), "target").unwrap();

        let mtime = FileTime::from_unix_time(1_700_000_000, 123_000_000);
        filetime::set_file_mtime(source.join("file.txt"), mtime).unwrap();
        filetime::set_file_mtime(destination.join("file.txt"), mtime).unwrap();

        let mut progress = Vec::new();
        copy_tree(&source, &destination, CopyPolicy::SkipUnchanged, |entry| {
            progress.push(entry)
        })
        .unwrap();

        assert_eq!(
            fs::read_to_string(destination.join("file.txt")).unwrap(),
            "target"
        );
        assert!(progress.iter().any(|entry| {
            entry.relative_path == PathBuf::from("file.txt")
                && entry.action == CopyAction::SkippedUnchanged
        }));
        assert_eq!(entry_names(&destination), [OsString::from("file.txt")]);
    }

    #[test]
    fn copy_tree_force_overwrites_file_when_size_and_mtime_match() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(source.join("file.txt"), "source").unwrap();
        fs::write(destination.join("file.txt"), "target").unwrap();

        let mtime = FileTime::from_unix_time(1_700_000_000, 123_000_000);
        filetime::set_file_mtime(source.join("file.txt"), mtime).unwrap();
        filetime::set_file_mtime(destination.join("file.txt"), mtime).unwrap();

        let mut progress = Vec::new();
        copy_tree(&source, &destination, CopyPolicy::ForceOverwrite, |entry| {
            progress.push(entry)
        })
        .unwrap();

        assert_eq!(
            fs::read_to_string(destination.join("file.txt")).unwrap(),
            "source"
        );
        assert!(progress.iter().any(|entry| {
            entry.relative_path == PathBuf::from("file.txt") && entry.action == CopyAction::Copied
        }));
    }

    #[test]
    fn copy_tree_leaves_no_temp_file_behind() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::write(source.join("nested/file.txt"), "nested").unwrap();
        fs::write(source.join("regular.txt"), "regular").unwrap();

        copy_tree(&source, &destination, CopyPolicy::SkipUnchanged, |_| {}).unwrap();

        assert_eq!(
            entry_names(&destination),
            [OsString::from("nested"), OsString::from("regular.txt")]
        );
        assert_eq!(
            entry_names(&destination.join("nested")),
            [OsString::from("file.txt")]
        );
    }

    #[test]
    fn copy_tree_overwrites_destination_and_preserves_source_mtime() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        let source_file = source.join("file.txt");
        let destination_file = destination.join("file.txt");
        fs::write(&source_file, "source").unwrap();
        fs::write(&destination_file, "target").unwrap();

        let source_mtime = FileTime::from_unix_time(1_600_000_000, 456_000_000);
        let destination_mtime = FileTime::from_unix_time(1_500_000_000, 0);
        filetime::set_file_mtime(&source_file, source_mtime).unwrap();
        filetime::set_file_mtime(&destination_file, destination_mtime).unwrap();

        copy_tree(&source, &destination, CopyPolicy::ForceOverwrite, |_| {}).unwrap();

        assert_eq!(fs::read_to_string(&destination_file).unwrap(), "source");
        assert_eq!(
            FileTime::from_last_modification_time(&fs::metadata(&destination_file).unwrap()),
            source_mtime
        );
        assert_eq!(entry_names(&destination), [OsString::from("file.txt")]);
    }

    #[test]
    fn copy_file_removes_the_temp_file_when_the_copy_fails() {
        let root = testdir!();
        // A directory as the copy source fails once the temp file exists, which
        // is the point: the failure has to leave the destination untouched.
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        let destination_file = destination.join("file.txt");
        let metadata = preserved_metadata(&fs::metadata(&source).unwrap()).unwrap();

        let result = copy_file(
            &source,
            &destination_file,
            &metadata,
            0,
            false,
            "copy source file",
            CopyPolicy::ForceOverwrite,
        );

        assert!(result.is_err());
        assert!(entry_names(&destination).is_empty());
        assert!(!destination_file.exists());
    }

    #[test]
    fn copy_tree_preserves_file_mtime() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        let source_file = source.join("file.txt");
        fs::write(&source_file, "content").unwrap();

        let mtime = FileTime::from_unix_time(1_600_000_000, 456_000_000);
        filetime::set_file_mtime(&source_file, mtime).unwrap();
        let source_metadata = fs::metadata(&source_file).unwrap();
        let expected_mtime = FileTime::from_last_modification_time(&source_metadata);

        copy_tree(&source, &destination, CopyPolicy::SkipUnchanged, |_| {}).unwrap();

        let destination_metadata = fs::metadata(destination.join("file.txt")).unwrap();
        assert_eq!(
            FileTime::from_last_modification_time(&destination_metadata),
            expected_mtime
        );
    }

    #[cfg(unix)]
    #[test]
    fn copy_tree_preserves_unix_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        let source_file = source.join("file.txt");
        fs::write(&source_file, "content").unwrap();
        fs::set_permissions(&source_file, fs::Permissions::from_mode(0o640)).unwrap();
        let expected_mode = fs::metadata(&source_file).unwrap().permissions().mode() & 0o777;

        copy_tree(&source, &destination, CopyPolicy::SkipUnchanged, |_| {}).unwrap();

        let mode = fs::metadata(destination.join("file.txt"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, expected_mode);
    }

    #[cfg(unix)]
    #[test]
    fn copy_tree_ignores_unix_permissions_when_skipping() {
        use std::os::unix::fs::PermissionsExt;

        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        let source_file = source.join("file.txt");
        let destination_file = destination.join("file.txt");
        fs::write(&source_file, "source").unwrap();
        fs::write(&destination_file, "target").unwrap();

        let mtime = FileTime::from_unix_time(1_700_000_000, 123_000_000);
        filetime::set_file_mtime(&source_file, mtime).unwrap();
        let source_mode = fs::metadata(&source_file).unwrap().permissions().mode() & 0o777;
        fs::set_permissions(
            &destination_file,
            fs::Permissions::from_mode(source_mode ^ 0o111),
        )
        .unwrap();
        filetime::set_file_mtime(&destination_file, mtime).unwrap();

        let destination_mode = fs::metadata(&destination_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        if source_mode == destination_mode {
            return;
        }

        let mut progress = Vec::new();
        copy_tree(&source, &destination, CopyPolicy::SkipUnchanged, |entry| {
            progress.push(entry)
        })
        .unwrap();

        assert_eq!(fs::read_to_string(&destination_file).unwrap(), "target");
        assert_eq!(
            fs::metadata(&destination_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            destination_mode
        );
        assert!(progress.iter().any(|entry| {
            entry.relative_path == PathBuf::from("file.txt")
                && entry.action == CopyAction::SkippedUnchanged
        }));
    }

    #[cfg(windows)]
    #[test]
    fn copy_tree_handles_read_only_destination() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        let source_file = source.join("file.txt");
        let destination_file = destination.join("file.txt");
        fs::write(&source_file, "content").unwrap();
        fs::write(&destination_file, "content").unwrap();

        let mtime = FileTime::from_unix_time(1_600_000_000, 456_000_000);
        filetime::set_file_mtime(&source_file, mtime).unwrap();
        filetime::set_file_mtime(&destination_file, mtime).unwrap();
        let mut permissions = fs::metadata(&destination_file).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&destination_file, permissions).unwrap();

        copy_tree(&source, &destination, CopyPolicy::SkipUnchanged, |_| {}).unwrap();

        let destination_metadata = fs::metadata(&destination_file).unwrap();
        assert_eq!(
            FileTime::from_last_modification_time(&destination_metadata),
            mtime
        );

        fs::write(&source_file, "updated").unwrap();
        filetime::set_file_mtime(
            &source_file,
            FileTime::from_unix_time(1_700_000_000, 123_000_000),
        )
        .unwrap();
        copy_tree(&source, &destination, CopyPolicy::ForceOverwrite, |_| {}).unwrap();
        assert_eq!(fs::read_to_string(&destination_file).unwrap(), "updated");
        assert!(
            fs::metadata(&destination_file)
                .unwrap()
                .permissions()
                .readonly()
        );
        assert_eq!(
            FileTime::from_last_modification_time(&fs::metadata(&source_file).unwrap()),
            FileTime::from_last_modification_time(&fs::metadata(&destination_file).unwrap())
        );
        assert_eq!(entry_names(&destination), [OsString::from("file.txt")]);
    }

    #[cfg(windows)]
    #[test]
    fn copy_tree_copies_a_read_only_source() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        let source_file = source.join("file.txt");
        let destination_file = destination.join("file.txt");
        fs::write(&source_file, "content").unwrap();

        let mtime = FileTime::from_unix_time(1_600_000_000, 456_000_000);
        filetime::set_file_mtime(&source_file, mtime).unwrap();
        let mut permissions = fs::metadata(&source_file).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&source_file, permissions).unwrap();

        copy_tree(&source, &destination, CopyPolicy::SkipUnchanged, |_| {}).unwrap();

        // `fs::copy` propagates the read-only attribute, so the flush needs write
        // access on a temp that is itself read-only.
        assert_eq!(fs::read_to_string(&destination_file).unwrap(), "content");
        assert!(
            fs::metadata(&destination_file)
                .unwrap()
                .permissions()
                .readonly()
        );
        assert_eq!(
            FileTime::from_last_modification_time(&fs::metadata(&destination_file).unwrap()),
            mtime
        );
        assert_eq!(entry_names(&destination), [OsString::from("file.txt")]);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn copy_tree_copies_nested_files_and_handles_symlinks() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        let nested = source.join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("file.txt"), "nested content").unwrap();
        fs::write(source.join("regular.txt"), "regular content").unwrap();
        create_file_symlink(&nested.join("file.txt"), &source.join("file-link"));
        create_dir_symlink(&nested, &source.join("dir-link"));

        let mut progress = Vec::new();
        copy_tree(&source, &destination, CopyPolicy::SkipUnchanged, |entry| {
            progress.push(entry.relative_path);
        })
        .unwrap();

        assert_eq!(
            fs::read_to_string(destination.join("nested/file.txt")).unwrap(),
            "nested content"
        );
        assert_eq!(
            fs::read_to_string(destination.join("regular.txt")).unwrap(),
            "regular content"
        );
        assert_eq!(
            fs::read_to_string(destination.join("file-link")).unwrap(),
            "nested content"
        );
        assert!(!destination.join("dir-link").exists());
        assert!(!destination.join("dir-link/file.txt").exists());
        assert!(progress.contains(&PathBuf::from("nested")));
        assert!(progress.contains(&PathBuf::from("nested/file.txt")));
        assert!(progress.contains(&PathBuf::from("regular.txt")));
    }

    #[test]
    fn copy_tree_returns_error_when_walker_fails() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        let iter = WalkTree {
            stack: vec![],
            error: Some(io::Error::other("forced iterator failure")),
        };

        let result = copy_tree_entries(
            &source,
            &destination,
            iter,
            CopyPolicy::SkipUnchanged,
            &mut |_| {},
            &mut BTreeSet::new(),
            &mut CopyStats::default(),
        );

        assert!(matches!(
            result,
            Err(BackupHelperError::CopyError(message))
                if message.contains("forced iterator failure")
        ));
    }

    #[cfg(unix)]
    fn create_file_symlink(target: &std::path::Path, link: &std::path::Path) {
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    #[cfg(unix)]
    fn create_dir_symlink(target: &std::path::Path, link: &std::path::Path) {
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    #[cfg(windows)]
    fn create_file_symlink(target: &std::path::Path, link: &std::path::Path) {
        std::os::windows::fs::symlink_file(target, link).unwrap();
    }

    #[cfg(windows)]
    fn create_dir_symlink(target: &std::path::Path, link: &std::path::Path) {
        std::os::windows::fs::symlink_dir(target, link).unwrap();
    }
}
