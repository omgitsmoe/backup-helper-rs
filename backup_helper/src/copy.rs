use std::{
    fs, io,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use filetime::FileTime;

#[cfg(unix)]
use libc::{EIO, EREMOTEIO, ESTALE};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    ERROR_BAD_NET_NAME, ERROR_BAD_NET_RESP, ERROR_BAD_NETPATH, ERROR_DEV_NOT_EXIST,
    ERROR_IO_PENDING, ERROR_NETNAME_DELETED, ERROR_NETWORK_ACCESS_DENIED, ERROR_NETWORK_BUSY,
    ERROR_NETWORK_UNREACHABLE, ERROR_NO_SYSTEM_RESOURCES, ERROR_OPERATION_ABORTED,
    ERROR_SEM_TIMEOUT, ERROR_SHARING_VIOLATION,
};

use crate::BackupHelperError;

const RETRY_DELAYS: [Duration; 3] = [
    Duration::from_millis(100),
    Duration::from_millis(200),
    Duration::from_millis(400),
];

pub(crate) fn is_directory(path: &Path) -> io::Result<bool> {
    Ok(retry_io(|| fs::metadata(path))?.is_dir())
}

fn retry_io<T>(mut operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    retry_io_with(&mut operation, &RETRY_DELAYS, &mut |delay| {
        thread::sleep(delay)
    })
}

fn retry_io_with<T>(
    operation: &mut impl FnMut() -> io::Result<T>,
    retry_delays: &[Duration],
    sleep: &mut impl FnMut(Duration),
) -> io::Result<T> {
    let mut retry_index = 0;
    loop {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if is_retryable_io_error(&error) && retry_index < retry_delays.len() => {
                sleep(retry_delays[retry_index]);
                retry_index += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

pub(crate) fn is_retryable_io_error(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::StaleNetworkFileHandle
            | io::ErrorKind::ResourceBusy
            | io::ErrorKind::WriteZero
            | io::ErrorKind::UnexpectedEof
    ) {
        return true;
    }

    is_retryable_raw_os_error(error)
}

// Network filesystems can expose transient failures as uncategorized raw errors.
#[cfg(unix)]
fn is_retryable_raw_os_error(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code == EIO || code == EREMOTEIO || code == ESTALE)
}

#[cfg(windows)]
fn is_retryable_raw_os_error(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code as u32 == ERROR_BAD_NET_NAME
        || code as u32 == ERROR_BAD_NETPATH
        || code as u32 == ERROR_BAD_NET_RESP
        || code as u32 == ERROR_DEV_NOT_EXIST
        || code as u32 == ERROR_IO_PENDING
        || code as u32 == ERROR_NETNAME_DELETED
        || code as u32 == ERROR_NETWORK_ACCESS_DENIED
        || code as u32 == ERROR_NETWORK_BUSY
        || code as u32 == ERROR_NETWORK_UNREACHABLE
        || code as u32 == ERROR_NO_SYSTEM_RESOURCES
        || code as u32 == ERROR_OPERATION_ABORTED
        || code as u32 == ERROR_SEM_TIMEOUT
        || code as u32 == ERROR_SHARING_VIOLATION)
}

#[cfg(not(any(unix, windows)))]
fn is_retryable_raw_os_error(_error: &io::Error) -> bool {
    false
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
) -> Result<(), BackupHelperError> {
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

    let iter =
        WalkTree::new(source).map_err(|error| copy_io_error("walk source", source, error))?;
    copy_tree_entries(source, destination, iter, policy, &mut on_progress)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyAction {
    Copied,
    SkippedUnchanged,
    Directory,
    Ignored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyProgress {
    pub relative_path: PathBuf,
    pub action: CopyAction,
}

#[derive(Debug, Clone)]
struct PreservedMetadata {
    modified: FileTime,
    #[cfg(unix)]
    permissions: fs::Permissions,
}

fn preserved_metadata(metadata: &fs::Metadata) -> io::Result<PreservedMetadata> {
    let modified = metadata.modified().map(FileTime::from)?;

    Ok(PreservedMetadata {
        modified,
        #[cfg(unix)]
        permissions: metadata.permissions(),
    })
}

fn restore_metadata(path: &Path, metadata: &PreservedMetadata) -> io::Result<()> {
    restore_file_times(path, metadata)?;

    #[cfg(unix)]
    fs::set_permissions(path, metadata.permissions.clone())?;

    Ok(())
}

#[cfg(unix)]
fn restore_file_times(path: &Path, metadata: &PreservedMetadata) -> io::Result<()> {
    filetime::set_file_mtime(path, metadata.modified)
}

#[cfg(windows)]
fn restore_file_times(path: &Path, metadata: &PreservedMetadata) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_WRITE_ATTRIBUTES,
    };

    // Attribute-only access lets read-only destinations receive the source mtime.
    let file = fs::OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    filetime::set_file_handle_times(&file, None, Some(metadata.modified))
}

#[cfg(not(any(unix, windows)))]
fn restore_file_times(path: &Path, metadata: &PreservedMetadata) -> io::Result<()> {
    filetime::set_file_mtime(path, metadata.modified)
}

// Temporarily clear an existing read-only attribute, then restore it after replacement.
#[cfg(windows)]
struct ReadOnlyDestination {
    path: PathBuf,
    permissions: fs::Permissions,
}

#[cfg(windows)]
impl ReadOnlyDestination {
    fn restore(self) -> io::Result<()> {
        retry_io(|| fs::set_permissions(&self.path, self.permissions.clone()))
    }
}

#[cfg(windows)]
fn prepare_destination_for_copy(
    path: &Path,
) -> Result<Option<ReadOnlyDestination>, BackupHelperError> {
    let metadata = match retry_io(|| fs::symlink_metadata(path)) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound && !is_retryable_io_error(&error) => {
            return Ok(None);
        }
        Err(error) => return Err(copy_io_error("read destination metadata", path, error)),
    };

    let original_permissions = metadata.permissions();
    if !original_permissions.readonly() {
        return Ok(None);
    }

    let mut writable_permissions = original_permissions.clone();
    writable_permissions.set_readonly(false);
    retry_io(|| fs::set_permissions(path, writable_permissions.clone()))
        .map_err(|error| copy_io_error("make destination writable", path, error))?;

    Ok(Some(ReadOnlyDestination {
        path: path.to_path_buf(),
        permissions: original_permissions,
    }))
}

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

/// Rejects a copy that wrote fewer bytes than the source holds. `fs::copy`
/// returns the number of bytes written, which used to be discarded, so a short
/// copy was indistinguishable from a complete one.
fn ensure_complete_copy(
    source: &Path,
    copied: u64,
    expected_len: u64,
) -> Result<(), BackupHelperError> {
    if copied == expected_len {
        return Ok(());
    }

    Err(BackupHelperError::CopyError(format!(
        "Failed to copy {source:?}: copied {copied} of {expected_len} bytes"
    )))
}

fn copy_file(
    source: &Path,
    destination: &Path,
    source_metadata: &PreservedMetadata,
    source_len: u64,
    source_is_file: bool,
    operation: &str,
    policy: CopyPolicy,
) -> Result<CopyAction, BackupHelperError> {
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
            return Ok(CopyAction::SkippedUnchanged);
        }
    }

    #[cfg(windows)]
    let read_only_destination = if source_is_file {
        prepare_destination_for_copy(destination)?
    } else {
        None
    };

    let copy_result = retry_io(|| fs::copy(source, destination));
    #[cfg(windows)]
    let restore_read_only_result = match read_only_destination {
        Some(destination) => destination.restore(),
        None => Ok(()),
    };

    let copied = match copy_result {
        Ok(copied) => copied,
        Err(error) => return Err(copy_io_error(operation, source, error)),
    };
    #[cfg(windows)]
    restore_read_only_result
        .map_err(|error| copy_io_error("restore destination permissions", destination, error))?;

    // Meaningless for sources that are not regular files, and a symlink to a file
    // reports the length of its target, which is what `fs::copy` writes.
    if source_is_file {
        ensure_complete_copy(source, copied, source_len)?;
    }

    retry_io(|| restore_metadata(destination, source_metadata))
        .map_err(|error| copy_io_error("restore destination metadata", destination, error))?;

    Ok(CopyAction::Copied)
}

fn copy_tree_entries(
    source: &Path,
    destination: &Path,
    mut iter: WalkTree,
    policy: CopyPolicy,
    on_progress: &mut impl FnMut(CopyProgress),
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

        let action = if meta.is_dir() {
            retry_io(|| fs::create_dir_all(&destination_path)).map_err(|error| {
                copy_io_error("create destination directory", &destination_path, error)
            })?;
            CopyAction::Directory
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
                CopyAction::Ignored
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

        on_progress(CopyProgress {
            relative_path: relative.to_path_buf(),
            action,
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
    use std::fs;
    use testdir::testdir;

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
    fn retry_io_retries_transient_errors_until_success() {
        let retry_delays = [Duration::from_millis(0), Duration::from_millis(0)];
        let mut attempts = 0;
        let mut sleeps = Vec::new();
        let mut operation = || -> io::Result<&'static str> {
            attempts += 1;
            if attempts < 3 {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            } else {
                Ok("copied")
            }
        };

        let result = retry_io_with(&mut operation, &retry_delays, &mut |delay| {
            sleeps.push(delay);
        });

        assert_eq!(result.unwrap(), "copied");
        assert_eq!(attempts, 3);
        assert_eq!(sleeps, retry_delays);
    }

    #[test]
    fn retry_io_stops_after_retry_budget() {
        let retry_delays = [Duration::from_millis(0), Duration::from_millis(0)];
        let mut attempts = 0;
        let mut sleeps = Vec::new();
        let mut operation = || -> io::Result<()> {
            attempts += 1;
            Err(io::Error::from(io::ErrorKind::ConnectionReset))
        };

        let result = retry_io_with(&mut operation, &retry_delays, &mut |delay| {
            sleeps.push(delay);
        });

        assert!(matches!(
            result,
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset
        ));
        assert_eq!(attempts, retry_delays.len() + 1);
        assert_eq!(sleeps, retry_delays);
    }

    #[test]
    fn retry_io_does_not_retry_permanent_errors() {
        let retry_delays = [Duration::from_millis(0)];
        let mut attempts = 0;
        let mut sleeps = Vec::new();
        let mut operation = || -> io::Result<()> {
            attempts += 1;
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        };

        let result = retry_io_with(&mut operation, &retry_delays, &mut |delay| {
            sleeps.push(delay);
        });

        assert!(matches!(
            result,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert_eq!(attempts, 1);
        assert!(sleeps.is_empty());
    }

    #[test]
    fn common_transient_error_kinds_are_retryable() {
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Interrupted,
            io::ErrorKind::TimedOut,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::NotConnected,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::NetworkDown,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::StaleNetworkFileHandle,
            io::ErrorKind::ResourceBusy,
            io::ErrorKind::WriteZero,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert!(
                is_retryable_io_error(&io::Error::from(kind)),
                "expected {kind:?} to be retryable"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn eagain_is_retryable() {
        let error = io::Error::from_raw_os_error(11);

        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(is_retryable_io_error(&error));
    }

    #[cfg(unix)]
    #[test]
    fn uncategorized_unix_io_errors_are_retryable() {
        for code in [libc::EIO, libc::EREMOTEIO, libc::ESTALE] {
            let error = io::Error::from_raw_os_error(code);

            assert!(
                is_retryable_io_error(&error),
                "expected raw Unix error {code} to be retryable"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn uncategorized_windows_io_errors_are_retryable() {
        for code in [
            windows_sys::Win32::Foundation::ERROR_BAD_NETPATH,
            windows_sys::Win32::Foundation::ERROR_BAD_NET_NAME,
            windows_sys::Win32::Foundation::ERROR_NETWORK_BUSY,
        ] {
            let error = io::Error::from_raw_os_error(code as i32);

            assert!(
                is_retryable_io_error(&error),
                "expected raw Windows error {code} to be retryable"
            );
        }
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
    fn short_copy_is_rejected() {
        let source = Path::new("/source/file.txt");

        assert!(ensure_complete_copy(source, 12, 12).is_ok());
        assert!(matches!(
            ensure_complete_copy(source, 10, 12),
            Err(BackupHelperError::CopyError(message))
                if message.contains("copied 10 of 12 bytes")
        ));
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
