use std::{
    ffi::{OsStr, OsString},
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

/// Marks a destination file that has not been published yet. The name is built as
/// `.{name}.bh-tmp-{pid}-{attempt}` so that a leftover from a crashed run is both
/// identifiable as ours and traceable back to its source file.
const TEMP_MARKER: &str = ".bh-tmp-";

/// Longest single path component, in bytes on Unix and in UTF-16 code units on
/// Windows. The temp name has to fit the same limit as the final name, otherwise a
/// long source name fails the copy with `ENAMETOOLONG`.
const TEMP_NAME_MAX: usize = 255;

/// How many names to try before giving up on reserving a temp name.
const TEMP_RESERVE_ATTEMPTS: u32 = 8;

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

// Temporarily clear an existing read-only attribute, then restore it after the
// operation that needed the file to be writable.
#[cfg(windows)]
struct ReadOnlyFile {
    path: PathBuf,
    permissions: fs::Permissions,
}

#[cfg(windows)]
impl ReadOnlyFile {
    fn restore(self) -> io::Result<()> {
        retry_io(|| fs::set_permissions(&self.path, self.permissions.clone()))
    }
}

#[cfg(windows)]
fn clear_read_only_attribute(path: &Path) -> io::Result<Option<ReadOnlyFile>> {
    let metadata = match retry_io(|| fs::symlink_metadata(path)) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound && !is_retryable_io_error(&error) => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };

    let original_permissions = metadata.permissions();
    if !original_permissions.readonly() {
        return Ok(None);
    }

    let mut writable_permissions = original_permissions.clone();
    writable_permissions.set_readonly(false);
    retry_io(|| fs::set_permissions(path, writable_permissions.clone()))?;

    Ok(Some(ReadOnlyFile {
        path: path.to_path_buf(),
        permissions: original_permissions,
    }))
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

/// Owns a destination file that has not been published yet. The file is removed on
/// drop unless it was renamed onto its final name, so a failed copy never leaves a
/// plausible-looking partial file behind.
struct TempFile {
    path: PathBuf,
    published: bool,
}

impl TempFile {
    /// Reserves an unused temp name next to `destination` and creates it empty.
    ///
    /// The temp has to live in the destination directory: `rename` is only atomic
    /// within a filesystem, and a staging area on another device would turn the
    /// publish into a non-atomic second copy.
    fn reserve(destination: &Path) -> Result<Self, BackupHelperError> {
        let directory = destination.parent().ok_or_else(|| {
            BackupHelperError::CopyError(format!(
                "Destination path {:?} has no parent directory",
                destination
            ))
        })?;
        let file_name = destination.file_name().ok_or_else(|| {
            BackupHelperError::CopyError(format!(
                "Destination path {:?} has no file name",
                destination
            ))
        })?;

        for attempt in 0..TEMP_RESERVE_ATTEMPTS {
            let path = directory.join(temp_file_name(file_name, attempt));
            let reservation = retry_io(|| {
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
            });
            match reservation {
                Ok(_) => {
                    return Ok(Self {
                        path,
                        published: false,
                    });
                }
                // A temp from an earlier run holds the name until the stale sweep
                // is old enough to remove it, so move on to the next attempt.
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(copy_io_error("create destination temp file", &path, error));
                }
            }
        }

        Err(BackupHelperError::CopyError(format!(
            "Failed to create a destination temp file for {:?}: all {TEMP_RESERVE_ATTEMPTS} names are taken",
            destination
        )))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Keeps the file, because it now lives under its final name.
    fn publish(&mut self) {
        self.published = true;
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn temp_file_name(file_name: &OsStr, attempt: u32) -> OsString {
    let suffix = format!("{TEMP_MARKER}{}-{attempt}", std::process::id());
    // The marker and the pid are ASCII, so their length is the same in bytes and
    // in UTF-16 code units. One byte is spent on the leading dot.
    let budget = TEMP_NAME_MAX.saturating_sub(1).saturating_sub(suffix.len());

    let mut name = OsString::from(".");
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        // Cutting on a byte boundary can split a UTF-8 sequence. The result is
        // still a valid filename, it only renders oddly, and this name only exists
        // for the duration of a single copy.
        let bytes = file_name.as_bytes();
        name.push(OsStr::from_bytes(&bytes[..bytes.len().min(budget)]));
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};

        // Cutting on a char boundary can still leave a lone high surrogate, which
        // is not a valid Windows name.
        let mut units: Vec<u16> = file_name.encode_wide().take(budget).collect();
        if let Some(&unit) = units.last()
            && (0xD800..=0xDBFF).contains(&unit)
        {
            units.pop();
        }
        name.push(OsString::from_wide(&units));
    }
    name.push(suffix);
    name
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

    let mut temp = TempFile::reserve(destination)?;

    let copied = retry_io(|| fs::copy(source, temp.path()))
        .map_err(|error| copy_io_error(operation, source, error))?;
    // Meaningless for sources that are not regular files, and a symlink to a file
    // reports the length of its target, which is what `fs::copy` writes.
    if source_is_file {
        ensure_complete_copy(source, copied, source_len)?;
    }

    // Applied before the rename so that the file is published complete: `rename`
    // does not touch the mtime of the inode it moves.
    retry_io(|| restore_metadata(temp.path(), source_metadata))
        .map_err(|error| copy_io_error("restore destination metadata", temp.path(), error))?;
    retry_io(|| sync_file(temp.path()))
        .map_err(|error| copy_io_error("flush destination file", temp.path(), error))?;

    // `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING` replaces the destination but
    // refuses to do so while the destination is read-only.
    #[cfg(windows)]
    let read_only_destination = if source_is_file {
        clear_read_only_attribute(destination)
            .map_err(|error| copy_io_error("make destination writable", destination, error))?
    } else {
        None
    };

    let publish_result = retry_io(|| fs::rename(temp.path(), destination));
    // Restored even when the rename failed, otherwise the destination would stay
    // writable.
    #[cfg(windows)]
    let restore_read_only_result = match read_only_destination {
        Some(destination) => destination.restore(),
        None => Ok(()),
    };

    if let Err(error) = publish_result {
        return Err(copy_io_error(
            "publish destination file",
            destination,
            error,
        ));
    }
    temp.publish();
    #[cfg(windows)]
    restore_read_only_result
        .map_err(|error| copy_io_error("restore destination permissions", destination, error))?;

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

#[cfg(unix)]
fn sync_file(path: &Path) -> io::Result<()> {
    // Read-only, because the source's own mode is already applied and a write-only
    // or execute-only source has no readable handle to flush.
    fs::File::open(path)?.sync_all()
}

// `FlushFileBuffers` requires the handle to hold `GENERIC_WRITE`, so the
// read-only open that is enough for `fsync` is rejected with
// `ERROR_ACCESS_DENIED` here. `fs::copy` propagates the read-only attribute from
// the source, so a read-only source has to have it cleared for the flush.
#[cfg(windows)]
fn sync_file(path: &Path) -> io::Result<()> {
    let read_only = clear_read_only_attribute(path)?;
    let flush_result = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.sync_all());
    let restore_result = match read_only {
        Some(read_only) => read_only.restore(),
        None => Ok(()),
    };

    flush_result.and(restore_result)
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
    fn unpublished_temp_file_is_removed() {
        let root = testdir!();
        let destination = root.join("file.txt");
        fs::write(&destination, "existing").unwrap();

        let temp = TempFile::reserve(&destination).unwrap();
        let temp_path = temp.path().to_path_buf();
        assert!(temp_path.exists());
        assert!(
            temp_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with('.')
        );

        drop(temp);

        assert!(!temp_path.exists());
        assert_eq!(fs::read_to_string(&destination).unwrap(), "existing");
    }

    #[test]
    fn published_temp_file_is_kept() {
        let root = testdir!();
        let destination = root.join("file.txt");

        let mut temp = TempFile::reserve(&destination).unwrap();
        let temp_path = temp.path().to_path_buf();
        temp.publish();
        drop(temp);

        assert!(temp_path.exists());
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

    #[cfg(unix)]
    #[test]
    fn temp_file_name_fits_a_long_source_name() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        // Longer than a temp name derived from it would be allowed to be.
        let long_name = "n".repeat(TEMP_NAME_MAX - 5);
        fs::write(source.join(&long_name), "content").unwrap();

        copy_tree(&source, &destination, CopyPolicy::SkipUnchanged, |_| {}).unwrap();

        assert_eq!(
            fs::read_to_string(destination.join(&long_name)).unwrap(),
            "content"
        );
        assert_eq!(entry_names(&destination), [OsString::from(long_name)]);
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
