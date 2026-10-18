use std::{
    error::Error,
    ffi::{OsStr, OsString},
    fmt, fs, io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use filetime::FileTime;

mod retry;
pub use retry::{is_retryable_io_error, retry_io};

// Keep the existing marker so leftovers from older backup runs remain recognizable.
const TEMP_MARKER: &str = ".bh-tmp-";
const TEMP_NAME_MAX: usize = 255;
const TEMP_RESERVE_ATTEMPTS: u32 = 8;
const TEMP_STALE_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug)]
pub struct CopyError(pub String);

impl fmt::Display for CopyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for CopyError {}

fn copy_io_error(operation: &str, path: &Path, error: io::Error) -> CopyError {
    CopyError(format!("Failed to {operation} {path:?}: {error}"))
}

#[derive(Debug, Clone)]
pub struct PreservedMetadata {
    pub modified: FileTime,
    #[cfg(unix)]
    pub permissions: fs::Permissions,
}

pub fn preserved_metadata(metadata: &fs::Metadata) -> io::Result<PreservedMetadata> {
    Ok(PreservedMetadata {
        modified: metadata.modified().map(FileTime::from)?,
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

#[cfg(not(windows))]
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

/// An unpublished file is removed on drop so a failed transfer cannot leave a
/// plausible-looking partial destination behind.
struct TempFile {
    path: PathBuf,
    published: bool,
}

impl TempFile {
    fn reserve(destination: &Path) -> Result<Self, CopyError> {
        let directory = destination.parent().ok_or_else(|| {
            CopyError(format!(
                "Destination path {destination:?} has no parent directory"
            ))
        })?;
        let file_name = destination.file_name().ok_or_else(|| {
            CopyError(format!("Destination path {destination:?} has no file name"))
        })?;

        // A sibling temp keeps publication on the same filesystem, where rename is atomic.
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
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(copy_io_error("create destination temp file", &path, error));
                }
            }
        }
        Err(CopyError(format!(
            "Failed to create a destination temp file for {destination:?}: all {TEMP_RESERVE_ATTEMPTS} names are taken"
        )))
    }

    fn path(&self) -> &Path {
        &self.path
    }

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

fn is_temp_file_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(rest) = name.strip_prefix('.') else {
        return false;
    };
    let Some((source_name, ids)) = rest.rsplit_once(TEMP_MARKER) else {
        return false;
    };
    !source_name.is_empty()
        && ids.split_once('-').is_some_and(|(pid, attempt)| {
            !pid.is_empty()
                && !attempt.is_empty()
                && pid
                    .bytes()
                    .chain(attempt.bytes())
                    .all(|b| b.is_ascii_digit())
        })
}

/// Best-effort cleanup; call once per directory before starting its transfers,
/// never while it holds a temp file belonging to a live copy.
pub fn sweep_stale_temps(directory: &Path) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        if !is_temp_file_name(&entry.file_name()) {
            continue;
        }
        let Ok(modified) = entry.metadata().and_then(|metadata| metadata.modified()) else {
            continue;
        };
        // Clock skew must not make a future-dated file eligible for cleanup.
        if SystemTime::now()
            .duration_since(modified)
            .is_ok_and(|age| age >= TEMP_STALE_AFTER)
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn temp_file_name(file_name: &OsStr, attempt: u32) -> OsString {
    let suffix = format!("{TEMP_MARKER}{}-{attempt}", std::process::id());
    // ASCII suffix length is the same in Unix bytes and Windows UTF-16 units.
    let budget = TEMP_NAME_MAX.saturating_sub(1).saturating_sub(suffix.len());
    let mut name = OsString::from(".");
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = file_name.as_bytes();
        name.push(OsStr::from_bytes(&bytes[..bytes.len().min(budget)]));
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let mut units: Vec<u16> = file_name.encode_wide().take(budget).collect();
        // Truncation must not leave an unmatched high surrogate.
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

fn ensure_complete_copy(source: &Path, copied: u64, expected_len: u64) -> Result<(), CopyError> {
    if copied == expected_len {
        Ok(())
    } else {
        Err(CopyError(format!(
            "Failed to copy {source:?}: copied {copied} of {expected_len} bytes"
        )))
    }
}

/// Replaces the destination through a sibling temp file and returns bytes copied.
/// The caller must create and validate the destination parent, decide whether to
/// skip, and flush the parent directory after publication. `expected_len` is
/// `Some` for regular files (including followed file symlinks), `None` otherwise.
pub fn copy_file(
    source: &Path,
    destination: &Path,
    metadata: &PreservedMetadata,
    expected_len: Option<u64>,
    operation: &str,
) -> Result<u64, CopyError> {
    let mut temp = TempFile::reserve(destination)?;
    let copied = retry_io(|| fs::copy(source, temp.path()))
        .map_err(|error| copy_io_error(operation, source, error))?;
    if let Some(expected_len) = expected_len {
        ensure_complete_copy(source, copied, expected_len)?;
    }

    // CIFS can discard the stamp when a writable flush handle closes. Flush
    // first; nothing after restore_metadata may reopen the temp for writing.
    retry_io(|| sync_file(temp.path()))
        .map_err(|error| copy_io_error("flush destination file", temp.path(), error))?;
    retry_io(|| restore_metadata(temp.path(), metadata))
        .map_err(|error| copy_io_error("restore destination metadata", temp.path(), error))?;

    // Windows cannot replace a read-only destination with MoveFileExW.
    #[cfg(windows)]
    let read_only_destination = if expected_len.is_some() {
        clear_read_only_attribute(destination)
            .map_err(|error| copy_io_error("make destination writable", destination, error))?
    } else {
        None
    };

    let publish_result = retry_io(|| fs::rename(temp.path(), destination));
    // Restore permissions even if publication failed.
    #[cfg(windows)]
    let restore_read_only_result = match read_only_destination {
        Some(destination) => destination.restore(),
        None => Ok(()),
    };
    publish_result
        .map_err(|error| copy_io_error("publish destination file", destination, error))?;
    temp.publish();
    #[cfg(windows)]
    restore_read_only_result
        .map_err(|error| copy_io_error("restore destination permissions", destination, error))?;
    Ok(copied)
}

#[cfg(unix)]
fn sync_file(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(windows)]
fn sync_file(path: &Path) -> io::Result<()> {
    // FlushFileBuffers needs GENERIC_WRITE; fs::copy propagates read-only attributes.
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

#[cfg(unix)]
pub fn sync_parent_directory(directory: &Path) -> io::Result<()> {
    match fs::File::open(directory).and_then(|handle| handle.sync_all()) {
        // Unsupported directory flush weakens durability, not rename atomicity.
        Err(error) if is_unsupported_directory_sync(&error) => Ok(()),
        result => result,
    }
}

#[cfg(unix)]
fn is_unsupported_directory_sync(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code == libc::ENOTSUP
        || code == libc::EINVAL || code == libc::EBADF || code == libc::EISDIR)
        || error.kind() == io::ErrorKind::Unsupported
}

#[cfg(not(unix))]
pub fn sync_parent_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use testdir::testdir;

    fn entry_names(directory: &Path) -> Vec<OsString> {
        let mut names: Vec<_> = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn unpublished_temp_file_is_removed() {
        let root = testdir!();
        let destination = root.join("file.txt");
        fs::write(&destination, "existing").unwrap();
        let temp = TempFile::reserve(&destination).unwrap();
        let temp_path = temp.path().to_path_buf();
        assert!(temp_path.exists());
        assert!(is_temp_file_name(temp_path.file_name().unwrap()));
        drop(temp);
        assert!(!temp_path.exists());
        assert_eq!(fs::read_to_string(destination).unwrap(), "existing");
    }

    #[test]
    fn published_temp_file_is_kept() {
        let root = testdir!();
        let mut temp = TempFile::reserve(&root.join("file.txt")).unwrap();
        let temp_path = temp.path().to_path_buf();
        temp.publish();
        drop(temp);
        assert!(temp_path.exists());
    }

    #[test]
    fn reservation_does_not_overwrite_existing_temps() {
        let root = testdir!();
        let destination = root.join("file.txt");
        for attempt in 0..TEMP_RESERVE_ATTEMPTS {
            fs::write(
                root.join(temp_file_name(OsStr::new("file.txt"), attempt)),
                "keep",
            )
            .unwrap();
        }
        assert!(TempFile::reserve(&destination).is_err());
        for entry in fs::read_dir(&root).unwrap() {
            assert_eq!(fs::read_to_string(entry.unwrap().path()).unwrap(), "keep");
        }
    }

    #[cfg(unix)]
    #[test]
    fn temp_file_name_fits_a_long_source_name() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        // Longer than a temp name derived from it would be allowed to be.
        let long_name = "n".repeat(TEMP_NAME_MAX - 5);
        let source_path = source.join(&long_name);
        let destination_path = destination.join(&long_name);
        fs::write(&source_path, "content").unwrap();
        let source_metadata = fs::metadata(&source_path).unwrap();
        let metadata = preserved_metadata(&source_metadata).unwrap();

        copy_file(
            &source_path,
            &destination_path,
            &metadata,
            Some(source_metadata.len()),
            "copy source file",
        )
        .unwrap();

        assert_eq!(fs::read_to_string(destination_path).unwrap(), "content");
        assert_eq!(entry_names(&destination), [OsString::from(long_name)]);
    }

    #[test]
    fn temp_file_names_are_matched_exactly() {
        let temp_name = temp_file_name(OsStr::new("file.txt"), 0);
        assert!(is_temp_file_name(&temp_name));
        assert!(temp_name.as_encoded_bytes().len() <= TEMP_NAME_MAX);
        for name in [
            "file.txt.bh-tmp-4242-0",
            ".file.txt.bh-tmp-abc",
            ".file.txt.bh-tmp-4242",
            ".file.txt.bh-tmp-4242-0.txt",
            ".mine.bh-tmp-abc.txt",
            ".bh-tmp-4242-0",
        ] {
            assert!(!is_temp_file_name(OsStr::new(name)), "{name:?}");
        }
    }

    #[test]
    fn sweep_removes_only_stale_temp_files() {
        let root = testdir!();
        let stale = root.join(format!(".old.txt{TEMP_MARKER}4242-0"));
        let fresh = root.join(format!(".new.txt{TEMP_MARKER}4242-0"));
        let lookalike = root.join(format!(".mine{TEMP_MARKER}abc.txt"));
        let real = root.join("real.txt");
        for path in [&stale, &fresh, &lookalike, &real] {
            fs::write(path, "content").unwrap();
        }
        filetime::set_file_mtime(&stale, FileTime::from_unix_time(1_000_000, 0)).unwrap();
        sweep_stale_temps(&root);
        assert!(!stale.exists());
        assert!(fresh.exists());
        assert!(lookalike.exists());
        assert!(real.exists());
    }

    #[test]
    fn copy_uses_explicit_metadata_and_returns_bytes() {
        let root = testdir!();
        let source = root.join("source.txt");
        let destination = root.join("renamed.txt");
        fs::write(&source, "content").unwrap();
        fs::write(&destination, "old").unwrap();
        let source_meta = fs::metadata(&source).unwrap();
        let mut metadata = preserved_metadata(&source_meta).unwrap();
        let mtime = FileTime::from_unix_time(1_600_000_000, 456_000_000);
        metadata.modified = mtime;
        assert_ne!(FileTime::from_last_modification_time(&source_meta), mtime);

        let copied = copy_file(
            &source,
            &destination,
            &metadata,
            Some(7),
            "copy source file",
        )
        .unwrap();
        sync_parent_directory(&root).unwrap();

        assert_eq!(copied, 7);
        assert_eq!(fs::read_to_string(&destination).unwrap(), "content");
        assert_eq!(
            FileTime::from_last_modification_time(&fs::metadata(destination).unwrap()),
            mtime
        );
        assert_eq!(
            entry_names(&root),
            [OsString::from("renamed.txt"), OsString::from("source.txt")]
        );
    }

    #[test]
    fn wrong_length_keeps_existing_destination_and_cleans_temp() {
        let root = testdir!();
        let source = root.join("source.txt");
        let destination = root.join("destination.txt");
        fs::write(&source, "short").unwrap();
        fs::write(&destination, "existing").unwrap();
        let metadata = preserved_metadata(&fs::metadata(&source).unwrap()).unwrap();

        let error = copy_file(
            &source,
            &destination,
            &metadata,
            Some(12),
            "copy source file",
        )
        .unwrap_err();

        assert!(error.to_string().contains("copied 5 of 12 bytes"));
        assert_eq!(fs::read_to_string(destination).unwrap(), "existing");
        assert_eq!(
            entry_names(&root),
            [
                OsString::from("destination.txt"),
                OsString::from("source.txt")
            ]
        );
    }

    #[test]
    fn failed_copy_keeps_existing_destination_and_cleans_temp() {
        let root = testdir!();
        let source = root.join("source.txt");
        let destination = root.join("destination.txt");
        fs::write(&source, "content").unwrap();
        fs::write(&destination, "existing").unwrap();
        let metadata = preserved_metadata(&fs::metadata(&source).unwrap()).unwrap();
        fs::remove_file(&source).unwrap();

        assert!(
            copy_file(
                &source,
                &destination,
                &metadata,
                Some(7),
                "copy source file"
            )
            .is_err()
        );
        assert_eq!(fs::read_to_string(destination).unwrap(), "existing");
        assert_eq!(entry_names(&root), [OsString::from("destination.txt")]);
    }

    #[test]
    fn failed_publication_cleans_temp() {
        let root = testdir!();
        let source = root.join("source.txt");
        let destination = root.join("destination");
        fs::write(&source, "content").unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("keep.txt"), "keep").unwrap();
        let metadata = preserved_metadata(&fs::metadata(&source).unwrap()).unwrap();

        let error = copy_file(
            &source,
            &destination,
            &metadata,
            Some(7),
            "copy source file",
        )
        .unwrap_err();

        assert!(error.to_string().contains("publish destination file"));
        assert_eq!(
            fs::read_to_string(destination.join("keep.txt")).unwrap(),
            "keep"
        );
        assert_eq!(
            entry_names(&root),
            [OsString::from("destination"), OsString::from("source.txt")]
        );
    }

    #[test]
    fn short_copy_is_rejected() {
        let source = Path::new("/source/file.txt");
        assert!(ensure_complete_copy(source, 12, 12).is_ok());
        assert!(
            ensure_complete_copy(source, 10, 12)
                .unwrap_err()
                .to_string()
                .contains("copied 10 of 12 bytes")
        );
    }

    #[cfg(unix)]
    #[test]
    fn sync_parent_directory_works_on_a_local_filesystem() {
        assert!(sync_parent_directory(&testdir!()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn only_unsupported_directory_sync_errors_are_tolerated() {
        for code in [libc::ENOTSUP, libc::EINVAL, libc::EBADF, libc::EISDIR] {
            assert!(is_unsupported_directory_sync(
                &io::Error::from_raw_os_error(code)
            ));
        }
        assert!(is_unsupported_directory_sync(&io::Error::from(
            io::ErrorKind::Unsupported
        )));
        assert!(!is_unsupported_directory_sync(
            &io::Error::from_raw_os_error(libc::EIO)
        ));
        assert!(!is_unsupported_directory_sync(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
    }
}
