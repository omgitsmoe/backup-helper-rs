use crate::file_tree::{EntryHandle, FileTree};

use filetime::FileTime;

use std::path;
use std::fmt;
use std::error::Error;

type Result<T> = std::result::Result<T, HashedFileError>;

#[derive(Debug)]
enum HashedFileError {
    MissingMTime,
    // wrap io::Error
    IOError(std::io::Error),
}

impl fmt::Display for HashedFileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HashedFileError::MissingMTime =>
                write!(f, "missing modification time"),
            // The wrapped error contains additional information and is available
            // via the source() method.
            HashedFileError::IOError(..) =>
                write!(f, "disk i/o error"),
        }
    }
}

impl Error for HashedFileError {
    // return the source for this error, e.g. std::io::Eror if we wrapped it
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            HashedFileError::MissingMTime => None,
            // The cause is the underlying implementation error type. Is implicitly
            // cast to the trait object `&error::Error`. This works because the
            // underlying type already implements the `Error` trait.
            HashedFileError::IOError(ref e) => Some(e),
        }
    }
}

// TODO map from python hash algo name
// {'shake_128', 'sha3_224', 'md5', 'shake_256', 'blake2s', 'sha3_512', 'sha1', 'sha224', 'sha3_256', 'sha256', 'sha512', 'blake2b', 'sha3_384', 'sha384'}
struct FileRaw {
    path: EntryHandle,
    mtime: Option<FileTime>,
    size: Option<usize>,
    // TODO enum?
    hash_type: &'static str,
    hash_bytes: Vec<u8>,
}

impl FileRaw {
    fn new(filename: EntryHandle) -> Self {
        Self {
            path: filename,
            mtime: None,
            size: None,
            hash_type: "unknown",
            hash_bytes: vec![],
        }
    }

    fn path(&self, file_tree: &FileTree) -> path::PathBuf {
        file_tree.path(&self.path)
    }

    fn fetch_mtime(&mut self, file_tree: &FileTree) -> Result<FileTime> {
        let path = self.path(file_tree);
        let metadata = std::fs::metadata(path)
            .map_err(|e| HashedFileError::IOError(e))?;
        Ok(FileTime::from_last_modification_time(&metadata))
    }

    fn mtime(&self) -> Option<FileTime> {
        self.mtime
    }

    fn update_mtime(&mut self, mtime: Option<FileTime>) {
        self.mtime = mtime
    }

    fn mtime_to_disk(
        &mut self,
        file_tree: &FileTree,
    ) -> Result<()> {
        let path = self.path(file_tree);
        filetime::set_file_mtime(path, self.mtime.ok_or(HashedFileError::MissingMTime)?)
            .map_err(|e| HashedFileError::IOError(e))
    }
}

// TODO only give out this and rename above to FileRaw or sth.?
pub struct File<'a> {
    file: FileRaw,
    context: &'a FileTree,
}

impl<'a> File<'a> {
    pub fn new(context: &'a FileTree, path: &EntryHandle) -> File<'a> {
        File{
            file: FileRaw::new(path.clone()),
            context,
        }
    }
}
