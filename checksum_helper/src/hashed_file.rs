use crate::file_tree::{EntryHandle, FileTree};

use filetime::FileTime;

use std::path;
use std::fmt;
use std::error::Error;

type Result<T> = std::result::Result<T, HashedFileError>;

#[derive(Debug)]
pub enum HashedFileError {
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

pub struct FileRaw {
    path: EntryHandle,
    mtime: Option<FileTime>,
    size: Option<u64>,
    hash_type: HashType,
    hash_bytes: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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
    Shake128,
    Shake256,
    Blake2s,
    Blake2b,
}

impl HashType {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Shake128 => "shake_128",
            Self::Sha3_224 => "sha3_224",
            Self::Md5 => "md5",
            Self::Shake256 => "shake_256",
            Self::Blake2s => "blake2s",
            Self::Sha3_512 => "sha3_512",
            Self::Sha1 => "sha1",
            Self::Sha224 => "sha224",
            Self::Sha3_256 => "sha3_256",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
            Self::Blake2b => "blake2b",
            Self::Sha3_384 => "sha3_384",
            Self::Sha384 => "sha384",
        }
    }
}

impl TryFrom<&str> for HashType {
    type Error = String;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "shake_128" => Ok(Self::Shake128),
            "sha3_224" => Ok(Self::Sha3_224),
            "md5" => Ok(Self::Md5),
            "shake_256" => Ok(Self::Shake256),
            "blake2s" => Ok(Self::Blake2s),
            "sha3_512" => Ok(Self::Sha3_512),
            "sha1" => Ok(Self::Sha1),
            "sha224" => Ok(Self::Sha224),
            "sha3_256" => Ok(Self::Sha3_256),
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            "blake2b" => Ok(Self::Blake2b),
            "sha3_384" => Ok(Self::Sha3_384),
            "sha384" => Ok(Self::Sha384),
            _ => Err(format!("Unsupported hash type: {}", value)),
        }
    }
}

impl Into<&'static str> for HashType {
    fn into(self) -> &'static str {
        self.to_str()
    }
}

impl ToString for HashType {
    fn to_string(&self) -> String {
        self.to_str().to_owned()
    }
}

impl FileRaw {
    pub(crate) fn bare(filename: EntryHandle, hash_type: HashType) -> Self {
        Self {
            path: filename,
            mtime: None,
            size: None,
            hash_type,
            hash_bytes: vec![],
        }
    }

    pub(crate) fn new(filename: EntryHandle, mtime: Option<FileTime>, size: Option<u64>, hash_type: HashType, hash_bytes: Vec<u8>) -> Self {
        Self {
            path: filename,
            mtime,
            size,
            hash_type,
            hash_bytes,
        }
    }

    pub fn relative_path(&self, file_tree: &FileTree) -> path::PathBuf {
        file_tree.relative_path(&self.path)
    }

    pub fn mtime(&self) -> Option<FileTime> { self.mtime }

    pub fn mtime_str(&self) -> Option<String> {
        self.mtime
            .and_then(|m| {
                // NOTE: to_string returns the string with the OS' epoch
                //       so we need to do our own conversion that is portable
                let usecs = m.unix_seconds() as f64;
                let nanosecs = m.nanoseconds();
                const SECS_PER_NS: f64 =  1.0 / 1_000_000_000.0;
                let fract = (nanosecs as f64) * SECS_PER_NS;
                let combined = (usecs as f64) + fract;
                Some(format!("{}", combined))
            })
    }
    pub fn size(&self) -> Option<u64> { self.size }

    pub fn hash_type(&self) -> HashType { self.hash_type }

    pub fn hash_bytes(&self) -> &[u8] { self.hash_bytes.as_slice() }

    pub(crate) fn with_context<'a>(&'a mut self, root: &'a path::Path, file_tree: &'a FileTree) -> File<'a> {
        File::from_raw(self, root, file_tree)
    }
}

pub struct File<'a> {
    file: &'a mut FileRaw,
    root: &'a path::Path,
    context: &'a FileTree,
}

impl<'a> File<'a> {
    pub fn from_raw(raw: &'a mut FileRaw, root: &'a path::Path, file_tree: &'a FileTree) -> File<'a> {
        File{
            file: raw,
            root,
            context: file_tree,
        }
    }

    pub fn raw(&'a mut self) -> &'a mut FileRaw {
        self.file
    }

    fn relative_path(&self) -> path::PathBuf {
        self.context.relative_path(&self.file.path)
    }

    fn fetch_mtime(&mut self, root: &path::Path) -> Result<FileTime> {
        let path = root.join(self.relative_path());
        let metadata = std::fs::metadata(path)
            .map_err(|e| HashedFileError::IOError(e))?;
        Ok(FileTime::from_last_modification_time(&metadata))
    }

    fn mtime(&self) -> Option<FileTime> {
        self.file.mtime
    }

    fn update_mtime(&mut self, mtime: Option<FileTime>) {
        self.file.mtime = mtime
    }

    fn mtime_to_disk(
        &mut self,
        root: &path::Path,
    ) -> Result<()> {
        let path = root.join(self.relative_path());
        filetime::set_file_mtime(path, self.file.mtime.ok_or(HashedFileError::MissingMTime)?)
            .map_err(|e| HashedFileError::IOError(e))
    }

    fn size(self) -> Option<u64> { self.file.size }

    fn hash_type(self) -> HashType { self.file.hash_type.clone() }

    fn hash_bytes(self) -> &'a [u8] { self.file.hash_bytes.as_slice() }
}
