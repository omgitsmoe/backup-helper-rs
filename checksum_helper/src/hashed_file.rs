use crate::file_tree::{EntryHandle, FileTree};

use filetime::FileTime;
use sha2::Digest;

use std::error::Error;
use std::fmt;
use std::path;
use std::io::{BufRead, BufReader};
use std::fs;

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
            HashedFileError::MissingMTime => write!(f, "missing modification time"),
            // The wrapped error contains additional information and is available
            // via the source() method.
            HashedFileError::IOError(..) => write!(f, "disk i/o error"),
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

impl From<std::io::Error> for HashedFileError {
    fn from(value: std::io::Error) -> Self {
        HashedFileError::IOError(value)
    }
}

#[derive(Debug, PartialEq)]
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

impl TryFrom<&std::ffi::OsStr> for HashType {
    type Error = String;

    fn try_from(value: &std::ffi::OsStr) -> std::result::Result<Self, Self::Error> {
        let Some(str) = value.to_str() else {
            return Err(format!("Unsupported hash type: {:?}", value));
        };
        Self::try_from(str)
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

    pub(crate) fn new(
        filename: EntryHandle,
        mtime: Option<FileTime>,
        size: Option<u64>,
        hash_type: HashType,
        hash_bytes: Vec<u8>,
    ) -> Self {
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

    pub fn mtime(&self) -> Option<FileTime> {
        self.mtime
    }

    pub fn update_mtime(&mut self, mtime: Option<FileTime>) {
        self.mtime = mtime
    }

    pub fn mtime_str(&self) -> Option<String> {
        self.mtime.and_then(|m| {
            // NOTE: to_string returns the string with the OS' epoch
            //       so we need to do our own conversion that is portable
            let usecs = m.unix_seconds() as f64;
            let nanosecs = m.nanoseconds();
            const SECS_PER_NS: f64 = 1.0 / 1_000_000_000.0;
            let fract = (nanosecs as f64) * SECS_PER_NS;
            let combined = (usecs as f64) + fract;
            Some(format!("{}", combined))
        })
    }
    pub fn size(&self) -> Option<u64> {
        self.size
    }

    pub fn hash_type(&self) -> HashType {
        self.hash_type
    }

    pub fn hash_bytes(&self) -> &[u8] {
        self.hash_bytes.as_slice()
    }

    pub(crate) fn with_context<'a>(
        &'a mut self,
        root: &'a path::Path,
        file_tree: &'a FileTree,
    ) -> File<'a> {
        File::from_raw(self, root, file_tree)
    }
}

pub struct File<'a> {
    file: &'a mut FileRaw,
    root: &'a path::Path,
    context: &'a FileTree,
}

impl<'a> File<'a> {
    pub fn from_raw(
        raw: &'a mut FileRaw,
        root: &'a path::Path,
        file_tree: &'a FileTree,
    ) -> File<'a> {
        File {
            file: raw,
            root,
            context: file_tree,
        }
    }

    pub fn raw(&'a mut self) -> &'a mut FileRaw {
        self.file
    }

    fn relative_path(&self) -> path::PathBuf {
        self.file.relative_path(self.context)
    }

    // TODO do we need to make sure this is absolute and only
    //      absolute paths in general?
    fn path_with_root(&self) -> path::PathBuf {
        self.root.join(self.relative_path())
    }

    fn fetch_size(&self) -> Result<u64> {
        let path = self.path_with_root();
        let metadata = std::fs::metadata(path)?;
        Ok(metadata.len())
    }

    fn fetch_mtime(&self) -> Result<FileTime> {
        let path = self.path_with_root();
        let metadata = std::fs::metadata(path)?;
        Ok(FileTime::from_last_modification_time(&metadata))
    }

    fn mtime_to_disk(&self) -> Result<()> {
        let path = self.path_with_root();
        filetime::set_file_mtime(path, self.file.mtime.ok_or(HashedFileError::MissingMTime)?)
            .map_err(|e| HashedFileError::IOError(e))
    }

    pub fn verify(&self) -> Result<VerifyResult> {
        let path = self.path_with_root();
        if !fs::exists(path)? {
            return Ok(VerifyResult::FileMissing);
        }

        // TODO @Perf fetch metadata only once and get mtime/size manually from it?
        match self.file.size() {
            Some(ref expected) => {
                let size_on_disk = self.fetch_size()?;
                if size_on_disk != *expected {
                    return Ok(VerifyResult::MismatchSize);
                }
            },
            None => {},
        };

        let hash_on_disk = self.compute_hash()?;
        if hash_on_disk == self.file.hash_bytes {
            return Ok(VerifyResult::Ok);
        }

        if self.file.mtime().is_none() {
            return Ok(VerifyResult::Mismatch);
        }

        let mtime_on_disk = self.fetch_mtime()?;
        if self.file.mtime().expect("checked above") == mtime_on_disk {
            Ok(VerifyResult::MismatchCorrupted)
        } else {
            Ok(VerifyResult::MismatchOutdatedHash)
        }
    }

    pub fn compute_hash(&self) -> Result<Vec<u8>> {
        self.compute_hash_with(self.file.hash_type)
    }

    pub fn compute_hash_with(&self, hash_type: HashType) -> Result<Vec<u8>> {
        let path = self.path_with_root();
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        compute_hash(reader, hash_type)
    }
}

#[derive(Debug, PartialEq)]
pub enum VerifyResult {
    /// The hashes matched.
    Ok,

    /// Could not compare hashes, since the file on disk was not found.
    FileMissing,

    /// The file on disk did not match the stored hash. There was no stored
    /// modification time, so it is unknown whether the file is corrupted.
    Mismatch,

    /// The size of the file on disk did not match. No hashes were computed!
    MismatchSize,

    /// The file on disk did not match the stored hash. Since the modification
    /// time matches with the file on disk, we can assume that the file has
    /// very likely been corrupted.
    MismatchCorrupted,

    /// The file on disk did not match the stored hash, but the modification
    /// time of the file on disk is newer or older compared to the stored
    /// modification time. The stored hash might be outdated.
    MismatchOutdatedHash,
}

fn compute_hash<R: BufRead>(reader: R, hash_type: HashType) -> Result<Vec<u8>> {
    match hash_type {
        HashType::Md5 => {
            let mut hasher = md5::Md5::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        },
        HashType::Sha1 => {
            let mut hasher = sha1::Sha1::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        },
        HashType::Sha224 => {
            let mut hasher = sha2::Sha224::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        },
        HashType::Sha256 => {
            let mut hasher = sha2::Sha256::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        },
        HashType::Sha384 => {
            let mut hasher = sha2::Sha384::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        },
        HashType::Sha512 => {
            let mut hasher = sha2::Sha512::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        },
        HashType::Sha3_224 => {
            let mut hasher = sha3::Sha3_224::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        },
        HashType::Sha3_256 => {
            let mut hasher = sha3::Sha3_256::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        },
        HashType::Sha3_384 => {
            let mut hasher = sha3::Sha3_384::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        },
        HashType::Sha3_512 => {
            let mut hasher = sha3::Sha3_512::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        },
        HashType::Shake128 => {
            let mut hasher = sha1::Sha1::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        },
        HashType::Shake256 => {
            let mut hasher = sha1::Sha1::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        },
        HashType::Blake2s => {
            let mut hasher = sha1::Sha1::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        },
        HashType::Blake2b => {
            let mut hasher = sha1::Sha1::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        },
    }
}

fn update_in_chunks<R: BufRead>(mut reader: R, hasher: &mut impl Digest) -> Result<()> {
    // reading 64k (65536 bytes) chunks turned out to be most performant
    let mut buf = [0u8; 65536];
    loop {
        let bytes_read = reader.read(&mut buf)
            .map_err(|e| HashedFileError::IOError(e))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buf[..bytes_read]);
    }
    Ok(())
}

