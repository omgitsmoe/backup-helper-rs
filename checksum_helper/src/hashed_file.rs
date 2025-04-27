use crate::file_tree::{EntryHandle, FileTree};

use filetime::FileTime;
use sha2::Digest;

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path;

type Result<T> = std::result::Result<T, HashedFileError>;

#[derive(Debug, Eq, PartialEq)]
pub enum HashedFileError {
    MissingMTime,
    MissingHash,
    // wrap io::Error
    IOError((Option<path::PathBuf>, std::io::ErrorKind)),
}

impl fmt::Display for HashedFileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HashedFileError::MissingMTime => write!(f, "missing modification time"),
            HashedFileError::MissingHash => write!(f, "missing hash"),
            // The wrapped error contains additional information and is available
            // via the source() method.
            HashedFileError::IOError((Some(ref p), kind)) =>
                write!(f, "disk i/o error at '{:?}': {}", p, kind),
            HashedFileError::IOError((None, kind)) =>
                write!(f, "disk i/o error: {}", kind.clone()),
        }
    }
}

impl Error for HashedFileError {
    // return the source for this error, e.g. std::io::Eror if we wrapped it
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            _ => None,
        }
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

    pub fn relative_path_to(&self, file_tree: &FileTree, base: impl AsRef<path::Path>) -> path::PathBuf {
        file_tree.relative_path_to(&self.path, base)
    }

    pub fn absolute_path(&self, file_tree: &FileTree) -> path::PathBuf {
        file_tree.absolute_path(&self.path)
    }

    pub fn mtime(&self) -> Option<FileTime> {
        self.mtime
    }

    pub fn update_mtime(&mut self, mtime: Option<FileTime>) {
        self.mtime = mtime
    }

    pub fn mtime_str(&self) -> Option<String> {
        self.mtime.map(|m| {
            // NOTE: to_string returns the string with the OS' epoch
            //       so we need to do our own conversion that is portable
            let usecs = m.unix_seconds() as f64;
            let nanosecs = m.nanoseconds();
            const SECS_PER_NS: f64 = 1.0 / 1_000_000_000.0;
            let fract = (nanosecs as f64) * SECS_PER_NS;
            let combined = (usecs as f64) + fract;
            format!("{}", combined)
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
        &'a self,
        file_tree: &'a FileTree,
    ) -> File<'a> {
        File::from_raw(self, file_tree)
    }

    pub(crate) fn with_context_mut<'a>(
        &'a mut self,
        file_tree: &'a FileTree,
    ) -> File<'a> {
        File::from_raw(self, file_tree)
    }
}

// @Design could use a shared trait here that works for wrapping both a
// mut FileRaw and non-mut, but then we'd have to impl that for each
// of those variations.
// Makes more sense if you have more types. Here it's just two distinctions
// and we're not trying to abstract mainly common behaviour.
// Instead we chose to use separate structs, one for wrapping a mut,
// one for a non-mut reference. This reduces duplication, since
// the mut wrapper can just return a non-mut one.
pub struct File<'a> {
    file: &'a FileRaw,
    context: &'a FileTree,
}

pub struct FileMut<'a> {
    file: &'a mut FileRaw,
    context: &'a FileTree,
}

impl<'a> FileMut<'a> {
    pub fn from_raw(file: &'a mut FileRaw, file_tree: &'a FileTree) -> FileMut<'a> {
        FileMut { file, context: file_tree }
    }

    // NOTE: Use a closure here so we don't run into borrow/lifetime issues
    pub fn raw<C, R>(&mut self, func: C) -> R
    where
        C: FnOnce(&mut FileRaw) -> R,
    {
        func(self.file)
    }

    pub fn as_file(&'a self) -> File<'a> {
        File { file: self.file, context: self.context }
    }
}

impl<'a> File<'a> {
    pub fn from_raw(file: &'a FileRaw, file_tree: &'a FileTree) -> File<'a> {
        File { file, context: file_tree }
    }

    // NOTE: Use a closure here so we don't run into borrow/lifetime issues
    pub fn raw<C, R>(&mut self, func: C) -> R
    where
        C: FnOnce(&FileRaw) -> R,
    {
        func(self.file)
    }

    // TODO this should probably return the path relative to the collection root, not
    //      to the file tree
    //      or just return an absolute path?
    fn relative_path(&self) -> path::PathBuf {
        self.file.relative_path(self.context)
    }

    fn absolute_path(&self) -> path::PathBuf {
        self.file.absolute_path(self.context)
    }

    fn fetch_size(&self) -> Result<u64> {
        let path = self.absolute_path();
        let metadata = std::fs::metadata(&path)
            .map_err(|e| HashedFileError::IOError((Some(path.clone()), e.kind())))?;
        Ok(metadata.len())
    }

    fn fetch_mtime(&self) -> Result<FileTime> {
        let path = self.absolute_path();
        let metadata = std::fs::metadata(&path)
            .map_err(|e| HashedFileError::IOError((Some(path.clone()), e.kind())))?;
        Ok(FileTime::from_last_modification_time(&metadata))
    }

    fn mtime_to_disk(&self) -> Result<()> {
        let path = self.absolute_path();
        filetime::set_file_mtime(&path, self.file.mtime.ok_or(HashedFileError::MissingMTime)?)
            .map_err(|e| HashedFileError::IOError((Some(path.clone()), e.kind())))
    }

    pub fn verify(&self) -> Result<VerifyResult> {
        if self.file.hash_bytes.is_empty() {
            return Err(HashedFileError::MissingHash);
        }

        let path = self.absolute_path();
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(e) => return Ok(VerifyResult::FileMissing(e.kind())),
        };

        if let Some(ref expected) = self.file.size() {
            let size_on_disk = meta.len();
            if size_on_disk != *expected {
                return Ok(VerifyResult::MismatchSize);
            }
        };

        let hash_on_disk = self.compute_hash()?;
        if hash_on_disk == self.file.hash_bytes {
            return Ok(VerifyResult::Ok);
        }

        if self.file.mtime().is_none() {
            return Ok(VerifyResult::Mismatch);
        }

        let mtime_on_disk = filetime::FileTime::from_last_modification_time(&meta);
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
        let path = self.absolute_path();
        let file = fs::File::open(&path)
            .map_err(|e| HashedFileError::IOError((Some(path.clone()), e.kind())))?;
        let reader = BufReader::new(file);
        compute_hash(reader, hash_type)
    }
}

#[derive(Debug, PartialEq)]
pub enum VerifyResult {
    /// The hashes matched.
    Ok,

    /// Could not compare hashes, since the file on disk was not found
    /// or there were permission errors. Inspect the `std::io::ErrorKind`
    /// to find the concrete reason.
    FileMissing(std::io::ErrorKind),

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
        }
        HashType::Sha1 => {
            let mut hasher = sha1::Sha1::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        }
        HashType::Sha224 => {
            let mut hasher = sha2::Sha224::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        }
        HashType::Sha256 => {
            let mut hasher = sha2::Sha256::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        }
        HashType::Sha384 => {
            let mut hasher = sha2::Sha384::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        }
        HashType::Sha512 => {
            let mut hasher = sha2::Sha512::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        }
        HashType::Sha3_224 => {
            let mut hasher = sha3::Sha3_224::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        }
        HashType::Sha3_256 => {
            let mut hasher = sha3::Sha3_256::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        }
        HashType::Sha3_384 => {
            let mut hasher = sha3::Sha3_384::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        }
        HashType::Sha3_512 => {
            let mut hasher = sha3::Sha3_512::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        }
        HashType::Shake128 => {
            let mut hasher = sha1::Sha1::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        }
        HashType::Shake256 => {
            let mut hasher = sha1::Sha1::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        }
        HashType::Blake2s => {
            let mut hasher = sha1::Sha1::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        }
        HashType::Blake2b => {
            let mut hasher = sha1::Sha1::new();
            update_in_chunks(reader, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        }
    }
}

fn update_in_chunks<R: BufRead>(mut reader: R, hasher: &mut impl Digest) -> Result<()> {
    // reading 64k (65536 bytes) chunks turned out to be most performant
    let mut buf = [0u8; 65536];
    loop {
        let bytes_read = reader
            .read(&mut buf)
            .map_err(|e| HashedFileError::IOError((None, e.kind())))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buf[..bytes_read]);
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::*;

    fn setup_testfile<'a>() -> (
        path::PathBuf,
        path::PathBuf,
        path::PathBuf,
        &'a str,
        FileTree,
        FileRaw,
        &'a str,
    ) {
        let testdir = testdir!();
        let testfile_name = path::Path::new("foo.txt");
        let testfile = testdir.join(testfile_name);
        let testcontent = "foobar";
        fs::write(&testfile, testcontent).unwrap();

        let mut ft = FileTree::new(&testdir).unwrap();
        let path_handle = ft.add_file(&testfile_name).unwrap();
        let mut raw = FileRaw::bare(path_handle, HashType::Md5);
        let expected_hex = "3858f62230ac3c915f300c664312c63f";
        let expected = hex::decode(expected_hex).unwrap();
        raw.hash_bytes = expected;
        raw.size = Some(testcontent.len() as u64);

        (
            testdir,
            testfile_name.to_path_buf(),
            testfile,
            testcontent,
            ft,
            raw,
            expected_hex,
        )
    }

    #[test]
    fn test_fetch_size() {
        let (testdir, _, _, testcontent, ft, mut raw, _) = setup_testfile();
        let file = File::from_raw(&mut raw, &ft);
        assert_eq!(file.fetch_size().unwrap(), testcontent.len() as u64);
    }

    #[test]
    fn test_fetch_mtime() {
        let (testdir, _, testfile, _, ft, mut raw, _) = setup_testfile();

        let expected_mtime = filetime::FileTime::from_unix_time(1337, 1_300_000);
        filetime::set_file_mtime(&testfile, expected_mtime).unwrap();

        let file = File::from_raw(&mut raw, &ft);
        assert_eq!(file.fetch_mtime().unwrap(), expected_mtime);
    }

    #[test]
    fn test_mtime_to_disk() {
        let (testdir, _, _, _, ft, mut raw, _) = setup_testfile();
        let expected_mtime = filetime::FileTime::from_unix_time(1337, 1_300_000);
        let mut file = FileMut::from_raw(&mut raw,  &ft);

        file.raw(|raw| raw.update_mtime(Some(expected_mtime)));

        file.as_file().mtime_to_disk().unwrap();

        assert_eq!(file.as_file().fetch_mtime().unwrap(), expected_mtime);
    }

    #[test]
    fn test_compute_hash() {
        let (testdir, _testfile_name, _testfile_abs, testcontent, ft, mut raw, expected_hex) =
            setup_testfile();
        let mut file = File::from_raw(&mut raw, &ft);

        let expected = hex::decode(expected_hex).unwrap();
        assert_eq!(
            compute_hash(
                std::io::Cursor::new(testcontent),
                file.raw(|r| r.hash_type())
            )
            .unwrap(),
            expected
        );

        assert_eq!(file.compute_hash().unwrap(), expected);
        assert_eq!(file.compute_hash_with(HashType::Md5).unwrap(), expected);
    }

    #[test]
    fn test_verify_ok() {
        let (testdir, _testfile_name, _testfile_abs, _testcontent, ft, mut raw, _) =
            setup_testfile();
        let file = File::from_raw(&mut raw, &ft);

        assert_eq!(file.verify().unwrap(), VerifyResult::Ok);
    }

    #[test]
    fn test_verify_missing_hash() {
        let (testdir, _testfile_name, _testfile_abs, _testcontent, ft, mut raw, _) =
            setup_testfile();
        let mut file = FileMut::from_raw(&mut raw, &ft);

        file.raw(|raw| raw.hash_bytes = vec![]);

        // NOTE: using this to circumvent io error not implementing PartialEq
        // this could be used to check the contents as well:
        // assert!(matches!(file.verify(), Err(HashedFileError::IOError(k))
        //         if k.kind() == std::io::ErrorKind::NotFound));
        assert!(matches!(file.as_file().verify(), Err(HashedFileError::MissingHash)));
    }

    #[test]
    fn test_verify_missing_file() {
        let (testdir, _testfile_name, testfile_abs, _testcontent, ft, mut raw, _) = setup_testfile();
        let file = File::from_raw(&mut raw,&ft);

        std::fs::remove_file(testfile_abs).unwrap();

        let result = file.verify();
        assert!(matches!(result, Ok(VerifyResult::FileMissing(std::io::ErrorKind::NotFound))));
    }

    #[test]
    fn test_verify_mismatch_size() {
        let (testdir, _testfile_name, testfile_abs, _testcontent, ft, mut raw, _) = setup_testfile();
        let file = File::from_raw(&mut raw,&ft);

        std::fs::write(testfile_abs, "newsize1234").unwrap();

        let result = file.verify();
        assert!(matches!(result, Ok(VerifyResult::MismatchSize)));
    }

    #[test]
    fn test_verify_mismatch() {
        let (testdir, _testfile_name, testfile_abs, testcontent, ft, mut raw, _) = setup_testfile();
        let file = File::from_raw(&mut raw,&ft);

        let new_content = "foobaz";
        assert_eq!(testcontent.len(), new_content.len());
        std::fs::write(testfile_abs, new_content).unwrap();

        let result = file.verify();
        assert!(matches!(result, Ok(VerifyResult::Mismatch)));
    }

    #[test]
    fn test_verify_mismatch_corrupted() {
        let (testdir, _testfile_name, testfile_abs, testcontent, ft, mut raw, _) = setup_testfile();
        let mut file = FileMut::from_raw(&mut raw, &ft);

        let new_content = "foobaz";
        assert_eq!(testcontent.len(), new_content.len());
        std::fs::write(testfile_abs, new_content).unwrap();
        let new_mtime = file.as_file().fetch_mtime().unwrap();
        file.raw(|raw| raw.update_mtime(Some(new_mtime)));

        let result = file.as_file().verify();
        assert!(matches!(result, Ok(VerifyResult::MismatchCorrupted)));
    }

    #[test]
    fn test_verify_mismatch_outdated() {
        let (testdir, _testfile_name, testfile_abs, testcontent, ft, mut raw, _) = setup_testfile();
        let mut file = FileMut::from_raw(&mut raw,&ft);
        let current_mtime = file.as_file().fetch_mtime().unwrap();
        let outdated_mtime = filetime::FileTime::from_unix_time(
            current_mtime.seconds() - 5, current_mtime.nanoseconds());
        file.raw(|raw| raw.update_mtime(Some(outdated_mtime)));

        let new_content = "foobaz";
        assert_eq!(testcontent.len(), new_content.len());
        std::fs::write(testfile_abs, new_content).unwrap();

        let result = file.as_file().verify();
        assert!(matches!(result, Ok(VerifyResult::MismatchOutdatedHash)));
    }
}
