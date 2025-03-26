use crate::file_tree::{EntryHandle, ErrorKind, FileTree};
use crate::hashed_file::{FileRaw, HashType};

use log::{debug, error, info, warn};

use std::cmp::{Eq, PartialEq};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{BufReader, Cursor, Write};
use std::path::{Path, PathBuf};

mod parser;
mod serialize;

pub use serialize::sort_serialized;

type Result<T> = std::result::Result<T, HashCollectionError>;

pub struct HashCollection {
    root_dir: Option<PathBuf>,
    // TODO just change this to a String?
    name: Option<OsString>,
    map: HashMap<EntryHandle, FileRaw>,
    // TODO needs mtime
    // TODO provide restore_mtime method, so afer relocate + write
    //      one can reset it when nothing else has changed
}

// TODO verify method
impl HashCollection {
    pub fn new(path: Option<&impl AsRef<Path>>) -> Result<HashCollection> {
        Ok(HashCollection {
            map: HashMap::new(),
            name: match path {
                Some(p) => Some(
                    p.as_ref()
                        .file_name()
                        .ok_or_else(|| HashCollectionError::InvalidPath(p.as_ref().to_path_buf()))?
                        .to_owned(),
                ),
                None => None,
            },
            root_dir: match path {
                Some(p) => Some(
                    p.as_ref()
                        .parent()
                        .ok_or_else(|| HashCollectionError::InvalidPath(p.as_ref().to_path_buf()))?
                        .to_owned(),
                ),
                None => None,
            },
        })
    }

    pub fn relocate(&mut self, root_dir: &Path, file_tree: &mut FileTree) -> Result<()> {
        match self.root_dir {
            None => self.root_dir = Some(root_dir.to_path_buf()),
            Some(ref old_root) => {
                todo!("transform all paths to add new_root.relative_to(old_root)")
            }
        }

        Ok(())
    }

    pub fn rename(&mut self, name: &OsStr) {
        // TODO check extension?
        self.name = Some(name.to_owned());
    }

    pub fn update(&mut self, path_handle: EntryHandle, hashed_file: FileRaw) {
        self.map.insert(path_handle, hashed_file);
    }

    pub fn get(&mut self, path_handle: &EntryHandle) -> Option<&FileRaw> {
        self.map.get(path_handle)
    }

    pub fn get_mut(&mut self, path_handle: &EntryHandle) -> Option<&mut FileRaw> {
        self.map.get_mut(path_handle)
    }

    pub fn from_str(str: &str, file_tree: &mut FileTree) -> Result<HashCollection> {
        parser::parse(Cursor::new(str), file_tree)
    }

    pub fn from_disk(path: &Path, file_tree: &mut FileTree) -> Result<HashCollection> {
        let file = fs::File::open(path)?;
        let root = path
            .parent()
            .ok_or_else(|| HashCollectionError::InvalidPath(path.to_owned()))?;
        let file_name = path
            .file_name()
            .ok_or_else(|| HashCollectionError::InvalidPath(path.to_owned()))?;
        let reader = BufReader::new(file);

        let extension = path
            .extension()
            .ok_or_else(|| HashCollectionError::InvalidExtension(OsString::new()))?;
        let result = if extension == OsStr::new("cshd") {
            parser::parse(reader, file_tree)
        } else {
            let hash_type = HashType::try_from(extension)
                .map_err(|_| HashCollectionError::InvalidExtension(extension.to_os_string()))?;
            parser::parse_single_hash(reader, hash_type, file_tree)
        };

        match result {
            Ok(mut hc) => {
                hc.relocate(root, file_tree)
                    .expect("must succeed, since root_dir should be None");
                hc.rename(file_name);

                Ok(hc)
            }
            Err(e) => Err(e),
        }
    }

    // TODO: flush-able hash collection
    pub fn serialize<W: Write>(&self, writer: &mut W, file_tree: &FileTree) -> Result<()> {
        serialize::serialize(self, writer, file_tree)
    }

    pub fn write(&self, file_tree: &FileTree) -> Result<()> {
        if self.root_dir.is_none() || self.name.is_none() {
            return Err(HashCollectionError::MissingPath((
                self.root_dir.clone(),
                self.name.clone(),
            )));
        }

        let full_path = self
            .root_dir
            .as_ref()
            .expect("was checked above")
            .join(self.name.as_ref().expect("was checked above"));
        let file = fs::File::create_new(full_path)?;
        let mut buf_writer = std::io::BufWriter::new(file);
        self.serialize(&mut buf_writer, file_tree)
    }

    pub fn flush(&mut self, file_tree: &FileTree) -> Result<()> {
        todo!("flushes the current entries to disk")
    }

    /// Merges all entries in `other` into `self`
    pub fn merge(&mut self, mut other: Self, file_tree: &mut FileTree) -> Result<()> {
        if self.root_dir.is_none() || other.root_dir.is_none() {
            return Err(HashCollectionError::MissingPathInMerge((
                self.root_dir.clone(),
                other.root_dir,
            )));
        }

        // make the paths relative to our root_dir
        other.relocate(self.root_dir.as_ref().expect("checked above"), file_tree)?;

        for (path_handle, theirs) in other.map {
            match self.map.get_mut(&path_handle) {
                Some(ours) => {}
                None => {
                    self.map.insert(path_handle, theirs);
                }
            }
        }

        Ok(())
    }
}

fn is_path_above_hash_file(path: &str) -> bool {
    let mut depth = 0;
    for component in path.split(&['/', '\\']) {
        if component == ".." {
            depth -= 1;
        } else if component == "." {
            continue;
        } else {
            depth += 1;
        }

        if depth < 0 {
            return true;
        }
    }

    depth < 0
}

#[derive(Debug, Eq, PartialEq)]
pub enum HashCollectionError {
    InvalidPath(PathBuf),
    InvalidVersionHeader(String),
    InvalidHashLine((String, String)),
    InvalidSingleHashLine((String, String)),
    InvalidExtension(OsString),
    AbsolutePath(String),
    MissingPath((Option<PathBuf>, Option<OsString>)),
    MissingPathInMerge((Option<PathBuf>, Option<PathBuf>)),
    FileTreeError(ErrorKind),
    UnsupportedHashType(String),
    IOError(std::io::ErrorKind),
    NonUnicodePath(PathBuf),
}

impl fmt::Display for HashCollectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HashCollectionError::InvalidPath(ref p) => write!(f, "invalid file path: {:?}", p),
            HashCollectionError::InvalidHashLine((ref current, ref rest)) => {
                write!(f, "invalid hash line: current {} rest {}", current, rest)
            }
            HashCollectionError::InvalidSingleHashLine((ref current, ref rest)) => {
                write!(f, "invalid single hash line! expected '<hash_hex> <path>', got: current {} rest {}", current, rest)
            }
            HashCollectionError::InvalidVersionHeader(ref l) => {
                write!(f, "invalid version header: {}", l)
            }
            HashCollectionError::InvalidExtension(ref l) => {
                write!(
                    f,
                    "invalid extension '{:?}', expected 'cshd' or the name of a known hash type",
                    l
                )
            }
            HashCollectionError::AbsolutePath(ref p) => write!(f, "absolute path found: {}", p),
            HashCollectionError::FileTreeError(ref p) => write!(f, "file tree error: {:?}", p),
            HashCollectionError::UnsupportedHashType(ref t) => {
                write!(f, "unsupported hash type: {}", t)
            }
            HashCollectionError::IOError(ref e) => {
                write!(f, "io error: {}", e)
            }
            HashCollectionError::NonUnicodePath(ref e) => {
                write!(f, "non-unicode path error: {:?}", e)
            }
            HashCollectionError::MissingPath((ref root, ref name)) => {
                write!(
                    f,
                    "missing hash file collection path: root {:?} name {:?}",
                    root, name
                )
            }
            HashCollectionError::MissingPathInMerge((ref ours, ref theirs)) => {
                write!(
                    f,
                    "can't merge with a missing root path: ours {:?} theirs {:?}",
                    ours, theirs
                )
            }
        }
    }
}

impl Error for HashCollectionError {
    // return the source for this error, e.g. std::io::Eror if we wrapped it
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            _ => None,
        }
    }
}

impl From<std::io::Error> for HashCollectionError {
    fn from(value: std::io::Error) -> Self {
        HashCollectionError::IOError(value.kind())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hashed_file::HashType;
    use crate::test_utils::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_path_above_hash_file() {
        assert!(is_path_above_hash_file("./.."));
        // NOTE: this exists the "root" so we don't know if we enter the same
        //       directory again
        assert!(is_path_above_hash_file("./../foo/"));
        assert!(is_path_above_hash_file(".."));
        assert!(is_path_above_hash_file("../foo/bar/baz"));
        assert!(is_path_above_hash_file("./foo/bar/../../../xer"));
        assert!(is_path_above_hash_file("foo/./../baz/../.."));

        assert!(!is_path_above_hash_file("foo"));
        assert!(!is_path_above_hash_file("./foo"));
        assert!(!is_path_above_hash_file("././"));
        assert!(!is_path_above_hash_file("././././foo"));
        assert!(!is_path_above_hash_file("./foo/./../baz/.."));
        assert!(!is_path_above_hash_file("foo/./../baz/.."));
        assert!(!is_path_above_hash_file("./foo/././baz/.."));
    }

    pub fn setup_minimal_hc() -> (HashCollection, FileTree, &'static str) {
        let mut ft = FileTree::new();

        let mut hc = HashCollection::new(None::<&&str>).unwrap();
        let path_handle = ft.add_file("./foo/bar/baz.txt").unwrap();
        hc.update(
            path_handle.clone(),
            FileRaw::new(
                path_handle.clone(),
                Some(filetime::FileTime::from_unix_time(1337, 1_330_000)),
                Some(1337),
                HashType::Sha512,
                vec![0xde, 0xad, 0xbe, 0xef],
            ),
        );

        let path_handle = ft.add_file("bar/foo.txt").unwrap();
        hc.update(
            path_handle.clone(),
            FileRaw::new(
                path_handle.clone(),
                Some(filetime::FileTime::from_unix_time(1212, 0)),
                None,
                HashType::Md5,
                vec![0xaa, 0xbb, 0xcc, 0xdd],
            ),
        );

        let path_handle = ft.add_file("./xer.mp4").unwrap();
        hc.update(
            path_handle.clone(),
            FileRaw::new(
                path_handle.clone(),
                None,
                Some(4206969),
                HashType::Sha3_512,
                vec![0xee, 0xff, 0x00, 0x11],
            ),
        );

        let expected_serialization_sorted = "\
# version 1
1212,,md5,aabbccdd bar/foo.txt
1337.00133,1337,sha512,deadbeef foo/bar/baz.txt
,4206969,sha3_512,eeff0011 xer.mp4\n";

        (hc, ft, expected_serialization_sorted)
    }

    #[test]
    fn test_write_never_overwrites() {
        let testdir = testdir!();
        let path = testdir.join("foo.cshd");
        let ft = FileTree::new();
        let hc = HashCollection::new(Some(&path)).unwrap();
        fs::write(path, "foo").unwrap();

        let result = hc.write(&ft);

        assert_eq!(
            result,
            Err(HashCollectionError::IOError(
                std::io::ErrorKind::AlreadyExists
            ))
        );
    }

    #[test]
    fn test_write() {
        let testdir = testdir!();
        let path = testdir.join("foo.cshd");
        let (mut hc, mut ft, expected_serialization) = setup_minimal_hc();
        hc.relocate(&testdir, &mut ft).unwrap();
        hc.rename(&OsString::from("foo.cshd"));

        hc.write(&ft).unwrap();

        let read_back = fs::read_to_string(path).unwrap();
        assert_eq!(
            serialize::sort_serialized(&read_back).unwrap(),
            expected_serialization,
        );
    }

    #[test]
    fn test_from_disk() {
        let testdir = testdir!();
        let path = testdir.join("foo.cshd");
        let (mut hc, mut ft, _) = setup_minimal_hc();
        hc.relocate(&testdir, &mut ft).unwrap();
        hc.rename(&OsString::from("foo.cshd"));

        hc.write(&ft).unwrap();
        let expected_len = ft.len();

        let actual = HashCollection::from_disk(&path, &mut ft).unwrap();
        assert_eq!(actual.root_dir, Some(testdir));
        assert_eq!(actual.name.unwrap(), path.file_name().unwrap());
        assert_eq!(ft.len(), expected_len);

        for (ph, f) in actual.map {
            let expected = hc.get(&ph).unwrap();
            assert_eq!(expected, &f);
        }

        assert_eq!(
            to_file_list(ft),
            "FileTree{
  foo/bar/baz.txt
  bar/foo.txt
  xer.mp4
}"
        );
    }

    #[test]
    fn test_from_disk_single_hash() {
        let testdir = testdir!();
        let hash_type = HashType::Sha512;
        let path = testdir.join(format!("foo.{}", hash_type.to_str()));
        let hash_hex = "90b834a83748223190dd1cce445bb1e7582e55948234e962aba9a3004cc558ce061c865a4fae255e048768e7d7011f958dad463243bb3560ee49335ec4c9e8a0";
        let single_hash = format!(
            "\
{} .gitignore
abcdefff foo/bar/baz
abcdefff foo/xer.mp4
\
        ",
            hash_hex
        );
        fs::write(&path, single_hash).unwrap();
        let mut ft = FileTree::new();

        let hc = HashCollection::from_disk(&path, &mut ft).unwrap();

        let key = ft.find(".gitignore").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new(".gitignore"));
        assert_eq!(hf.mtime_str(), None);
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), hash_type);
        assert_eq!(hf.hash_bytes(), hex::decode(hash_hex).unwrap());

        let key = ft.find("foo/bar/baz").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new("foo/bar/baz"));
        assert_eq!(hf.mtime_str(), None);
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), hash_type);
        assert_eq!(hf.hash_bytes(), vec![0xab, 0xcd, 0xef, 0xff]);

        let key = ft.find("foo/xer.mp4").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new("foo/xer.mp4"));
        assert_eq!(hf.mtime_str(), None);
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), hash_type);
        assert_eq!(hf.hash_bytes(), vec![0xab, 0xcd, 0xef, 0xff]);

        assert_eq!(
            to_file_list(ft),
            "FileTree{
  .gitignore
  foo/bar/baz
  foo/xer.mp4
}"
        );
    }
}
