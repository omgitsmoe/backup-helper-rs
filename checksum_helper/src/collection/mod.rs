use crate::file_tree::{EntryHandle, ErrorKind, FileTree};
use crate::hashed_file::FileRaw;

use log::{debug, error, info, warn};

use std::cmp::{Eq, PartialEq};
use std::collections::HashMap;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{Cursor, Write};
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
}

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

    pub fn relocate(&mut self, root_dir: &Path) -> Result<()> {
        match self.root_dir {
            None => self.root_dir = Some(root_dir.to_path_buf()),
            Some(ref old_root) => {
                todo!("transform all paths to add new_root.relative_to(old_root)")
            }
        }

        Ok(())
    }

    pub fn rename(&mut self, name: &OsStr) {
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
    AbsolutePath(String),
    MissingPath((Option<PathBuf>, Option<OsString>)),
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
            HashCollectionError::InvalidVersionHeader(ref l) => {
                write!(f, "invalid version header: {}", l)
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
    use crate::hashed_file::HashType;
    use super::*;
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

    #[test]
    fn test_from_str_line_handles_empty_string() {
        let mut ft = FileTree::new();
        assert!(HashCollection::from_str("", &mut ft,)
            .inspect_err(|e| println!("{}", e))
            .is_ok());

        assert!(HashCollection::from_str("\n", &mut ft,)
            .inspect_err(|e| println!("{}", e))
            .is_ok());
    }

    #[test]
    fn test_from_str_line_version_1() {
        let mut ft = FileTree::new();
        let mtime = "1673815645.7979772";
        let size = 1337;
        let hash_type = HashType::Sha512;
        let hash_hex = "90b834a83748223190dd1cce445bb1e7582e55948234e962aba9a3004cc558ce061c865a4fae255e048768e7d7011f958dad463243bb3560ee49335ec4c9e8a0";
        let file_path = ".gitignore";
        let hc = HashCollection::from_str(
            &format!(
                "\
# version 1
{},{},{},{} {}
0,1337,md5,abcdef foo/bar/baz
,,sha3_256,abcdefff foo/xer.mp4
\
        ",
                mtime,
                size,
                hash_type.to_str(),
                hash_hex,
                file_path
            ),
            &mut ft,
        )
        .inspect_err(|e| println!("{}", e))
        .unwrap();

        let key = ft.find(".gitignore").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new(file_path));
        assert_eq!(hf.mtime_str(), Some(mtime.to_owned()));
        assert_eq!(hf.size(), Some(size));
        assert_eq!(hf.hash_type(), hash_type);
        assert_eq!(hf.hash_bytes(), hex::decode(hash_hex).unwrap());

        let key = ft.find("foo/xer.mp4").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new("foo/xer.mp4"));
        assert_eq!(hf.mtime_str(), None);
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), HashType::Sha3_256);
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

    #[test]
    fn test_from_str_line_version_0() {
        let mut ft = FileTree::new();
        let mtime = "1673815645.7979772";
        let hash_type = HashType::Sha512;
        let hash_hex = "90b834a83748223190dd1cce445bb1e7582e55948234e962aba9a3004cc558ce061c865a4fae255e048768e7d7011f958dad463243bb3560ee49335ec4c9e8a0";
        let file_path = ".gitignore";
        let hc = HashCollection::from_str(
            &format!(
                "\
{},{},{} {}
0,md5,abcdefff foo/bar/baz
,sha3_256,abcdefff foo/xer.mp4
\
        ",
                mtime,
                hash_type.to_str(),
                hash_hex,
                file_path
            ),
            &mut ft,
        )
        .inspect_err(|e| println!("{}", e))
        .unwrap();

        let key = ft.find(".gitignore").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new(file_path));
        assert_eq!(hf.mtime_str(), Some(mtime.to_owned()));
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), hash_type);
        assert_eq!(hf.hash_bytes(), hex::decode(hash_hex).unwrap());

        let key = ft.find("foo/xer.mp4").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new("foo/xer.mp4"));
        assert_eq!(hf.mtime_str(), None);
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), HashType::Sha3_256);
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

    pub fn setup_minimal_hc() -> (HashCollection, FileTree, &'static str) {
        let mut ft = FileTree::new();

        let mut hc = HashCollection::new(None::<&&str>).unwrap();
        let path_handle = ft.add_file("./foo/bar/baz.txt").unwrap();
        hc.update(
            path_handle.clone(),
            FileRaw::new(
                path_handle.clone(),
                Some(filetime::FileTime::from_unix_time(1337, 1_337_000)),
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
1337.001337,1337,sha512,deadbeef foo/bar/baz.txt
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
        let (mut hc, ft, expected_serialization) = setup_minimal_hc();
        hc.relocate(&testdir).unwrap();
        hc.rename(&OsString::from("foo.cshd"));

        hc.write(&ft)
            .unwrap();

        let read_back = fs::read_to_string(path).unwrap();
        assert_eq!(
            serialize::sort_serialized(&read_back).unwrap(),
            expected_serialization,
        );
    }
}
