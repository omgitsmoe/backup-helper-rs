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
use std::string::ToString;

mod parser;
mod serialize;

pub use serialize::sort_serialized;

type Result<T> = std::result::Result<T, HashCollectionError>;

pub struct HashCollection {
    root_dir: Option<PathBuf>,
    // TODO just change this to a String?
    name: Option<OsString>,
    map: HashMap<EntryHandle, FileRaw>,
    mtime: Option<filetime::FileTime>,
    // TODO provide restore_mtime method, so afer relocate + write
    //      one can reset it when nothing else has changed
}

impl HashCollection {
    pub fn new(path: Option<&impl AsRef<Path>>, mtime: Option<filetime::FileTime>) -> Result<HashCollection> {
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
            mtime,
        })
    }

    /// Set the root_dir of the HashCollection.
    /// Note that this will not move any files. Instead it will change the relative
    /// paths, which are serialized.
    pub fn relocate(&mut self, root_dir: impl AsRef<Path>) {
        self.root_dir = Some(root_dir.as_ref().to_path_buf());
    }

    pub fn rename(&mut self, name: &OsStr) {
        // TODO check extension?
        self.name = Some(name.to_owned());
    }

    pub fn set_mtime(&mut self, mtime: Option<filetime::FileTime>) {
        self.mtime = mtime;
    }

    pub fn restore_mtime(&self) -> Result<()> {
        if let (Some(root_dir), Some(name)) = (&self.root_dir, &self.name) {
            if self.mtime.is_none() {
                return Err(HashCollectionError::MissingMTime);
            }

            filetime::set_file_mtime(
                root_dir.join(name),
                self.mtime.expect("should be some, checked above"))?;
            Ok(())
        } else {
            Err(HashCollectionError::MissingPath((self.root_dir.clone(), self.name.clone())))
        }
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

    pub fn from_str(str: &str, collection_path: impl AsRef<Path>, file_tree: &mut FileTree) -> Result<HashCollection> {
        parser::parse(Cursor::new(str), collection_path, file_tree)
    }

    pub fn from_disk(path: &Path, file_tree: &mut FileTree) -> Result<HashCollection> {
        let file = fs::File::open(path)?;
        let mtime = filetime::FileTime::from_last_modification_time(
            &file.metadata()?);
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
            parser::parse(reader, path, file_tree)
        } else {
            let hash_type = HashType::try_from(extension)
                .map_err(|_| HashCollectionError::InvalidExtension(extension.to_os_string()))?;
            parser::parse_single_hash(reader, hash_type, path, file_tree)
        };

        match result {
            Ok(mut hc) => {
                hc.relocate(root);
                hc.rename(file_name);
                hc.set_mtime(Some(mtime));

                Ok(hc)
            }
            Err(e) => Err(e),
        }
    }

    // TODO: flush-able hash collection
    pub fn serialize<W: Write>(&self, writer: &mut W, file_tree: &FileTree) -> Result<()> {
        serialize::serialize(self, writer, file_tree)
    }

    pub fn to_str(&self, file_tree: &FileTree) -> Result<String> {
        let mut buf = vec!();
        self.serialize(&mut buf, file_tree)?;
        String::from_utf8(buf)
            .map_err(|e| HashCollectionError::InvalidUtf8(e.into_bytes()))
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

    /// Merges all entries in `other` into `self`. If there are conflicts:
    /// Keep the data from the __collection__ with the more recent mtime.
    /// An mtime of None is always considered older.
    /// If both mtimes are None then our entries are preferred.
    pub fn merge(&mut self, mut other: Self) -> Result<()> {
        if self.root_dir.is_none() || other.root_dir.is_none() {
            return Err(HashCollectionError::MissingPathInMerge((
                self.root_dir.clone(),
                other.root_dir,
            )));
        }

        // make the paths relative to our root_dir
        // NOTE: should be a nop
        other.relocate(self.root_dir.as_ref().expect("checked above"));

        let keep_ours = match (self.mtime, other.mtime) {
            (Some(our_mtime), Some(their_mtime)) =>
                our_mtime > their_mtime,
            (None, Some(_)) => false,
            (Some(_), None) => true,
            (None, None) => true,
        };
        for (path_handle, theirs) in other.map {
            match self.map.get_mut(&path_handle) {
                Some(ours) => {
                    if !keep_ours {
                        self.map.insert(path_handle, theirs);
                    }
                },
                None => {
                    self.map.insert(path_handle, theirs);
                }
            }
        }

        Ok(())
    }

    /// `include`: Predicate function which determines whether to include the
    ///            Path passed to it in verification. The path is relative
    ///            to the `file_tree.root()`.
    pub fn verify<F, P>(&self, file_tree: &FileTree, include: F, progress: P) -> Result<()>
    where
        F: Fn(&Path) -> bool,
        P: FnMut(&Path, ),
    {
        // NOTE: root??? what is meant here?
        for (path_handle, file_raw) in self.map.iter() {
            let path = file_tree.relative_path(path_handle);
            if !include(&path) {
                continue;
            }

            let file = file_raw.with_context(file_tree);
            // TODO should verify just never error and instead return it as part of VerifyResult?
            //      and what should we pass on to progress?
            match file.verify() {
                Ok(result) => todo!(),
                Err(e) => todo!(),
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
    InvalidUtf8(Vec<u8>),
    InvalidCollectionRoot(Option<PathBuf>),
    AbsolutePath(String),
    MissingPath((Option<PathBuf>, Option<OsString>)),
    MissingPathInMerge((Option<PathBuf>, Option<PathBuf>)),
    MissingMTime,
    FileTreeError(ErrorKind),
    UnsupportedHashType(String),
    IOError(std::io::ErrorKind),
    NonUnicodePath(PathBuf),
    HashedFileError(crate::hashed_file::HashedFileError),
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
            HashCollectionError::InvalidUtf8(_) => {
                write!(f, "invalid utf8")
            }
            HashCollectionError::InvalidCollectionRoot(ref root) => {
                write!(f, "the root path of an collection must be a subpath of the FileTree/ChecksumHelper root, got: {:?}", root)
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
            },
            HashCollectionError::MissingMTime => {
                write!(f, "missing modification time")
            },
            HashCollectionError::HashedFileError(ref e) => {
                write!(f, "hashed file error: {}", e)
            },
        }
    }
}

impl Error for HashCollectionError {
    // return the source for this error, e.g. std::io::Eror if we wrapped it
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            HashCollectionError::HashedFileError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for HashCollectionError {
    fn from(value: std::io::Error) -> Self {
        HashCollectionError::IOError(value.kind())
    }
}

impl From<crate::hashed_file::HashedFileError> for HashCollectionError {
    fn from(value: crate::hashed_file::HashedFileError) -> Self {
        HashCollectionError::HashedFileError(value)
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

    pub fn setup_minimal_hc(root: &Path) -> (HashCollection, FileTree, &'static str) {
        let mut ft = FileTree::new(root).unwrap();

        let mut hc = HashCollection::new(None::<&&str>, None).unwrap();
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
        let ft = FileTree::new(&testdir).unwrap();
        let hc = HashCollection::new(Some(&path), None).unwrap();
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
        let (mut hc, mut ft, expected_serialization) = setup_minimal_hc(&testdir);
        hc.relocate(&testdir);
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
        let (mut hc, mut ft, _) = setup_minimal_hc(&testdir);
        hc.relocate(&testdir);
        hc.rename(&OsString::from("foo.cshd"));

        hc.write(&ft).unwrap();
        let expected_mtime = filetime::FileTime::from_unix_time(
            1337, 0);
        filetime::set_file_mtime(&path, expected_mtime).unwrap();
        let expected_len = ft.len();

        let actual = HashCollection::from_disk(&path, &mut ft).unwrap();
        assert_eq!(actual.root_dir, Some(testdir));
        assert_eq!(actual.name.unwrap(), path.file_name().unwrap());
        assert_eq!(actual.mtime, Some(expected_mtime));
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
        let expected_mtime = filetime::FileTime::from_unix_time(
            1337, 0);
        filetime::set_file_mtime(&path, expected_mtime).unwrap();
        let mut ft = FileTree::new(&testdir).unwrap();

        let hc = HashCollection::from_disk(&path, &mut ft).unwrap();
        assert_eq!(hc.root_dir, Some(testdir));
        assert_eq!(hc.name.unwrap(), path.file_name().unwrap());
        assert_eq!(hc.mtime, Some(expected_mtime));

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

    #[test]
    fn relocate_changes_serialized_paths() {
        let root = Path::new("/foo");
        let mut ft = FileTree::new(root).unwrap();

        let mut hc = HashCollection::new(
            Some(&root.join("foo.cshd")), None).unwrap();
        let path_handle = ft.add_file("./foo/bar/baz/file.txt").unwrap();
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

        let path_handle = ft.add_file("foo/bar/foo.txt").unwrap();
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

        let path_handle = ft.add_file("./foo/xer.mp4").unwrap();
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
1337.00133,1337,sha512,deadbeef foo/bar/baz/file.txt
1212,,md5,aabbccdd foo/bar/foo.txt
,4206969,sha3_512,eeff0011 foo/xer.mp4\n";

        let result = sort_serialized(&hc.to_str(&ft).unwrap()).unwrap();
        assert_eq!(
            result,
            expected_serialization_sorted,
        );

        hc.relocate(Path::new("/foo/foo"));

        let expected_serialization_sorted_relocated = "\
# version 1
1337.00133,1337,sha512,deadbeef bar/baz/file.txt
1212,,md5,aabbccdd bar/foo.txt
,4206969,sha3_512,eeff0011 xer.mp4\n";
        let result = sort_serialized(&hc.to_str(&ft).unwrap()).unwrap();
        assert_eq!(
            result,
            expected_serialization_sorted_relocated,
        );
    }

    #[test]
    fn restore_mtime() {
        let testdir = testdir!();
        let path = testdir.join("foo.cshd");
        std::fs::write(&path, "foo").unwrap();
        let hc =
            HashCollection::new(
                Some(&path),
                Some(filetime::FileTime::from_unix_time(1337, 0)))
            .unwrap();
        let mtime = filetime::FileTime::from_last_modification_time(
            &std::fs::File::open(&path)
                .unwrap()
                .metadata()
                .unwrap());

        hc.restore_mtime().unwrap();


        let new_mtime = filetime::FileTime::from_last_modification_time(
            &std::fs::File::open(&path)
                .unwrap()
                .metadata()
                .unwrap());

        assert_ne!(mtime, new_mtime);
        assert_eq!(new_mtime, hc.mtime.unwrap());
    }

    fn setup_two_collections_for_merge() -> (FileTree, HashCollection, HashCollection) {
        let mut ft = FileTree::new(Path::new("/foo")).unwrap();
        let mut hc = HashCollection::new(
            Some(&"/foo/hc.cshd"),
            Some(filetime::FileTime::from_unix_time(123, 0))).unwrap();
        let path_handle = ft.add_file("foo/file1.txt").unwrap();
        let path_handle2 = ft.add_file("bar/file2.txt").unwrap();
        hc.update(
            path_handle.clone(),
            FileRaw::new(
                path_handle.clone(),
                Some(filetime::FileTime::from_unix_time(222, 0)),
                Some(1337),
                HashType::Md5,
                vec![0xaa, 0xbb, 0xcc, 0xdd],
            ),
        );
        hc.update(
            path_handle2.clone(),
            FileRaw::new(
                path_handle2.clone(),
                Some(filetime::FileTime::from_unix_time(123, 0)),
                Some(1337),
                HashType::Md5,
                vec![0xab, 0xbc, 0xcd, 0xde],
            ),
        );

        let mut other = HashCollection::new(
            Some(&"./foo/other.cshd"), 
            Some(filetime::FileTime::from_unix_time(1337, 0))).unwrap();
        other.update(
            path_handle.clone(),
            FileRaw::new(
                path_handle.clone(),
                Some(filetime::FileTime::from_unix_time(111, 0)),
                None,
                HashType::Md5,
                vec![0xee, 0xff, 0x00, 0x11],
            ),
        );
        other.update(
            path_handle2.clone(),
            FileRaw::new(
                path_handle2.clone(),
                Some(filetime::FileTime::from_unix_time(337, 0)),
                None,
                HashType::Md5,
                vec![0xef, 0xf0, 0x01, 0x12],
            ),
        );

        (ft, hc, other)
    }

    #[test]
    fn merge_keeps_entries_from_newer_collection() {

        let (ft, mut hc, mut other) =
            setup_two_collections_for_merge();
        hc.set_mtime(Some(filetime::FileTime::from_unix_time(123, 0)));
        other.set_mtime(Some(filetime::FileTime::from_unix_time(1337, 0)));

        hc.merge(other).unwrap();

        let serialized = sort_serialized(&hc.to_str(&ft).unwrap()).unwrap();
        assert_eq!(
            serialized,
            "\
# version 1
337,,md5,eff00112 bar/file2.txt
111,,md5,eeff0011 foo/file1.txt
"
        );
    }

    #[test]
    fn merge_keeps_entries_from_collection_with_some_mtime() {

        let (ft, mut hc, mut other) =
            setup_two_collections_for_merge();
        hc.set_mtime(Some(filetime::FileTime::from_unix_time(123, 0)));
        other.set_mtime(None);

        hc.merge(other).unwrap();

        let serialized = sort_serialized(&hc.to_str(&ft).unwrap()).unwrap();
        assert_eq!(
            serialized,
            "\
# version 1
123,1337,md5,abbccdde bar/file2.txt
222,1337,md5,aabbccdd foo/file1.txt
"
        );
    }

    #[test]
    fn merge_keeps_entries_from_self_if_no_mtime() {

        let (ft, mut hc, mut other) =
            setup_two_collections_for_merge();
        hc.set_mtime(None);
        other.set_mtime(None);

        hc.merge(other).unwrap();

        let serialized = sort_serialized(&hc.to_str(&ft).unwrap()).unwrap();
        assert_eq!(
            serialized,
            "\
# version 1
123,1337,md5,abbccdde bar/file2.txt
222,1337,md5,aabbccdd foo/file1.txt
"
        );
    }

    #[test]
    fn merge_adds_entries_in_other() {
        let mut ft = FileTree::new(Path::new("/foo")).unwrap();

        let mut hc = HashCollection::new(Some(&"/foo/hc.cshd"), None).unwrap();
        let path_handle = ft.add_file("foo/file1.txt").unwrap();
        let path_handle2 = ft.add_file("bar/file2.txt").unwrap();
        hc.update(
            path_handle.clone(),
            FileRaw::new(
                path_handle.clone(),
                Some(filetime::FileTime::from_unix_time(222, 0)),
                Some(1337),
                HashType::Md5,
                vec![0xaa, 0xbb, 0xcc, 0xdd],
            ),
        );

        let mut other = HashCollection::new(Some(&"./foo/other.cshd"), None).unwrap();
        other.update(
            path_handle2.clone(),
            FileRaw::new(
                path_handle2.clone(),
                Some(filetime::FileTime::from_unix_time(337, 0)),
                None,
                HashType::Md5,
                vec![0xee, 0xff, 0x00, 0x11],
            ),
        );

        hc.merge(other).unwrap();

        let serialized = sort_serialized(&hc.to_str(&ft).unwrap()).unwrap();
        assert_eq!(
            serialized,
            "\
# version 1
337,,md5,eeff0011 bar/file2.txt
222,1337,md5,aabbccdd foo/file1.txt
"
        );
    }
}
