use crate::file_tree::{EntryHandle, ErrorKind, FileTree};
use crate::hashed_file::{FileRaw, File, HashType, VerifyResult};
use crate::alias::{Map, MapIter};

use log::{debug, error, info, warn};

use std::cmp::{Eq, PartialEq};
use std::convert::TryFrom;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{BufReader, Cursor, Write};
use std::path::{Path, PathBuf};

mod parser;
mod serialize;
mod writer;

pub use serialize::sort_serialized;
pub use writer::HashCollectionWriter;

type Result<T> = std::result::Result<T, HashCollectionError>;

pub struct HashCollection {
    root_dir: Option<PathBuf>,
    // TODO just change this to a String?
    name: Option<OsString>,
    map: Map<EntryHandle, FileRaw>,
    mtime: Option<filetime::FileTime>,
    // TODO provide restore_mtime method, so afer relocate + write
    //      one can reset it when nothing else has changed
}

// TODO: add datetime/mtime of the collection itself to the file, then we don't have to
//       rely on mtime for cshd >=v1 files
impl HashCollection {
    pub fn new(
        path: Option<&impl AsRef<Path>>,
        mtime: Option<filetime::FileTime>,
    ) -> Result<HashCollection> {
        Ok(HashCollection {
            map: Map::new(),
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

    pub fn full_path(&self) -> Result<PathBuf> {
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
        Ok(full_path)
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
                self.mtime.expect("should be some, checked above"),
            )?;
            Ok(())
        } else {
            Err(HashCollectionError::MissingPath((
                self.root_dir.clone(),
                self.name.clone(),
            )))
        }
    }

    pub fn update(&mut self, path_handle: EntryHandle, hashed_file: FileRaw) {
        self.map.insert(path_handle, hashed_file);
    }

    pub fn contains_path(&self, path: impl AsRef<Path>, file_tree: &FileTree) -> bool {
        let path = path.as_ref();
        assert!(path.is_relative(), "Only paths relative to file_tree allowed!");
        let handle = file_tree.find(path);
        if handle.is_none() {
            return false;
        }

        self.get(&handle.unwrap()).is_some()
    }

    pub fn get(&self, path_handle: &EntryHandle) -> Option<&FileRaw> {
        self.map.get(path_handle)
    }

    pub fn get_mut(&mut self, path_handle: &EntryHandle) -> Option<&mut FileRaw> {
        self.map.get_mut(path_handle)
    }

    pub fn filter_missing(&mut self) -> Result<()> {
        todo!("filter out all files that do no longer exist")
    }

    pub fn from_str(
        str: &str,
        collection_path: impl AsRef<Path>,
        file_tree: &mut FileTree,
    ) -> Result<HashCollection> {
        parser::parse(Cursor::new(str), collection_path, file_tree)
    }

    // TODO separate into Reader?
    pub fn from_disk(path: &Path, file_tree: &mut FileTree) -> Result<HashCollection> {
        let file = fs::File::open(path)?;
        let mtime = filetime::FileTime::from_last_modification_time(&file.metadata()?);
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

    pub fn serialize<W: Write>(&self, writer: &mut W, file_tree: &FileTree) -> Result<()> {
        serialize::serialize(self, writer, file_tree, true)
    }

    pub fn to_str(&self, file_tree: &FileTree) -> Result<String> {
        let mut buf = vec![];
        self.serialize(&mut buf, file_tree)?;
        String::from_utf8(buf).map_err(|e| HashCollectionError::InvalidUtf8(e.into_bytes()))
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
            (Some(our_mtime), Some(their_mtime)) => our_mtime > their_mtime,
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
                }
                None => {
                    self.map.insert(path_handle, theirs);
                }
            }
        }

        Ok(())
    }

    /// Verify all files matching predicated `include` in the `HashCollection`
    ///
    /// Warning: The passed `file_tree` has to match the file_tree used for the
    ///          added files in the `HashCollection`.
    ///
    /// `include`: Predicate function which determines whether to include the
    ///            Path passed to it in verification. The path is relative
    ///            to the `file_tree.root()`.
    /// `progress`: Progress callback that receives a `VerifyProgress`
    ///             before and after procressing the file.
    pub fn verify<F, P>(&self, file_tree: &FileTree, include: F, mut progress: P) -> Result<()>
    where
        F: Fn(&Path) -> bool,
        P: FnMut(VerifyProgress),
    {
        let tree_root = self.root_dir.as_ref().ok_or_else(|| {
            HashCollectionError::MissingPath((self.root_dir.clone(), self.name.clone()))
        })?;
        let files_total = self.map.len() as u64;
        let size_total_bytes: u64 = self.map.values().map(|file| file.size().unwrap_or(0)).sum();
        let mut size_processed_bytes = 0u64;

        for (idx, (path_handle, file_raw)) in self.map.iter().enumerate() {
            let path = file_tree.relative_path(path_handle);
            if !include(&path) {
                continue;
            }

            progress(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root,
                relative_path: &path,
                file_number_processed: idx as u64,
                file_number_total: files_total,
                size_processed_bytes,
                size_total_bytes,
            }));

            let file = file_raw.with_context(file_tree);
            // NOTE: Only errors that need to stop the verification progress can come from
            //       verify, so it's fine to use `?` here. For everything else a corresponding
            //       VerifyResult is used.
            // TODO: pass along
            let result = file.verify(|_| {})?;
            size_processed_bytes += file.raw(|f| f.size().unwrap_or(0));

            progress(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root,
                    relative_path: &path,
                    file_number_processed: (idx + 1) as u64,
                    file_number_total: files_total,
                    size_processed_bytes,
                    size_total_bytes,
                },
                result: &result,
            }));
        }

        Ok(())
    }

    pub fn iter_with_context<'a>(&'a self, file_tree: &'a FileTree) -> HashCollectionIter<'a> {
        HashCollectionIter {
            map_iter: self.map.iter(),
            file_tree,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum VerifyProgress<'a> {
    // TODO: Read updating bytes read/total
    Pre(VerifyProgressCommon<'a>),
    Post(VerifyProgressPost<'a>),
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyProgressCommon<'a> {
    tree_root: &'a Path,
    relative_path: &'a Path,
    file_number_processed: u64,
    file_number_total: u64,
    size_processed_bytes: u64,
    size_total_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyProgressPost<'a> {
    progress: VerifyProgressCommon<'a>,
    result: &'a VerifyResult,
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

pub struct HashCollectionIter<'a> {
    map_iter: MapIter<'a, EntryHandle, FileRaw>,
    file_tree: &'a FileTree,
}

impl<'a> Iterator for HashCollectionIter<'a> {
    type Item = (PathBuf, File<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((handle, file_raw)) = self.map_iter.next() {
            let path = self.file_tree.absolute_path(handle);
            let file = File::from_raw(file_raw, self.file_tree);
            return Some((path, file));
        }
        None
    }
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
            }
            HashCollectionError::MissingMTime => {
                write!(f, "missing modification time")
            }
            HashCollectionError::HashedFileError(ref e) => {
                write!(f, "hashed file error: {}", e)
            }
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
pub mod test {
    use super::*;
    use crate::hashed_file::HashType;
    use crate::test_utils::*;
    use hashes::sha2::sha512;
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
    fn test_from_disk() {
        let testdir = testdir!();
        let path = testdir.join("foo.cshd");
        let (mut hc, mut ft, _) = setup_minimal_hc(&testdir);
        hc.relocate(&testdir);
        hc.rename(&OsString::from("foo.cshd"));

        let mut writer = writer::HashCollectionWriter::new();
        writer.write(&mut hc, &ft).unwrap();

        let expected_mtime = filetime::FileTime::from_unix_time(1337, 0);
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
            to_file_list(&ft),
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
        let expected_mtime = filetime::FileTime::from_unix_time(1337, 0);
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
            to_file_list(&ft),
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

        let mut hc = HashCollection::new(Some(&root.join("foo.cshd")), None).unwrap();
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
        assert_eq!(result, expected_serialization_sorted,);

        hc.relocate(Path::new("/foo/foo"));

        let expected_serialization_sorted_relocated = "\
# version 1
1337.00133,1337,sha512,deadbeef bar/baz/file.txt
1212,,md5,aabbccdd bar/foo.txt
,4206969,sha3_512,eeff0011 xer.mp4\n";
        let result = sort_serialized(&hc.to_str(&ft).unwrap()).unwrap();
        assert_eq!(result, expected_serialization_sorted_relocated,);
    }

    #[test]
    fn restore_mtime() {
        let testdir = testdir!();
        let path = testdir.join("foo.cshd");
        std::fs::write(&path, "foo").unwrap();
        let hc = HashCollection::new(
            Some(&path),
            Some(filetime::FileTime::from_unix_time(1337, 0)),
        )
        .unwrap();
        let mtime = filetime::FileTime::from_last_modification_time(
            &std::fs::File::open(&path).unwrap().metadata().unwrap(),
        );

        hc.restore_mtime().unwrap();

        let new_mtime = filetime::FileTime::from_last_modification_time(
            &std::fs::File::open(&path).unwrap().metadata().unwrap(),
        );

        assert_ne!(mtime, new_mtime);
        assert_eq!(new_mtime, hc.mtime.unwrap());
    }

    fn setup_two_collections_for_merge() -> (FileTree, HashCollection, HashCollection) {
        let mut ft = FileTree::new(Path::new("/foo")).unwrap();
        let mut hc = HashCollection::new(
            Some(&"/foo/hc.cshd"),
            Some(filetime::FileTime::from_unix_time(123, 0)),
        )
        .unwrap();
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
            Some(filetime::FileTime::from_unix_time(1337, 0)),
        )
        .unwrap();
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
        let (ft, mut hc, mut other) = setup_two_collections_for_merge();
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
        let (ft, mut hc, mut other) = setup_two_collections_for_merge();
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
        let (ft, mut hc, mut other) = setup_two_collections_for_merge();
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

    #[test]
    fn verify() {
        let testdir = testdir!();
        fs::create_dir_all(testdir.join("foo/bar")).unwrap();
        let mut ft = FileTree::new(&testdir).unwrap();

        let mut hc = HashCollection::new(None::<&&str>, None).unwrap();
        hc.relocate(&testdir);

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
        fs::write(testdir.join("foo/bar/baz.txt"), "").unwrap();

        let path_handle = ft.add_file("./foo/bar/baz2.txt").unwrap();
        hc.update(
            path_handle.clone(),
            FileRaw::new(
                path_handle.clone(),
                Some(filetime::FileTime::from_unix_time(1337, 1_330_000)),
                Some(3),
                HashType::Sha512,
                vec![
                    0xf7, 0xfb, 0xba, 0x6e, 0x06, 0x36, 0xf8, 0x90, 0xe5, 0x6f, 0xbb, 0xf3, 0x28,
                    0x3e, 0x52, 0x4c, 0x6f, 0xa3, 0x20, 0x4a, 0xe2, 0x98, 0x38, 0x2d, 0x62, 0x47,
                    0x41, 0xd0, 0xdc, 0x66, 0x38, 0x32, 0x6e, 0x28, 0x2c, 0x41, 0xbe, 0x5e, 0x42,
                    0x54, 0xd8, 0x82, 0x07, 0x72, 0xc5, 0x51, 0x8a, 0x2c, 0x5a, 0x8c, 0x0c, 0x7f,
                    0x7e, 0xda, 0x19, 0x59, 0x4a, 0x7e, 0xb5, 0x39, 0x45, 0x3e, 0x1e, 0xd7,
                ],
            ),
        );
        fs::write(testdir.join("foo/bar/baz2.txt"), "foo").unwrap();

        let path_handle = ft.add_file("./foo/bar/baz3.txt").unwrap();
        hc.update(
            path_handle.clone(),
            FileRaw::new(
                path_handle.clone(),
                Some(filetime::FileTime::from_unix_time(1337, 1_330_000)),
                Some(10),
                HashType::Sha512,
                vec![0xde, 0xad, 0xbe, 0xef],
            ),
        );
        fs::write(testdir.join("foo/bar/baz3.txt"), "0123456789").unwrap();

        let mut idx = 0u64;
        hc.verify(
            &ft,
            |_| true,
            |p| {
                match (idx, p) {
                    (0, VerifyProgress::Pre(p)) => {
                        assert_eq!(p.tree_root, testdir);
                        assert_eq!(p.relative_path, Path::new("foo/bar/baz.txt"));
                        assert_eq!(p.file_number_processed, 0);
                        assert_eq!(p.file_number_total, 3);
                        assert_eq!(p.size_processed_bytes, 0);
                        assert_eq!(p.size_total_bytes, 1350);
                    }
                    (1, VerifyProgress::Post(p)) => {
                        assert_eq!(p.progress.tree_root, testdir);
                        assert_eq!(p.progress.relative_path, Path::new("foo/bar/baz.txt"));
                        assert_eq!(p.progress.file_number_processed, 1);
                        assert_eq!(p.progress.file_number_total, 3);
                        assert_eq!(p.progress.size_processed_bytes, 1337);
                        assert_eq!(p.progress.size_total_bytes, 1350);
                        assert_eq!(
                            p.result,
                            &VerifyResult::MismatchSize,
                        );
                    }
                    (2, VerifyProgress::Pre(p)) => {
                        assert_eq!(p.tree_root, testdir);
                        assert_eq!(p.relative_path, Path::new("foo/bar/baz2.txt"));
                        assert_eq!(p.file_number_processed, 1);
                        assert_eq!(p.file_number_total, 3);
                        assert_eq!(p.size_processed_bytes, 1337);
                        assert_eq!(p.size_total_bytes, 1350);
                    }
                    (3, VerifyProgress::Post(p)) => {
                        assert_eq!(p.progress.tree_root, testdir);
                        assert_eq!(p.progress.relative_path, Path::new("foo/bar/baz2.txt"));
                        assert_eq!(p.progress.file_number_processed, 2);
                        assert_eq!(p.progress.file_number_total, 3);
                        assert_eq!(p.progress.size_processed_bytes, 1340);
                        assert_eq!(p.progress.size_total_bytes, 1350);
                        assert_eq!(
                            p.result,
                            &VerifyResult::Ok
                        );
                    }
                    (4, VerifyProgress::Pre(p)) => {
                        assert_eq!(p.tree_root, testdir);
                        assert_eq!(p.relative_path, Path::new("foo/bar/baz3.txt"));
                        assert_eq!(p.file_number_processed, 2);
                        assert_eq!(p.file_number_total, 3);
                        assert_eq!(p.size_processed_bytes, 1340);
                        assert_eq!(p.size_total_bytes, 1350);
                    }
                    (5, VerifyProgress::Post(p)) => {
                        assert_eq!(p.progress.tree_root, testdir);
                        assert_eq!(p.progress.relative_path, Path::new("foo/bar/baz3.txt"));
                        assert_eq!(p.progress.file_number_processed, 3);
                        assert_eq!(p.progress.file_number_total, 3);
                        assert_eq!(p.progress.size_processed_bytes, 1350);
                        assert_eq!(p.progress.size_total_bytes, 1350);
                        assert_eq!(
                            p.result,
                            &VerifyResult::MismatchOutdatedHash
                        );
                    }
                    _ => unreachable!(),
                }

                idx += 1;
            },
        )
        .unwrap();

        assert!(idx % 2 == 0);
    }

    #[test]
    fn not_contained_when_not_in_file_tree() {
        let ft = FileTree::new("/foo/bar").unwrap();
        let hc = HashCollection::new(None::<&&str>, None).unwrap();
        assert!(!hc.contains_path("baz", &ft));
        assert!(!hc.contains_path("baz/bar", &ft));
        assert!(!hc.contains_path("foo/bar/baz", &ft));
    }

    #[test]
    fn contains_path_when_in_file_tree() {
        let mut ft = FileTree::new("/foo/bar").unwrap();
        let eh1 = ft.add_file(Path::new("baz.txt")).unwrap();
        let eh2 = ft.add_file(Path::new("baz/file.txt")).unwrap();
        let mut hc = HashCollection::new(None::<&&str>, None).unwrap();
        hc.update(
            eh1.clone(),
            FileRaw::new(
                eh1.clone(),
                None,
                None,
                HashType::Sha512,
                vec![0xde, 0xad, 0xbe, 0xef],
            ),
        );
        hc.update(
            eh2.clone(),
            FileRaw::new(
                eh2.clone(),
                None,
                None,
                HashType::Sha512,
                vec![0xde, 0xad, 0xbe, 0xef],
            ),
        );

        assert!(!hc.contains_path("baz", &ft));
        assert!(!hc.contains_path("baz/bar", &ft));
        assert!(!hc.contains_path("foo/bar/baz", &ft));
        assert!(hc.contains_path("baz.txt", &ft));
        assert!(hc.contains_path("baz/file.txt", &ft));
    }

    #[test]
    fn collection_iter() {
        let mut ft = FileTree::new("/foo/bar").unwrap();
        let eh1 = ft.add_file(Path::new("baz.txt")).unwrap();
        let eh2 = ft.add_file(Path::new("baz/file.txt")).unwrap();
        let mut hc = HashCollection::new(None::<&&str>, None).unwrap();
        let f1 = FileRaw::new(
            eh1.clone(),
            None,
            None,
            HashType::Sha512,
            vec![0xde, 0xad, 0xbe, 0xef],
        );
        hc.update(
            eh1.clone(),
            f1,
        );
        let f2 = FileRaw::new(
            eh2.clone(),
            None,
            None,
            HashType::Sha512,
            vec![0xde, 0xad, 0xbe, 0xef],
        );
        hc.update(
            eh2.clone(),
            f2,
        );

        let mut iter = hc.iter_with_context(&ft);

        let (path, file) = iter.next().unwrap();
        let expected_path = PathBuf::from("/foo/bar/baz.txt");
        assert_eq!(path, expected_path);
        assert_eq!(file.raw(|f| f.absolute_path(&ft)), expected_path);

        let (path, file) = iter.next().unwrap();
        let expected_path = PathBuf::from("/foo/bar/baz/file.txt");
        assert_eq!(path, expected_path);
        assert_eq!(file.raw(|f| f.absolute_path(&ft)), expected_path);

        assert!(iter.next().is_none());
    }
}
