use crate::file_tree::{is_absolute, EntryHandle, ErrorKind, FileTree};
use crate::hashed_file::{FileRaw, HashType};

use hex;
use log::{debug, error, info, warn};

use std::cmp::{Eq, PartialEq};
use std::collections::HashMap;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, BufRead, Cursor, Write};
use std::path::{Path, PathBuf};

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
        Self::parse(Cursor::new(str), file_tree)
    }

    // TODO from single hash file with hash_type as parameter
    // TODO separate parser that just has a feed/feed_line method -> more flexible?
    pub fn parse<R: BufRead>(reader: R, file_tree: &mut FileTree) -> Result<HashCollection> {
        let mut lines = reader.lines();
        let mut result =
            HashCollection::new(None::<&&str>).expect("should always succeed without root");
        let mut warned_above_hash_file = false;

        let version = match &lines.next() {
            Some(Ok(line)) => {
                let (found, version) = Self::parse_version_header(&line)?;
                if !found {
                    // no header line found, parse the line
                    Self::parse_line(
                        &line,
                        file_tree,
                        version,
                        &mut warned_above_hash_file,
                        &mut result,
                    )?;
                }
                version
            }
            Some(Err(e)) => return Err(HashCollectionError::IOError(e.kind())),
            // no error, but there was no line -> empty string
            None => return Ok(result),
        };

        for line in lines {
            match line {
                Ok(line) => Self::parse_line(
                    &line,
                    file_tree,
                    version,
                    &mut warned_above_hash_file,
                    &mut result,
                )?,
                Err(e) => return Err(HashCollectionError::IOError(e.kind())),
            };
        }

        Ok(result)
    }

    fn parse_line(
        line: &str,
        file_tree: &mut FileTree,
        version: u32,
        warned_above_hash_file: &mut bool,
        result: &mut HashCollection,
    ) -> Result<()> {
        if line.starts_with('#') {
            return Ok(());
        }

        if line.trim().is_empty() {
            return Ok(());
        }

        let (mtime, rest) = Self::parse_mtime(line)?;
        let (size, rest) = if version > 0 {
            Self::parse_size(rest)?
        } else {
            (None, rest)
        };

        let (hash_type, hash_bytes, file_path) = Self::parse_hash(rest)?;

        if !*warned_above_hash_file && is_path_above_hash_file(file_path) {
            warn!(
                "Found a file path going beyond the hash file's directory. \
                This is strongly discouraged, as it makes the hash file \
                not portable! Path: {}",
                file_path
            );
            *warned_above_hash_file = true;
        }

        let path_handle = match file_tree.add(Path::new(file_path), false) {
            Ok(path_handle) => path_handle,
            Err(e) => return Err(HashCollectionError::FileTreeError(e)),
        };

        if let Some(old) = result.map.insert(
            path_handle.clone(),
            FileRaw::new(path_handle, mtime, size, hash_type, hash_bytes),
        ) {
            error!(
                "Duplicate file path: {}",
                old.relative_path(file_tree).display()
            );
        };

        Ok(())
    }

    fn parse_version_header(line: &str) -> Result<(bool, u32)> {
        if line.starts_with("# version ") {
            let version_start = line
                .strip_prefix("# version ")
                .expect("must not fail, was checked above");
            let version_str = version_start.trim();

            Ok((
                true,
                version_str.parse::<u32>().map_err(|_| {
                    error!(
                        "Malformed version number, expected an usigned integer, got {}",
                        version_str
                    );
                    HashCollectionError::InvalidVersionHeader(version_str.to_owned())
                })?,
            ))
        } else {
            Ok((false, 0))
        }
    }

    fn parse_mtime(str: &str) -> Result<(Option<filetime::FileTime>, &str)> {
        let Some((mtime, rest)) = str.split_once(',') else {
            error!(
                "Expected ',' delimeter after modification time field, got '{}'",
                str
            );
            return Err(HashCollectionError::InvalidHashLine((
                str.to_owned(),
                String::new(),
            )));
        };
        let mtime = mtime.trim();
        if mtime.is_empty() {
            return Ok((None, rest));
        }
        let Ok(mtime) = mtime.parse::<f64>() else {
            error!("Failed to parse modification time string: {}", mtime);
            return Err(HashCollectionError::InvalidHashLine((
                mtime.to_owned(),
                str.to_owned(),
            )));
        };

        const NS_PER_SEC: f64 = 1_000_000_000.0;
        let seconds = mtime.trunc() as i64;
        let nanoseconds = (mtime.fract() * NS_PER_SEC) as u32;
        let mtime = filetime::FileTime::from_unix_time(seconds, nanoseconds);

        Ok((Some(mtime), rest))
    }

    fn parse_size(str: &str) -> Result<(Option<u64>, &str)> {
        let (size_str, after_size) =
            str.split_once(',')
                .ok_or(HashCollectionError::InvalidHashLine((
                    str.to_owned(),
                    String::new(),
                )))?;
        let size_str = size_str.trim();
        if size_str.is_empty() {
            return Ok((None, after_size));
        }

        Ok((
            Some(size_str.parse::<u64>().map_err(|_| {
                HashCollectionError::InvalidHashLine((size_str.to_owned(), str.to_owned()))
            })?),
            after_size,
        ))
    }

    fn parse_hash(str: &str) -> Result<(HashType, Vec<u8>, &str)> {
        let Some((hash_type, rest)) = str.split_once(',') else {
            error!("Expected ',' delimiter after hash type, got '{}'", str);
            return Err(HashCollectionError::InvalidHashLine((
                str.to_owned(),
                String::new(),
            )));
        };
        let Ok(hash_type): std::result::Result<HashType, _> = hash_type.try_into() else {
            error!("Malformed or unsupported hash type '{}'", hash_type);
            return Err(HashCollectionError::UnsupportedHashType(
                hash_type.to_owned(),
            ));
        };

        let Some((hash_hex, file_path)) = rest.split_once(' ') else {
            error!("Expected ' ' delimiter after hash type, got '{}'", str);
            return Err(HashCollectionError::InvalidHashLine((
                rest.to_owned(),
                String::new(),
            )));
        };

        let Ok(hash_bytes) = hex::decode(hash_hex) else {
            error!(
                "Malformed hex representation of hash '{}': '{}'",
                hash_type.to_str(),
                hash_hex
            );
            return Err(HashCollectionError::InvalidHashLine((
                hash_hex.to_owned(),
                String::new(),
            )));
        };

        if is_absolute(file_path) {
            error!(
                "Only relative paths are allowed in hash files, but found: {}",
                file_path
            );
            return Err(HashCollectionError::AbsolutePath(file_path.to_owned()));
        }

        Ok((hash_type, hash_bytes, file_path))
    }

    const VERSION_HEADER: &str = "# version 1\n";
    // TODO: flush-able hash collection
    pub fn serialize<W: Write>(&self, writer: &mut W, file_tree: &FileTree) -> Result<()> {
        writer.write_all(Self::VERSION_HEADER.as_bytes())?;
        for (path_handle, hashed_file) in &self.map {
            Self::serialize_entry(writer, path_handle, &hashed_file, file_tree)?;
        }
        Ok(())
    }

    fn serialize_entry<W: Write>(
        writer: &mut W,
        path_handle: &EntryHandle,
        hashed_file: &FileRaw,
        file_tree: &FileTree,
    ) -> Result<()> {
        let path = file_tree.relative_path(&path_handle);
        let Some(path) = path.to_str() else {
            return Err(HashCollectionError::NonUnicodePath(path));
        };
        let path = path.replace("\\", "/");
        let mtime = hashed_file.mtime_str().unwrap_or("".to_string());
        let size = match hashed_file.size() {
            Some(size) => size.to_string(),
            None => String::from(""),
        };
        let hash_type = hashed_file.hash_type().to_string();
        let hash_hex = hex::encode(hashed_file.hash_bytes());

        write!(writer, "{mtime},{size},{hash_type},{hash_hex} {path}\n")?;

        Ok(())
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

    /// Warning: Does not preserve comments that do not directly follow the
    ///          header!
    pub fn sort_serialized(serialized: &str) -> Option<String> {
        let mut header = Vec::new();
        let mut iter = serialized.lines();
        let mut lines = Vec::new();

        // Collect header lines manually, ensuring the first non-header line is not consumed
        let mut in_header = true;
        while let Some(line) = iter.next() {
            let is_comment = line.starts_with('#');
            if in_header {
                if !is_comment {
                    in_header = false;
                } else {
                    header.push(line);
                }
            }

            if !is_comment {
                lines.push(line.split_once(' ').map(|parts| (line, parts))?);
            }
        }
        lines.sort_by(|a, b| a.1 .1.cmp(b.1 .1));
        let mut result = header
            .iter()
            .chain(lines.iter().map(|(line, _)| line))
            // NOTE: @Perf avoid extra intermediate vec and add directly to a string
            .fold(String::new(), |mut acc, &line| {
                if !acc.is_empty() {
                    acc.push('\n'); // Manually add newline instead of join()
                }
                acc.push_str(line);
                acc
            });
        // enforce trailing newline
        result.push('\n');
        Some(result)
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
    use super::*;
    use crate::test_utils::*;
    use filetime::FileTime;
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

    #[test]
    fn test_parse_version_header_no_version() {
        assert_eq!(
            HashCollection::parse_version_header("").unwrap(),
            (false, 0)
        );
        assert_eq!(
            HashCollection::parse_version_header("# ver foo").unwrap(),
            (false, 0)
        );
        assert_eq!(
            HashCollection::parse_version_header("# foo").unwrap(),
            (false, 0)
        );
    }

    #[test]
    fn test_parse_version_header_with_version() {
        assert_eq!(
            HashCollection::parse_version_header("# version 1\n").unwrap(),
            (true, 1)
        );
        assert_eq!(
            HashCollection::parse_version_header("# version 1337\n").unwrap(),
            (true, 1337)
        );
        assert_eq!(
            HashCollection::parse_version_header("# version    1337    \n").unwrap(),
            (true, 1337)
        );
    }

    #[test]
    fn test_parse_version_header_error_cases() {
        // malformed version number
        assert_eq!(
            HashCollection::parse_version_header("# version foo"),
            Err(HashCollectionError::InvalidVersionHeader("foo".to_string()))
        );
        assert_eq!(
            HashCollection::parse_version_header("# version 13.37"),
            Err(HashCollectionError::InvalidVersionHeader(
                "13.37".to_string()
            ))
        );
    }

    #[test]
    fn test_parse_mtime_empty() {
        assert_eq!(
            HashCollection::parse_mtime(",foo,bar"),
            Ok((None, "foo,bar"))
        );
        assert_eq!(
            HashCollection::parse_mtime("   ,foo,bar"),
            Ok((None, "foo,bar"))
        );
    }

    // TODO: error cases
    #[test]
    fn test_parse_mtime() {
        assert_eq!(
            HashCollection::parse_mtime("1337,foo,bar"),
            Ok((Some(FileTime::from_unix_time(1337, 0)), "foo,bar"))
        );
        assert_eq!(
            HashCollection::parse_mtime("   1337.00133     ,foo,bar"),
            Ok((Some(FileTime::from_unix_time(1337, 1_330_000)), "foo,bar"))
        );
    }

    #[test]
    fn test_parse_size_empty() {
        assert_eq!(
            HashCollection::parse_size(",foo,bar"),
            Ok((None, "foo,bar"))
        );
        assert_eq!(
            HashCollection::parse_size("   ,foo,bar"),
            Ok((None, "foo,bar"))
        );
    }

    // TODO: error cases
    #[test]
    fn test_parse_size() {
        assert_eq!(
            HashCollection::parse_size("42069,foo,bar"),
            Ok((Some(42069), "foo,bar"))
        );
        assert_eq!(
            HashCollection::parse_size("   1337   ,foo,bar"),
            Ok((Some(1337), "foo,bar"))
        );
    }

    #[test]
    fn test_serialize_entry() {
        let mut ft = FileTree::new();
        let mut buf = vec![];
        let path_handle = ft.add_file("./foo/bar/baz.txt").unwrap();
        let file = FileRaw::new(
            path_handle.clone(),
            Some(filetime::FileTime::from_unix_time(1337, 1_337_000)),
            Some(1337),
            HashType::Sha512,
            vec![0xde, 0xad, 0xbe, 0xef],
        );

        HashCollection::serialize_entry(&mut buf, &path_handle, &file, &ft).unwrap();

        let result = std::str::from_utf8(&buf).unwrap();

        assert_eq!(result, "1337.001337,1337,sha512,deadbeef foo/bar/baz.txt\n",);
    }

    #[test]
    fn test_serialize_entry_missing_mtime_and_size() {
        let mut ft = FileTree::new();
        let mut buf = vec![];
        let path_handle = ft.add_file("./foo/bar/baz.txt").unwrap();
        let file = FileRaw::new(
            path_handle.clone(),
            None,
            None,
            HashType::Blake2s,
            vec![0xab, 0xcd, 0xef, 0x09],
        );

        HashCollection::serialize_entry(&mut buf, &path_handle, &file, &ft).unwrap();

        let result = std::str::from_utf8(&buf).unwrap();

        assert_eq!(result, ",,blake2s,abcdef09 foo/bar/baz.txt\n",);
    }

    fn setup_minimal_hc() -> (HashCollection, FileTree, &'static str) {
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
    fn test_serialize() {
        let mut buf = vec![];
        let (hc, ft, expected_serialization) = setup_minimal_hc();

        hc.serialize(&mut buf, &ft).unwrap();

        let result = HashCollection::sort_serialized(std::str::from_utf8(&buf).unwrap()).unwrap();
        assert_eq!(
            result,
            expected_serialization,
        );
    }

    #[test]
    fn test_sort_serialized() {
        let unsorted = "\
# version 1
# comment
,4206969,sha3_512,eeff0011 xer.mp4
# comment intra
1212,,md5,aabbccdd bar/foo.txt
# comment intra2
1337.001337,1337,sha512,deadbeef foo/bar/baz.txt";

        assert_eq!(
            HashCollection::sort_serialized(unsorted).unwrap(),
            "\
# version 1
# comment
1212,,md5,aabbccdd bar/foo.txt
1337.001337,1337,sha512,deadbeef foo/bar/baz.txt
,4206969,sha3_512,eeff0011 xer.mp4\n",
        );
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
            HashCollection::sort_serialized(&read_back).unwrap(),
            expected_serialization,
        );
    }
}
