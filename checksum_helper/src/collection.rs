use crate::file_tree::{is_absolute, EntryHandle, ErrorKind, FileTree};
use crate::hashed_file::{FileRaw, HashType};

use hex;
use log::{debug, error, info, warn};

use std::cmp::{Eq, PartialEq};
use std::collections::HashMap;
use std::convert::Into;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::hash::Hash;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, HashCollectionError>;

pub struct HashCollection {
    root_dir: Option<PathBuf>,
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

    pub fn from_str(str: &str, file_tree: &mut FileTree) -> Result<HashCollection> {
        let trimmed = str.trim();
        let version = Self::parse_version_header(trimmed)?;

        let mut result =
            HashCollection::new(None::<&&str>).expect("should always succeed without root");
        let mut warned_above_hash_file = false;
        for line in trimmed.lines() {
            if line.starts_with('#') {
                continue;
            }

            let (mtime, rest) = Self::parse_mtime(line)?;
            let (size, rest) = if version > 0 {
                Self::parse_size(rest)?
            } else {
                (None, rest)
            };

            let (hash_type, hash_bytes, file_path) = Self::parse_hash(rest)?;

            if !warned_above_hash_file && is_path_above_hash_file(file_path) {
                warn!(
                    "Found a file path going beyond the hash file's directory. \
                     This is strongly discouraged, as it makes the hash file \
                     not portable! Path: {}",
                    file_path
                );
                warned_above_hash_file = true;
            }

            let path_handle = match file_tree.add(Path::new(file_path), false) {
                Ok(path_handle) => path_handle,
                Err(e) => return Err(HashCollectionError::FileTreeError(e)),
            };

            if let Some(old) = result.map.insert(
                path_handle.clone(),
                FileRaw::new(path_handle, Some(mtime), size, hash_type, hash_bytes),
            ) {
                error!(
                    "Duplicate file path: {}",
                    old.relative_path(file_tree).display()
                );
            };
        }

        Ok(result)
    }

    fn parse_version_header(str: &str) -> Result<u64> {
        if str.starts_with("# version ") {
            let version_start = str
                .strip_prefix("# version ")
                .expect("must not fail, was checked above");
            let Some(line_end) = version_start.find('\n') else {
                error!("Missing new line after version header: {}", version_start);
                return Err(HashCollectionError::InvalidVersionHeader);
            };
            let version_str = version_start.split_at(line_end).0.trim();

            Ok(version_str.parse::<u64>().map_err(|_| {
                error!(
                    "Malformed version number, expected an usigned integer, got {}",
                    version_str
                );
                HashCollectionError::InvalidHashLine((version_str.to_owned(), String::new()))
            })?)
        } else {
            Ok(0)
        }
    }

    fn parse_mtime(str: &str) -> Result<(filetime::FileTime, &str)> {
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

        Ok((mtime, rest))
    }

    fn parse_size(str: &str) -> Result<(Option<u64>, &str)> {
        let (size_str, after_size) =
            str.split_once(',')
                .ok_or(HashCollectionError::InvalidHashLine((
                    str.to_owned(),
                    String::new(),
                )))?;

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

    pub fn write(&self, path: &Path) -> Result<()> {
        todo!();
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
    InvalidVersionHeader,
    InvalidHashLine((String, String)),
    AbsolutePath(String),
    FileTreeError(ErrorKind),
    UnsupportedHashType(String),
}

impl fmt::Display for HashCollectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HashCollectionError::InvalidPath(ref p) => write!(f, "invalid file path: {:?}", p),
            HashCollectionError::InvalidHashLine((ref current, ref rest)) => {
                write!(f, "invalid hash line: current {} rest {}", current, rest)
            }
            HashCollectionError::InvalidVersionHeader => write!(f, "invalid version header"),
            HashCollectionError::AbsolutePath(ref p) => write!(f, "absolute path found: {}", p),
            HashCollectionError::FileTreeError(ref p) => write!(f, "file tree error: {:?}", p),
            HashCollectionError::UnsupportedHashType(ref t) => {
                write!(f, "unsupported hash type: {}", t)
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

#[cfg(test)]
mod test {
    use super::*;

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

    fn to_file_list(ft: FileTree) -> String {
        format!("{}", ft)
            // always use / as separator
            .replace('\\', "/")
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

        assert_eq!(
            to_file_list(ft),
            "FileTree{
  .gitignore
  foo/bar/baz
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
0,md5,abcdef foo/bar/baz
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

        assert_eq!(
            to_file_list(ft),
            "FileTree{
  .gitignore
  foo/bar/baz
}"
        );
    }

    #[test]
    fn test_parse_version_header_no_version() {
        assert_eq!(HashCollection::parse_version_header("").unwrap(), 0);
        assert_eq!(
            HashCollection::parse_version_header("# ver foo").unwrap(),
            0
        );
        assert_eq!(HashCollection::parse_version_header("# foo").unwrap(), 0);
    }

    #[test]
    fn test_parse_version_header_with_version() {
        assert_eq!(
            HashCollection::parse_version_header("# version 1\n").unwrap(),
            1
        );
        assert_eq!(
            HashCollection::parse_version_header("# version 1337\n").unwrap(),
            1337
        );
        assert_eq!(
            HashCollection::parse_version_header("# version    1337    \n").unwrap(),
            1337
        );
    }

    #[test]
    fn test_parse_version_header_error_cases() {
        // missing new line
        assert_eq!(
            HashCollection::parse_version_header("# version 1"),
            Err(HashCollectionError::InvalidVersionHeader)
        );

        // malformed version number
        assert_eq!(
            HashCollection::parse_version_header("# version foo"),
            Err(HashCollectionError::InvalidVersionHeader)
        );
        assert_eq!(
            HashCollection::parse_version_header("# version 13.37"),
            Err(HashCollectionError::InvalidVersionHeader)
        );
    }
}
