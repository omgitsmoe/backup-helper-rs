use crate::file_tree::{EntryHandle, FileTree};
use crate::hashed_file::File;

use std::cmp::{Eq, PartialEq};
use std::collections::HashMap;
use std::hash::Hash;
use std::path::{Path, PathBuf};
use std::ffi::OsString;
use std::fmt;
use std::error::Error;

type Result<T> = std::result::Result<T, HashCollectionError>;

pub struct HashCollection<'a> {
    root_dir: PathBuf,
    name: OsString,
    map: HashMap<EntryHandle, File<'a>>,
}

impl<'a> HashCollection<'a> {
    pub fn new(path: &impl AsRef<Path>) -> Result<HashCollection<'a>> {
        let path = path.as_ref();
        Ok(HashCollection {
            map: HashMap::new(),
            name: path.file_name()
                .ok_or_else(|| HashCollectionError::InvalidPath(
                        path.to_path_buf()))?.to_owned(),
            root_dir: path.parent()
                .ok_or_else(|| HashCollectionError::InvalidPath(
                        path.to_path_buf()))?.to_owned(),
        })
    }
}

#[derive(Debug)]
pub enum HashCollectionError {
    InvalidPath(PathBuf),
}

impl fmt::Display for HashCollectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HashCollectionError::InvalidPath(ref p) =>
                write!(f, "invalid file path: {:?}", p),
        }
    }
}

impl Error for HashCollectionError {
    // return the source for this error, e.g. std::io::Eror if we wrapped it
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            HashCollectionError::InvalidPath(_) => None,
        }
    }
}

// TODO allow lookup of relative paths for FileTree, such that:
// /home/m/foo/bar/baz/file.txt
// ^-----^ root
// /media/backup/foo/bar/baz/file.txt
// ^-----------^ root
// can resolve to the same entry handle
// then also provide a `relative_path` method so a different "root" can
// be used
// => this would allow just using an EntryHandle itself as hash key
// struct PathKey<'a> {
//     entry: EntryHandle,
//     context: &'a FileTree,
// }

// impl<'a> PathKey<'a> {
//     pub fn path(&self) -> PathBuf {
//         self.context.path(&self.entry)
//     }
// }

// impl<'a> PartialEq for PathKey<'a> {
//     fn eq(&self, other: &Self) -> bool {
//         self.path() == other.path()
//     }
// }
// impl<'a> Eq for PathKey<'a> {}

// impl<'a> Hash for PathKey<'a> {
//     fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
//         // TODO @Perf creating path every time we hash
//         self.path().hash(state);
//     }
// }
