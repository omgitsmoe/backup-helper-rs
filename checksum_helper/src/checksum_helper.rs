use crate::collection::HashCollection;
use crate::file_tree::FileTree;
use crate::gather::{gather, VisitType};

use std::cmp::{Eq, PartialEq};
use std::error::Error;
use std::fmt;
use std::path;

type Result<T> = std::result::Result<T, ChecksumHelperError>;

const HASH_FILE_EXTENSIONS: &'static [&'static str] = &[
    "cshd",
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
    "shake_128",
    "shake_256",
    "blake2b",
    "blake2s",
];

pub struct ChecksumHelper {
    file_tree: FileTree,
    gathered_hash_files: bool,
    most_current: Option<HashCollection>,
}

pub struct DiscoverResult {
    pub hash_file_paths: Vec<path::PathBuf>,
    pub errors: Vec<String>,
}

// TODO options
// - include_unchanged_files_incremental
// - discover_hash_files_depth
// - incremental_skip_unchanged
// - allow/block list
impl ChecksumHelper {
    pub fn new(root: &path::Path) -> Result<ChecksumHelper> {
        if root.is_relative() {
            Err(ChecksumHelperError::RootIsRelative(root.to_path_buf()))
        } else {
            Ok(ChecksumHelper {
                gathered_hash_files: false,
                most_current: None,
                file_tree: FileTree::new(root)
                    .expect("must succeed, since path was checked to be absolute!"),
            })
        }
    }

    pub fn root(&self) -> path::PathBuf {
        self.file_tree.absolute_path(&self.file_tree.root())
    }

    pub fn incremental(&mut self) -> &HashCollection {
        todo!();
    }

    pub fn fill_missing(&mut self) -> &HashCollection {
        todo!("find files that don't have a checksum in most current yet and generat them")
    }

    pub fn check_missing(self) -> Result<path::PathBuf> {
        // TODO optionally with filter?
        todo!("find files that don't have a checksum in most current yet and list them")
    }

    pub fn update_most_current(&mut self) {
        todo!();
    }

    // TODO copy as well?
    fn move_collection() {
        todo!("move a hash collection; relocating paths, but preserving mtime of the collection")
    }

    pub fn move_path() {
        todo!("move files modifying their relative paths in disocovered collections, calling move_collection if it's a collection")
    }

    pub fn discover_hash_files(&self, max_depth: Option<u32>) -> Result<DiscoverResult> {
        let mut files = vec![];
        let result = gather(&self.root(), |visit_type| {
            match visit_type {
                VisitType::File((_, e)) => match e.path().extension() {
                    None => {}
                    Some(file_ext) => {
                        for ext in HASH_FILE_EXTENSIONS {
                            if *ext == file_ext {
                                files.push(e.path());
                            }
                        }
                    }
                },
                VisitType::Directory((depth, _)) => {
                    if let Some(max_depth) = max_depth {
                        if depth > max_depth {
                            return false;
                        }
                    }
                }
                _ => {}
            }

            true
        })
        .map_err(|e| ChecksumHelperError::GatherError(e))?;

        Ok(DiscoverResult {
            hash_file_paths: files,
            errors: result.errors,
        })
    }
}

#[derive(Debug)]
pub enum ChecksumHelperError {
    RootIsRelative(path::PathBuf),
    HashCollectionError(crate::collection::HashCollectionError),
    HashedFileError(crate::hashed_file::HashedFileError),
    // TODO error Trait
    GatherError(crate::gather::Error),
    // TODO error Trait
    FileTreeError(crate::file_tree::ErrorKind),
}

impl fmt::Display for ChecksumHelperError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ChecksumHelperError::RootIsRelative(ref p) => write!(f, "root must be absolute, got: {:?}", p),
            ChecksumHelperError::HashCollectionError(..) => write!(f, "hash collection error"),
            ChecksumHelperError::HashedFileError(..) => write!(f, "hashed file error"),
            ChecksumHelperError::GatherError(..) => write!(f, "gather files error"),
            ChecksumHelperError::FileTreeError(..) => write!(f, "file tree error"),
        }
    }
}

impl Error for ChecksumHelperError {
    // return the source for this error, e.g. std::io::Eror if we wrapped it
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            ChecksumHelperError::HashCollectionError(ref e) => Some(e),
            ChecksumHelperError::HashedFileError(ref e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
