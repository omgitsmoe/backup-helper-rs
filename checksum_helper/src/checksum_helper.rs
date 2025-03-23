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
    root: path::PathBuf,
    file_tree: FileTree,
    gathered_hash_files: bool,
    most_current: HashCollection,
}

pub struct DiscoverResult {
    pub hash_file_paths: Vec<path::PathBuf>,
    pub errors: Vec<String>,
}

impl ChecksumHelper {
    pub fn new(root: &path::Path) -> ChecksumHelper {
        ChecksumHelper {
            root: root.to_path_buf(),
            gathered_hash_files: false,
            most_current: HashCollection::new(None::<&&str>)
                .expect("the path <root>/most_current should be a valid file path"),
            file_tree: FileTree::new(),
        }
    }

    pub fn incremental(&mut self) -> &HashCollection {
        todo!();
    }

    pub fn update_most_current(&mut self) {
        todo!();
    }

    pub fn discover_hash_files(&mut self, max_depth: Option<u32>) -> Result<DiscoverResult> {
        let mut files = vec![];
        let result = gather(&self.root, |visit_type| {
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
