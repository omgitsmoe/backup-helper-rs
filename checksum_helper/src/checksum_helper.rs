use crate::collection::{HashCollection, VerifyProgress, HashCollectionError};
use crate::file_tree::FileTree;
use crate::gather::{gather, VisitType};
use crate::pathmatcher::PathMatcher;

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
    most_current: Option<HashCollection>,
}

pub struct DiscoverResult {
    pub hash_file_paths: Vec<path::PathBuf>,
    pub errors: Vec<String>,
}

// TODO options
impl ChecksumHelper {
    pub fn new(root: &path::Path) -> Result<ChecksumHelper> {
        if root.is_relative() {
            Err(ChecksumHelperError::RootIsRelative(root.to_path_buf()))
        } else {
            Ok(ChecksumHelper {
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
        // TODO progress callback
        // prob best to gather files first then do the checksumming -> better progress indicator
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
        let hash_files = self.discover_hash_files(
            |v| {
                // TODO filter from options
                true
            });
    }

    pub fn verify<F, P>(&self, collection: &HashCollection, include: F, progress: P) -> Result<()>
    where
        F: Fn(&path::Path) -> bool,
        P: FnMut(VerifyProgress),
    {
        collection.verify(&self.file_tree, include, progress)?;

        Ok(())
    }

    pub fn verify_root<F, P>(&self, include: F, progress: P) -> Result<()>
    where
        F: Fn(&path::Path) -> bool,
        P: FnMut(VerifyProgress),
    {
        todo!("verify files matching predicate include in self.root_dir")
    }

    // TODO copy as well?
    fn move_collection() {
        todo!("move a hash collection; relocating paths, but preserving mtime of the collection")
    }

    pub fn move_path() {
        todo!("move files modifying their relative paths in disocovered collections, calling move_collection if it's a collection")
    }

    pub fn discover_hash_files<F>(&self, include: F) -> Result<DiscoverResult> 
    where
        F: Fn(&VisitType) -> bool,
    {
        let mut files = vec![];
        let result = gather(&self.root(), |visit_type| {
            match visit_type {
                VisitType::File((_, e)) => match e.path().extension() {
                    None => false,
                    Some(file_ext) => {
                        for ext in HASH_FILE_EXTENSIONS {
                            if *ext == file_ext && include(&visit_type) {
                                files.push(e.path());
                                return true;
                            }
                        }
                        false
                    }
                },
                VisitType::Directory(_) => {
                    include(&visit_type)
                }
                _ => true,
            }
        })
        .map_err(ChecksumHelperError::GatherError)?;

        Ok(DiscoverResult {
            hash_file_paths: files,
            errors: result.errors,
        })
    }
}

pub struct ChecksumHelperOptions {
    /// Whether to include files in the output, which did not change compared
    /// to the previous latest available hash found.
    incremental_include_unchanged_files: bool,

    /// Whether to skip files when computing hashes if that files has the same
    /// modification time as in the latest available hash found.
    incremental_skip_unchanged: bool,

    /// Up to which depth should the root and its subdirectories be searched
    /// for hash files (*.cshd, *.md5, *.sha512, etc.) to determine the
    /// current state of hashes.
    discover_hash_files_depth: Option<u32>,

    /// Allow/block list like matching for hash files which will be used
    /// for building the most current state of hashes.
    /// These hashes will be used when e.g. using the `incremental`
    /// method.
    hash_files_matcher: PathMatcher,

    /// Allow/block list like matching for all files.
    /// Affects all file discovery behaviour: which files get included
    /// in an incremental hash file, which files are ignored when checking
    /// for files that don't have checksums in `check_missing`, etc.
    all_files_matcher: PathMatcher,
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

impl From<HashCollectionError> for ChecksumHelperError {
    fn from(value: HashCollectionError) -> Self {
        ChecksumHelperError::HashCollectionError(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
