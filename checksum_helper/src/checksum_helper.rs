use crate::collection::{HashCollection, VerifyProgress, HashCollectionError};
use crate::file_tree::FileTree;
use crate::gather::{gather, VisitType};
use crate::pathmatcher::{PathMatcher, PathMatcherBuilder};

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
    options: ChecksumHelperOptions,
    most_current: Option<HashCollection>,
}

pub struct DiscoverResult {
    pub hash_file_paths: Vec<path::PathBuf>,
    pub errors: Vec<String>,
}

impl ChecksumHelper {
    pub fn new(root: &path::Path) -> Result<ChecksumHelper> {
        if root.is_relative() {
            Err(ChecksumHelperError::RootIsRelative(root.to_path_buf()))
        } else {
            Ok(ChecksumHelper {
                most_current: None,
                options: ChecksumHelperOptions::default(),
                file_tree: FileTree::new(root)
                    .expect("must succeed, since path was checked to be absolute!"),
            })
        }
    }

    pub fn with_options(root: &path::Path, options: ChecksumHelperOptions) -> Result<ChecksumHelper> {
        let mut ch = ChecksumHelper::new(root)?;
        ch.options = options;

        Ok(ch)
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
        let hash_files = self.discover_hash_files();
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

    pub fn discover_hash_files(&self) -> Result<DiscoverResult> 
    {
        // TODO how to support PathMatcher efficiently such that we don't enter
        //      directories we don't have to since they're already excluded
        //      offer extra is_excluded method and call that on the directory?
        let mut files = vec![];
        let result = gather(&self.root(), |visit_type| {
            match visit_type {
                VisitType::File((_, e)) => match e.path().extension() {
                    None => false,
                    Some(file_ext) => {
                        for ext in HASH_FILE_EXTENSIONS {
                            if *ext == file_ext {
                                files.push(e.path());
                                return true;
                            }
                        }
                        false
                    }
                },
                VisitType::Directory((depth, _)) => {
                    if let Some(max_depth) = self.options.discover_hash_files_depth {
                        // NOTE: since 0 -> same directory
                        // 1 -> one directory down
                        // and we decide if we want to enter here, so it needs to be >=
                        if depth >= max_depth {
                            return false;
                        }
                    }

                    true
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
    /// Zero means only files in the root directory will be considered.
    /// One means at most one subdirectory will be allowed.
    /// None means no depth limit.
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

impl ChecksumHelperOptions {
    pub fn new() -> Self {
        ChecksumHelperOptions{
            incremental_include_unchanged_files: true,
            incremental_skip_unchanged: false,
            discover_hash_files_depth: None,
            hash_files_matcher: PathMatcherBuilder::new().build()
                .expect("An empty PathMatcher should always be valid"),
            all_files_matcher: PathMatcherBuilder::new().build()
                .expect("An empty PathMatcher should always be valid"),
        }
    }
}

impl Default for ChecksumHelperOptions {
    fn default() -> Self {
        Self::new()
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

impl From<HashCollectionError> for ChecksumHelperError {
    fn from(value: HashCollectionError) -> Self {
        ChecksumHelperError::HashCollectionError(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use pretty_assertions::assert_eq;

    fn setup_dir_hash_files() -> std::path::PathBuf {
        let testdir = testdir!();
        create_ftree(&testdir,
"\
foo/bar/baz/file.md5
foo/bar/baz/file.cshd
foo/bar/baz/file.txt
foo/bar/bar.blake2b
foo/bar/bar.mp4
foo/foo.shake_128
foo/foo.bin
bar/baz/baz_2025-06-28.sha256
bar/baz/save.sav
bar/baz_2025-06-28.cshd
bar/other.txt
root.sha3_384
file.rs");
        testdir
    }

    #[test]
    fn discover_hash_files_all_hash_files_found() {
        let testdir = setup_dir_hash_files();
        let ch = ChecksumHelper::new(&testdir).unwrap();
        let mut result = ch.discover_hash_files()
            .unwrap();
        assert!(result.errors.is_empty());
        result.hash_file_paths.sort();
        assert_eq!(
            result.hash_file_paths,
            vec!{
                testdir.join("bar").join("baz").join("baz_2025-06-28.sha256"),
                testdir.join("bar").join("baz_2025-06-28.cshd"),
                testdir.join("foo").join("bar").join("bar.blake2b"),
                testdir.join("foo").join("bar").join("baz").join("file.cshd"),
                testdir.join("foo").join("bar").join("baz").join("file.md5"),
                testdir.join("foo").join("foo.shake_128"),
                testdir.join("root.sha3_384"),
            }
        );
    }

    #[test]
    fn discover_hash_files_respsects_hash_files_depth() {
        // NOTE: decided this should be part of discover_hash_files
        //       since update_most_current has a different task
        //       harder to reuse discover_hash_files then, but
        //       most likely the options should be respected for everything anyway
        let testdir = setup_dir_hash_files();
        let options = ChecksumHelperOptions{
            discover_hash_files_depth: Some(1),
            ..Default::default()
        };
        
        let ch = ChecksumHelper::with_options(&testdir, options).unwrap();
        let mut result = ch.discover_hash_files()
            .unwrap();
        assert!(result.errors.is_empty());

        result.hash_file_paths.sort();
        assert_eq!(
            result.hash_file_paths,
            vec!{
                testdir.join("bar").join("baz_2025-06-28.cshd"),
                testdir.join("foo").join("foo.shake_128"),
                testdir.join("root.sha3_384"),
            }
        );
    }

    #[test]
    fn discover_hash_files_respsects_hash_files_matcher() {
        // NOTE: decided this should be part of discover_hash_files
        //       since update_most_current has a different task
        //       harder to reuse discover_hash_files then, but
        //       most likely the options should be respected for everything anyway
        let testdir = setup_dir_hash_files();
        let matcher = PathMatcherBuilder::new()
            .allow("**/*.cshd").unwrap()
            .build().unwrap();
        let options = ChecksumHelperOptions{
            hash_files_matcher: matcher,
            ..Default::default()
        };
        
        let ch = ChecksumHelper::with_options(&testdir, options).unwrap();
        let mut result = ch.discover_hash_files()
            .unwrap();
        assert!(result.errors.is_empty());

        result.hash_file_paths.sort();
        // TODO fix
        assert_eq!(
            result.hash_file_paths,
            vec!{
                testdir.join("bar").join("baz_2025-06-28.cshd"),
                testdir.join("foo").join("bar").join("baz").join("file.cshd"),
            }
        );
    }
}
