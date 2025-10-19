use crate::collection::{HashCollection, HashCollectionError, VerifyProgress, HashCollectionWriter};
use crate::file_tree::FileTree;
use crate::gather::{gather, VisitType};
use crate::pathmatcher::{PathMatcher, PathMatcherBuilder};
use crate::most_current::{update_most_current};

use std::cmp::{Eq, PartialEq};
use std::error::Error;
use std::fmt;
use std::path;

pub use crate::most_current::MostCurrentProgress;

type Result<T> = std::result::Result<T, ChecksumHelperError>;

pub struct ChecksumHelper {
    file_tree: FileTree,
    options: ChecksumHelperOptions,
    most_current: Option<HashCollection>,
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

    pub fn with_options(
        root: &path::Path,
        options: ChecksumHelperOptions,
    ) -> Result<ChecksumHelper> {
        let mut ch = ChecksumHelper::new(root)?;
        ch.options = options;

        Ok(ch)
    }

    pub fn root(&self) -> path::PathBuf {
        self.file_tree.absolute_path(&self.file_tree.root())
    }

    pub fn incremental<P>(&mut self, mut progress: P) -> Result<&HashCollection>
    where
        P: FnMut(IncrementalProgress)

    {
        let root = self.root();
        if self.most_current.is_none() {
            self.most_current = Some(update_most_current(&root, &mut self.file_tree, &self.options, |p| progress(IncrementalProgress::BuildMostCurrent(p)))?);
        }

        // TODO progress callback
        // prob best to gather files first then do the checksumming -> better progress indicator
        todo!();
    }

    pub fn fill_missing<P>(&mut self, mut progress: P) -> Result<HashCollection>
    where
        P: FnMut(IncrementalProgress)
    {
        let root = self.root();
        if self.most_current.is_none() {
            self.most_current = Some(update_most_current(&root, &mut self.file_tree, &self.options, |p| progress(IncrementalProgress::BuildMostCurrent(p)))?);
        }

        todo!("find files that don't have a checksum in most current yet and generat them")
    }

    // TODO progress cb
    pub fn check_missing(&mut self) -> Result<CheckMissingResult>
    {
        let root = self.root();
        if self.most_current.is_none() {
            self.most_current = Some(update_most_current(&root, &mut self.file_tree, &self.options, |_| {})?);
        }

        // first find all directories that have at least one file and add all
        // its parents,
        // if we find a directory later that is not in this set,
        // we can record it as missing entirely
        let mut dirs_with_hashed_file = std::collections::HashSet::new();
        dirs_with_hashed_file.insert(root.clone());

        let most_current = self.most_current.as_ref()
            .expect("checked above");
        for (path, _) in most_current
            .iter_with_context(&self.file_tree) {
                let relative = path.strip_prefix(&root)
                    .expect("paths in the file tree must be relative to the ChecksumHelper root");
                let mut current = relative;
                while let Some(path) = current.parent() {
                    dirs_with_hashed_file.insert(path.to_owned());
                    current = path;
                }
        }

        let mut missing_directories = vec!();
        let mut missing_files = vec!();
        let gather_errors = gather(&root, |v| {
            match v {
                VisitType::Directory((_, e)) => {
                    let path = e.path();
                    let relative = path.strip_prefix(&root)
                        .expect("paths under root must be relative to root");

                    if self.options.all_files_matcher.is_excluded(relative) ||
                        !self.options.all_files_matcher.is_match(relative) {
                        return false;
                    }

                    if dirs_with_hashed_file.contains(relative) {
                        true
                    } else {
                        missing_directories.push(relative.to_owned());
                        false
                    }
                },
                VisitType::File((_, e)) => {
                    let path = e.path();
                    let relative = path.strip_prefix(&root)
                        .expect("paths under root must be relative to root");

                    if !self.options.all_files_matcher.is_match(relative) {
                        return false;
                    }

                    if !most_current.contains_path(relative, &self.file_tree) {
                        missing_files.push(relative.to_owned());
                    }

                    true
                },
                _ => true,
            }
        })?;

        Ok(CheckMissingResult{
            directories: missing_directories,
            files: missing_files,
            errors: gather_errors.errors,
        })
    }

    pub fn build_most_current<P>(&mut self, progress: P) -> Result<()>
    where
        P: FnMut(MostCurrentProgress)
    {
        if self.most_current.is_none() {
            self.most_current = Some(update_most_current(self.root(), &mut self.file_tree, &self.options, progress)?);
        }

        if let Some(most_current) = &mut self.most_current {
            let mut writer = HashCollectionWriter::new();
            writer.write(most_current, &self.file_tree)?;
            Ok(())
        } else {
            Err(ChecksumHelperError::InvalidMostCurrentHashFile)
        }
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

    fn move_collection() {
        // should use copy_collection internally
        todo!("move a hash collection; relocating paths, but preserving mtime of the collection")
    }

    fn copy_collection() {
        todo!("copy a hash collection; relocating paths, but preserving mtime of the collection")
    }

    pub fn move_path() {
        todo!("move files modifying their relative paths in disocovered collections, calling move_collection if it's a collection")
    }
}

pub struct ChecksumHelperOptions {
    /// Whether to include files in the output, which did not change compared
    /// to the previous latest available hash found.
    pub incremental_include_unchanged_files: bool,

    /// Whether to skip files when computing hashes if that files has the same
    /// modification time as in the latest available hash found.
    pub incremental_skip_unchanged: bool,

    /// Up to which depth should the root and its subdirectories be searched
    /// for hash files (*.cshd, *.md5, *.sha512, etc.) to determine the
    /// current state of hashes.
    /// Zero means only files in the root directory will be considered.
    /// One means at most one subdirectory will be allowed.
    /// None means no depth limit.
    pub discover_hash_files_depth: Option<u32>,

    /// Allow/block list like matching for hash files which will be used
    /// for building the most current state of hashes.
    /// These hashes will be used when e.g. using the `incremental`
    /// method.
    pub hash_files_matcher: PathMatcher,

    /// Allow/block list like matching for all files.
    /// Affects all file discovery behaviour: which files get included
    /// in an incremental hash file, which files are ignored when checking
    /// for files that don't have checksums in `check_missing`, etc.
    pub all_files_matcher: PathMatcher,
}

impl ChecksumHelperOptions {
    pub fn new() -> Self {
        ChecksumHelperOptions {
            incremental_include_unchanged_files: true,
            incremental_skip_unchanged: false,
            discover_hash_files_depth: None,
            hash_files_matcher: PathMatcherBuilder::new()
                .build()
                .expect("An empty PathMatcher should always be valid"),
            all_files_matcher: PathMatcherBuilder::new()
                .build()
                .expect("An empty PathMatcher should always be valid"),
        }
    }

    pub fn incremental_include_unchanged_files(self, value: bool) -> Self {
        Self {
            incremental_include_unchanged_files: value,
            ..self
        }
    }

    pub fn incremental_skip_unchanged(self, value: bool) -> Self {
        Self {
            incremental_skip_unchanged: value,
            ..self
        }
    }

    pub fn discover_hash_files_depth(self, value: Option<u32>) -> Self {
        Self {
            discover_hash_files_depth: value,
            ..self
        }
    }

    pub fn hash_files_matcher(self, value: PathMatcher) -> Self {
        Self {
            hash_files_matcher: value,
            ..self
        }
    }

    pub fn all_files_matcher(self, value: PathMatcher) -> Self {
        Self {
            all_files_matcher: value,
            ..self
        }
    }
}

impl Default for ChecksumHelperOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct CheckMissingResult {
    pub directories: Vec<path::PathBuf>,
    pub files: Vec<path::PathBuf>,
    pub errors: Vec<String>,
}

#[derive(Debug)]
pub enum IncrementalProgress {
    BuildMostCurrent(MostCurrentProgress),
    /// Found a file that will be included in check summing.
    DiscoverFilesFound(usize),
    /// Ignored a path (file or directory).
    DiscoverFilesIgnored(path::PathBuf),
    /// Finished discovering files to hash: number of files to hash, number of ignored files.
    DiscoverFilesDone(usize, usize),
    PreRead(path::PathBuf),
    /// Read progress in bytes: read, total.
    Read(u64, u64),
    /// File matched the recorded hash.
    FileMatch(path::PathBuf),
    /// Skipped a file, which matched the recorded `mtime`.
    /// Turn this behaviour on or off using `ChecksumHelperOptions::incremental_skip_unchanged`.
    FileUnchangedSkipped(path::PathBuf),
    /// File changed with a newer `mtime` compared to the recorded one or there
    /// was no recorded `mtime`.
    FileChanged(path::PathBuf),
    /// File matched the recorded `mtime`, but the computed hash was different.
    FileChangedCorrupted(path::PathBuf),
    /// File changed, where the `mtime` of the file on disk is __older__ than the
    /// recorded `mtime`.
    FileChangedOlder(path::PathBuf),
    FileNew(path::PathBuf),
    FileRemoved(path::PathBuf),
    Finished,
}

#[derive(Debug)]
pub enum ChecksumHelperError {
    RootIsRelative(path::PathBuf),
    InvalidMostCurrentHashFile,
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
            ChecksumHelperError::RootIsRelative(ref p) => {
                write!(f, "root must be absolute, got: {:?}", p)
            }
            ChecksumHelperError::InvalidMostCurrentHashFile => {
                write!(f, "invalid most current hash file")
            }
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

impl From<crate::gather::Error> for ChecksumHelperError {
    fn from(value: crate::gather::Error) -> Self {
        ChecksumHelperError::GatherError(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use pretty_assertions::assert_eq;

    fn setup_dir_check_missing() -> std::path::PathBuf {
        let testdir = testdir!();
        create_ftree(
            &testdir,
            "\
foo/bar/baz/file.bin
foo/bar/baz/file.txt
foo/bar/bar.test
foo/bar/bar.mp4
foo/foo.txt
foo/foo.bin
bar/baz/baz_2025-06-28.foo
bar/baz/save.sav
bar/baz_2025-06-28.foo
bar/other.txt
root.mp4
file.rs",
        );
        testdir
    }

    #[test]
    fn check_missing_no_hashed_files() {
        let testdir = setup_dir_check_missing();
        let mut ch = ChecksumHelper::new(&testdir)
            .unwrap();
        let result = ch.check_missing().unwrap();
        assert_eq!(
            result,
            CheckMissingResult{
                directories: vec!{
                    path::PathBuf::from("bar"),
                    path::PathBuf::from("foo"),
                },
                files: vec!{
                    path::PathBuf::from("file.rs"),
                    path::PathBuf::from("root.mp4"),
                },
                errors: vec!{
                },

            }
        );
    }


    #[test]
    fn check_missing_with_hashed_files() {
        let testdir = setup_dir_check_missing();
        std::fs::write(testdir.join("test.md5"), "\
e37276a93ac1e99188340e3f61e3673b  foo/bar/baz/file.bin
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.test
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.mp4
e37276a93ac1e99188340e3f61e3673b  bar/baz_2025-06-28.foo
e37276a93ac1e99188340e3f61e3673b  bar/other.txt
e37276a93ac1e99188340e3f61e3673b  file.rs").unwrap();

        let mut ch = ChecksumHelper::new(&testdir)
            .unwrap();
        let result = ch.check_missing().unwrap();
        assert_eq!(
            result,
            CheckMissingResult{
                directories: vec!{
                    path::PathBuf::from("bar").join("baz"),
                },
                files: vec!{
                    path::PathBuf::from("root.mp4"),
                    path::PathBuf::from("test.md5"),
                    path::PathBuf::from("foo").join("foo.bin"),
                    path::PathBuf::from("foo").join("foo.txt"),
                    path::PathBuf::from("foo/bar/baz/file.txt"),
                },
                errors: vec!{
                },

            }
        );
    }

    #[test]
    fn check_missing_dir_missing_completely() {
        let testdir = setup_dir_check_missing();
        std::fs::write(testdir.join("test.md5"), "\
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.test
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.mp4
e37276a93ac1e99188340e3f61e3673b  file.rs").unwrap();

        let mut ch = ChecksumHelper::new(&testdir)
            .unwrap();
        let result = ch.check_missing().unwrap();
        assert_eq!(
            result,
            CheckMissingResult{
                directories: vec!{
                    path::PathBuf::from("bar"),
                    path::PathBuf::from("foo").join("bar").join("baz"),
                },
                files: vec!{
                    path::PathBuf::from("root.mp4"),
                    path::PathBuf::from("test.md5"),
                    path::PathBuf::from("foo").join("foo.bin"),
                    path::PathBuf::from("foo").join("foo.txt"),
                },
                errors: vec!{
                },

            }
        );
    }

    #[test]
    fn check_missing_respects_filters() {
        let testdir = setup_dir_check_missing();
        std::fs::write(testdir.join("test.md5"), "\
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.test
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.mp4
e37276a93ac1e99188340e3f61e3673b  file.rs").unwrap();

        let matcher = PathMatcherBuilder::new()
            .block("bar/").unwrap()
            .block("**/*.md5").unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            all_files_matcher: matcher,
            ..Default::default()
        };

        let mut ch = ChecksumHelper::with_options(&testdir, options).unwrap();
        let result = ch.check_missing().unwrap();
        assert_eq!(
            result,
            CheckMissingResult{
                directories: vec!{
                    path::PathBuf::from("foo").join("bar").join("baz"),
                },
                files: vec!{
                    path::PathBuf::from("root.mp4"),
                    path::PathBuf::from("foo").join("foo.bin"),
                    path::PathBuf::from("foo").join("foo.txt"),
                },
                errors: vec!{
                },

            }
        );
    }
}
