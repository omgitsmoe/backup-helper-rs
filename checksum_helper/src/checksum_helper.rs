use crate::collection::{HashCollection, HashCollectionError, VerifyProgress, HashCollectionWriter};
use crate::file_tree::FileTree;
use crate::gather::{gather, VisitType};
use crate::pathmatcher::{PathMatcher, PathMatcherBuilder};

use std::cmp::{Eq, PartialEq};
use std::error::Error;
use std::fmt;
use std::path;
use std::fs;

use chrono;

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
        if self.most_current.is_none() {
            self.update_most_current(|p| progress(IncrementalProgress::BuildMostCurrent(p)))?;
        }

        // TODO progress callback
        // prob best to gather files first then do the checksumming -> better progress indicator
        todo!();
    }

    pub fn fill_missing(&mut self) -> Result<HashCollection> {
        if self.most_current.is_none() {
            self.update_most_current(|_| {})?;
        }

        todo!("find files that don't have a checksum in most current yet and generat them")
    }

    pub fn check_missing(&mut self) -> Result<CheckMissingResult> {
        if self.most_current.is_none() {
            self.update_most_current(|_| {})?;
        }

        let root = self.root();
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

    fn update_most_current<P>(&mut self, mut progress: P) -> Result<()>
    where
        P: FnMut(MostCurrentProgress)
    {
        let discover_result = self.discover_hash_files(&mut progress)?;
        let most_current_path = self.root().join(
        self.most_current_filename());
        let mut most_current = HashCollection::new(
            Some(&most_current_path), None)
            .expect("creating an empty hash file collection must succeed");

        for hash_file_path in discover_result.hash_file_paths {
            progress(MostCurrentProgress::MergeHashFile(hash_file_path.clone()));
            let hc = HashCollection::from_disk(
                &hash_file_path, &mut self.file_tree)?;
            most_current.merge(hc)?;
        }

        self.most_current = Some(most_current);

        Ok(())
    }

    pub fn build_most_current<P>(&mut self, progress: P) -> Result<()>
    where
        P: FnMut(MostCurrentProgress)
    {
        if self.most_current.is_none() {
            self.update_most_current(progress)?;
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

    fn discover_hash_files<P>(&self, mut progress: P) -> Result<DiscoverResult>
    where
        P: FnMut(MostCurrentProgress)
    {
        let mut files = vec![];
        let root = self.root();
        let result = gather(&root, |visit_type| {
            match visit_type {
                VisitType::File((_, e)) => {

                    if self.include_hash_file(&root, &e.path(), &mut progress) {
                        files.push(e.path());
                        true
                    } else {
                        false
                    }
                },
                VisitType::Directory((depth, dirent)) => {
                    self.include_hash_file_dir(&root, depth, &dirent.path(), &mut progress)
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

    fn include_hash_file<P>(&self, root: &path::Path, hash_file: &path::Path, progress: &mut P) -> bool
    where
        P: FnMut(MostCurrentProgress)
    {
        match hash_file.extension() {
            None => false,
            Some(file_ext) => {
                let mut include = false;
                for ext in HASH_FILE_EXTENSIONS {
                    if *ext == file_ext {
                        include = true;
                        break;
                    }
                }
                if !include {
                    return false;
                }

                let relative_path = pathdiff::diff_paths(
                    hash_file, root)
                    .expect("discover_hash_files paths must alway be \
                        relative to the ChecksumHelper root!");
                assert!(
                    !relative_path.starts_with(".."),
                    "discover_hash_files path must always be a sub-path of the ChecksumHelper root!");

                if self.options.hash_files_matcher.is_match(&relative_path) {
                    progress(MostCurrentProgress::FoundFile(
                        relative_path.to_owned()));
                    true
                } else {
                    progress(MostCurrentProgress::IgnoredPath(
                        relative_path.to_owned()));
                    false
                }
            }
        }
    }

    fn include_hash_file_dir<P>(&self, root: &path::Path, depth: u32, dir: &path::Path, progress: &mut P) -> bool
    where
        P: FnMut(MostCurrentProgress)
    {
        if let Some(max_depth) = self.options.discover_hash_files_depth {
            // NOTE: since 0 -> same directory
            // 1 -> one directory down
            // and we decide if we want to enter here, so it needs to be >=
            if depth >= max_depth {
                return false;
            }
        }

        let relative_path = pathdiff::diff_paths(
            dir, root)
            .expect("discover_hash_files paths must alway be \
                relative to the ChecksumHelper root!");
        assert!(
            !relative_path.starts_with(".."),
            "discover_hash_files path must always be a sub-path of the ChecksumHelper root!");

        if self.options.hash_files_matcher.is_excluded(&relative_path) {
            progress(MostCurrentProgress::IgnoredPath(
                    relative_path.to_owned()));
            return false;
        }

        true
    }

    fn most_current_filename(&self) -> std::ffi::OsString {
        let now = chrono::offset::Local::now();
        let datetime = now.format("%Y-%m-%dT%H%M%S");
        let root = self.root();
        let default = std::ffi::OsString::from("most_current");
        let base = root.file_name()
            .unwrap_or(&default);
        let base = base.to_string_lossy(); // Cow<str>

        format!("{}_{}.cshd", base, datetime).into()
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
pub enum MostCurrentProgress {
    /// Found a hash file that will be included in the most current hash file.
    FoundFile(path::PathBuf),
    /// Ignored a file or directory path. Not used when pre-filtering known hash file
    /// extensions.
    IgnoredPath(path::PathBuf),
    /// Load and merge hash file into most current.
    MergeHashFile(path::PathBuf),
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

    fn setup_dir_hash_files() -> std::path::PathBuf {
        let testdir = testdir!();
        create_ftree(
            &testdir,
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
file.rs",
        );
        testdir
    }

    #[test]
    fn discover_hash_files_all_hash_files_found() {
        let testdir = setup_dir_hash_files();
        let ch = ChecksumHelper::new(&testdir).unwrap();
        let mut found_cb = vec!();
        let mut result = ch.discover_hash_files(|p| {
            if let MostCurrentProgress::FoundFile(p) = p {
                found_cb.push(p);
            } else {
                unreachable!();
            }
        }).unwrap();
        assert!(result.errors.is_empty());
        result.hash_file_paths.sort();
        let expected = vec! {
            testdir.join("bar").join("baz").join("baz_2025-06-28.sha256"),
            testdir.join("bar").join("baz_2025-06-28.cshd"),
            testdir.join("foo").join("bar").join("bar.blake2b"),
            testdir.join("foo").join("bar").join("baz").join("file.cshd"),
            testdir.join("foo").join("bar").join("baz").join("file.md5"),
            testdir.join("foo").join("foo.shake_128"),
            testdir.join("root.sha3_384"),
        };
        assert_eq!(
            result.hash_file_paths,
            expected
        );

        found_cb.sort();
        assert_eq!(
            found_cb,
            expected.iter().map(|p| p.strip_prefix(&testdir).unwrap())
                .collect::<Vec<&path::Path>>(),
        );
    }

    #[test]
    fn discover_hash_files_respects_hash_files_depth() {
        // NOTE: decided this should be part of discover_hash_files
        //       since update_most_current has a different task
        //       harder to reuse discover_hash_files then, but
        //       most likely the options should be respected for everything anyway
        let testdir = setup_dir_hash_files();
        let options = ChecksumHelperOptions {
            discover_hash_files_depth: Some(1),
            ..Default::default()
        };

        let ch = ChecksumHelper::with_options(&testdir, options).unwrap();
        let mut result = ch.discover_hash_files(|_| {}).unwrap();
        assert!(result.errors.is_empty());

        result.hash_file_paths.sort();
        assert_eq!(
            result.hash_file_paths,
            vec! {
                testdir.join("bar").join("baz_2025-06-28.cshd"),
                testdir.join("foo").join("foo.shake_128"),
                testdir.join("root.sha3_384"),
            }
        );
    }

    #[test]
    fn discover_hash_files_respects_hash_files_matcher() {
        // NOTE: decided this should be part of discover_hash_files
        //       since update_most_current has a different task
        //       harder to reuse discover_hash_files then, but
        //       most likely the options should be respected for everything anyway
        let testdir = setup_dir_hash_files();
        let matcher = PathMatcherBuilder::new()
            .allow("**/*.cshd")
            .unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            hash_files_matcher: matcher,
            ..Default::default()
        };
        let ch = ChecksumHelper::with_options(&testdir, options).unwrap();

        let mut found_cb = vec!();
        let mut ignored_cb = vec!();
        let mut result = ch.discover_hash_files(|p| {
            match p {
                MostCurrentProgress::FoundFile(p) => found_cb.push(p),
                MostCurrentProgress::IgnoredPath(p) => ignored_cb.push(p),
                _ => unreachable!(),
            }
        }).unwrap();

        assert!(result.errors.is_empty());

        result.hash_file_paths.sort();
        let expected = vec! {
            testdir.join("bar").join("baz_2025-06-28.cshd"),
            testdir.join("foo").join("bar").join("baz").join("file.cshd"),
        };
        assert_eq!(
            result.hash_file_paths,
            expected,
        );

        found_cb.sort();
        assert_eq!(
            found_cb,
            expected.iter().map(|p| p.strip_prefix(&testdir).unwrap())
                .collect::<Vec<&path::Path>>(),
        );

        ignored_cb.sort();
        assert_eq!(
            ignored_cb,
            vec! {
                path::PathBuf::from("bar").join("baz").join("baz_2025-06-28.sha256"),
                path::PathBuf::from("foo").join("bar").join("bar.blake2b"),
                path::PathBuf::from("foo").join("bar").join("baz").join("file.md5"),
                path::PathBuf::from("foo").join("foo.shake_128"),
                path::PathBuf::from("root.sha3_384"),
            },
        );
    }

    #[test]
    fn discover_hash_files_skips_excluded_directories_early() {
        let testdir = setup_dir_hash_files();
        let matcher = PathMatcherBuilder::new()
            .block("foo/").unwrap()
            .block("bar/*").unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            hash_files_matcher: matcher,
            ..Default::default()
        };

        let ch = ChecksumHelper::with_options(&testdir, options).unwrap();
        let mut found_cb = vec!();
        let mut ignored_cb = vec!();
        let mut result = ch.discover_hash_files(|p| {
            match p {
                MostCurrentProgress::FoundFile(p) => found_cb.push(p),
                MostCurrentProgress::IgnoredPath(p) => ignored_cb.push(p),
                _ => unreachable!(),
            }
        }).unwrap();
        assert!(result.errors.is_empty());

        result.hash_file_paths.sort();
        let expected = vec! {
            testdir.join("root.sha3_384"),
        };
        assert_eq!(
            result.hash_file_paths,
            expected
        );

        found_cb.sort();
        assert_eq!(
            found_cb,
            expected.iter().map(|p| p.strip_prefix(&testdir).unwrap())
                .collect::<Vec<&path::Path>>(),
        );

        ignored_cb.sort();
        assert_eq!(
            ignored_cb,
            vec! {
                // excluded whole directory early and then no more ignore cbs
                path::PathBuf::from("bar").join("baz"),
                path::PathBuf::from("bar").join("baz_2025-06-28.cshd"),
                path::PathBuf::from("foo"),
            },
        );
    }

    #[test]
    fn discover_hash_files_does_not_exclude_directories_containing_matched_files() {
        // NOTE: discover_hash_files must not exclude directories that would
        //       still have files in it that were not excluded
        let testdir = setup_dir_hash_files();
        let matcher = PathMatcherBuilder::new()
            // must visit all dirs still
            .block("**/*.blake2b").unwrap()
            // must still visit baz itself
            .block("**/baz/*.cshd").unwrap()
            .block("**/baz/*.md5").unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            hash_files_matcher: matcher,
            ..Default::default()
        };

        let ch = ChecksumHelper::with_options(&testdir, options).unwrap();
        let mut found_cb = vec!();
        let mut ignored_cb = vec!();
        let mut result = ch.discover_hash_files(|p| {
            match p {
                MostCurrentProgress::FoundFile(p) => found_cb.push(p),
                MostCurrentProgress::IgnoredPath(p) => ignored_cb.push(p),
                _ => unreachable!(),
            }
        }).unwrap();
        assert!(result.errors.is_empty());

        result.hash_file_paths.sort();
        let expected = vec! {
            testdir.join("bar").join("baz").join("baz_2025-06-28.sha256"),
            testdir.join("bar").join("baz_2025-06-28.cshd"),
            testdir.join("foo").join("foo.shake_128"),
            testdir.join("root.sha3_384"),
        };
        assert_eq!(
            result.hash_file_paths,
            expected,
        );

        found_cb.sort();
        assert_eq!(
            found_cb,
            expected.iter().map(|p| p.strip_prefix(&testdir).unwrap())
                .collect::<Vec<&path::Path>>(),
        );

        ignored_cb.sort();
        // NOTE: no directory excluded early, still traversed all directories
        assert_eq!(
            ignored_cb,
            vec! {
                path::PathBuf::from("foo").join("bar").join("bar.blake2b"),
                path::PathBuf::from("foo").join("bar").join("baz").join("file.cshd"),
                path::PathBuf::from("foo").join("bar").join("baz").join("file.md5"),
            },
        );
    }

    #[test]
    #[should_panic]
    fn include_hash_file_panics_on_path_outside_of_root() {
        let ch = ChecksumHelper::new(path::Path::new("/foo")).unwrap();
        ch.include_hash_file(
            &ch.root(), path::Path::new("/home/bar/f.cshd"), &mut |_| {});
    }

    #[test]
    fn include_hash_file_skips_non_hash_files() {
        let ch = ChecksumHelper::new(path::Path::new("/")).unwrap();
        for ext in HASH_FILE_EXTENSIONS {
            assert!(
                ch.include_hash_file(
                    &ch.root(), path::Path::new(&format!("/opt/foo.{}", ext)), &mut |_| {})
            );
        }

        for ext in vec!["txt", "bin", "iso", "rs"] {
            assert!(
                !ch.include_hash_file(
                    &ch.root(), path::Path::new(&format!("/opt/foo.{}", ext)), &mut |_| {})
            );
        }
    }

    #[test]
    fn include_hash_file_respects_hash_files_matcher() {
        let matcher = PathMatcherBuilder::new()
            .allow("**/*.cshd")
            .unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            hash_files_matcher: matcher,
            ..Default::default()
        };
        let ch = ChecksumHelper::with_options(
            path::Path::new("/"), options).unwrap();

        assert!(ch.include_hash_file(&ch.root(), path::Path::new("/foo.cshd"), &mut |_| {}));
        assert!(!ch.include_hash_file(&ch.root(), path::Path::new("/foo.md5"), &mut |_| {}));
    }

    #[test]
    fn include_hash_file_calls_the_progress_callback() {
        let matcher = PathMatcherBuilder::new()
            .allow("**/*.cshd")
            .unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            hash_files_matcher: matcher,
            ..Default::default()
        };
        let ch = ChecksumHelper::with_options(
            path::Path::new("/"), options).unwrap();

        let mut was_called = false;
        assert!(ch.include_hash_file(&ch.root(), path::Path::new("/foo.cshd"), &mut |p| {
            was_called = true;
            assert!(matches!(
                    p,
                    MostCurrentProgress::FoundFile(ref f) if f == path::Path::new("foo.cshd")
            ));
        }));
        assert!(was_called);

        let mut was_called = false;
        assert!(!ch.include_hash_file(&ch.root(), path::Path::new("/foo.md5"), &mut |p| {
            was_called = true;
            assert!(matches!(
                    p,
                    MostCurrentProgress::IgnoredPath(ref f) if f == path::Path::new("foo.md5")
            ));
        }));
        assert!(was_called);
    }

    #[test]
    #[should_panic]
    fn include_hash_file_dir_panics_on_path_outside_of_root() {
        let ch = ChecksumHelper::new(path::Path::new("/foo")).unwrap();
        ch.include_hash_file_dir(
            &ch.root(),  1, path::Path::new("/home/bar"), &mut |_| {});
    }

    #[test]
    fn include_hash_file_dir_respects_disover_hash_files_depth() {
        let options = ChecksumHelperOptions {
            discover_hash_files_depth: Some(3),
            ..Default::default()
        };
        let ch = ChecksumHelper::with_options(
            &path::Path::new("/"), options).unwrap();
        assert!(ch.include_hash_file_dir(&ch.root(), 0, path::Path::new("/foo"), &mut |_| {}));
        assert!(ch.include_hash_file_dir(&ch.root(), 1, path::Path::new("/foo/bar"), &mut |_| {}));
        assert!(ch.include_hash_file_dir(&ch.root(), 2, path::Path::new("/foo/bar/baz"), &mut |_| {}));
        assert!(!ch.include_hash_file_dir(&ch.root(), 3, path::Path::new("/foo/bar/baz/qux"), &mut |_| {}));
        assert!(!ch.include_hash_file_dir(&ch.root(), 4, path::Path::new("/foo/bar/baz/qux/xer"), &mut |_| {}));
    }

    #[test]
    fn include_hash_file_dir_respects_hash_files_matcher() {
        let matcher = PathMatcherBuilder::new()
            .allow("**/*.*")
            .unwrap()
            .block("*/home/")
            .unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            hash_files_matcher: matcher,
            ..Default::default()
        };
        let ch = ChecksumHelper::with_options(
            path::Path::new("/"), options).unwrap();

        // TODO should include_hash_file_dir also check if the path could not match any
        //      of the allowed paths?
        //      would be annoying, since you'd have to split up the pattern into components
        //      and match up to the current depth etc.
        //      -> then
        //      .allow("fo*b/**/*.*")
        //      should only allow /foob/, not /foo/
        assert!(ch.include_hash_file_dir(&ch.root(), 3, path::Path::new("/foo"), &mut |_| {}));
        assert!(!ch.include_hash_file_dir(&ch.root(), 3, path::Path::new("/foob/home"), &mut |_| {}));
    }

    #[test]
    fn include_hash_file_dir_calls_the_progress_callback() {
        let matcher = PathMatcherBuilder::new()
            .allow("**/*.*")
            .unwrap()
            .block("home/")
            .unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            hash_files_matcher: matcher,
            ..Default::default()
        };
        let ch = ChecksumHelper::with_options(
            path::Path::new("/"), options).unwrap();

        let mut was_called = false;
        assert!(ch.include_hash_file_dir(&ch.root(), 3, path::Path::new("/foo"), &mut |p| {}));
        assert!(!was_called);

        assert!(!ch.include_hash_file_dir(&ch.root(), 3, path::Path::new("/home"), &mut |p| {
            was_called = true;
            assert!(matches!(
                    p,
                    MostCurrentProgress::IgnoredPath(ref f) if f == path::Path::new("home")
            ));
        }));
        assert!(was_called);
    }

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
