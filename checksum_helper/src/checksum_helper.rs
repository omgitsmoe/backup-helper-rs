use crate::collection::{HashCollection, HashCollectionError, VerifyProgress, HashCollectionWriter};
use crate::file_tree::FileTree;
use crate::gather::{gather, VisitType};
use crate::pathmatcher::{PathMatcher, PathMatcherBuilder};

use std::cmp::{Eq, PartialEq};
use std::error::Error;
use std::fmt;
use std::path;

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

    pub fn incremental<P>(&mut self, progress: P) -> Result<&HashCollection> 
    where
        P: Fn(IncrementalProgress)

    {
        // TODO progress callback
        // prob best to gather files first then do the checksumming -> better progress indicator
        todo!();
    }

    pub fn fill_missing(&mut self) -> Result<HashCollection> {
        if self.most_current.is_none() {
            self.update_most_current()?;
        }

        todo!("find files that don't have a checksum in most current yet and generat them")
    }

    pub fn check_missing(&mut self) -> Result<CheckMissingResult> {
        if self.most_current.is_none() {
            self.update_most_current()?;
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

    fn update_most_current(&mut self) -> Result<()> {
        let discover_result = self.discover_hash_files()?;
        let most_current_path = self.root().join(
        self.most_current_filename());
        let mut most_current = HashCollection::new(
            Some(&most_current_path), None)
            .expect("creating an empty hash file collection must succeed");

        for hash_file_path in discover_result.hash_file_paths {
            let hc = HashCollection::from_disk(
                &hash_file_path, &mut self.file_tree)?;
            most_current.merge(hc)?;
        }

        self.most_current = Some(most_current);

        Ok(())
    }

    pub fn build_most_current(&mut self) -> Result<()> {
        if self.most_current.is_none() {
            self.update_most_current()?;
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

    // TODO extract extension/depth/etc matching into separate function and then
    //      check early dir skipping based on that
    fn discover_hash_files(&self) -> Result<DiscoverResult> {
        let mut files = vec![];
        let root = self.root();
        let result = gather(&root, |visit_type| {
            match visit_type {
                VisitType::File((_, e)) => match e.path().extension() {
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
                            e.path(), &root)
                            .expect("discover_hash_files paths must alway be \
                                relative to the ChecksumHelper root!");

                        #[cfg(test)]
                        println!("Visiting f {:?}", relative_path);

                        if self.options.hash_files_matcher.is_match(relative_path) {
                            files.push(e.path());
                            true
                        } else {
                            false
                        }
                    }
                },
                VisitType::Directory((depth, dirent)) => {
                    if let Some(max_depth) = self.options.discover_hash_files_depth {
                        // NOTE: since 0 -> same directory
                        // 1 -> one directory down
                        // and we decide if we want to enter here, so it needs to be >=
                        if depth >= max_depth {
                            return false;
                        }
                    }

                    let relative_path = pathdiff::diff_paths(
                        dirent.path(), &root)
                        .expect("discover_hash_files paths must alway be \
                            relative to the ChecksumHelper root!");

                    #[cfg(test)]
                    println!("Visiting d {:?}", relative_path);

                    if self.options.hash_files_matcher.is_excluded(relative_path) {
                        return false;
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

    fn most_current_filename(&self) -> std::ffi::OsString {
        let now = chrono::offset::Local::now();
        let datetime = now.format("%Y-%m-%dT%H%M%S");
        let root = self.root();
        let default = std::ffi::OsString::from("most_current");
        let base = root.file_name()
            .unwrap_or(&default);
        format!("{:?}_{}", base, datetime).into()
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
    // TODO most_current progress (discovering hash files?)
    DiscoverFiles, // num found, num ignored
    PreRead,
    Read,
    PostRead,
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
        let mut result = ch.discover_hash_files().unwrap();
        assert!(result.errors.is_empty());
        result.hash_file_paths.sort();
        assert_eq!(
            result.hash_file_paths,
            vec! {
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
        let options = ChecksumHelperOptions {
            discover_hash_files_depth: Some(1),
            ..Default::default()
        };

        let ch = ChecksumHelper::with_options(&testdir, options).unwrap();
        let mut result = ch.discover_hash_files().unwrap();
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
    fn discover_hash_files_respsects_hash_files_matcher() {
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
        let mut result = ch.discover_hash_files().unwrap();
        assert!(result.errors.is_empty());

        result.hash_file_paths.sort();
        assert_eq!(
            result.hash_file_paths,
            vec! {
                testdir.join("bar").join("baz_2025-06-28.cshd"),
                testdir.join("foo").join("bar").join("baz").join("file.cshd"),
            }
        );
    }

    #[test]
    fn discover_hash_files_skips_exluded_directories_early() {
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
        let mut result = ch.discover_hash_files().unwrap();
        assert!(result.errors.is_empty());

        result.hash_file_paths.sort();
        assert_eq!(
            result.hash_file_paths,
            vec! {
                testdir.join("root.sha3_384"),
            }
        );

        // TODO extract hash files depth/ext/etc. logic and then test it separately
        // for manually testing debug output
        // panic!();
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
        let mut result = ch.discover_hash_files().unwrap();
        assert!(result.errors.is_empty());

        result.hash_file_paths.sort();
        assert_eq!(
            result.hash_file_paths,
            vec! {
                testdir.join("bar").join("baz").join("baz_2025-06-28.sha256"),
                testdir.join("bar").join("baz_2025-06-28.cshd"),
                testdir.join("foo").join("foo.shake_128"),
                testdir.join("root.sha3_384"),
            }
        );

        // for manually testing debug output
        // panic!();
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
