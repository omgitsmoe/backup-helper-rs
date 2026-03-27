use crate::collection::{
    HashCollection, HashCollectionError, HashCollectionIter, HashCollectionWriter, VerifyProgress,
};
use crate::file_tree::FileTree;
use crate::gather::{filtered, VisitType};
use crate::hash_type::HashType;
use crate::hashed_file::FileRaw;
use crate::incremental::Incremental;
use crate::most_current::update_most_current;
use crate::pathmatcher::{PathMatcher, PathMatcherBuilder};

use std::cell::RefCell;
use std::cmp::{Eq, PartialEq};
use std::error::Error;
use std::fmt;
use std::io::Write;
use std::path;

pub use crate::incremental::IncrementalProgress;
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

    pub fn incremental<P>(&mut self, mut progress: P) -> Result<HashCollection>
    where
        P: FnMut(IncrementalProgress),
    {
        let root = self.root();
        if self.most_current.is_none() {
            self.most_current = Some(update_most_current(
                &root,
                &mut self.file_tree,
                &self.options,
                |p| progress(IncrementalProgress::BuildMostCurrent(p)),
            )?);
        }

        let inc = Incremental::new(
            &root,
            &mut self.file_tree,
            &self.options,
            self.most_current.take().expect("checked above"),
        );

        // NOTE: does not make sense to use this as new most_current, since only
        //       new files might be contained etc.
        inc.generate(progress)
    }

    /// Generate a [`HashCollection`], which only contains the hashes of
    /// files that do not have checksum in any matched hash file yet.
    pub fn fill_missing<P>(&mut self, mut progress: P) -> Result<HashCollection>
    where
        P: FnMut(IncrementalProgress),
    {
        // NOTE: can't use check_missing's result, since the file list is incomplete
        //       if there are directories missing!
        let root = self.root();
        if self.most_current.is_none() {
            self.most_current = Some(update_most_current(
                &root,
                &mut self.file_tree,
                &self.options,
                |p| progress(IncrementalProgress::BuildMostCurrent(p)),
            )?);
        }
        let most_current = self.most_current.as_ref().expect("checked above");

        let root = self.root();
        let filename = default_filename(&root, "missing", "_missing_");
        let mut hc = HashCollection::new(Some(&root.join(filename)), None)?;
        // dyanmic borrow checking needed, since we use it in the predicate closure
        // as well as in our for loop while the closure is still alive
        let progress = std::cell::RefCell::new(progress);
        let mut ignored_num = 0usize;
        // NOTE: does currently not follow the same pattern of discover first,
        //       then checksum files after like in `incremental`
        let iter = filtered(&root, &self.options.all_files_matcher, |e| {
            if e.ignored {
                progress.borrow_mut()(IncrementalProgress::DiscoverFilesIgnored(
                    e.entry.relative_to_root.to_owned(),
                ));
                ignored_num += 1;

                return false;
            }

            true
        });
        for v in iter {
            let v = v?;
            if let VisitType::File(v) = v {
                if most_current.contains_path(&v.relative_to_root, &self.file_tree) {
                    continue;
                }

                // TODO make it easier to create a hashed file
                let entry = self.file_tree.add_file(&v.relative_to_root)?;
                let mut file_raw = FileRaw::bare(entry.clone(), self.options.hash_type);
                let mut file = file_raw.with_context_mut(&self.file_tree);

                progress.borrow_mut()(IncrementalProgress::PreRead(v.relative_to_root.to_owned()));
                file.update_size_and_mtime_from_disk()?;
                file.update_hash_from_disk(|(read, total)| {
                    progress.borrow_mut()(IncrementalProgress::Read(read, total));
                })?;
                progress.borrow_mut()(IncrementalProgress::FileNew(v.relative_to_root.to_owned()));

                hc.update(entry, file_raw);
            }
        }

        progress.borrow_mut()(IncrementalProgress::Finished);

        Ok(hc)
    }

    /// Returns a result object containing all individual files that do not have checksums
    /// in `self.root` yet.
    /// If a directory has files and is completely missing it will be listed
    /// in `directories`.
    /// Note: The files of that directory will not appear in the file list.
    pub fn check_missing<P>(&mut self, mut progress: P) -> Result<CheckMissingResult>
    where
        P: FnMut(IncrementalProgress),
    {
        let root = self.root();
        if self.most_current.is_none() {
            self.most_current = Some(update_most_current(
                &root,
                &mut self.file_tree,
                &self.options,
                |p| progress(IncrementalProgress::BuildMostCurrent(p)),
            )?);
        }

        // first find all directories that have at least one file and add all
        // its parents,
        // if we find a directory later that is not in this set,
        // we can record it as missing entirely
        let mut dirs_with_hashed_file = std::collections::HashSet::new();
        dirs_with_hashed_file.insert(root.clone());

        let most_current = self.most_current.as_ref().expect("checked above");
        for (path, _) in most_current.iter_with_context(&self.file_tree) {
            let relative = path
                .strip_prefix(&root)
                .expect("paths in the file tree must be relative to the ChecksumHelper root");
            let mut current = relative;
            while let Some(path) = current.parent() {
                dirs_with_hashed_file.insert(path.to_owned());
                current = path;
            }
        }

        // dyanmic borrow checking needed, since we use it in the predicate closure
        // as well as in our for loop while the closure is still alive
        let progress = RefCell::new(progress);
        let mut missing_directories = vec![];
        let mut missing_files = vec![];
        let iter = filtered(&root, &self.options.all_files_matcher, |e| {
            if e.ignored {
                // TODO unify what kind of path is returned:
                //      absolute or relative to root
                progress.borrow_mut()(IncrementalProgress::DiscoverFilesIgnored(
                    e.entry.dir_entry.path(),
                ));
                return false;
            }

            let relative = e.entry.relative_to_root;
            if e.entry.is_directory {
                if dirs_with_hashed_file.contains(relative) {
                    true
                } else {
                    missing_directories.push(relative.to_owned());
                    false
                }
            } else {
                true
            }
        });

        let mut found = 0u64;
        for visit_result in iter {
            let visit_result = visit_result?;
            if let VisitType::File(v) = visit_result {
                let relative = v.relative_to_root;
                found += 1;
                progress.borrow_mut()(IncrementalProgress::DiscoverFilesFound(found));
                if !most_current.contains_path(&relative, &self.file_tree) {
                    missing_files.push(relative);
                }
            }
        }

        Ok(CheckMissingResult {
            directories: missing_directories,
            files: missing_files,
        })
    }

    pub fn build_most_current<P>(&mut self, progress: P) -> Result<()>
    where
        P: FnMut(MostCurrentProgress),
    {
        if self.most_current.is_none() {
            self.most_current = Some(update_most_current(
                self.root(),
                &mut self.file_tree,
                &self.options,
                progress,
            )?);
        }

        if let Some(most_current) = &mut self.most_current {
            let mut writer = HashCollectionWriter::new();
            writer.write(most_current, &self.file_tree)?;
            Ok(())
        } else {
            Err(ChecksumHelperError::InvalidMostCurrentHashFile)
        }
    }

    pub fn iter_collection<'a>(&'a self, collection: &'a HashCollection) -> HashCollectionIter<'a> {
        collection.iter_with_context(&self.file_tree)
    }

    pub fn read_collection(&mut self, path: &path::Path) -> Result<HashCollection> {
        Ok(HashCollection::from_disk(path, &mut self.file_tree)?)
    }

    pub fn write_collection(&self, collection: &HashCollection) -> Result<()> {
        collection.write_to_disk(&self.file_tree)?;

        Ok(())
    }

    pub fn write_into<W: Write>(&self, collection: &HashCollection, writer: &mut W) -> Result<()> {
        collection.serialize(writer, &self.file_tree)?;

        Ok(())
    }

    /// Verify all files matching predicated `include` in the `HashCollection`
    ///
    /// `include`: Predicate function which determines whether to include the
    ///            Path passed to it in verification. The path is relative
    ///            to the `file_tree.root()`.
    /// `progress`: Progress callback that receives a `VerifyProgress`
    ///             before and after processing the file.
    pub fn verify<F, P>(&self, collection: &HashCollection, include: F, progress: P) -> Result<()>
    where
        F: Fn(&path::Path) -> bool,
        P: FnMut(VerifyProgress),
    {
        collection.verify(&self.file_tree, include, progress)?;

        Ok(())
    }

    pub fn verify_root<F, P>(&mut self, include: F, mut progress: P) -> Result<()>
    where
        F: Fn(&path::Path) -> bool,
        P: FnMut(VerifyRootProgress),
    {
        // TODO update_most_current discards missing files based on most_current_filter_deleted:
        //      do we never want to do that or should we provide that option?
        let without_filter_deleted = ChecksumHelperOptions {
            most_current_filter_deleted: false,
            ..self.options.clone()
        };

        let most_current = update_most_current(
            self.root(),
            &mut self.file_tree,
            &without_filter_deleted,
            |p| progress(VerifyRootProgress::BuildMostCurrent(p)),
        )?;

        most_current.verify(&self.file_tree, include, |p| {
            progress(VerifyRootProgress::Verify(p))
        })?;

        Ok(())
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

pub(crate) fn default_filename(
    root: impl AsRef<path::Path>,
    default: &str,
    infix: &str,
) -> std::ffi::OsString {
    let now = chrono::offset::Local::now();
    let datetime = now.format("%Y-%m-%dT%H%M%S");
    let root = root.as_ref();
    let default = std::ffi::OsString::from(default);
    let base = root.file_name().unwrap_or(&default);
    let base = base.to_string_lossy(); // Cow<str>

    format!("{}_{}{}.cshd", base, infix, datetime).into()
}

#[derive(Debug, Clone)]
pub struct ChecksumHelperOptions {
    /// Which hash algorithm to use for generating new hashes.
    pub hash_type: HashType,

    /// Whether to include files in the output, which did not change compared
    /// to the previous latest available hash found.
    pub incremental_include_unchanged_files: bool,

    /// Whether to skip files when computing hashes if that files has the same
    /// modification time as in the latest available hash found.
    pub incremental_skip_unchanged: bool,

    /// If `true`, periodically flushes the incremental hash collection
    /// to disk upon the next modification after the specified time interval.
    pub incremental_periodic_write_interval: std::time::Duration,

    /// Up to which depth should the root and its subdirectories be searched
    /// for hash files (*.cshd, *.md5, *.sha512, etc.) to determine the
    /// current state of hashes.
    /// Zero means only files in the root directory will be considered.
    /// One means at most one subdirectory will be allowed.
    /// None means no depth limit.
    pub discover_hash_files_depth: Option<u32>,

    /// Whether the most_current hash file should filter out all files that are
    /// not found on disk at the time of generation.
    pub most_current_filter_deleted: bool,

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
            hash_type: HashType::Sha512,
            incremental_include_unchanged_files: true,
            incremental_skip_unchanged: false,
            incremental_periodic_write_interval: std::time::Duration::from_secs(60),
            discover_hash_files_depth: None,
            most_current_filter_deleted: true,
            hash_files_matcher: PathMatcherBuilder::new()
                .build()
                .expect("An empty PathMatcher should always be valid"),
            all_files_matcher: PathMatcherBuilder::new()
                .build()
                .expect("An empty PathMatcher should always be valid"),
        }
    }

    pub fn hash_type(self, value: HashType) -> Self {
        Self {
            hash_type: value,
            ..self
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

    pub fn incremental_periodic_write_interval(self, value: std::time::Duration) -> Self {
        Self {
            incremental_periodic_write_interval: value,
            ..self
        }
    }

    pub fn discover_hash_files_depth(self, value: Option<u32>) -> Self {
        Self {
            discover_hash_files_depth: value,
            ..self
        }
    }

    pub fn most_current_filter_deleted(self, value: bool) -> Self {
        Self {
            most_current_filter_deleted: value,
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
    /// Directories containing matched files, but which are completely missing
    /// from any hash collection.
    /// Files from directories in that list will not be listed in `files`.
    pub directories: Vec<path::PathBuf>,
    /// Matched files completely missing a hash. Does not contain files in
    /// directories that are completely missing.
    pub files: Vec<path::PathBuf>,
}

#[derive(Debug)]
pub enum ChecksumHelperError {
    RootIsRelative(path::PathBuf),
    InvalidMostCurrentHashFile,
    HashCollectionError(crate::collection::HashCollectionError),
    HashedFileError(crate::hashed_file::HashedFileError),
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
            ChecksumHelperError::GatherError(ref e) => Some(e),
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

impl From<crate::file_tree::ErrorKind> for ChecksumHelperError {
    fn from(value: crate::file_tree::ErrorKind) -> Self {
        ChecksumHelperError::FileTreeError(value)
    }
}

impl From<crate::hashed_file::HashedFileError> for ChecksumHelperError {
    fn from(value: crate::hashed_file::HashedFileError) -> Self {
        ChecksumHelperError::HashedFileError(value)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum VerifyRootProgress<'a> {
    BuildMostCurrent(MostCurrentProgress),
    Verify(VerifyProgress<'a>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hashed_file::VerifyResult, test_utils::*};
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
        let mut ch = ChecksumHelper::new(&testdir).unwrap();
        let result = ch.check_missing(|_| {}).unwrap();
        assert_eq!(
            result,
            CheckMissingResult {
                directories: vec! {
                    path::PathBuf::from("bar"),
                    path::PathBuf::from("foo"),
                },
                files: vec! {
                    path::PathBuf::from("file.rs"),
                    path::PathBuf::from("root.mp4"),
                },
            }
        );
    }

    #[test]
    fn check_missing_with_hashed_files() {
        let testdir = setup_dir_check_missing();
        std::fs::write(
            testdir.join("test.md5"),
            "\
e37276a93ac1e99188340e3f61e3673b  foo/bar/baz/file.bin
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.test
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.mp4
e37276a93ac1e99188340e3f61e3673b  bar/baz_2025-06-28.foo
e37276a93ac1e99188340e3f61e3673b  bar/other.txt
e37276a93ac1e99188340e3f61e3673b  file.rs",
        )
        .unwrap();

        let mut ch = ChecksumHelper::new(&testdir).unwrap();
        let result = ch.check_missing(|_| {}).unwrap();
        assert_eq!(
            result,
            CheckMissingResult {
                directories: vec! {
                    path::PathBuf::from("bar").join("baz"),
                },
                files: vec! {
                    path::PathBuf::from("root.mp4"),
                    path::PathBuf::from("test.md5"),
                    path::PathBuf::from("foo").join("foo.bin"),
                    path::PathBuf::from("foo").join("foo.txt"),
                    path::PathBuf::from("foo/bar/baz/file.txt"),
                },
            }
        );
    }

    #[test]
    fn check_missing_dir_missing_completely() {
        let testdir = setup_dir_check_missing();
        std::fs::write(
            testdir.join("test.md5"),
            "\
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.test
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.mp4
e37276a93ac1e99188340e3f61e3673b  file.rs",
        )
        .unwrap();

        let mut ch = ChecksumHelper::new(&testdir).unwrap();
        let result = ch.check_missing(|_| {}).unwrap();
        assert_eq!(
            result,
            CheckMissingResult {
                directories: vec! {
                    path::PathBuf::from("bar"),
                    path::PathBuf::from("foo").join("bar").join("baz"),
                },
                files: vec! {
                    path::PathBuf::from("root.mp4"),
                    path::PathBuf::from("test.md5"),
                    path::PathBuf::from("foo").join("foo.bin"),
                    path::PathBuf::from("foo").join("foo.txt"),
                },
            }
        );
    }

    #[test]
    fn check_missing_respects_filters() {
        let testdir = setup_dir_check_missing();
        std::fs::write(
            testdir.join("test.md5"),
            "\
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.test
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.mp4
e37276a93ac1e99188340e3f61e3673b  file.rs",
        )
        .unwrap();

        let matcher = PathMatcherBuilder::new()
            .block("bar/")
            .unwrap()
            .block("**/*.md5")
            .unwrap()
            .allow("**/*.*")
            .unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            all_files_matcher: matcher,
            ..Default::default()
        };

        let mut ch = ChecksumHelper::with_options(&testdir, options).unwrap();
        let result = ch.check_missing(|_| {}).unwrap();
        assert_eq!(
            result,
            CheckMissingResult {
                directories: vec! {
                    path::PathBuf::from("foo").join("bar").join("baz"),
                },
                files: vec! {
                    path::PathBuf::from("root.mp4"),
                    path::PathBuf::from("foo").join("foo.bin"),
                    path::PathBuf::from("foo").join("foo.txt"),
                },
            }
        );
    }

    #[test]
    fn check_missing_calls_progress_callback() {
        let testdir = setup_dir_check_missing();
        std::fs::write(
            testdir.join("test.md5"),
            "\
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.test
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.mp4
e37276a93ac1e99188340e3f61e3673b  file.rs",
        )
        .unwrap();

        let matcher = PathMatcherBuilder::new()
            .block("bar/")
            .unwrap()
            .block("**/*.md5")
            .unwrap()
            .allow("**/*.*")
            .unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            all_files_matcher: matcher,
            ..Default::default()
        };

        let mut ignored = vec![];
        let mut found = vec![];
        let mut has_most_current_cb = false;
        let mut ch = ChecksumHelper::with_options(&testdir, options).unwrap();
        let result = ch
            .check_missing(|p| match p {
                IncrementalProgress::BuildMostCurrent(_) => has_most_current_cb = true,
                IncrementalProgress::DiscoverFilesFound(n) => {
                    found.push(n);
                }
                IncrementalProgress::DiscoverFilesIgnored(p) => {
                    ignored.push(p);
                }
                _ => {}
            })
            .unwrap();

        assert!(has_most_current_cb);
        assert_eq!(found, (1..=6).collect::<Vec<_>>(),);
        assert_eq!(
            ignored,
            vec! {
                testdir.join("bar"),
                testdir.join("test.md5"),
            },
        );
        assert_eq!(
            result,
            CheckMissingResult {
                directories: vec! {
                    path::PathBuf::from("foo").join("bar").join("baz"),
                },
                files: vec! {
                    path::PathBuf::from("root.mp4"),
                    path::PathBuf::from("foo").join("foo.bin"),
                    path::PathBuf::from("foo").join("foo.txt"),
                },
            }
        );
    }

    #[test]
    fn fill_missing() {
        let testdir = setup_dir_check_missing();
        std::fs::write(
            testdir.join("test.md5"),
            "\
e37276a93ac1e99188340e3f61e3673b  foo/bar/baz/file.bin
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.test
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.mp4
e37276a93ac1e99188340e3f61e3673b  bar/baz_2025-06-28.foo
e37276a93ac1e99188340e3f61e3673b  bar/other.txt
e37276a93ac1e99188340e3f61e3673b  file.rs",
        )
        .unwrap();

        let mut ch = ChecksumHelper::new(&testdir).unwrap();
        let hc = ch.fill_missing(|_| {}).unwrap();
        assert_eq!(
            cshd_str_paths_only_sorted(&hc.to_str(&ch.file_tree).unwrap()),
            "\
bar/baz/baz_2025-06-28.foo
bar/baz/save.sav
foo/bar/baz/file.txt
foo/foo.bin
foo/foo.txt
root.mp4
test.md5
"
        );
    }

    #[test]
    fn fill_missing_respects_filters() {
        let testdir = setup_dir_check_missing();
        std::fs::write(
            testdir.join("test.md5"),
            "\
e37276a93ac1e99188340e3f61e3673b  bar/baz_2025-06-28.foo
e37276a93ac1e99188340e3f61e3673b  bar/other.txt
e37276a93ac1e99188340e3f61e3673b  file.rs",
        )
        .unwrap();

        let matcher = PathMatcherBuilder::new()
            .block("foo/bar/")
            .unwrap()
            .block("**/*.md5")
            .unwrap()
            .block("**/*.bin")
            .unwrap()
            .allow("**/*.md5")
            .unwrap()
            .allow("**/*.bin")
            .unwrap()
            .allow("**/*.foo")
            .unwrap()
            .allow("**/*.txt")
            .unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            all_files_matcher: matcher,
            ..Default::default()
        };
        let mut ch = ChecksumHelper::with_options(&testdir, options).unwrap();
        let hc = ch.fill_missing(|_| {}).unwrap();
        assert_eq!(
            cshd_str_paths_only_sorted(&hc.to_str(&ch.file_tree).unwrap()),
            "\
bar/baz/baz_2025-06-28.foo
foo/foo.txt
"
        );
    }

    #[test]
    fn fill_missing_calls_progress_callback() {
        let testdir = setup_dir_check_missing();
        std::fs::write(
            testdir.join("test.md5"),
            "\
e37276a93ac1e99188340e3f61e3673b  bar/baz_2025-06-28.foo
e37276a93ac1e99188340e3f61e3673b  bar/other.txt
e37276a93ac1e99188340e3f61e3673b  file.rs",
        )
        .unwrap();

        let matcher = PathMatcherBuilder::new()
            .block("foo/bar/")
            .unwrap()
            .block("**/*.md5")
            .unwrap()
            .block("**/*.bin")
            .unwrap()
            .allow("**/*.md5")
            .unwrap()
            .allow("**/*.bin")
            .unwrap()
            .allow("**/*.foo")
            .unwrap()
            .allow("**/*.txt")
            .unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            all_files_matcher: matcher,
            ..Default::default()
        };
        let mut ch = ChecksumHelper::with_options(&testdir, options).unwrap();
        let mut progress_recieved = vec![];
        let _ = ch.fill_missing(|p| progress_recieved.push(p)).unwrap();
        assert_eq!(
            progress_recieved,
            vec! {
                IncrementalProgress::BuildMostCurrent(
                    MostCurrentProgress::FoundFile(
                        path::PathBuf::from("test.md5"),
                    ),
                ),
                IncrementalProgress::BuildMostCurrent(
                    MostCurrentProgress::MergeHashFile(
                        testdir.join("test.md5"),
                    ),
                ),
                IncrementalProgress::DiscoverFilesIgnored(
                    path::PathBuf::from("file.rs")
                ),
                IncrementalProgress::DiscoverFilesIgnored(
                    path::PathBuf::from("root.mp4")
                ),
                IncrementalProgress::DiscoverFilesIgnored(
                    path::PathBuf::from("test.md5")
                ),
                IncrementalProgress::DiscoverFilesIgnored(
                    path::PathBuf::from("foo/bar")
                ),
                IncrementalProgress::DiscoverFilesIgnored(
                    path::PathBuf::from("foo/foo.bin")
                ),
                IncrementalProgress::PreRead(
                    path::PathBuf::from("foo/foo.txt"),
                ),
                IncrementalProgress::Read(11, 11),
                IncrementalProgress::FileNew(
                    path::PathBuf::from("foo/foo.txt"),
                ),
                IncrementalProgress::PreRead(
                    path::PathBuf::from("bar/baz/baz_2025-06-28.foo"),
                ),
                IncrementalProgress::Read(26, 26),
                IncrementalProgress::FileNew(
                    path::PathBuf::from("bar/baz/baz_2025-06-28.foo"),
                ),
                IncrementalProgress::DiscoverFilesIgnored(
                    path::PathBuf::from("bar/baz/save.sav")
                ),
                IncrementalProgress::Finished,
            }
        );
    }

    fn setup_dir_verify_root() -> std::path::PathBuf {
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

        // let cshd_root = "\
        // 1774640824.4384162,sha512,617cf33d1fda9f6f15d686c41cfb03ef959a6296956cf9275c99a2890bce44033d77f2995e2f6c080d156e4af681333dc2314c17eec2667a5fb7639ffd41c986 file.rs
        // 1774640824.438311,sha512,6ab2a146e0608e139ecfa9406a318035ccafa050b77a09819c1ca4cf8ccc19a68359166b93373daffe33c2d2e71e7e1ad9692600557be9b6cbf5134a699a55b7 root.mp4
        // 1774640824.4381008,sha512,242acb52c5a6ddd30b700a892a051900d8749e406c205382859219639c4f11979bcd631030eac530caa8121fb2b38f76a995671d75aafd2380cb261533886f3d bar/baz_2025-06-28.foo
        // 1774640824.438212,sha512,7d7cabd45d04fcc5b8609c01eecf46f05fa205fc44d99e23568fae9d80ff787fb47d26886b2ea6259d0a5d76ef657feeeb3103d851343da5ef322ce98ca24617 bar/other.txt
        // 1774640824.4378712,sha512,dd1a6810dc91e4b4f6a55606ace0dc793a91608dfe776a7077014a420d16e59ccbd6fd70d1bcce70a926ee0f6631bff86092e4aa56902f74cf3baa5251800c84 bar/baz/baz_2025-06-28.foo
        // 1774640824.4379904,sha512,5b7f0dd92e529aa88471152757a796a548244c2330123a5fe9eb237fac38e2daffd22d765901c0f8af7bc466ed178d635cb31f323fdbc61806291526e7581df1 bar/baz/save.sav
        // 1774640824.4376843,sha512,847f8f7a2df6539773aa192eb7e449b26cb765aeea13e66010be6ae14a447bfcea4ef99628dffd2dbcd17c624164c521692f43e5e8894955d0fa393b86112b44 foo/foo.bin
        // 1774640824.4375193,sha512,05c2926bd5af39e0054a35776924c1af9a960da676a3590fffdc82071f9476184dd126460c416a220872b6e76e3b7801320cb9ebfb3b935fccbccfeb1bfc9a29 foo/foo.txt
        // 1774640824.4374044,sha512,2cff1435df6bb662a8297cc28f6b00803f91b8dc49d879099e19596b95319a7c2b8a8643ff090ed520f59efc5d5d9a3d9a2c4602dec2fd0996fd60a725947e17 foo/bar/bar.mp4
        // 1774640824.4372783,sha512,d361f5a1ddf2da60264aa38fcacc6702e58107fdec8cc9cd1df19cfe7d7cf33ae45eda3c48e1e3f48c382bec2804fc6ed4751b1f330777ab443c2e122c17c20c foo/bar/bar.test
        // 1774640824.4370198,sha512,a2005e4d2d686bd755654073d50c1a421fffb3ddc2e8904e929c01bf6aeb5c9973be2f6bd23ef29ef614aec9252abcbf95da79853ba42469ab869d748ac6d012 foo/bar/baz/file.bin
        // 1774640824.4371605,sha512,368ade34bd90afe3db2a9a655e883288aef03284cb40481def21b62a9a0b66a7d048a3264c836d6f48fa536daa319e9acb53e21ad6cea3982ad77c90174e8939 foo/bar/baz/file.txt
        // 1774640824.4384162,md5,8ad5f2184620b91ad9384857bc9c1370 file.rs
        // 1774640824.438311,md5,e2e676034d46bfa72dd35482ee8b13dc root.mp4
        // 1774640873.3941352,md5,04a4a142183e3a29f4c1534ffdc2d648 verify_root_2026-03-27.cshd
        // 1774640824.4381008,md5,4b2eb3e4b5fb7741320b7a87bf720eca bar/baz_2025-06-28.foo
        // 1774640824.438212,md5,96c4a1331ef7bf12846403e8fd5889ce bar/other.txt
        // 1774640824.4378712,md5,a2ec00356c963af73814724b3376816d bar/baz/baz_2025-06-28.foo
        // 1774640824.4379904,md5,10b2d370ae88690e8923e0261b556de9 bar/baz/save.sav
        // 1774640824.4376843,md5,207174fb3b77ee29ea3d88ecbfd6885a foo/foo.bin
        // 1774640824.4375193,md5,df42718d7eeae06c17b7280e5aece23c foo/foo.txt
        // 1774640824.4374044,md5,d4ca4c74d827424ca5e6cb552cc039d3 foo/bar/bar.mp4
        // 1774640824.4372783,md5,9078064e1ecedbf0852b51996522049b foo/bar/bar.test
        // 1774640824.4370198,md5,0c078ca63b3ec5d6e599f97d82faf064 foo/bar/baz/file.bin
        // 1774640824.4371605,md5,ac06ffd974d80119666da2b17d1595c9 foo/bar/baz/file.txt
        // 1774640824.4384162,sha256,47b87f0dcbaa440876109db0ffc55478049eb13151b87616893cc2b4e99837c8 file.rs
        // 1774640824.438311,sha256,a1cde1106e788b3811c4f238892319775166c00cd6721ac7f26a1177a8ebf305 root.mp4
        // 1774640873.3941352,sha256,455cdc91706b5cf7c44468d6e1eadce2c741402455326e515c31a57603119fb3 verify_root_2026-03-27.cshd
        // 1774640899.0435686,sha256,6be2440bb6debc062b63f8fff977dbb32866732cc41199c4c6d0b9cf9381d9ab verify_root_2026-03-27T204819.cshd
        // 1774640824.4381008,sha256,d7a760256371fcb13da806678d1feb3b8f3567e262e99de451fe24aaa4108e4e bar/baz_2025-06-28.foo
        // 1774640824.438212,sha256,934ec8eb0d640b5652cbfa46372f581c53b4fa40da7ffb46d773af206fa5a6a6 bar/other.txt
        // 1774640824.4378712,sha256,e66f40a6224b0462c8a91b002d2bc8574787984e3f5754aab8bb3891ca9224cd bar/baz/baz_2025-06-28.foo
        // 1774640824.4379904,sha256,11623d616ebcb16d0a4adbb801426cdf475c734e6558e35c560b2910382c2b4d bar/baz/save.sav
        // 1774640824.4376843,sha256,ee15ee25da94386f5851fe226ec6f5bd59cd1f451fc1a2f29bab79bdacf8ae21 foo/foo.bin
        // 1774640824.4375193,sha256,233f41d7c3d047dd574bcca261d9f9087869e82afe1e498e92594568325681a7 foo/foo.txt
        // 1774640824.4374044,sha256,0da7a46c5f77f42bba3f26ebfcb37a6cda87ad64bbaaa3ec033f1695237ac13a foo/bar/bar.mp4
        // 1774640824.4372783,sha256,50f46217112133af42c91ce489a17ee5a98f4b7ec3cba0ba0fadba06e4e22136 foo/bar/bar.test
        // 1774640824.4370198,sha256,49fa8ad5377ddc53ffccc3a76207487694ce5861eae62afde38c8016079c2c75 foo/bar/baz/file.bin
        // 1774640824.4371605,sha256,8586beeed9a89d3ec07af5ebbdc982c47b548652e4b467269d0c54b655919f50 foo/bar/baz/file.txt
        // ";
        testdir
    }

    #[test]
    fn verify_root_verifies_checksum_files_found() {
        let testdir = setup_dir_verify_root();

        let cshd_root = "\
# version 1
1774640824.438311,,md5,e2e676034d46bfa72dd35482ee8b13dc does_not_exist
1774640824.4384162,7,md5,8ad5f2184620b91ad9384857bc9c1370 file.rs
1774640824.4379904,,md5,10b2d370ae88690e8923e0261b556de9 bar/baz/save.sav
1774640824.4381008,,md5,4b2eb3e4b5fb7741320b7a87bf720eca bar/baz_2025-06-28.foo
1774640824.4372783,,md5,9078064e1ecedbf0852b51996522049b foo/bar/bar.test";
        std::fs::write(testdir.join("root.cshd"), cshd_root).unwrap();

        let cshd_bar = "\
1774640824.438212,md5,96c4a1331ef7bf12846403e8fd5889ce other.txt
1774640824.438311,md5,f2e676034d46bfa72dd35482ee8b13dc does_not_exist
1774640824.4378712,sha256,e66f40a6224b0462c8a91b002d2bc8574787984e3f5754aab8bb3891ca9224cd bar/baz/baz_2025-06-28.foo";
        std::fs::write(testdir.join("bar").join("bar.cshd"), cshd_bar).unwrap();

        let md5_root = "\
e2e676034d46bfa72dd35482ee8b13dc  root.mp4
207174fb3b77ee29ea3d88ecbfd6885a  foo/foo.bin
307174fb3b77ee29ea3d88ecbfd6885a  foo/bar/foo/xer/does_not_exist
0c078ca63b3ec5d6e599f97d82faf064  foo/bar/baz/file.bin";
        std::fs::write(testdir.join("root.md5"), md5_root).unwrap();

        let md5_foo = "\
df42718d7eeae06c17b7280e5aece23c  foo.txt
d4ca4c74d827424ca5e6cb552cc039d3  bar/bar.mp4
e4ca4c74d827424ca5e6cb552cc039d3  bar/baz/foo/does_not_exist
ac06ffd974d80119666da2b17d1595c9  bar/baz/file.txt";
        std::fs::write(testdir.join("foo").join("foo.md5"), md5_foo).unwrap();

        let corrupt_files = vec![
            "root.mp4",
            "bar/baz_2025-06-28.foo",
            "bar/other.txt",
            "foo/bar/bar.mp4",
            "foo/bar/baz/file.bin",
        ];

        for p in corrupt_files {
            std::fs::write(testdir.join(p), "corrupted").unwrap();
        }

        use crate::collection::{
            HashProgress, VerifyProgress, VerifyProgressCommon, VerifyProgressPost,
        };
        let progress_expected = vec![
            VerifyRootProgress::BuildMostCurrent(MostCurrentProgress::FoundFile(
                std::path::PathBuf::from("root.cshd"),
            )),
            VerifyRootProgress::BuildMostCurrent(MostCurrentProgress::FoundFile(
                std::path::PathBuf::from("root.md5"),
            )),
            VerifyRootProgress::BuildMostCurrent(MostCurrentProgress::FoundFile(
                std::path::PathBuf::from("foo/foo.md5"),
            )),
            VerifyRootProgress::BuildMostCurrent(MostCurrentProgress::FoundFile(
                std::path::PathBuf::from("bar/bar.cshd"),
            )),
            // merged in ascending mtime order!
            VerifyRootProgress::BuildMostCurrent(MostCurrentProgress::MergeHashFile(
                testdir.join("root.cshd"),
            )),
            VerifyRootProgress::BuildMostCurrent(MostCurrentProgress::MergeHashFile(
                testdir.join("bar/bar.cshd"),
            )),
            VerifyRootProgress::BuildMostCurrent(MostCurrentProgress::MergeHashFile(
                testdir.join("root.md5"),
            )),
            VerifyRootProgress::BuildMostCurrent(MostCurrentProgress::MergeHashFile(
                testdir.join("foo/foo.md5"),
            )),
            // does_not_exist
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("does_not_exist"),
                file_number_processed: 0,
                file_number_total: 16,
                size_processed_bytes: 0,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("does_not_exist"),
                    file_number_processed: 1,
                    file_number_total: 16,
                    // just based on size stored in cshd
                    // here: none, so 0 bytes processed
                    size_processed_bytes: 0,
                    size_total_bytes: 7,
                },
                result: VerifyResult::FileMissing(std::io::ErrorKind::NotFound),
            })),
            // file.rs
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("file.rs"),
                file_number_processed: 1,
                file_number_total: 16,
                size_processed_bytes: 0,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::During(HashProgress {
                bytes_read: 7,
                bytes_total: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("file.rs"),
                    file_number_processed: 2,
                    file_number_total: 16,
                    size_processed_bytes: 7,
                    size_total_bytes: 7,
                },
                result: VerifyResult::Ok,
            })),
            // bar/baz/save.sav
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("bar/baz/save.sav"),
                file_number_processed: 2,
                file_number_total: 16,
                size_processed_bytes: 7,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::During(HashProgress {
                bytes_read: 16,
                bytes_total: 16,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("bar/baz/save.sav"),
                    file_number_processed: 3,
                    file_number_total: 16,
                    size_processed_bytes: 7,
                    size_total_bytes: 7,
                },
                result: VerifyResult::Ok,
            })),
            // bar/baz_2025-06-28.foo
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("bar/baz_2025-06-28.foo"),
                file_number_processed: 3,
                file_number_total: 16,
                size_processed_bytes: 7,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::During(HashProgress {
                bytes_read: 9,
                bytes_total: 9,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("bar/baz_2025-06-28.foo"),
                    file_number_processed: 4,
                    file_number_total: 16,
                    size_processed_bytes: 7,
                    size_total_bytes: 7,
                },
                result: VerifyResult::MismatchOutdatedHash,
            })),
            // foo/bar/bar.test
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("foo/bar/bar.test"),
                file_number_processed: 4,
                file_number_total: 16,
                size_processed_bytes: 7,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::During(HashProgress {
                bytes_read: 16,
                bytes_total: 16,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("foo/bar/bar.test"),
                    file_number_processed: 5,
                    file_number_total: 16,
                    size_processed_bytes: 7,
                    size_total_bytes: 7,
                },
                result: VerifyResult::Ok,
            })),
            // bar/other.txt
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("bar/other.txt"),
                file_number_processed: 5,
                file_number_total: 16,
                size_processed_bytes: 7,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::During(HashProgress {
                bytes_read: 9,
                bytes_total: 9,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("bar/other.txt"),
                    file_number_processed: 6,
                    file_number_total: 16,
                    size_processed_bytes: 7,
                    size_total_bytes: 7,
                },
                result: VerifyResult::MismatchOutdatedHash,
            })),
            // bar/does_not_exist
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("bar/does_not_exist"),
                file_number_processed: 6,
                file_number_total: 16,
                size_processed_bytes: 7,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("bar/does_not_exist"),
                    file_number_processed: 7,
                    file_number_total: 16,
                    size_processed_bytes: 7,
                    size_total_bytes: 7,
                },
                result: VerifyResult::FileMissing(std::io::ErrorKind::NotFound),
            })),
            // bar/bar/baz/baz_2025-06-28.foo
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("bar/bar/baz/baz_2025-06-28.foo"),
                file_number_processed: 7,
                file_number_total: 16,
                size_processed_bytes: 7,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("bar/bar/baz/baz_2025-06-28.foo"),
                    file_number_processed: 8,
                    file_number_total: 16,
                    size_processed_bytes: 7,
                    size_total_bytes: 7,
                },
                result: VerifyResult::FileMissing(std::io::ErrorKind::NotFound),
            })),
            // root.mp4
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("root.mp4"),
                file_number_processed: 8,
                file_number_total: 16,
                size_processed_bytes: 7,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::During(HashProgress {
                bytes_read: 9,
                bytes_total: 9,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("root.mp4"),
                    file_number_processed: 9,
                    file_number_total: 16,
                    size_processed_bytes: 7,
                    size_total_bytes: 7,
                },
                result: VerifyResult::Mismatch,
            })),
            // foo/foo.bin
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("foo/foo.bin"),
                file_number_processed: 9,
                file_number_total: 16,
                size_processed_bytes: 7,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::During(HashProgress {
                bytes_read: 11,
                bytes_total: 11,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("foo/foo.bin"),
                    file_number_processed: 10,
                    file_number_total: 16,
                    size_processed_bytes: 7,
                    size_total_bytes: 7,
                },
                result: VerifyResult::Ok,
            })),
            // foo/bar/foo/xer/does_not_exist
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("foo/bar/foo/xer/does_not_exist"),
                file_number_processed: 10,
                file_number_total: 16,
                size_processed_bytes: 7,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("foo/bar/foo/xer/does_not_exist"),
                    file_number_processed: 11,
                    file_number_total: 16,
                    size_processed_bytes: 7,
                    size_total_bytes: 7,
                },
                result: VerifyResult::FileMissing(std::io::ErrorKind::NotFound),
            })),
            // foo/bar/baz/file.bin
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("foo/bar/baz/file.bin"),
                file_number_processed: 11,
                file_number_total: 16,
                size_processed_bytes: 7,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::During(HashProgress {
                bytes_read: 9,
                bytes_total: 9,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("foo/bar/baz/file.bin"),
                    file_number_processed: 12,
                    file_number_total: 16,
                    size_processed_bytes: 7,
                    size_total_bytes: 7,
                },
                result: VerifyResult::Mismatch,
            })),
            // foo/foo.txt
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("foo/foo.txt"),
                file_number_processed: 12,
                file_number_total: 16,
                size_processed_bytes: 7,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::During(HashProgress {
                bytes_read: 11,
                bytes_total: 11,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("foo/foo.txt"),
                    file_number_processed: 13,
                    file_number_total: 16,
                    size_processed_bytes: 7,
                    size_total_bytes: 7,
                },
                result: VerifyResult::Ok,
            })),
            // foo/bar/bar.mp4
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("foo/bar/bar.mp4"),
                file_number_processed: 13,
                file_number_total: 16,
                size_processed_bytes: 7,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::During(HashProgress {
                bytes_read: 9,
                bytes_total: 9,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("foo/bar/bar.mp4"),
                    file_number_processed: 14,
                    file_number_total: 16,
                    size_processed_bytes: 7,
                    size_total_bytes: 7,
                },
                result: VerifyResult::Mismatch,
            })),
            // foo/bar/baz/foo/does_not_exist
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("foo/bar/baz/foo/does_not_exist"),
                file_number_processed: 14,
                file_number_total: 16,
                size_processed_bytes: 7,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("foo/bar/baz/foo/does_not_exist"),
                    file_number_processed: 15,
                    file_number_total: 16,
                    size_processed_bytes: 7,
                    size_total_bytes: 7,
                },
                result: VerifyResult::FileMissing(std::io::ErrorKind::NotFound),
            })),
            // foo/bar/baz/file.txt
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("foo/bar/baz/file.txt"),
                file_number_processed: 15,
                file_number_total: 16,
                size_processed_bytes: 7,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::During(HashProgress {
                bytes_read: 20,
                bytes_total: 20,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("foo/bar/baz/file.txt"),
                    file_number_processed: 16,
                    file_number_total: 16,
                    size_processed_bytes: 7,
                    size_total_bytes: 7,
                },
                result: VerifyResult::Ok,
            })),
        ];
        let mut progress_index = 0usize;

        let mut ch = ChecksumHelper::new(&testdir).unwrap();
        ch.verify_root(
            |_path| true,
            |progress| {
                assert_eq!(progress, progress_expected[progress_index]);

                progress_index += 1;
            },
        )
        .unwrap();

        assert_eq!(progress_index, progress_expected.len());
    }

    #[test]
    fn verify_root_does_not_ignore_missing_files() {
        let testdir = setup_dir_verify_root();

        let cshd_root = "\
# version 1
1774640824.438311,,md5,e2e676034d46bfa72dd35482ee8b13dc does_not_exist
1774640824.4379904,,md5,10b2d370ae88690e8923e0261b556de9 bar/baz/does_not_exist";
        std::fs::write(testdir.join("root.cshd"), cshd_root).unwrap();

        let mut missing_count = 0usize;
        let missing_paths = [
            path::Path::new("does_not_exist"),
            path::Path::new("bar/baz/does_not_exist"),
        ];

        let mut ch = ChecksumHelper::with_options(&testdir, ChecksumHelperOptions {
            most_current_filter_deleted: true,
            ..Default::default()
        }).unwrap();
        ch.verify_root(
            |_path| true,
            |progress| {
                if let VerifyRootProgress::Verify(VerifyProgress::Post(verify)) = progress {
                    assert_eq!(
                        verify.result,
                        VerifyResult::FileMissing(std::io::ErrorKind::NotFound)
                    );
                    assert_eq!(verify.progress.relative_path, missing_paths[missing_count]);
                    missing_count += 1;
                }
            },
        )
        .unwrap();

        assert_eq!(missing_count, 2);
    }

    #[test]
    fn verify_root_uses_newer_checksums_on_duplicate() {
        let testdir = setup_dir_verify_root();

        let outdated = "\
1771337.1337,md5,deadbeef4620b91ad9384857bc9c1370 file.rs";
        let outdated_path = testdir.join("outdated.cshd");
        std::fs::write(&outdated_path, outdated).unwrap();

        let current = "\
1774640824.4384162,md5,8ad5f2184620b91ad9384857bc9c1370 file.rs";
        std::fs::write(testdir.join("current.cshd"), current).unwrap();

        let mut count = 0usize;

        let mut ch = ChecksumHelper::new(&testdir).unwrap();
        ch.verify_root(
            |_path| true,
            |progress| {
                if let VerifyRootProgress::Verify(VerifyProgress::Post(verify)) = progress {
                    assert_eq!(
                        verify.result,
                        VerifyResult::Ok
                    );
                    count += 1;
                }
            },
        )
        .unwrap();

        assert_eq!(count, 1);
    }

    #[test]
    fn verify_root_respects_include() {
        let testdir = setup_dir_verify_root();

        let cshd_root = "\
# version 1
1774640824.438311,,md5,e2e676034d46bfa72dd35482ee8b13dc does_not_exist
1774640824.4384162,7,md5,8ad5f2184620b91ad9384857bc9c1370 file.rs
1774640824.4379904,,md5,10b2d370ae88690e8923e0261b556de9 bar/baz/save.sav
1774640824.4381008,,md5,4b2eb3e4b5fb7741320b7a87bf720eca bar/baz_2025-06-28.foo
1774640824.4381008,,md5,deadbeefb5fb7741320b7a87bf720eca bar/baz/does_not_exist
1774640824.4372783,,md5,9078064e1ecedbf0852b51996522049b foo/bar/bar.test";
        std::fs::write(testdir.join("root.cshd"), cshd_root).unwrap();

        std::fs::write(testdir.join("bar/baz_2025-06-28.foo"), "corrupted").unwrap();

        use crate::collection::{
            HashProgress, VerifyProgress, VerifyProgressCommon, VerifyProgressPost,
        };
        let progress_expected = [
            // bar/baz/save.sav
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("bar/baz/save.sav"),
                file_number_processed: 2,
                file_number_total: 6,
                size_processed_bytes: 0,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::During(HashProgress {
                bytes_read: 16,
                bytes_total: 16,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("bar/baz/save.sav"),
                    file_number_processed: 3,
                    file_number_total: 6,
                    size_processed_bytes: 0,
                    size_total_bytes: 7,
                },
                result: VerifyResult::Ok,
            })),
            // bar/baz_2025-06-28.foo
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("bar/baz_2025-06-28.foo"),
                file_number_processed: 3,
                file_number_total: 6,
                size_processed_bytes: 0,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::During(HashProgress {
                bytes_read: 9,
                bytes_total: 9,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("bar/baz_2025-06-28.foo"),
                    file_number_processed: 4,
                    file_number_total: 6,
                    size_processed_bytes: 0,
                    size_total_bytes: 7,
                },
                result: VerifyResult::MismatchOutdatedHash,
            })),
            // bar/baz/does_not_exist
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("bar/baz/does_not_exist"),
                file_number_processed: 4,
                file_number_total: 6,
                size_processed_bytes: 0,
                size_total_bytes: 7,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("bar/baz/does_not_exist"),
                    file_number_processed: 5,
                    file_number_total: 6,
                    size_processed_bytes: 0,
                    size_total_bytes: 7,
                },
                result: VerifyResult::FileMissing(std::io::ErrorKind::NotFound),
            })),
        ];
        let mut progress_index = 0usize;

        let mut ch = ChecksumHelper::new(&testdir).unwrap();
        ch.verify_root(
            |path| path.starts_with("bar/"),
            |progress| {
                if let VerifyRootProgress::Verify(_) = progress {
                    assert_eq!(progress, progress_expected[progress_index]);

                    progress_index += 1;
                }
            },
        )
        .unwrap();

        assert_eq!(progress_index, progress_expected.len());
    }

    #[test]
    fn verify_root_respects_hash_file_filter() {
        let testdir = setup_dir_verify_root();

        let cshd_root = "\
# version 1
1774640824.438311,,md5,deadbeef4d46bfa72dd35482ee8b13dc does_not_exist
1774640824.4384162,7,md5,deadbeef4620b91ad9384857bc9c1370 file.rs
1774640824.4379904,,md5,deadbeefae88690e8923e0261b556de9 bar/baz/save.sav
1774640824.4381008,,md5,deadbeefb5fb7741320b7a87bf720eca bar/baz_2025-06-28.foo
1774640824.4381008,,md5,deadbeefb5fb7741320b7a87bf720eca bar/baz/does_not_exist
1774640824.4372783,,md5,deadbeef1ecedbf0852b51996522049b foo/bar/bar.test";
        std::fs::write(testdir.join("root.cshd"), cshd_root).unwrap();

        let cshd_bar = "\
# version 1
1774640824.4379904,,md5,10b2d370ae88690e8923e0261b556de9 baz/save.sav
1774640824.4381008,,md5,4b2eb3e4b5fb7741320b7a87bf720eca baz_2025-06-28.foo
1774640824.4381008,,md5,deadbeefb5fb7741320b7a87bf720eca baz/does_not_exist";
        std::fs::write(testdir.join("bar").join("bar.cshd"), cshd_bar).unwrap();

        std::fs::write(testdir.join("bar/baz_2025-06-28.foo"), "corrupted").unwrap();

        use crate::collection::{
            HashProgress, VerifyProgress, VerifyProgressCommon, VerifyProgressPost,
        };
        let progress_expected = [
            // bar/baz/save.sav
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("bar/baz/save.sav"),
                file_number_processed: 0,
                file_number_total: 3,
                size_processed_bytes: 0,
                size_total_bytes: 0,
            })),
            VerifyRootProgress::Verify(VerifyProgress::During(HashProgress {
                bytes_read: 16,
                bytes_total: 16,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("bar/baz/save.sav"),
                    file_number_processed: 1,
                    file_number_total: 3,
                    size_processed_bytes: 0,
                    size_total_bytes: 0,
                },
                result: VerifyResult::Ok,
            })),
            // bar/baz_2025-06-28.foo
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("bar/baz_2025-06-28.foo"),
                file_number_processed: 1,
                file_number_total: 3,
                size_processed_bytes: 0,
                size_total_bytes: 0,
            })),
            VerifyRootProgress::Verify(VerifyProgress::During(HashProgress {
                bytes_read: 9,
                bytes_total: 9,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("bar/baz_2025-06-28.foo"),
                    file_number_processed: 2,
                    file_number_total: 3,
                    size_processed_bytes: 0,
                    size_total_bytes: 0,
                },
                result: VerifyResult::MismatchOutdatedHash,
            })),
            // bar/baz/does_not_exist
            VerifyRootProgress::Verify(VerifyProgress::Pre(VerifyProgressCommon {
                tree_root: testdir.as_path(),
                relative_path: std::path::Path::new("bar/baz/does_not_exist"),
                file_number_processed: 2,
                file_number_total: 3,
                size_processed_bytes: 0,
                size_total_bytes: 0,
            })),
            VerifyRootProgress::Verify(VerifyProgress::Post(VerifyProgressPost {
                progress: VerifyProgressCommon {
                    tree_root: testdir.as_path(),
                    relative_path: std::path::Path::new("bar/baz/does_not_exist"),
                    file_number_processed: 3,
                    file_number_total: 3,
                    size_processed_bytes: 0,
                    size_total_bytes: 0,
                },
                result: VerifyResult::FileMissing(std::io::ErrorKind::NotFound),
            })),
        ];
        let mut progress_index = 0usize;

        // only include cshd_bar
        let mut ch = ChecksumHelper::with_options(&testdir, ChecksumHelperOptions{
            hash_files_matcher: PathMatcherBuilder::new()
                .allow("bar/*.cshd").unwrap()
                .build().unwrap(),
            ..Default::default()
        }).unwrap();
        ch.verify_root(
            |_path| true,
            |progress| {
                if let VerifyRootProgress::Verify(_) = progress {
                    assert_eq!(progress, progress_expected[progress_index]);

                    progress_index += 1;
                }
            },
        )
        .unwrap();

        assert_eq!(progress_index, progress_expected.len());
    }
}
