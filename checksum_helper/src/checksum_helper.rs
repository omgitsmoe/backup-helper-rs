use crate::collection::{
    HashCollection, HashCollectionError, HashCollectionIter, HashCollectionWriter, VerifyProgress,
};
use crate::hash_type::HashType;
use crate::hashed_file::FileRaw;
use crate::file_tree::FileTree;
use crate::gather::{filtered, VisitType};
use crate::pathmatcher::{PathMatcher, PathMatcherBuilder};
use crate::most_current::{update_most_current};
use crate::incremental::Incremental;

use std::cmp::{Eq, PartialEq};
use std::error::Error;
use std::fmt;
use std::path;
use std::cell::RefCell;
use std::io::Write;

pub use crate::most_current::MostCurrentProgress;
pub use crate::incremental::IncrementalProgress;

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
        P: FnMut(IncrementalProgress)

    {
        let root = self.root();
        if self.most_current.is_none() {
            self.most_current = Some(
                update_most_current(
                    &root, &mut self.file_tree, &self.options,
                    |p| {
                        progress(IncrementalProgress::BuildMostCurrent(p))
                    })?);
        }

        let inc = Incremental::new(
            &root,
            &mut self.file_tree,
            &self.options,
            self.most_current.take()
                .expect("checked above"),
        );

        // NOTE: does not make sense to use this as new most_current, since only
        //       new files might be contained etc.
        inc.generate(progress)
    }

    /// Generate a [`HashCollection`], which only contains the hashes of
    /// files that do not have checksum in any matched hash file yet.
    pub fn fill_missing<P>(&mut self, mut progress: P) -> Result<HashCollection>
    where
        P: FnMut(IncrementalProgress)
    {
        // NOTE: can't use check_missing's result, since the file list is incomplete
        //       if there are directories missing!
        let root = self.root();
        if self.most_current.is_none() {
            self.most_current = Some(
                update_most_current(
                    &root, &mut self.file_tree, &self.options,
                    |p| {
                        progress(IncrementalProgress::BuildMostCurrent(p))
                    })?);
        }
        let most_current = self.most_current
            .as_ref().expect("checked above");

        let root = self.root();
        let filename = default_filename(&root, "missing", "_missing_");
        let mut hc = HashCollection::new(
            Some(&root.join(filename)), None)?;
        let iter = filtered(
            &root, &self.options.all_files_matcher,
            |e| !e.ignored);
        for v in iter {
            let v = v?;
            if let VisitType::File(v) = v {
                if most_current.contains_path(&v.relative_to_root, &self.file_tree) {
                    continue;
                }

                // TODO make it easier to create a hashed file
                let entry = self.file_tree.add_file(&v.relative_to_root)?;
                let mut file_raw = FileRaw::bare(
                    entry.clone(),
                    self.options.hash_type,
                );
                let mut file = file_raw.with_context_mut(&self.file_tree);

                progress(IncrementalProgress::PreRead(v.relative_to_root.to_owned()));
                file.update_size_and_mtime_from_disk()?;
                file.update_hash_from_disk(|(read, total)| {
                    progress(IncrementalProgress::Read(read, total));
                })?;

                hc.update(entry, file_raw);
            }
        }

        Ok(hc)
    }

    /// Returns a result object containing all individual files that do not have checksums
    /// in `self.root` yet.
    /// If a directory has files and is completely missing it will be listed
    /// in `directories`.
    /// Note: The files of that directory will not appear in the file list.
    pub fn check_missing<P>(&mut self, mut progress: P) -> Result<CheckMissingResult>
    where
        P: FnMut(IncrementalProgress)
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

        // dyanmic borrow checking needed, since we use it in the predicate closure
        // as well as in our for loop while the closure is still alive
        let progress = RefCell::new(progress);
        let mut missing_directories = vec!();
        let mut missing_files = vec!();
        let iter = filtered(
            &root, &self.options.all_files_matcher,
            |e| {
                if e.ignored {
                    // TODO unify what kind of path is returned:
                    //      absolute or relative to root
                    progress.borrow_mut()(IncrementalProgress::DiscoverFilesIgnored(
                        e.entry.dir_entry.path()));
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

        Ok(CheckMissingResult{
            directories: missing_directories,
            files: missing_files,
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

    pub fn iter_collection<'a>(&'a self, collection: &'a HashCollection) -> HashCollectionIter<'a> {
        collection.iter_with_context(&self.file_tree)
    }

    pub fn write_collection(
        &self,
        collection: &HashCollection,
    ) -> Result<()> {
        collection.write_to_disk(&self.file_tree)?;

        Ok(())
    }

    pub fn write_into<W: Write>(&self, collection: &HashCollection, writer: &mut W) -> Result<()> {
        collection.serialize(writer, &self.file_tree)?;

        Ok(())
    }

    /// Verify all files matching predicated `include` in the `HashCollection`
    ///
    /// Warning: The passed `file_tree` has to match the file_tree used for the
    ///          added files in the `HashCollection`.
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

pub(crate) fn default_filename(
    root: impl AsRef<path::Path>, default: &str, infix: &str
) -> std::ffi::OsString {
    let now = chrono::offset::Local::now();
    let datetime = now.format("%Y-%m-%dT%H%M%S");
    let root = root.as_ref();
    let default = std::ffi::OsString::from(default);
    let base = root.file_name().unwrap_or(&default);
    let base = base.to_string_lossy(); // Cow<str>

    format!("{}_{}{}.cshd", base, infix, datetime).into()
}


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
    // TODO use this
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
        let result = ch.check_missing(|_| {}).unwrap();
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
        let result = ch.check_missing(|_| {}).unwrap();
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
        let result = ch.check_missing(|_| {}).unwrap();
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
            .allow("**/*.*").unwrap()
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
            CheckMissingResult{
                directories: vec!{
                    path::PathBuf::from("foo").join("bar").join("baz"),
                },
                files: vec!{
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
        std::fs::write(testdir.join("test.md5"), "\
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.test
e37276a93ac1e99188340e3f61e3673b  foo/bar/bar.mp4
e37276a93ac1e99188340e3f61e3673b  file.rs").unwrap();

        let matcher = PathMatcherBuilder::new()
            .block("bar/").unwrap()
            .block("**/*.md5").unwrap()
            .allow("**/*.*").unwrap()
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
        let result = ch.check_missing(|p| {
            match p {
                IncrementalProgress::BuildMostCurrent(_) => has_most_current_cb = true,
                IncrementalProgress::DiscoverFilesFound(n) => {
                    found.push(n);
                },
                IncrementalProgress::DiscoverFilesIgnored(p) => {
                    ignored.push(p);
                },
                _ => {},
            }

        }).unwrap();

        assert!(has_most_current_cb);
        assert_eq!(
            found,
            (1..=6).collect::<Vec<_>>(),
        );
        assert_eq!(
            ignored,
            vec!{
                testdir.join("bar"),
                testdir.join("test.md5"),
            },
        );
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
            }
        );
    }

    #[test]
    fn fill_missing() {
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
");
    }

    #[test]
    fn fill_missing_respects_filters() {
        let testdir = setup_dir_check_missing();
        std::fs::write(testdir.join("test.md5"), "\
e37276a93ac1e99188340e3f61e3673b  bar/baz_2025-06-28.foo
e37276a93ac1e99188340e3f61e3673b  bar/other.txt
e37276a93ac1e99188340e3f61e3673b  file.rs").unwrap();

        let matcher = PathMatcherBuilder::new()
            .block("foo/bar/").unwrap()
            .block("**/*.md5").unwrap()
            .block("**/*.bin").unwrap()
            .allow("**/*.md5").unwrap()
            .allow("**/*.bin").unwrap()
            .allow("**/*.foo").unwrap()
            .allow("**/*.txt").unwrap()
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
");
    }

    #[test]
    fn fill_missing_calls_progress_callback() {
        let testdir = setup_dir_check_missing();
        std::fs::write(testdir.join("test.md5"), "\
e37276a93ac1e99188340e3f61e3673b  bar/baz_2025-06-28.foo
e37276a93ac1e99188340e3f61e3673b  bar/other.txt
e37276a93ac1e99188340e3f61e3673b  file.rs").unwrap();

        let matcher = PathMatcherBuilder::new()
            .block("foo/bar/").unwrap()
            .block("**/*.md5").unwrap()
            .block("**/*.bin").unwrap()
            .allow("**/*.md5").unwrap()
            .allow("**/*.bin").unwrap()
            .allow("**/*.foo").unwrap()
            .allow("**/*.txt").unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            all_files_matcher: matcher,
            ..Default::default()
        };
        let mut ch = ChecksumHelper::with_options(&testdir, options).unwrap();
        let mut progress_recieved = vec!{};
        let _ = ch.fill_missing(|p| progress_recieved.push(p))
            .unwrap();
        assert_eq!(
            progress_recieved,
            vec!{
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
                IncrementalProgress::PreRead(
                    path::PathBuf::from("foo/foo.txt"),
                ),
                IncrementalProgress::Read(11, 11),
                IncrementalProgress::PreRead(
                    path::PathBuf::from("bar/baz/baz_2025-06-28.foo"),
                ),
                IncrementalProgress::Read(26, 26),
            }
        );

    }
}
