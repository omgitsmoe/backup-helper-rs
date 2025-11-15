use crate::collection::HashCollection;
use crate::file_tree::{FileTree, EntryHandle};
use crate::gather::{filtered, VisitType};
use crate::most_current::MostCurrentProgress;
use crate::{ChecksumHelperError, ChecksumHelperOptions};

use std::path;

type Result<T> = std::result::Result<T, ChecksumHelperError>;

#[derive(Debug, PartialEq)]
pub enum IncrementalProgress {
    BuildMostCurrent(MostCurrentProgress),
    /// Found a file that will be included in check summing.
    DiscoverFilesFound(u64),
    /// Ignored a path (file or directory).
    DiscoverFilesIgnored(path::PathBuf),
    /// Finished discovering files to hash: number of files to hash, number of ignored files or
    /// directories. Note that the number of ignored files does not contain
    /// the amount of ignored files, which would be discovered in ignored directories.
    DiscoverFilesDone(usize, usize),
    /// Path relative to the ChecksumHelper root of the file that is going to be hashed next.
    PreRead(path::PathBuf),
    /// Read progress in bytes: read, total.
    Read(u64, u64),
    /// File matched the recorded hash. The path is relative to the ChecksumHelper root.
    FileMatch(path::PathBuf),
    /// Skipped a file, which matched the recorded `mtime`.
    /// Turn this behaviour on or off using `ChecksumHelperOptions::incremental_skip_unchanged`.
    /// The path is relative to the ChecksumHelper root.
    FileUnchangedSkipped(path::PathBuf),
    /// File changed with a newer `mtime` compared to the recorded one or there
    /// was no recorded `mtime`.
    /// The path is relative to the ChecksumHelper root.
    FileChanged(path::PathBuf),
    /// File matched the recorded `mtime`, but the computed hash was different.
    /// The path is relative to the ChecksumHelper root.
    FileChangedCorrupted(path::PathBuf),
    /// File changed, where the `mtime` of the file on disk is __older__ than the
    /// recorded `mtime`.
    /// The path is relative to the ChecksumHelper root.
    FileChangedOlder(path::PathBuf),
    /// The path is relative to the ChecksumHelper root.
    FileNew(path::PathBuf),
    /// The path is relative to the ChecksumHelper root.
    FileRemoved(path::PathBuf),
    Finished,
}

pub(crate) struct Incremental<'a> {
    root: &'a path::Path,
    file_tree: &'a mut FileTree,
    options: &'a ChecksumHelperOptions,
    most_current: HashCollection,
    files_to_checksum: Vec<EntryHandle>,
}

impl<'a> Incremental<'a> {
    /// Creates a new [`Incremental`] instance.
    ///
    /// # Parameters
    ///
    /// * `root` — Root path for the file hierarchy being processed.
    /// * `file_tree` — Mutable reference to the file tree used for discovery.
    /// * `options` — Hashing and filtering configuration options.
    /// * `most_current` — The most recent [`HashCollection`] to build upon.
    ///
    /// # Returns
    ///
    /// A new [`Incremental`] ready to generate a new [`HashCollection`].
    pub fn new(
        root: &'a path::Path,
        file_tree: &'a mut FileTree,
        options: &'a ChecksumHelperOptions,
        most_current: HashCollection,
    ) -> Self {
        Incremental {
            root,
            file_tree,
            options,
            most_current,
            files_to_checksum: vec!{},
        }
    }

    pub fn generate<P>(mut self, mut progress: P) -> Result<HashCollection>
    where
        P: FnMut(IncrementalProgress),
    {
        self.discover_files(&mut progress)?;
        self.checksum_files(&mut progress)
    }

    fn discover_files<P>(&mut self, progress: P) -> Result<()>
    where
        P: FnMut(IncrementalProgress),
    {
        // dyanmic borrow checking needed, since we use it in the predicate closure
        // as well as in our for loop while the closure is still alive
        // TODO restructure gather iterator/filter to return ignored entries as well
        let progress = std::cell::RefCell::new(progress);
        let mut ignored_num = 0usize;
        let iter = filtered(
            self.root, &self.options.all_files_matcher,
            |e| {
                if e.ignored {
                    progress.borrow_mut()(IncrementalProgress::DiscoverFilesIgnored(
                        e.entry.relative_to_root.to_owned()));
                    ignored_num += 1;

                    return false;
                }

                if let Some(d) = self.options.discover_hash_files_depth {
                    if e.entry.depth > d {
                        return false;
                    }
                }

                true
            });

        for entry in iter {
            let entry = entry?;
            match entry {
                VisitType::File(v) => {
                    let handle = self.file_tree.add_file(v.relative_to_root)?;
                    self.files_to_checksum.push(handle);
                    progress.borrow_mut()(IncrementalProgress::DiscoverFilesFound(
                        self.files_to_checksum.len() as u64,
                    ));
                }
                _ => {}
            }
        }

        let mut progress = progress.into_inner();
        progress(
            IncrementalProgress::DiscoverFilesDone(
                self.files_to_checksum.len(), ignored_num));

        Ok(())
    }

    fn checksum_files<P>(&mut self, mut progress: P) -> Result<HashCollection>
    where
        P: FnMut(IncrementalProgress),
    {
        // TODO this needs to flush intermediate results to disk depending on
        //      self.options.incremental_periodic_write_interval
        // Build a new collection and remove processed
        // entries from self.most_current (Python version does this, without removal)
        todo!()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{pathmatcher::PathMatcherBuilder, test_utils::*};
    use crate::file_tree::FileTree;
    use pretty_assertions::assert_eq;

    fn setup_ftree() -> path::PathBuf {
        let test_path = testdir!();
        create_ftree(
            test_path.as_ref(),
            "file.txt
            vid.mp4
            subdir/foo.txt
            subdir/chksum.md5
            subdir/nested/bar.txt
            subdir/nested/vid.mov
            subdir/nested/nested/chksum.md5
            subdir/nested/nested/cgi.bin
            subdir/other/chksms.md5
            subdir/other/file.txt",
        );

        test_path
    }

    #[test]
    fn discover_files_writes_found_file_handles() {
        let test_path = setup_ftree();
        let mut ft = FileTree::new(&test_path).unwrap();
        let options = ChecksumHelperOptions::default();
        let hc = HashCollection::new(None::<&&str>, None).unwrap();
        let mut inc = Incremental::new(
            &test_path, &mut ft, &options, hc);

        inc.discover_files(|_| {}).unwrap();

        assert_eq!(
            "FileTree{
  file.txt
  vid.mp4
  subdir/chksum.md5
  subdir/foo.txt
  subdir/other/chksms.md5
  subdir/other/file.txt
  subdir/nested/bar.txt
  subdir/nested/vid.mov
  subdir/nested/nested/cgi.bin
  subdir/nested/nested/chksum.md5
}",
            to_file_list(&inc.file_tree)
        );

        assert_eq!(
            "\
file.txt
subdir/chksum.md5
subdir/foo.txt
subdir/nested/bar.txt
subdir/nested/nested/cgi.bin
subdir/nested/nested/chksum.md5
subdir/nested/vid.mov
subdir/other/chksms.md5
subdir/other/file.txt
vid.mp4",
            file_handles_to_file_list(&inc.file_tree, &inc.files_to_checksum)
        );

        assert_eq!(inc.files_to_checksum.len(), 10);
    }

    #[test]
    fn discover_files_respects_hash_files_depth() {
        let test_path = setup_ftree();
        let mut ft = FileTree::new(&test_path).unwrap();
        let options = ChecksumHelperOptions{
            discover_hash_files_depth: Some(1),
            ..Default::default()
        };
        let hc = HashCollection::new(None::<&&str>, None).unwrap();
        let mut inc = Incremental::new(
            &test_path, &mut ft, &options, hc);

        inc.discover_files(|_| {}).unwrap();

        assert_eq!(
            "FileTree{
  file.txt
  vid.mp4
  subdir/chksum.md5
  subdir/foo.txt
}",
            to_file_list(&inc.file_tree)
        );

        assert_eq!(
            "\
file.txt
subdir/chksum.md5
subdir/foo.txt
vid.mp4",
            file_handles_to_file_list(&inc.file_tree, &inc.files_to_checksum)
        );

        assert_eq!(inc.files_to_checksum.len(), 4);
    }

    #[test]
    fn discover_files_respects_matcher() {
        let test_path = setup_ftree();
        let mut ft = FileTree::new(&test_path).unwrap();
        let matcher = PathMatcherBuilder::new()
            .block("subdir/nested/").unwrap()
            .block("**/*.md5").unwrap()
            .block("**/*.bin").unwrap()
            .allow("**/*.md5").unwrap()
            .allow("**/*.txt").unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions{
            all_files_matcher: matcher,
            ..Default::default()
        };
        let hc = HashCollection::new(None::<&&str>, None).unwrap();
        let mut inc = Incremental::new(
            &test_path, &mut ft, &options, hc);

        inc.discover_files(|_| {}).unwrap();

        assert_eq!(
            "FileTree{
  file.txt
  subdir/foo.txt
  subdir/other/file.txt
}",
            to_file_list(&inc.file_tree)
        );

        assert_eq!(
            "\
file.txt
subdir/foo.txt
subdir/other/file.txt",
            file_handles_to_file_list(&inc.file_tree, &inc.files_to_checksum)
        );

        assert_eq!(inc.files_to_checksum.len(), 3);
    }

    #[test]
    fn discover_files_calls_progress_callback() {
        let test_path = setup_ftree();
        let mut ft = FileTree::new(&test_path).unwrap();
        let matcher = PathMatcherBuilder::new()
            .block("subdir/nested/").unwrap()
            .block("**/*.md5").unwrap()
            .block("**/*.bin").unwrap()
            .allow("**/*.md5").unwrap()
            .allow("**/*.txt").unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions{
            all_files_matcher: matcher,
            ..Default::default()
        };
        let hc = HashCollection::new(None::<&&str>, None).unwrap();
        let mut inc = Incremental::new(
            &test_path, &mut ft, &options, hc);

        let mut callbacks = vec![];
        inc.discover_files(|p| {
            callbacks.push(p);
        }).unwrap();

        assert_eq!(
            vec!{
                IncrementalProgress::DiscoverFilesFound(1),  // file.txt
                IncrementalProgress::DiscoverFilesIgnored(
                    path::PathBuf::from("vid.mp4"),
                ),
                IncrementalProgress::DiscoverFilesIgnored(
                    path::PathBuf::from("subdir/chksum.md5"),
                ),
                IncrementalProgress::DiscoverFilesFound(2),  // subdir/foo.txt
                IncrementalProgress::DiscoverFilesIgnored(
                    path::PathBuf::from("subdir/nested"),
                ),
                IncrementalProgress::DiscoverFilesIgnored(
                    path::PathBuf::from("subdir/other/chksms.md5"),
                ),
                IncrementalProgress::DiscoverFilesFound(3),
                IncrementalProgress::DiscoverFilesDone(3, 4)
            },
            callbacks,
        );

    }
}
