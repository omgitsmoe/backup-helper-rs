use crate::collection::HashCollection;
use crate::file_tree::FileTree;
use crate::{ChecksumHelperError, ChecksumHelperOptions};
use crate::most_current::MostCurrentProgress;

use std::path;

type Result<T> = std::result::Result<T, ChecksumHelperError>;


#[derive(Debug)]
pub enum IncrementalProgress {
    BuildMostCurrent(MostCurrentProgress),
    /// Found a file that will be included in check summing.
    DiscoverFilesFound(usize),
    /// Ignored a path (file or directory).
    DiscoverFilesIgnored(path::PathBuf),
    /// Finished discovering files to hash: number of files to hash, number of ignored files.
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
        Incremental{
            root,
            file_tree,
            options,
            most_current,
        }
    }

    pub fn generate<P>(mut self, mut progress: P) -> Result<HashCollection>
    where
        P: FnMut(IncrementalProgress)
    {
        self.discover_files(&mut progress)?;
        self.checksum_files(&mut progress)
    }

    fn discover_files<P>(&mut self, progress: P) -> Result<()>
    where
        P: FnMut(IncrementalProgress)
    {
        todo!()
    }

    fn checksum_files<P>(&mut self, progress: P) -> Result<HashCollection>
    where
        P: FnMut(IncrementalProgress)
    {
        // TODO this needs to flush intermediate results to disk depending on
        //      self.options.incremental_periodic_write_interval
        // Build a new collection and remove processed
        // entries from self.most_current (Python version does this, without removal)
        todo!()
    }
}
