use crate::collection::HashCollection;
use crate::hashed_file::{FileRaw, FileMut};
use crate::file_tree::{FileTree, EntryHandle};
use crate::gather::{filtered, VisitType};
use crate::most_current::MostCurrentProgress;
use crate::{ChecksumHelperError, ChecksumHelperOptions};
use crate::checksum_helper::default_filename;

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
        assert_eq!(root, file_tree.absolute_path(&file_tree.root()),
                   "Incremental root and the file tree root must match!");
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

                true
            });

        for entry in iter {
            let entry = entry?;
            if let VisitType::File(v) = entry {
                let handle = self.file_tree.add_file(v.relative_to_root)?;
                self.files_to_checksum.push(handle);
                progress.borrow_mut()(IncrementalProgress::DiscoverFilesFound(
                    self.files_to_checksum.len() as u64,
                ));
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
        let mut result = HashCollection::new(
            Some(&self.root.join(default_filename(self.root, "incremental", ""))),
            None,
        )?;

        let files_to_checksum = std::mem::take(&mut self.files_to_checksum);
        for handle in files_to_checksum {
            let path = self.file_tree.absolute_path(&handle);
            let relative_path = path.strip_prefix(self.root)
                .expect("Incremental root and FileTree root must match!");

            let mut file_raw = FileRaw::bare(
                handle.clone(),
                self.options.hash_type,
            );
            let mut file = file_raw.with_context_mut(self.file_tree);

            let previous = self.most_current.get(&handle);

            progress(IncrementalProgress::PreRead(relative_path.to_owned()));
            file.update_size_and_mtime_from_disk()?;
            if let (true, Some(p)) = (self.options.incremental_skip_unchanged, previous) {
                if p.mtime().is_some() && file.raw(|r| r.mtime()) == p.mtime() {
                    // we skip checking the hash on disk, since mtime is unchanged
                    // and the user set incremental_skip_unchanged
                    if self.options.incremental_include_unchanged_files {
                        result.update(
                            handle.clone(),
                            self.most_current
                                .remove(&handle)
                                .expect("checked that we have an entry for it above"),
                        );
                    }

                    progress(IncrementalProgress::FileUnchangedSkipped(
                        relative_path.to_owned()));
                    self.most_current.remove(&handle);
                    continue;
                }
            }

            file.update_hash_from_disk(|(read, total)| {
                progress(IncrementalProgress::Read(read, total));
            })?;
            let mut include = true;
            if let Some(p) = previous {
                include =
                    self.compare_files_and_include(&file, p, relative_path, &mut progress)?;
                self.most_current.remove(&handle);
            } else {
                progress(IncrementalProgress::FileNew(relative_path.to_owned()));
            }

            if include {
                result.update(handle, file_raw);
            }
        }

        for missing in self.most_current.iter_with_context(self.file_tree) {
            let (path_absolute, _) = missing;
            let path_relative = path_absolute.strip_prefix(self.root)
                .expect("Incremental root and FileTree root must match!");
            progress(IncrementalProgress::FileRemoved(path_relative.to_owned()));
        }

        progress(IncrementalProgress::Finished);
        Ok(result)
    }

    fn compare_files_and_include<P>(
        &self,
        on_disk: &FileMut,
        previous: &FileRaw,
        relative_path: &path::Path,
        progress: &mut P,
    ) -> Result<bool>
    where
        P: FnMut(IncrementalProgress),
    {
        let on_disk = on_disk.as_file();
        let is_match = if on_disk.hash_type() != previous.hash_type() {
            let on_disk_hash = on_disk.compute_hash_with(previous.hash_type(), |p| {
                progress(IncrementalProgress::Read(p.0, p.1));
            })?;

            on_disk_hash == previous.hash_bytes()
        } else {
            on_disk.hash_bytes() == previous.hash_bytes()
        };

        if is_match {
            progress(IncrementalProgress::FileMatch(relative_path.to_owned()));
            return Ok(self.options.incremental_include_unchanged_files);
        }

        match (previous.mtime(), on_disk.mtime()) {
            (None, _) => {
                progress(IncrementalProgress::FileChanged(relative_path.to_owned()));
            }
            (Some(prev_mtime), Some(mtime)) if mtime > prev_mtime => {
                progress(IncrementalProgress::FileChanged(relative_path.to_owned()));
            }
            (Some(prev_mtime), Some(mtime)) if mtime == prev_mtime => {
                progress(IncrementalProgress::FileChangedCorrupted(
                    relative_path.to_owned(),
                ));
            }
            (Some(prev_mtime), Some(mtime)) if mtime < prev_mtime => {
                progress(IncrementalProgress::FileChangedOlder(
                    relative_path.to_owned(),
                ));
            }
            _ => unreachable!("uncreachable, since we'd error upon a missing mtime"),
        }

        Ok(true)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hash_type::HashType;
    use crate::{pathmatcher::PathMatcherBuilder, test_utils::*};
    use crate::file_tree::FileTree;
    use pretty_assertions::assert_eq;

    fn ftree_all_files() -> Vec<&'static str> {
        return vec![
            "file.txt",
            "vid.mp4",
            "subdir/foo.txt",
            "subdir/chksum.md5",
            "subdir/nested/bar.txt",
            "subdir/nested/vid.mov",
            "subdir/nested/nested/chksum.md5",
            "subdir/nested/nested/cgi.bin",
            "subdir/other/chksms.md5",
            "subdir/other/file.txt",
        ];
    }

    fn setup_ftree() -> path::PathBuf {
        let test_path = testdir!();
        create_ftree(
            test_path.as_ref(),
            &ftree_all_files().join("\n"),
        );

        test_path
    }

    fn setup_ftree_minimal() -> (path::PathBuf, String, filetime::FileTime) {
        let test_path = testdir!();
        let path_relative = "subdir/nested/nested/cgi.bin";
        create_ftree(
            test_path.as_ref(),
            path_relative,
        );

        let filetime_cig_bin = filetime::FileTime::from_unix_time(69420, 3_300_000);
        filetime::set_file_times(
            &test_path.join(path_relative),
            filetime_cig_bin,
            filetime_cig_bin).unwrap();

        (test_path, path_relative.to_owned(), filetime_cig_bin)
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

    #[test]
    fn checksum_files_visits_all_files() {
        let test_path = setup_ftree();
        let mut ft = FileTree::new(&test_path).unwrap();
        let options = ChecksumHelperOptions::default();
        let hc = HashCollection::new(None::<&&str>, None).unwrap();
        let mut inc = Incremental::new(
            &test_path, &mut ft, &options, hc);

        inc.discover_files(|_| {}).unwrap();
        let new = inc.checksum_files(|_| {}).unwrap();
        let cshd_str = new.to_str(inc.file_tree).unwrap();

        assert_eq!(
            "file.txt
subdir/chksum.md5
subdir/foo.txt
subdir/nested/bar.txt
subdir/nested/nested/cgi.bin
subdir/nested/nested/chksum.md5
subdir/nested/vid.mov
subdir/other/chksms.md5
subdir/other/file.txt
vid.mp4
",
            cshd_str_paths_only_sorted(&cshd_str),
        );

        assert_eq!(new.len(), 10);
        assert_eq!(inc.most_current.len(), 0);
        assert_eq!(inc.files_to_checksum, vec![]);
    }

    #[test]
    fn checksum_files_respects_options_hash_type() {
        let test_path = setup_ftree();
        let mut ft = FileTree::new(&test_path).unwrap();
        let expected = HashType::Sha3_224;
        let options = ChecksumHelperOptions{
            hash_type: expected,
            ..Default::default()
        };
        let hc = HashCollection::new(None::<&&str>, None).unwrap();
        let mut inc = Incremental::new(
            &test_path, &mut ft, &options, hc);

        let handle = inc.file_tree.add_file("vid.mp4").unwrap();
        inc.files_to_checksum.push(handle.clone());

        let new = inc.checksum_files(|_| {}).unwrap();
        assert_eq!(expected, new.get(&handle).unwrap().hash_type());
        assert_eq!(new.len(), 1);
    }

    fn most_current_all() -> &'static str {
        return "# version 1
1763239693.8727274,8,sha512,98dfdd998999f4e05f71e500559bd366e67c2039b8b2da3215ea80a16fa92033d2e471fa02aca7f232572d41913a912e5dd8f241bcd889b1482b1967f93e353a file.txt
1763239693.8732224,7,sha512,d0fa60060582bca8845761653d41a4e60f13d00c458c745adc7b16e4c05afbc873fcce18fa37338d6ad65bbd6c4f4bd98f8fbfc8d9065237a7f739314ec1585d vid.mp4
1763239693.8742228,17,sha512,16240544f3fe5b23107522f59a68814267dca8faa51acc37bb56031f8d431bd6ab8466fed0c5dc6322c83be4032b67f5cc1b87d9391f18a850f093f508c44c4f subdir/chksum.md5
1763239693.873623,14,sha512,f05dcb8a07c2cbcd2dcee5a35d06efe95962e2d5d3e6f04452da2a7109d5082138c32ddde5bded2ea5796865721852beda24bf7eea901d4fa8aae62cc34e9b04 subdir/foo.txt
1763239693.8771043,23,sha512,16da0970840dd6cc2e854709c10484ce2911ce260629e5ca584c728b2a6c03268403c8714f90564396bba5f2ac401566e139ce6f4b137865b1f0a23090bfa0a5 subdir/other/chksms.md5
1763239693.8777964,21,sha512,10d2cfc0c6e314115f99cc95a31489c8c9d1934bc0e96f012d47f9c1a3be0e9f2550198efd8a06b972653db3cfeaf2214c3b6f344aa22bca6e57e864fcfc9f63 subdir/other/file.txt
1763239693.8747134,21,sha512,3b62a1e6bf057a53e1d3e61486d5b9ba4bade9193700ab0ec65015cef91274aae08bd16422115183ef5922f15f01a1863accd0abe204b8917bf9c05b0d0686d5 subdir/nested/bar.txt
1763239693.8753488,21,sha512,e374a8bbbfeaa038ddf2fcd8b62f2971607fd2c1d2e091c30410c73ad199ae8c8e0e319d33455f7547b246ee9792571dfb82821a8c8637caf6732ba2c9079108 subdir/nested/vid.mov
1763239693.8765886,28,sha512,5045ee6bd5128311600b8807ea40a1f17feadbf14a10b30c815b5371d6fb45ed99e96c55f925dbb69aed8a9b01a4b658fd35e21a6e39e7ae84a85d3138ee21e4 subdir/nested/nested/cgi.bin
1763239693.875868,31,sha512,879a1635ab8e8079238cb2471ed2c9c034430055482f93945f6a18a2340583a670e785df21477f35e02b8762f8d070a17365b0378f4345056c293dc41d044162 subdir/nested/nested/chksum.md5";
    }

    fn file_from_disk(
        file_tree: &mut FileTree,
        path: impl AsRef<path::Path>,
        hash_type: HashType,
    ) -> (EntryHandle, FileRaw) {
        let handle = file_tree.add_file(path).unwrap();
        let mut file_raw = FileRaw::bare(
            handle.clone(),
            hash_type,
        );
        let mut file = file_raw.with_context_mut(&file_tree);
        file.update_size_and_mtime_from_disk().unwrap();
        file.update_hash_from_disk(|_| {}).unwrap();

        (handle, file_raw)
    }

    #[test]
    fn checksum_files_respects_include_unchanged() {
        let combinations = vec![
            (true, "file.txt
subdir/chksum.md5
subdir/foo.txt
subdir/nested/bar.txt
subdir/nested/nested/cgi.bin
subdir/nested/nested/chksum.md5
subdir/nested/vid.mov
subdir/other/chksms.md5
subdir/other/file.txt
vid.mp4
"),
            (false, "subdir/chksum.md5
subdir/foo.txt
subdir/nested/bar.txt
subdir/nested/nested/chksum.md5
subdir/nested/vid.mov
subdir/other/chksms.md5
subdir/other/file.txt
vid.mp4
"),
        ];

        let test_path = setup_ftree();
        let mut ft = FileTree::new(&test_path).unwrap();

        for (include_unchanged, expected) in combinations {
            let options = ChecksumHelperOptions{
                incremental_include_unchanged_files: include_unchanged,
                ..Default::default()
            };

            let mut hc = HashCollection::new(None::<&&str>, None).unwrap();
            let file_txt = file_from_disk(&mut ft, "file.txt", HashType::Sha512);
            hc.update(file_txt.0, file_txt.1);
            let subdir_nested_nested_cgi_bin =
                file_from_disk(&mut ft, "subdir/nested/nested/cgi.bin", HashType::Sha512);
            hc.update(subdir_nested_nested_cgi_bin.0, subdir_nested_nested_cgi_bin.1);

            let mut inc = Incremental::new(
                &test_path, &mut ft, &options, hc);

            inc.discover_files(|_| {}).unwrap();
            let new = inc.checksum_files(|_| {}).unwrap();
            let cshd_str = new.to_str(inc.file_tree).unwrap();

            assert_eq!(
                expected,
                cshd_str_paths_only_sorted(&cshd_str),
            );
        }
    }

    #[test]
    fn checksum_files_respects_skip_unchanged() {
        let combinations = vec![
            (
                true,
                vec![
                    IncrementalProgress::FileUnchangedSkipped(path::PathBuf::from("file.txt")),
                    IncrementalProgress::FileUnchangedSkipped(path::PathBuf::from(
                        "subdir/nested/nested/cgi.bin",
                    )),
                ],
            ),
            (false, vec![]),
        ];

        let test_path = setup_ftree();
        let mut ft = FileTree::new(&test_path).unwrap();

        for (skip_unchanged, expected) in combinations {
            let options = ChecksumHelperOptions{
                incremental_include_unchanged_files: true,
                incremental_skip_unchanged: skip_unchanged,
                ..Default::default()
            };

            let mut hc = HashCollection::new(None::<&&str>, None).unwrap();
            let file_txt = file_from_disk(&mut ft, "file.txt", HashType::Sha512);
            hc.update(file_txt.0, file_txt.1);
            let subdir_nested_nested_cgi_bin =
                file_from_disk(&mut ft, "subdir/nested/nested/cgi.bin", HashType::Sha512);
            hc.update(subdir_nested_nested_cgi_bin.0, subdir_nested_nested_cgi_bin.1);

            let mut inc = Incremental::new(
                &test_path, &mut ft, &options, hc);

            inc.discover_files(|_| {}).unwrap();
            let mut skipped_callbacks = vec![];
            let new = inc.checksum_files(|p| {
                if let IncrementalProgress::FileUnchangedSkipped(_) = p {
                    skipped_callbacks.push(p);
                }
            }).unwrap();
            let cshd_str = new.to_str(inc.file_tree).unwrap();

            assert!(inc.most_current.is_empty());
            assert_eq!(
                expected,
                skipped_callbacks);

            assert_eq!(
                "file.txt
subdir/chksum.md5
subdir/foo.txt
subdir/nested/bar.txt
subdir/nested/nested/cgi.bin
subdir/nested/nested/chksum.md5
subdir/nested/vid.mov
subdir/other/chksms.md5
subdir/other/file.txt
vid.mp4
",
                cshd_str_paths_only_sorted(&cshd_str),
            );
        }
    }

    #[test]
    fn checksum_files_respects_skip_unchanged_and_incremental_unchanged() {
        struct Combination{
            skip_unchanged: bool,
            include_unchanged: bool,
            skipped_callbacks: Vec<IncrementalProgress>,
            expected_files: &'static str,
        }
        let combinations = vec![
            Combination {
                skip_unchanged: true,
                include_unchanged: true,
                skipped_callbacks: vec![
                    IncrementalProgress::FileUnchangedSkipped(path::PathBuf::from("file.txt")),
                    IncrementalProgress::FileUnchangedSkipped(path::PathBuf::from(
                        "subdir/nested/nested/cgi.bin",
                    )),
                ],
                expected_files: "file.txt
subdir/chksum.md5
subdir/foo.txt
subdir/nested/bar.txt
subdir/nested/nested/cgi.bin
subdir/nested/nested/chksum.md5
subdir/nested/vid.mov
subdir/other/chksms.md5
subdir/other/file.txt
vid.mp4
",
            },
            Combination {
                skip_unchanged: true,
                include_unchanged: false,
                skipped_callbacks: vec![
                    IncrementalProgress::FileUnchangedSkipped(path::PathBuf::from("file.txt")),
                    IncrementalProgress::FileUnchangedSkipped(path::PathBuf::from(
                        "subdir/nested/nested/cgi.bin",
                    )),
                ],
                expected_files: "subdir/chksum.md5
subdir/foo.txt
subdir/nested/bar.txt
subdir/nested/nested/chksum.md5
subdir/nested/vid.mov
subdir/other/chksms.md5
subdir/other/file.txt
vid.mp4
",
            },
            Combination {
                skip_unchanged: false,
                include_unchanged: true,
                skipped_callbacks: vec![
                ],
                expected_files: "file.txt
subdir/chksum.md5
subdir/foo.txt
subdir/nested/bar.txt
subdir/nested/nested/cgi.bin
subdir/nested/nested/chksum.md5
subdir/nested/vid.mov
subdir/other/chksms.md5
subdir/other/file.txt
vid.mp4
",
            },
            Combination {
                skip_unchanged: false,
                include_unchanged: false,
                skipped_callbacks: vec![
                ],
                expected_files: "subdir/chksum.md5
subdir/foo.txt
subdir/nested/bar.txt
subdir/nested/nested/chksum.md5
subdir/nested/vid.mov
subdir/other/chksms.md5
subdir/other/file.txt
vid.mp4
",
            },
        ];

        let test_path = setup_ftree();
        let mut ft = FileTree::new(&test_path).unwrap();

        for expected in combinations {
            let options = ChecksumHelperOptions{
                incremental_include_unchanged_files: expected.include_unchanged,
                incremental_skip_unchanged: expected.skip_unchanged,
                ..Default::default()
            };

            let mut hc = HashCollection::new(None::<&&str>, None).unwrap();
            let file_txt = file_from_disk(&mut ft, "file.txt", HashType::Sha512);
            hc.update(file_txt.0, file_txt.1);
            let subdir_nested_nested_cgi_bin =
                file_from_disk(&mut ft, "subdir/nested/nested/cgi.bin", HashType::Sha512);
            hc.update(subdir_nested_nested_cgi_bin.0, subdir_nested_nested_cgi_bin.1);

            let mut inc = Incremental::new(
                &test_path, &mut ft, &options, hc);

            inc.discover_files(|_| {}).unwrap();
            let mut skipped_callbacks = vec![];
            let new = inc.checksum_files(|p| {
                if let IncrementalProgress::FileUnchangedSkipped(_) = p {
                    skipped_callbacks.push(p);
                }
            }).unwrap();
            let cshd_str = new.to_str(inc.file_tree).unwrap();

            assert!(inc.most_current.is_empty());
            assert_eq!(
                expected.skipped_callbacks,
                skipped_callbacks);

            assert_eq!(
                expected.expected_files,
                cshd_str_paths_only_sorted(&cshd_str),
            );
        }
    }

    #[test]
    fn checksum_files_file_match() {
        let (test_path, path_cgi_bin, _filetime_cig_bin) = setup_ftree_minimal();
        let mut ft = FileTree::new(&test_path).unwrap();
        let mut hc = HashCollection::new(None::<&&str>, None).unwrap();
        let cgi_bin = file_from_disk(&mut ft, &path_cgi_bin, HashType::Sha512);
        hc.update(cgi_bin.0, cgi_bin.1);

        let options = ChecksumHelperOptions::default();
        let mut inc = Incremental::new(
            &test_path, &mut ft, &options, hc);

        inc.discover_files(|_| {}).unwrap();
        let mut callbacks = vec![];
        let new = inc.checksum_files(|p| callbacks.push(p)).unwrap();

        assert_eq!(
            new.to_str(inc.file_tree).unwrap(),
            "\
# version 1
69420.0033,28,sha512,5045ee6bd5128311600b8807ea40a1f17feadbf14a10b30c815b5371d6fb45ed99e96c55f925dbb69aed8a9b01a4b658fd35e21a6e39e7ae84a85d3138ee21e4 subdir/nested/nested/cgi.bin
",
        );

        assert_eq!(
            callbacks,
            vec![
                IncrementalProgress::PreRead(
                    path::PathBuf::from(&path_cgi_bin),
                ),
                IncrementalProgress::Read(
                    28,
                    28,
                ),
                IncrementalProgress::FileMatch(
                    path::PathBuf::from(&path_cgi_bin),
                ),
                IncrementalProgress::Finished,
            ],
        );
    }

    #[test]
    fn checksum_files_file_new() {
        let (test_path, path_cgi_bin, _filetime_cig_bin) = setup_ftree_minimal();
        let mut ft = FileTree::new(&test_path).unwrap();
        let hc = HashCollection::new(None::<&&str>, None).unwrap();

        let options = ChecksumHelperOptions::default();
        let mut inc = Incremental::new(
            &test_path, &mut ft, &options, hc);

        inc.discover_files(|_| {}).unwrap();
        let mut callbacks = vec![];
        let new = inc.checksum_files(|p| callbacks.push(p)).unwrap();

        assert_eq!(
            new.to_str(inc.file_tree).unwrap(),
            "\
# version 1
69420.0033,28,sha512,5045ee6bd5128311600b8807ea40a1f17feadbf14a10b30c815b5371d6fb45ed99e96c55f925dbb69aed8a9b01a4b658fd35e21a6e39e7ae84a85d3138ee21e4 subdir/nested/nested/cgi.bin
",
        );

        assert_eq!(
            callbacks,
            vec![
                IncrementalProgress::PreRead(
                    path::PathBuf::from(&path_cgi_bin),
                ),
                IncrementalProgress::Read(
                    28,
                    28,
                ),
                IncrementalProgress::FileNew(
                    path::PathBuf::from(&path_cgi_bin),
                ),
                IncrementalProgress::Finished,
            ],
        );
    }

    #[test]
    fn checksum_files_file_removed() {
        let (test_path, path_cgi_bin, _filetime_cig_bin) = setup_ftree_minimal();
        let mut ft = FileTree::new(&test_path).unwrap();
        let mut hc = HashCollection::new(None::<&&str>, None).unwrap();
        let cgi_bin = file_from_disk(&mut ft, &path_cgi_bin, HashType::Sha512);
        hc.update(cgi_bin.0, cgi_bin.1);

        std::fs::remove_file(test_path.join(&path_cgi_bin)).unwrap();

        let options = ChecksumHelperOptions::default();
        let mut inc = Incremental::new(
            &test_path, &mut ft, &options, hc);

        inc.discover_files(|_| {}).unwrap();
        let mut callbacks = vec![];
        let new = inc.checksum_files(|p| callbacks.push(p)).unwrap();

        assert!(new.is_empty());
        assert_eq!(
            callbacks,
            vec![
                IncrementalProgress::FileRemoved(
                    path::PathBuf::from(&path_cgi_bin),
                ),
                IncrementalProgress::Finished,
            ],
        );
    }

    #[test]
    fn checksum_files_file_changed_no_mtime() {
        let (test_path, path_cgi_bin, filetime_cig_bin) = setup_ftree_minimal();
        let mut ft = FileTree::new(&test_path).unwrap();
        let mut hc = HashCollection::new(None::<&&str>, None).unwrap();
        let mut cgi_bin = file_from_disk(&mut ft, &path_cgi_bin, HashType::Sha512);
        cgi_bin.1.set_mtime(None);
        hc.update(cgi_bin.0, cgi_bin.1);

        let path = test_path.join(&path_cgi_bin);
        std::fs::write(&path, "foo").unwrap();
        filetime::set_file_times(&path, filetime_cig_bin, filetime_cig_bin).unwrap();

        let options = ChecksumHelperOptions::default();
        let mut inc = Incremental::new(
            &test_path, &mut ft, &options, hc);


        inc.discover_files(|_| {}).unwrap();
        let mut callbacks = vec![];
        let new = inc.checksum_files(|p| callbacks.push(p)).unwrap();


        assert_eq!(
            new.to_str(inc.file_tree).unwrap(),
            "\
# version 1
69420.0033,3,sha512,f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7 subdir/nested/nested/cgi.bin
",
        );

        assert_eq!(
            callbacks,
            vec![
                IncrementalProgress::PreRead(
                    path::PathBuf::from(&path_cgi_bin),
                ),
                IncrementalProgress::Read(
                    3,
                    3,
                ),
                IncrementalProgress::FileChanged(
                    path::PathBuf::from(&path_cgi_bin),
                ),
                IncrementalProgress::Finished,
            ],
        );
    }

    #[test]
    fn checksum_files_file_changed_with_mtime() {
        let (test_path, path_cgi_bin, _filetime_cig_bin) = setup_ftree_minimal();
        let mut ft = FileTree::new(&test_path).unwrap();
        let mut hc = HashCollection::new(None::<&&str>, None).unwrap();
        let cgi_bin = file_from_disk(&mut ft, &path_cgi_bin, HashType::Sha512);
        hc.update(cgi_bin.0, cgi_bin.1);

        let path = test_path.join(&path_cgi_bin);
        let newer_filetime = filetime::FileTime::from_unix_time(
            133337, 1_330_000);
        std::fs::write(&path, "foo").unwrap();
        filetime::set_file_times(&path, newer_filetime, newer_filetime).unwrap();

        let options = ChecksumHelperOptions::default();
        let mut inc = Incremental::new(
            &test_path, &mut ft, &options, hc);


        inc.discover_files(|_| {}).unwrap();
        let mut callbacks = vec![];
        let new = inc.checksum_files(|p| callbacks.push(p)).unwrap();


        assert_eq!(
            new.to_str(inc.file_tree).unwrap(),
            "\
# version 1
133337.00133,3,sha512,f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7 subdir/nested/nested/cgi.bin
",
        );

        assert_eq!(
            callbacks,
            vec![
                IncrementalProgress::PreRead(
                    path::PathBuf::from(&path_cgi_bin),
                ),
                IncrementalProgress::Read(
                    3,
                    3,
                ),
                IncrementalProgress::FileChanged(
                    path::PathBuf::from(&path_cgi_bin),
                ),
                IncrementalProgress::Finished,
            ],
        );
    }

    #[test]
    fn checksum_files_file_changed_older() {
        let (test_path, path_cgi_bin, _filetime_cig_bin) = setup_ftree_minimal();
        let mut ft = FileTree::new(&test_path).unwrap();
        let mut hc = HashCollection::new(None::<&&str>, None).unwrap();
        let cgi_bin = file_from_disk(&mut ft, &path_cgi_bin, HashType::Sha512);
        hc.update(cgi_bin.0, cgi_bin.1);

        let path = test_path.join(&path_cgi_bin);
        let older_filetime = filetime::FileTime::from_unix_time(
            1337, 1_330_000);
        std::fs::write(&path, "foo").unwrap();
        filetime::set_file_times(&path, older_filetime, older_filetime).unwrap();

        let options = ChecksumHelperOptions::default();
        let mut inc = Incremental::new(
            &test_path, &mut ft, &options, hc);


        inc.discover_files(|_| {}).unwrap();
        let mut callbacks = vec![];
        let new = inc.checksum_files(|p| callbacks.push(p)).unwrap();


        assert_eq!(
            new.to_str(inc.file_tree).unwrap(),
            "\
# version 1
1337.00133,3,sha512,f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7 subdir/nested/nested/cgi.bin
",
        );

        assert_eq!(
            callbacks,
            vec![
                IncrementalProgress::PreRead(
                    path::PathBuf::from(&path_cgi_bin),
                ),
                IncrementalProgress::Read(
                    3,
                    3,
                ),
                IncrementalProgress::FileChangedOlder(
                    path::PathBuf::from(&path_cgi_bin),
                ),
                IncrementalProgress::Finished,
            ],
        );
    }

    #[test]
    fn checksum_files_file_changed_corrupted() {
        let (test_path, path_cgi_bin, filetime_cig_bin) = setup_ftree_minimal();
        let mut ft = FileTree::new(&test_path).unwrap();
        let mut hc = HashCollection::new(None::<&&str>, None).unwrap();
        let cgi_bin = file_from_disk(&mut ft, &path_cgi_bin, HashType::Sha512);
        hc.update(cgi_bin.0, cgi_bin.1);

        let path = test_path.join(&path_cgi_bin);
        std::fs::write(&path, "foo").unwrap();
        filetime::set_file_times(&path, filetime_cig_bin, filetime_cig_bin).unwrap();

        let options = ChecksumHelperOptions::default();
        let mut inc = Incremental::new(
            &test_path, &mut ft, &options, hc);


        inc.discover_files(|_| {}).unwrap();
        let mut callbacks = vec![];
        let new = inc.checksum_files(|p| callbacks.push(p)).unwrap();


        assert_eq!(
            new.to_str(inc.file_tree).unwrap(),
            "\
# version 1
69420.0033,3,sha512,f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7 subdir/nested/nested/cgi.bin
",
        );

        assert_eq!(
            callbacks,
            vec![
                IncrementalProgress::PreRead(
                    path::PathBuf::from(&path_cgi_bin),
                ),
                IncrementalProgress::Read(
                    3,
                    3,
                ),
                IncrementalProgress::FileChangedCorrupted(
                    path::PathBuf::from(&path_cgi_bin),
                ),
                IncrementalProgress::Finished,
            ],
        );
    }

    #[test]
    fn checksum_files_file_changed_different_hash_type() {
        let (test_path, path_cgi_bin, filetime_cig_bin) = setup_ftree_minimal();
        let mut ft = FileTree::new(&test_path).unwrap();
        let mut hc = HashCollection::new(None::<&&str>, None).unwrap();
        let cgi_bin = file_from_disk(&mut ft, &path_cgi_bin, HashType::Md5);
        hc.update(cgi_bin.0, cgi_bin.1);

        let path = test_path.join(&path_cgi_bin);
        std::fs::write(&path, "foo").unwrap();
        filetime::set_file_times(&path, filetime_cig_bin, filetime_cig_bin).unwrap();

        let options = ChecksumHelperOptions::default();
        assert_ne!(options.hash_type, HashType::Md5);
        let mut inc = Incremental::new(
            &test_path, &mut ft, &options, hc);


        inc.discover_files(|_| {}).unwrap();
        let mut callbacks = vec![];
        let new = inc.checksum_files(|p| callbacks.push(p)).unwrap();


        assert_eq!(
            new.to_str(inc.file_tree).unwrap(),
            "\
# version 1
69420.0033,3,sha512,f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7 subdir/nested/nested/cgi.bin
",
        );

        assert_eq!(
            callbacks,
            vec![
                IncrementalProgress::PreRead(
                    path::PathBuf::from(&path_cgi_bin),
                ),
                IncrementalProgress::Read(
                    3,
                    3,
                ),
                // second read due to different hash type -> recompute
                IncrementalProgress::Read(
                    3,
                    3,
                ),
                IncrementalProgress::FileChangedCorrupted(
                    path::PathBuf::from(&path_cgi_bin),
                ),
                IncrementalProgress::Finished,
            ],
        );
    }

    #[test]
    fn checksum_files_file_match_different_hash_type() {
        let (test_path, path_cgi_bin, _filetime_cig_bin) = setup_ftree_minimal();
        let mut ft = FileTree::new(&test_path).unwrap();
        let mut hc = HashCollection::new(None::<&&str>, None).unwrap();
        let cgi_bin = file_from_disk(&mut ft, &path_cgi_bin, HashType::Md5);
        hc.update(cgi_bin.0, cgi_bin.1);

        let options = ChecksumHelperOptions::default();
        assert_ne!(options.hash_type, HashType::Md5);
        let mut inc = Incremental::new(
            &test_path, &mut ft, &options, hc);


        inc.discover_files(|_| {}).unwrap();
        let mut callbacks = vec![];
        let new = inc.checksum_files(|p| callbacks.push(p)).unwrap();


        assert_eq!(
            new.to_str(inc.file_tree).unwrap(),
            "\
# version 1
69420.0033,28,sha512,5045ee6bd5128311600b8807ea40a1f17feadbf14a10b30c815b5371d6fb45ed99e96c55f925dbb69aed8a9b01a4b658fd35e21a6e39e7ae84a85d3138ee21e4 subdir/nested/nested/cgi.bin
",
        );

        assert_eq!(
            callbacks,
            vec![
                IncrementalProgress::PreRead(
                    path::PathBuf::from(&path_cgi_bin),
                ),
                IncrementalProgress::Read(
                    28,
                    28,
                ),
                // second read due to different hash type -> recompute
                IncrementalProgress::Read(
                    28,
                    28,
                ),
                IncrementalProgress::FileMatch(
                    path::PathBuf::from(&path_cgi_bin),
                ),
                IncrementalProgress::Finished,
            ],
        );
    }
}
