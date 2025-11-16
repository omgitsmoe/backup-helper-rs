use crate::pathmatcher::PathMatcher;

use std::fmt;
use std::fs;
use std::iter::Iterator;
use std::path;

#[derive(Debug)]
pub enum Error {
    ReadDirectory((path::PathBuf, String, std::io::ErrorKind)),
    ReadFileInfo((path::PathBuf, String, std::io::ErrorKind)),
    Iteration(String, std::io::ErrorKind),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ReadDirectory((p, e, _)) => {
                write!(f, "failed to read directory at '{:?}': {:?}", p, e)
            }
            Error::ReadFileInfo((p, e, _)) => {
                write!(f, "failed to read file information at '{:?}': {:?}", p, e)
            }
            Error::Iteration(e, _) => {
                write!(f, "failed to iterate directory: {:?}", e)
            }
        }
    }
}

impl std::error::Error for Error {}

pub struct VisitData {
    pub depth: u32,
    pub entry: fs::DirEntry,
    pub relative_to_root: path::PathBuf,
}

pub enum VisitType {
    ListDirStart(u32),
    ListDirStop(u32),
    Directory(VisitData),
    File(VisitData),
}

pub struct Entry<'a> {
    /// Depth relative to the root, where 0 => in root directory,
    /// 1 => one directory down from root
    pub depth: u32,
    pub is_directory: bool,
    pub dir_entry: &'a fs::DirEntry,
    /// Path relative to the start path passed into [`Gather::new`]
    pub relative_to_root: &'a path::Path,
}

/// Visits directories in a defined order:
/// .
/// ./foo/
/// ./file.txt
/// ./bar/
/// ./bar/file.txt
/// ./bar/baz/
/// ./xer.bin
///
/// Will be visited in:
/// 1) All the children of `.`
/// 2) Then all the directories of `.` in reverse order
/// ...
pub struct Gather<P> {
    predicate: P,
    // Whether a fatal error was returned and iteration should end on the next call.
    has_fatal_error: bool,
    root: path::PathBuf,
    directory_stack: Vec<(u32, path::PathBuf)>,
    current_depth: u32,
    current_dir_iter: Option<std::fs::ReadDir>,
}

impl<P> Gather<P>
where
    P: FnMut(Entry) -> bool,
{
    pub fn new(start: impl AsRef<path::Path>, predicate: P) -> Self {
        let root = start.as_ref().to_owned();
        Gather {
            predicate,
            has_fatal_error: false,
            directory_stack: vec![(0, root.clone())],
            current_depth: 0,
            current_dir_iter: None,
            root,
        }
    }

    fn next_dir_entry(&mut self) -> Option<Result<VisitType, Error>> {
        let iter = &mut self
            .current_dir_iter
            .as_mut()
            .expect("should've been checked in next");
        loop {
            let result = match iter.next() {
                Some(Ok(e)) => match e.file_type() {
                    Ok(file_type) => {
                        let is_dir = file_type.is_dir();
                        let relative_to_root = e.path()
                            .strip_prefix(&self.root)
                            .expect("paths under root must be relative to root")
                            .to_owned();

                        if !(self.predicate)(Entry {
                            depth: self.current_depth,
                            is_directory: is_dir,
                            dir_entry: &e,
                            relative_to_root: &relative_to_root,
                        }) {
                            continue;
                        }

                        if is_dir {
                            self.directory_stack
                                .push((self.current_depth + 1, e.path()));
                            Ok(VisitType::Directory(VisitData{
                                depth: self.current_depth,
                                entry: e,
                                relative_to_root,
                            }))
                        } else {
                            Ok(VisitType::File(VisitData{
                                depth: self.current_depth,
                                entry: e,
                                relative_to_root,
                            }))
                        }
                    }
                    Err(err) => Err(Error::ReadFileInfo((
                        e.path(),
                        format!("{:?}", err),
                        err.kind(),
                    ))),
                },
                Some(Err(e)) => Err(Error::Iteration(format!("{:?}", e), e.kind())),
                None => {
                    self.current_dir_iter = None;
                    Ok(VisitType::ListDirStop(self.current_depth))
                }
            };

            return Some(result);
        }
    }
}

impl<P> Iterator for Gather<P>
where
    P: FnMut(Entry) -> bool,
{
    type Item = Result<VisitType, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.has_fatal_error {
            return None;
        }

        if self.current_dir_iter.is_some() {
            return self.next_dir_entry();
        }

        if let Some((depth, directory)) = self.directory_stack.pop() {
            let iter_dir = match fs::read_dir(&directory) {
                Ok(iter) => iter,
                Err(e) => {
                    self.has_fatal_error = true;
                    return Some(Err(Error::ReadDirectory((
                        directory.clone(),
                        format!("{}", e),
                        e.kind(),
                    ))));
                }
            };

            self.current_depth = depth;
            self.current_dir_iter = Some(iter_dir.into_iter());
            Some(Ok(VisitType::ListDirStart(depth)))
        } else {
            None
        }
    }
}

pub struct FilteredEntry<'a> {
    pub entry: Entry<'a>,
    /// Whether the entry was ignored by [`GatherFiltered::filter`].
    /// Can be overriden, by e.g., returning `true` from the predicate.
    pub ignored: bool,
}

/// Create a filtered iterator using [`filter`], which walks directories
/// recursively starting at [`start`].
/// [`predicate`] is called for each file or directory, even
/// if it was already filtered, to allow overriding the result
/// or just for information.
pub fn filtered<'a, P>(
    start: impl AsRef<path::Path>,
    filter: &'a PathMatcher,
    mut predicate: P,
) -> Gather<impl FnMut(Entry) -> bool + 'a>
where
    P: FnMut(FilteredEntry) -> bool + 'a,
{
    Gather::new(start, move |e| {
        if e.is_directory {
            if filter.is_excluded(e.relative_to_root) {
                return predicate(FilteredEntry {
                    entry: e,
                    ignored: true,
                });
            }
        } else if !filter.is_match(e.relative_to_root) {
            return predicate(FilteredEntry {
                entry: e,
                ignored: true,
            });
        }

        predicate(FilteredEntry {
            entry: e,
            ignored: false,
        })
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{pathmatcher::PathMatcherBuilder, test_utils::*};
    use pretty_assertions::assert_eq;
    use crate::file_tree::{EntryHandle, FileTree};

    fn gather_into_file_tree<F>(
        start: &path::Path,
        file_tree: &mut FileTree,
        include_fn: F,
    ) -> Result<Vec<EntryHandle>, Error>
    where
        F: FnMut(Entry) -> bool,
    {
        // in case the file_tree wasn't empty we need a way to just iterate the files
        // that were gathered into the file_tree, without the previously existing ones
        let mut result_handles = vec![];

        let mut directories = vec![file_tree.root()];
        let mut handle = file_tree.root();
        let iter = Gather::new(start, include_fn);

        for visit_type in iter {
            match visit_type {
                Ok(VisitType::ListDirStart(_)) => {
                    handle = directories
                        .pop()
                        .expect("there should be a directory queued");
                }
                Ok(VisitType::Directory(v)) => {
                    let new_handle = file_tree.add_child(
                        &handle, v.entry.file_name(), true);
                    directories.push(new_handle);
                }
                Ok(VisitType::File(v)) => {
                    let handle = file_tree.add_child(
                        &handle, v.entry.file_name(), false);
                    result_handles.push(handle);
                }
                Err(e) => return Err(e),
                _ => {}
            }
        }

        Ok(result_handles)
    }

    #[test]
    fn gather_visit_no_filter() {
        let test_path = setup_ftree();
        create_ftree(
            test_path.as_ref(),
            "abc/other.txt
             abc/boo.txt",
        );

        let mut visits = vec![];
        let gather = Gather::new(&test_path, |_| true);
        for v in gather {
            let v = v.unwrap();
            match v {
                VisitType::ListDirStart(d) => visits.push(format!("start d{}", d)),
                VisitType::ListDirStop(d) => visits.push(format!("stop d{}", d)),
                VisitType::File(v) => visits.push(format!(
                    "file d{} {:?} r{:?}",
                    v.depth,
                    v.entry.path()
                        .strip_prefix(&test_path)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace("\\", "/"),
                    v.relative_to_root,
                )),
                VisitType::Directory(v) => visits.push(format!(
                    "dir d{} {:?} r{:?}",
                    v.depth,
                    v.entry.path()
                        .strip_prefix(&test_path)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace("\\", "/"),
                    v.relative_to_root,
                )),
            }
        }
        let actual = visits.join("\n");
        println!("actual:\n{}", actual);
        assert_eq!(
            actual,
            r#"start d0
dir d0 "abc" r"abc"
file d0 "file.txt" r"file.txt"
dir d0 "subdir" r"subdir"
file d0 "vid.mp4" r"vid.mp4"
stop d0
start d1
file d1 "subdir/chksum.md5" r"subdir/chksum.md5"
file d1 "subdir/foo.txt" r"subdir/foo.txt"
dir d1 "subdir/nested" r"subdir/nested"
dir d1 "subdir/other" r"subdir/other"
stop d1
start d2
file d2 "subdir/other/chksms.md5" r"subdir/other/chksms.md5"
file d2 "subdir/other/file.txt" r"subdir/other/file.txt"
stop d2
start d2
file d2 "subdir/nested/bar.txt" r"subdir/nested/bar.txt"
dir d2 "subdir/nested/nested" r"subdir/nested/nested"
file d2 "subdir/nested/vid.mov" r"subdir/nested/vid.mov"
stop d2
start d3
file d3 "subdir/nested/nested/cgi.bin" r"subdir/nested/nested/cgi.bin"
file d3 "subdir/nested/nested/chksum.md5" r"subdir/nested/nested/chksum.md5"
stop d3
start d1
file d1 "abc/boo.txt" r"abc/boo.txt"
file d1 "abc/other.txt" r"abc/other.txt"
stop d1"#
        );
    }

    #[test]
    fn int_file_tree_no_filter() {
        let test_path = setup_ftree();
        let mut file_tree = FileTree::new(&test_path).unwrap();
        let file_handles = gather_into_file_tree(&test_path, &mut file_tree, |_| true).unwrap();
        let str = to_file_list(&file_tree);
        assert_eq!(
            str,
            "FileTree{
  file.txt
  subdir/chksum.md5
  subdir/foo.txt
  subdir/nested/bar.txt
  subdir/nested/nested/cgi.bin
  subdir/nested/nested/chksum.md5
  subdir/nested/vid.mov
  subdir/other/chksms.md5
  subdir/other/file.txt
  vid.mp4
}"
        );

        assert_eq!(
            file_handles_to_file_list(&file_tree, &file_handles),
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
vid.mp4"
        );
    }

    #[test]
    fn filter_extension() {
        let test_path = setup_ftree();
        let mut file_tree = FileTree::new(&test_path).unwrap();
        let file_handles = gather_into_file_tree(&test_path, &mut file_tree, |e| {
            // NOTE: Path::ends_with matches the whole final component,
            //       so including the filename
            //       -> use extension or str::ends_with
            e.is_directory || e.dir_entry.path().to_string_lossy().ends_with(".md5")
        })
        .unwrap();
        let str = to_file_list(&file_tree);
        assert_eq!(
            str,
            "FileTree{
  subdir/chksum.md5
  subdir/nested/nested/chksum.md5
  subdir/other/chksms.md5
}"
        );
        assert_eq!(
            file_handles_to_file_list(&file_tree, &file_handles),
            "\
subdir/chksum.md5
subdir/nested/nested/chksum.md5
subdir/other/chksms.md5"
        );
    }

    #[test]
    fn filter_dir() {
        let test_path = setup_ftree();
        let mut file_tree = FileTree::new(&test_path).unwrap();
        let file_handles = gather_into_file_tree(&test_path, &mut file_tree, |e| {
            // NOTE: Path::ends_with matches the whole final component,
            //       so including the filename
            //       -> use extension or str::ends_with
            !e.is_directory || !e.dir_entry.path().ends_with("other")
        })
        .unwrap();
        let str = to_file_list(&file_tree);
        assert_eq!(
            str,
            "FileTree{
  file.txt
  subdir/chksum.md5
  subdir/foo.txt
  subdir/nested/bar.txt
  subdir/nested/nested/cgi.bin
  subdir/nested/nested/chksum.md5
  subdir/nested/vid.mov
  vid.mp4
}"
        );
        assert_eq!(
            file_handles_to_file_list(&file_tree, &file_handles),
            "\
file.txt
subdir/chksum.md5
subdir/foo.txt
subdir/nested/bar.txt
subdir/nested/nested/cgi.bin
subdir/nested/nested/chksum.md5
subdir/nested/vid.mov
vid.mp4"
        );
    }

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
    fn create_ftree_test() {
        use std::fs::exists;

        let test_path = testdir!();
        create_ftree(
            test_path.as_ref(),
            "file.txt
            vid.mp4
            subdir/foo.txt
            subdir/nested/bar.txt
            subdir/nested/vid.mov",
        );

        assert!(exists(test_path.join("file.txt")).unwrap());
        assert!(exists(test_path.join("vid.mp4")).unwrap());
        assert!(exists(test_path.join("subdir/foo.txt")).unwrap());
        assert!(exists(test_path.join("subdir/nested/bar.txt")).unwrap());
        assert!(exists(test_path.join("subdir/nested/vid.mov")).unwrap());
    }

    fn setup_dir_gather_filtered() -> std::path::PathBuf {
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
    fn gather_filtered_respects_filter() {
        let root = setup_dir_gather_filtered();
        let filter = PathMatcherBuilder::new()
            .block("bar/baz/")
            .unwrap()
            .allow("**/*.foo")
            .unwrap()
            .allow("**/*.txt")
            .unwrap()
            .build()
            .unwrap();

        let mut visited = vec![];
        let iter = filtered(&root, &filter, |e| {
            // NOTE: IMPRORTANT! need to return the reversed, since it's used
            //       to determine whether to descent into e.entry
            !e.ignored
        });

        for v in iter {
            match v {
                Ok(VisitType::File(v)) => {
                    visited.push((v.relative_to_root, v.entry.path()));
                },
                Ok(VisitType::Directory(v)) => {
                    visited.push((v.relative_to_root, v.entry.path()));
                },
                Err(_) => assert!(false),
                _ => {},
            }
        }
        assert_eq!(
            visited,
            vec! {
                (path::PathBuf::from("bar"), root.join("bar")),
                (path::PathBuf::from("foo"), root.join("foo")),
                (path::PathBuf::from("foo/bar"), root.join("foo/bar")),
                (path::PathBuf::from("foo/foo.txt"), root.join("foo/foo.txt")),
                (path::PathBuf::from("foo/bar/baz"), root.join("foo/bar/baz")),
                (path::PathBuf::from("foo/bar/baz/file.txt"), root.join("foo/bar/baz/file.txt")),
                (path::PathBuf::from("bar/baz_2025-06-28.foo"), root.join("bar/baz_2025-06-28.foo")),
                (path::PathBuf::from("bar/other.txt"), root.join("bar/other.txt")),

            }
        );
    }

    #[test]
    fn gather_filtered_respects_dirs_ignored_by_visit_func() {
        let root = setup_dir_gather_filtered();
        let filter = PathMatcherBuilder::new().build().unwrap();

        let mut visited = vec![];
        let iter = filtered(&root, &filter, |e| {
            // NOTE: !IMPRORTANT! need to return the reversed, since it's used
            //       to determine whether to descent into e.entry
            if e.ignored {
                return false;
            }

            println!("visit {:?}", e.entry.relative_to_root);
            if e.entry.is_directory {
                // only "./bar" is descended into
                e.entry.relative_to_root == path::Path::new("bar")
            } else {
                true
            }
        });

        for v in iter {
            match v {
                Ok(VisitType::File(v)) => {
                    visited.push((v.relative_to_root, v.entry.path()));
                },
                Ok(VisitType::Directory(v)) => {
                    visited.push((v.relative_to_root, v.entry.path()));
                },
                Err(_) => assert!(false),
                _ => {},
            }
        }

        assert_eq!(
            visited,
            // NOTE: dirs foo, bar/baz are visited by the predicate, but
            //       not returned by the iterator, since they're ignored
            vec! {
                (path::PathBuf::from("bar"), root.join("bar")),
                (path::PathBuf::from("file.rs"), root.join("file.rs")),
                (path::PathBuf::from("root.mp4"), root.join("root.mp4")),
                (path::PathBuf::from("bar/baz_2025-06-28.foo"), root.join("bar/baz_2025-06-28.foo")),
                (path::PathBuf::from("bar/other.txt"), root.join("bar/other.txt")),

            }
        );
    }

    #[test]
    fn gather_filtered_respects_predicate_override() {
        let root = setup_dir_gather_filtered();
        let filter = PathMatcherBuilder::new()
            .block("bar/baz/")
            .unwrap()
            .allow("**/*.foo")
            .unwrap()
            .allow("**/*.txt")
            .unwrap()
            .build()
            .unwrap();

        let mut visited = vec![];
        let mut at_least_one_ignored = false;
        let iter = filtered(&root, &filter, |e| {
            if e.ignored {
                at_least_one_ignored = true;
                true
            } else {
                false
            }
        });

        for v in iter {
            match v {
                Ok(VisitType::File(v)) => {
                    visited.push((v.relative_to_root, v.entry.path()));
                },
                Ok(VisitType::Directory(v)) => {
                    visited.push((v.relative_to_root, v.entry.path()));
                },
                Err(_) => assert!(false),
                _ => {},
            }
        }

        assert!(at_least_one_ignored);

        assert_eq!(
            visited,
            vec! {
                (path::PathBuf::from("file.rs"), root.join("file.rs")),
                (path::PathBuf::from("root.mp4"), root.join("root.mp4")),
            }
        );
    }
}
