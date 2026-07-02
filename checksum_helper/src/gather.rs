use crate::pathmatcher::PathMatcher;

use std::fmt;
use std::fs;
use std::iter::Iterator;
use std::path;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub enum Error {
    ReadDirectory((path::PathBuf, Box<str>, std::io::ErrorKind)),
    ReadFileInfo((path::PathBuf, Box<str>, std::io::ErrorKind)),
    Iteration(Box<str>, std::io::ErrorKind),
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
    pub entry: StoredEntry,
    pub relative_to_root: path::PathBuf,
}

#[derive(Debug, Clone)]
pub struct StoredEntry {
    pub path: path::PathBuf,
    pub ty: fs::FileType,
    pub depth: u32,
}

impl StoredEntry {
    // File name of the path or the whole path if it doesn't have a filename.
    // E.g. { path: "/" }.file_name() -> "/"
    #[cfg(test)]
    pub fn file_name(&self) -> &std::ffi::OsStr {
        self.path.file_name().unwrap_or_else(|| self.path.as_os_str())
    }
}

pub enum VisitType {
    #[allow(dead_code)]
    ListDirStart(u32),
    #[allow(dead_code)]
    ListDirStop(u32),
    #[allow(dead_code)]
    Directory(VisitData),
    File(VisitData),
    SpecialFile((path::PathBuf, std::fs::FileType)),
}

pub struct Entry<'a> {
    /// Depth relative to the root, where 0 => in root directory,
    /// 1 => one directory down from root
    pub depth: u32,
    pub is_directory: bool,
    pub file_type: std::fs::FileType,
    pub path: &'a path::Path,
    /// Path relative to the start path passed into [`Gather::new`]
    pub relative_to_root: &'a path::Path,
}

struct StackEntry {
    depth: u32,
    // next idx to visit in entries
    // None -> directory not "started" yet
    next_idx: Option<usize>,
    // sorted entries of the directory
    entries: Vec<Result<StoredEntry>>,
}

/// Visits directories in DFS order, where children are sorted lexically:
/// ./file.txt
/// ./foo/
/// ./foo/bar.txt
/// ./bar/
/// ./bar/baz/
/// ./bar/baz/vid.mp4
/// ./bar/file.txt
/// ./xer.bin
///
/// **Note**: Symlinks to directories are NOT followed!
pub struct Gather<P> {
    predicate: P,
    root: path::PathBuf,
    directory_stack: Vec<StackEntry>,
}

impl<P> Gather<P>
where
    P: FnMut(Entry) -> bool,
{
    pub fn new(start: impl AsRef<path::Path>, predicate: P) -> Result<Self> {
        let root = start.as_ref().to_owned();
        Ok(Gather {
            predicate,
            directory_stack: vec![StackEntry {
                depth: 0,
                next_idx: None,
                entries: Self::dir_entries(0, start)?,
            }],
            root,
        })
    }

    /// depth: new depth of the returned entries of [`directory`]
    fn dir_entries(depth: u32, directory: impl AsRef<path::Path>) -> Result<Vec<Result<StoredEntry>>> {
        let directory = directory.as_ref();
        // NOTE: for dfs stable order: extract what we need to
        //       restore dfs state when popping the stack
        //       if we keep the DirEntry around it'd be holding
        //       onto one file handle per depth level
        let dir = fs::read_dir(directory).map_err(|e| {
            Error::ReadDirectory((
                    directory.to_owned(),
                    format!("{}", e).into_boxed_str(),
                    e.kind(),
            ))
        })?;

        // NOTE: we could return on first error, but that would break pretty
        //       quickly when trying to checksum certain paths.
        //       instead, keep the error and give that as iterator item
        let mut entries: Vec<Result<StoredEntry>> = dir
            .map(|entry| {
                let d = entry.map_err(|e| Error::Iteration(format!("{:?}", e).into_boxed_str(), e.kind()))?;
                let ft = d.file_type().map_err(|e| {
                    Error::ReadFileInfo((
                        d.path(),
                        format!("{:?}", e).into_boxed_str(),
                        e.kind(),
                    ))
                })?;

                Ok(StoredEntry{
                    path: d.path(),
                    ty: ft,
                    depth,
                })
            })
            .collect();

        // Sort lexically by path preserving errors
        entries.sort_by(|a, b| match (a, b) {
            (Ok(a), Ok(b)) => a.path.cmp(&b.path),
            (Err(_), Err(_)) => std::cmp::Ordering::Equal,
            (Ok(_), Err(_)) => std::cmp::Ordering::Greater,
            (Err(_), Ok(_)) => std::cmp::Ordering::Less,
        });

        Ok(entries)
    }

    fn next_dir_entry(&mut self) -> Option<Result<VisitType>> {
        // TODO: also emit ignored items, then we don't need the loop and callbacks become easier
        loop {
            let current = {
                let StackEntry { depth, next_idx, entries } = self.directory_stack.last_mut()?;

                match next_idx {
                    Some(next_idx) => {
                        if *next_idx == entries.len() {
                            let finished_dir = self.directory_stack.pop()
                                .expect("checked above");
                            return Some(Ok(VisitType::ListDirStop(finished_dir.depth)));
                        }

                        let current_idx = *next_idx;
                        *next_idx += 1;
                        entries[current_idx].clone()
                    }
                    None => {
                        *next_idx = Some(0);
                        return Some(Ok(VisitType::ListDirStart(*depth)));
                    }
                }
            };

            let iter_item = match current {
                Ok(c) => {
                    let is_dir = c.ty.is_dir();
                    let relative_to_root = c
                        .path
                        .strip_prefix(&self.root)
                        .expect("paths under root must be relative to root")
                        .to_owned();

                    if !(self.predicate)(Entry {
                        depth: c.depth,
                        is_directory: is_dir,
                        file_type: c.ty,
                        path: &c.path,
                        relative_to_root: &relative_to_root,
                    }) {
                        continue;
                    }

                    if is_dir {
                        match Self::dir_entries(c.depth + 1, &c.path) {
                            Ok(entries) => {
                                self.directory_stack.push(
                                    StackEntry{
                                        depth: c.depth + 1,
                                        next_idx: None,
                                        entries,
                                    }
                                );
                            },
                            Err(e) => return Some(Err(e)),
                        }

                        Ok(VisitType::Directory(VisitData {
                            entry: c.clone(),
                            relative_to_root,
                        }))
                    } else if c.ty.is_file() {
                        Ok(VisitType::File(VisitData {
                            entry: c.clone(),
                            relative_to_root,
                        }))
                    } else {
                        Ok(VisitType::SpecialFile((c.path.clone(), c.ty)))
                    }
                },
                Err(e) => return Some(Err(e.clone()))
            };

            return Some(iter_item);
        }
    }
}

impl<P> Iterator for Gather<P>
where
    P: FnMut(Entry) -> bool,
{
    type Item = Result<VisitType>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_dir_entry()
    }
}

pub struct FilteredEntry<'a> {
    pub entry: Entry<'a>,
    /// Whether the entry was ignored by [`GatherFiltered::filter`]
    /// or if it was ignored due to being a special file.
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
) -> Result<Gather<impl FnMut(Entry) -> bool + 'a>>
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
        } else if !e.file_type.is_file() {
            // NOTE: better handling for symlinks and other special files:
            //      we will only visit regular files by default, but notify
            //      about skipped files!
            //
            //      options:
            //      - skip non-regular files
            //        - scorch: skips non-regular files
            //        - `find ./foo/ -type f -print0 | xargs -0 sha1sum`
            //          also skips non-regular files
            //      - follow the symlink for files, record error for faulty links
            //        - is confusing, since we don't follow links to directories
            //          and doing that would be a completely different rabbit hole
            //        - also most tools don't follow symlinks when copying by
            //          default, e.g. rsync BUT cp does follow BUT only
            //          in file, not directory-mode :/
            //      - hash the contents of a symlink
            //        - would lead to confusing results for links that point
            //          to the same path, but different contents depending
            //          on the environment
            //      - record the symlink itself as a special entry
            //        - same drawback as hashing the link contents
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
    use crate::file_tree::{EntryHandle, FileTree};
    use crate::{pathmatcher::PathMatcherBuilder, test_utils::*};
    use pretty_assertions::assert_eq;

    fn gather_into_file_tree<F>(
        file_tree: &mut FileTree,
        include_fn: F,
    ) -> Result<Vec<EntryHandle>>
    where
        F: FnMut(Entry) -> bool,
    {
        // in case the file_tree wasn't empty we need a way to just iterate the files
        // that were gathered into the file_tree, without the previously existing ones
        let mut result_handles = vec![];

        let mut directories = vec![file_tree.root()];
        let mut handle = file_tree.root();
        let iter = Gather::new(file_tree.absolute_path(&handle), include_fn).unwrap();

        for visit_type in iter {
            match visit_type {
                Ok(VisitType::ListDirStart(_)) => {
                    handle = directories
                        .pop()
                        .expect("there should be a directory queued");
                }
                Ok(VisitType::ListDirStop(_)) => {
                    handle = file_tree.parent(&handle);
                }
                Ok(VisitType::Directory(v)) => {
                    let new_handle = file_tree.add_child(&handle, v.entry.file_name(), true);
                    directories.push(new_handle);
                }
                Ok(VisitType::File(v)) => {
                    let handle = file_tree.add_child(&handle, v.entry.file_name(), false);
                    result_handles.push(handle);
                }
                Err(e) => return Err(e),
                _ => {}
            }
        }

        Ok(result_handles)
    }

    // fn memsize() -> std::io::Result<String> {
    //     use std::fs::File;
    //     use std::io::{BufRead, BufReader};

    //     let pid = std::process::id();
    //     let path = format!("/proc/{}/smaps", pid);

    //     let file = File::open(path)?;
    //     let reader = BufReader::new(file);

    //     let mut total_kb: u64 = 0;

    //     for line in reader.lines() {
    //         let line = line?;

    //         if line.starts_with("Pss:") {
    //             // Format: "Pss:   123 kB"
    //             if let Some(value) = line.split_whitespace().nth(1) {
    //                 if let Ok(kb) = value.parse::<u64>() {
    //                     total_kb += kb;
    //                 }
    //             }
    //         }
    //     }

    //     Ok(format!("{:.6} KB", total_kb))
    // }

    // TODO change filetree: the tree-like storage is not worh it,
    //      as seen below. Either just use full paths
    //      or
    //
    //      full tree-like instead of storing children
    //
    //      type NodeId = u32;
    //
    //      struct Node {
    //          parent: Option<NodeId>,
    //          name: NameId,              // interned or arena-stored component
    //          is_directory: bool,
    //          first_child: Option<NodeId>,
    //          next_sibling: Option<NodeId>,
    //      }
    //      struct Arena {
    //          nodes: Vec<Node>,
    //          names: Vec<std::ffi::OsString>,
    //          // optional: map OsString -> NameId for dedup
    //      }
    //
    //      mb first try
    //
    //      pub struct EntryHandle(u32);  // from usize
    //
    //      pub struct Entry {
    //          name: std::ffi::OsString,          // not PathBuf if this is one component
    //          is_directory: bool,
    //          parent: Option<EntryHandle>,
    //          children: Vec<EntryHandle>,        // no repeated names here
    //                                             // had that, was pretty slow due to lookup
    //      }
    //
    //      or try interning the names
    //
    // name: NameId
    // children: Vec<(NameId, EntryHandle)>
    // path
    // Files: 139356, PathsSum: 13772965
    // SIZE: 29226 KB
    // ftree
    // Files: 139356, PathsSum: 15475991
    // SIZE: 36506 KB

    // path
    // Files: 319966, PathsSum: 37396172
    // SIZE: 74302 KB
    // ft
    // Files: 319966, PathsSum: 109877724
    // SIZE: 77481 KB

    // path
    // Files: 1428201, PathsSum: 98463154
    // SIZE: 204929 KB
    // ft
    // Files: 1425530, PathsSum: 6438979976  (<- possible bug in gather_into_file_tree)
    // SIZE: 302157 KB
    // path
    // Files: 1422137, PathsSum: 98261527
    // SIZE: 204253 KB
    // ft (using gather directly, no gather_into_file_tree)
    // Files: 1422565, PathsSum: 98275256
    // SIZE: 301865 KB
    //
    // NOTE: forgot that we'd have to store the path twice, once as map key
    //       and on the HashedFile the second time.
    //
    // path (2x stored, map as k+v)
    // Files: 1581326, PathsSum: 105984310
    // SIZE: 411544 KB
    // ft (2x stored, map as k+v just handle, rest in ft)
    // Files: 1580506, PathsSum: 105957110
    // SIZE: 366588 KB
    //
    // => this still means FileTree is not the right abstraction: would be better
    //    to "intern" the strings and refer to them with handles
    //    like: Vec<PathBuf> and type PathId = u32;
    //    -> use PathId as map key and in HashedFile
    //       (may not work since we need the path->id and id->path lookup :/)
    // TODO benchmark FileTree vs storing full paths vs interning

    // fn include_mem(e: Entry) -> bool {
    //     let path = e.path;
    //     let valid_prefixes = [
    //         "/home",
    //         "/tmp",
    //         "/usr",
    //         "/etc",
    //         "/mnt",
    //         "/opt",
    //         "/proc",
    //     ];
    //     if valid_prefixes.iter().any(|p| path.starts_with(p)) {
    //         return true;
    //     }

    //     false
    // }

    // #[test]
    // fn _file_tree_mem_usage() {
    //     let root = std::path::Path::new("/");
    //     let mut ft = FileTree::new(root).unwrap();
    //     let iter = Gather::new(root, include_mem).unwrap();

    //     use std::collections::HashMap;
    //     let mut map = HashMap::new();
    //     for visit_type in iter {
    //         match visit_type {
    //             Ok(VisitType::File(v)) => {
    //                 let path = v.entry.path;
    //                 let path = path.strip_prefix("/").unwrap();
    //                 let handle = ft.add_file(path).unwrap();
    //                 map.insert(handle.clone(), handle.clone());
    //             }
    //             Err(e) => println!("err: {}", e),
    //             _ => {}
    //         }
    //     }

    //     let size = memsize().unwrap();

    //     let mut files = 0;
    //     let mut pathlensum = 0;
    //     for f in ft.iter() {
    //         let path = ft.absolute_path(&f);
    //         // println!("{:?}", path);
    //         files += 1;
    //         pathlensum += path.to_string_lossy().len();
    //     }

    //     println!("Files: {}, PathsSum: {}", files, pathlensum);
    //     println!("SIZE: {}", size);

    //     panic!()
    // }

    // #[test]
    // fn _path_memusage() {
    //     let iter = Gather::new("/", include_mem).unwrap();

    //     use std::collections::HashMap;
    //     let mut map = HashMap::new();
    //     for visit_type in iter {
    //         match visit_type {
    //             Ok(VisitType::File(v)) => {
    //                 let path = v.entry.path;
    //                 map.insert(path.clone(), path);
    //             }
    //             Err(e) => println!("err: {}", e),
    //             _ => {}
    //         }
    //     }

    //     let size = memsize().unwrap();

    //     let mut files = 0;
    //     let mut pathlensum = 0;
    //     for (p, _) in map {
    //         files += 1;
    //         pathlensum += p.to_string_lossy().len();
    //         // println!("{:?}", p);
    //     }

    //     println!("Files: {}, PathsSum: {}", files, pathlensum);
    //     println!("SIZE: {}", size);

    //     panic!()
    // }

    #[test]
    fn gather_visit_no_filter() {
        let test_path = setup_ftree();
        create_ftree(
            test_path.as_ref(),
            "abc/other.txt
             abc/boo.txt",
        );

        let mut visits = vec![];
        let gather = Gather::new(&test_path, |_| true).unwrap();
        for v in gather {
            let v = v.unwrap();
            match v {
                VisitType::ListDirStart(d) => visits.push(format!("start d{}", d)),
                VisitType::ListDirStop(d) => visits.push(format!("stop d{}", d)),
                VisitType::File(v) => visits.push(format!(
                    "file d{} {:?} r{:?}",
                    v.entry.depth,
                    v.entry
                        .path
                        .strip_prefix(&test_path)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace("\\", "/"),
                    v.relative_to_root.to_str().unwrap().replace('\\', "/"),
                )),
                VisitType::Directory(v) => visits.push(format!(
                    "dir d{} {:?} r{:?}",
                    v.entry.depth,
                    v.entry
                        .path
                        .strip_prefix(&test_path)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace("\\", "/"),
                    v.relative_to_root.to_str().unwrap().replace('\\', "/"),
                )),
                VisitType::SpecialFile(_) => unreachable!("no special files expected")
            }
        }
        let actual = visits.join("\n");
        println!("actual:\n{}", actual);

        let order_dfs =
r#"start d0
dir d0 "abc" r"abc"
start d1
file d1 "abc/boo.txt" r"abc/boo.txt"
file d1 "abc/other.txt" r"abc/other.txt"
stop d1
file d0 "file.txt" r"file.txt"
dir d0 "subdir" r"subdir"
start d1
file d1 "subdir/chksum.md5" r"subdir/chksum.md5"
file d1 "subdir/foo.txt" r"subdir/foo.txt"
dir d1 "subdir/nested" r"subdir/nested"
start d2
file d2 "subdir/nested/bar.txt" r"subdir/nested/bar.txt"
dir d2 "subdir/nested/nested" r"subdir/nested/nested"
start d3
file d3 "subdir/nested/nested/cgi.bin" r"subdir/nested/nested/cgi.bin"
file d3 "subdir/nested/nested/chksum.md5" r"subdir/nested/nested/chksum.md5"
stop d3
file d2 "subdir/nested/vid.mov" r"subdir/nested/vid.mov"
stop d2
dir d1 "subdir/other" r"subdir/other"
start d2
file d2 "subdir/other/chksms.md5" r"subdir/other/chksms.md5"
file d2 "subdir/other/file.txt" r"subdir/other/file.txt"
stop d2
stop d1
file d0 "vid.mp4" r"vid.mp4"
stop d0"#;

        assert_eq!(
            actual,
            order_dfs
        );
    }

    fn normalize(root: &path::Path, path: std::path::PathBuf) -> String {
        path.strip_prefix(root)
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/")
    }

    fn setup_symlink_testdir() -> path::PathBuf {
        use std::fs;

        let test_path = testdir!();

        // --- setup -------------------------------------------------------------

        // file
        fs::write(test_path.join("file.txt"), "hello").unwrap();

        // dir
        fs::create_dir(test_path.join("dir")).unwrap();

        // symlink -> file
        #[cfg(unix)]
        std::os::unix::fs::symlink(test_path.join("file.txt"), test_path.join("link_to_file"))
            .unwrap();

        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            test_path.join("file.txt"),
            test_path.join("link_to_file"),
        )
        .unwrap();

        // symlink -> dir
        #[cfg(unix)]
        std::os::unix::fs::symlink(test_path.join("dir"), test_path.join("link_to_dir")).unwrap();

        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(test_path.join("dir"), test_path.join("link_to_dir"))
            .unwrap();

        // symlink -> symlink -> file
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            test_path.join("link_to_file"),
            test_path.join("link_to_link"),
        )
        .unwrap();

        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            test_path.join("link_to_file"),
            test_path.join("link_to_link"),
        )
        .unwrap();

        test_path
    }

    #[test]
    fn gather_handles_symlinks() {
        let test_path = setup_symlink_testdir();

        let mut visits = vec![];
        let gather = Gather::new(&test_path, |_| true).unwrap();

        for v in gather {
            let v = v.unwrap();

            match v {
                VisitType::ListDirStart(d) => visits.push(format!("start d{}", d)),
                VisitType::ListDirStop(d) => visits.push(format!("stop d{}", d)),

                VisitType::File(v) => visits.push(format!(
                    "file d{} {}",
                    v.entry.depth,
                    normalize(&test_path, v.entry.path)
                )),

                VisitType::Directory(v) => visits.push(format!(
                    "dir d{} {}",
                    v.entry.depth,
                    normalize(&test_path, v.entry.path)
                )),
                VisitType::SpecialFile((p, file_type)) => visits.push(format!(
                    "special {} islink: {}",
                    normalize(&test_path, p),
                    file_type.is_symlink()
                )),
            }
        }

        let actual = visits.join("\n");
        println!("actual:\n{}", actual);

        // --- expected ----------------------------------------------------------

        // NOTE: we output iteration entries for symlinks, but we don't
        //       traverse into symlinked directories
        let expected = r#"start d0
dir d0 dir
start d1
stop d1
file d0 file.txt
special link_to_dir islink: true
special link_to_file islink: true
special link_to_link islink: true
stop d0"#;

        assert_eq!(actual, expected);
    }

    #[test]
    fn int_file_tree_no_filter() {
        let test_path = setup_ftree();
        let mut file_tree = FileTree::new(&test_path).unwrap();
        let file_handles = gather_into_file_tree(&mut file_tree, |_| true).unwrap();
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
        let file_handles = gather_into_file_tree(&mut file_tree, |e| {
            // NOTE: Path::ends_with matches the whole final component,
            //       so including the filename
            //       -> use extension or str::ends_with
            e.is_directory || e.path.to_string_lossy().ends_with(".md5")
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
        let file_handles = gather_into_file_tree(&mut file_tree, |e| {
            // NOTE: Path::ends_with matches the whole final component,
            //       so including the filename
            //       -> use extension or str::ends_with
            !e.is_directory || !e.path.ends_with("other")
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
        }).unwrap();

        for v in iter {
            match v {
                Ok(VisitType::File(v)) => {
                    visited.push((v.relative_to_root, v.entry.path));
                }
                Ok(VisitType::Directory(v)) => {
                    visited.push((v.relative_to_root, v.entry.path));
                }
                Err(_) => assert!(false),
                _ => {}
            }
        }

        visited.sort();

        assert_eq!(
            visited,
            vec! {
                (path::PathBuf::from("bar"), root.join("bar")),
                (path::PathBuf::from("bar/baz_2025-06-28.foo"), root.join("bar/baz_2025-06-28.foo")),
                (path::PathBuf::from("bar/other.txt"), root.join("bar/other.txt")),
                (path::PathBuf::from("foo"), root.join("foo")),
                (path::PathBuf::from("foo/bar"), root.join("foo/bar")),
                (path::PathBuf::from("foo/bar/baz"), root.join("foo/bar/baz")),
                (path::PathBuf::from("foo/bar/baz/file.txt"), root.join("foo/bar/baz/file.txt")),
                (path::PathBuf::from("foo/foo.txt"), root.join("foo/foo.txt")),

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
        }).unwrap();

        for v in iter {
            match v {
                Ok(VisitType::File(v)) => {
                    visited.push((v.relative_to_root, v.entry.path));
                }
                Ok(VisitType::Directory(v)) => {
                    visited.push((v.relative_to_root, v.entry.path));
                }
                Err(_) => assert!(false),
                _ => {}
            }
        }

        visited.sort();

        assert_eq!(
            visited,
            // NOTE: dirs foo, bar/baz are visited by the predicate, but
            //       not returned by the iterator, since they're ignored
            vec! {
                (path::PathBuf::from("bar"), root.join("bar")),
                (path::PathBuf::from("bar/baz_2025-06-28.foo"), root.join("bar/baz_2025-06-28.foo")),
                (path::PathBuf::from("bar/other.txt"), root.join("bar/other.txt")),
                (path::PathBuf::from("file.rs"), root.join("file.rs")),
                (path::PathBuf::from("root.mp4"), root.join("root.mp4")),

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
        }).unwrap();

        for v in iter {
            match v {
                Ok(VisitType::File(v)) => {
                    visited.push((v.relative_to_root, v.entry.path));
                }
                Ok(VisitType::Directory(v)) => {
                    visited.push((v.relative_to_root, v.entry.path));
                }
                Err(_) => assert!(false),
                _ => {}
            }
        }

        assert!(at_least_one_ignored);

        visited.sort();

        assert_eq!(
            visited,
            vec! {
                (path::PathBuf::from("file.rs"), root.join("file.rs")),
                (path::PathBuf::from("root.mp4"), root.join("root.mp4")),
            }
        );
    }

    #[test]
    fn filtered_ignores_symlinks_by_default() {
        let test_path = setup_symlink_testdir();

        let mut had_special_file = false;
        let filter = PathMatcherBuilder::new().build().unwrap();
        let iter = filtered(&test_path, &filter, |e| {
            if !e.entry.is_directory && !e.entry.file_type.is_file() {
                assert!(e.ignored);
                had_special_file = true;
            }

            // NOTE: !IMPRORTANT! need to return the reversed, since it's used
            //       to determine whether to descent into e.entry
            if e.ignored {
                return false;
            }

            true
        }).unwrap();

        for v in iter {
            let v = v.unwrap();

            if let VisitType::SpecialFile(_) = v {
                unreachable!()
            }
        }

        assert!(had_special_file);
    }

    #[test]
    fn filtered_ignored_symlink_can_be_overridden() {
        let test_path = setup_symlink_testdir();

        let mut had_special_file_pred = false;
        let filter = PathMatcherBuilder::new().build().unwrap();
        let iter = filtered(&test_path, &filter, |e| {
            if !e.entry.is_directory && !e.entry.file_type.is_file() {
                had_special_file_pred = true;

                return true;
            }

            // NOTE: !IMPRORTANT! need to return the reversed, since it's used
            //       to determine whether to descent into e.entry
            if e.ignored {
                return false;
            }

            true
        }).unwrap();

        let mut visited_special_file = false;
        for v in iter {
            let v = v.unwrap();

            if let VisitType::SpecialFile(_) = v {
                visited_special_file = true;
            }
        }

        assert!(had_special_file_pred);
        assert!(visited_special_file);
    }
}
