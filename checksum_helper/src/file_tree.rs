use std::path::{Path, PathBuf};
use std::fmt::Display;
use std::ffi::OsStr;

#[derive(Clone, Debug)]
pub struct FileTree {
    nodes: Vec<Entry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    PathNotValid,
    NotASubpathOfFileTreeRoot,
    NonCanoncialPath,
}

fn is_valid(path: impl AsRef<Path>) -> bool {
    // NOTE: Path.iter()/components() does some normalization itself
    //       -> need to use the OsStr directly
    if let Some(path) = path.as_ref().to_str() {
        path.split(|c: char| c == '/' || c == '\\')
            .enumerate()
            // allow . as the first path component
            .all(|(i, p)| (i == 0 || p != ".") && p != ".." )
    } else {
        // not valid unicode
        false
    }
}

/// Considers a path as "absolute" as soon as it's not considered relative to
/// the "current" directory
/// WARNING: Also considers `C:` as absoulte, even on Unixes
pub fn is_absolute(path: impl AsRef<Path>) -> bool {
    // NOTE: not using path.starts_with for / or \\, since it works
    //       on logical paths and would not count the \\? etc. prefixes
    let mut os = path.as_ref().as_os_str().as_encoded_bytes().iter();
    match os.next() {
        Some(b'c'..=b'z') | Some(b'C'..=b'Z') => {
            if os.next() == Some(&b':') {
                return true;
            }
        },
        Some(b'\\') | Some(b'/') => return true,
        _ => {}
    }

    false
}

impl FileTree {
    /// `root` must be a canonical unicode-encodable path, which means that it cannot
    /// contain any `.` or `..` components
    /// `root` is not canonicalized by this method, since otherwise
    /// we could not represent roots that do not currently exist on the
    /// system
    pub fn new() -> FileTree {
        FileTree {
            nodes: vec!(Entry{
                name: PathBuf::new(),
                is_directory: true,
                parent: None,
                children: vec!(),
            }),
        }
    }

    pub fn entry(&self, entry: &EntryHandle) -> Entry {
        self.nodes[entry.0].clone()
    }

    pub fn relative_path(&self, entry: &EntryHandle) -> PathBuf {
        let mut p = &self.nodes[entry.0];
        // TODO store handles not pathbufs
        let mut entries = vec!(&p.name);
        while let Some(ph) = &p.parent {
            let parent = &self.nodes[ph.0];
            entries.push(&parent.name);
            p = parent;
        }

        entries.iter().rev().fold(PathBuf::new(), |acc, e| {
            acc.join(e)
        })
    }

    /// Find the last existing node that is involved in `path`.
    /// Returns None if `path` is not a subpath of the file tree's root
    // TODO: @Perf can be sped up by having some type of (LRU) cache
    fn find_last_existing(&self, path: impl AsRef<Path>) -> (EntryHandle, bool) {
        let path = path.as_ref();
        assert!(path.is_relative(), "Only relative paths are allowed!");

        let mut current = 0 as usize;
        let mut full_match = true;
        for component_name in path.iter() {
            if component_name == "." {
                continue
            }
            assert!(component_name != "..", "Path must not contain pardir elements!");

            let entry = &self.nodes[current];
            let mut found = false;
            for child_handle in &entry.children {
                let child = &self.nodes[child_handle.0];
                if child.name == *component_name {
                    current = child_handle.0;
                    found = true;
                    break;
                }
            }

            if !found {
                full_match = false;
                break;
            }
        }

        (EntryHandle{0: current}, full_match)
    }

    pub fn find(&self, path: impl AsRef<Path>) -> Option<EntryHandle> {
        let path = path.as_ref();
        let (handle, full_match) = self.find_last_existing(path);
        if full_match {
            Some(handle)
        } else {
            None
        }
    }

    pub fn add(&mut self, path: impl AsRef<Path>, is_directory: bool) -> Result<EntryHandle, ErrorKind> {
        let path = path.as_ref();
        assert!(path.is_relative(), "Only relative paths are allowed!");

        let (last_existing, _) = self.find_last_existing(path);
        let prefix = self.relative_path(&last_existing);
        let remaining = path.strip_prefix(prefix)
            .expect("BUG: path must be prefixed by the path of the last existing node");
        let mut current_parent = last_existing;
        for component_name in remaining {
            if component_name == "." {
                continue
            } else if component_name == ".." {
                return Err(ErrorKind::NonCanoncialPath);
            }
            self.nodes.push(Entry{
                name: component_name.into(),
                is_directory: true,
                parent: Some(current_parent.clone()),
                children: vec!(),
            });
            let index = self.nodes.len() - 1;

            self.nodes[current_parent.0].children.push(EntryHandle{0: index});

            current_parent = EntryHandle{0: index};
        }

        self.nodes[current_parent.0].is_directory = is_directory;
        Ok(current_parent)
    }

    pub fn add_child(&mut self, parent: &EntryHandle, child_name: impl AsRef<OsStr>, is_directory: bool) -> EntryHandle {
        let child_name = child_name.as_ref();

        for child_handle in &self.nodes[parent.0].children {
            let entry = &self.nodes[child_handle.0];
            if entry.name == child_name {
                return child_handle.clone();
            }
        }

        // TODO child_name validation, must not contain path separators etc.
        self.nodes.push(Entry{
            name: child_name.into(),
            is_directory,
            parent: Some(parent.clone()),
            children: vec!(),
        });
        let index = self.nodes.len() - 1;

        self.nodes[parent.0].children.push(EntryHandle{0: index});

        EntryHandle{0: index}
    }

    pub fn root(&self) -> EntryHandle {
        EntryHandle{0: 0}
    }

    pub fn len(&self) -> usize { self.nodes.len() }
    // TODO remove
    pub fn cap(&self) -> usize { self.nodes.capacity() }

    pub fn iter<'a>(&'a self) -> FileTreeIter<'a> {
        FileTreeIter{
            file_tree: self,
            stack: vec!((EntryHandle{0: 0}, 0)),
        }
    }
}

impl Display for FileTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FileTree{{\n")?;
        for entry_handle in self.iter() {
            // NOTE: debug formatting {:?} will use escaping if chars would
            //       need it in a string literal,
            //       use .display directly, which is lossy if the path
            //       is not valid unicode
            write!(f, "  {}\n", self.relative_path(&entry_handle).display())?;
        }
        write!(f, "}}")
    }
}

pub struct FileTreeIter<'a> {
    file_tree: &'a FileTree,
    // dir, next child index
    stack: Vec<(EntryHandle, usize)>,
}

impl <'a>Iterator for FileTreeIter<'a> {
    type Item = EntryHandle;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(curr) = self.stack.pop() {
            let entry = &self.file_tree.nodes[curr.0.0];
            if curr.1 >= entry.children.len() {
                continue;
            }

            let child = entry.children[curr.1].clone();
            let child_entry = &self.file_tree.nodes[child.0];

            self.stack.push((curr.0, curr.1 + 1));
            if !child_entry.children.is_empty() {
                assert!(child_entry.is_directory, "Has children, but is_directory is false");
                self.stack.push((child.clone(), 0));
            }

            if child_entry.is_directory {
                continue;
            } else {
                return Some(child)
            }
        }

        None
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct EntryHandle(usize);

// TODO is_dir
#[derive(Debug, Clone)]
pub struct Entry {
    name: PathBuf,
    is_directory: bool,
    parent: Option<EntryHandle>,
    children: Vec<EntryHandle>,
}

#[cfg(test)]
mod test {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn test_is_valid() {
        assert!(!is_valid(&Path::new("/tmp/../other")));
        assert!(!is_valid(&Path::new("/tmp/./other")));
        assert!(!is_valid(&Path::new("/tmp/other/../foo")));

        unsafe {
            assert!(!is_valid(&OsStr::from_encoded_bytes_unchecked(b"\x80\xb8\xff")));
        }

        assert!(is_valid(&Path::new("/tmp/foo/bar/baz/file.txt")));
        assert!(is_valid(&Path::new("/tmp/.hidden/other")));
        assert!(is_valid(&Path::new("/tmp/..other/foo")));
        assert!(is_valid(&Path::new(".")));
        assert!(is_valid(&Path::new("./")));
        assert!(is_valid(&Path::new("./tmp/other")));
        assert!(is_valid(&Path::new(".\\")));
        assert!(is_valid(&Path::new(".\\tmp\\other")));
    }

    #[test]
    fn test_is_absolute() {
        assert!(is_absolute(Path::new("/tmp/foo")));
        assert!(is_absolute(Path::new("/")));
        assert!(is_absolute(Path::new("\\")));
        assert!(is_absolute(Path::new("\\\\?\\")));
        assert!(is_absolute(Path::new("C:\\windwos")));
        assert!(is_absolute(Path::new("C:")));
        assert!(is_absolute(Path::new("d:")));
        assert!(is_absolute(Path::new("d:\\")));
        assert!(is_absolute(Path::new("D:")));
        assert!(is_absolute(Path::new("D:\\")));
        assert!(is_absolute(Path::new("z:\\")));

        assert!(!is_absolute(Path::new("tmp")));
        assert!(!is_absolute(Path::new("tmp/")));
        assert!(!is_absolute(Path::new("tmp\\")));
        assert!(!is_absolute(Path::new("./tmp")));
        assert!(!is_absolute(Path::new(".\\tmp")));
        assert!(!is_absolute(Path::new("c")));
        assert!(!is_absolute(Path::new("C")));
    }

    #[test]
    fn test_add() {
        let mut ft = FileTree::new();
        let txt_path = Path::new("./bar/baz/file.txt");
        let txt = ft.add(txt_path, false).unwrap();
        assert_eq!(ft.relative_path(&txt), Path::new("bar").join("baz").join("file.txt"));

        let txt_entry = ft.entry(&txt);
        assert_eq!(txt_entry.name, Path::new("file.txt"));
        assert!(txt_entry.children.is_empty());
        assert_eq!(ft.find_last_existing(&txt_path).0, txt);

        let baz = ft.find_last_existing(Path::new("./bar/baz")).0;
        assert_eq!(txt_entry.parent.unwrap(), baz);
        let baz_entry = ft.entry(&baz);
        assert_eq!(baz_entry.name, Path::new("baz"));
        assert_eq!(baz_entry.children.len(), 1);
        assert_eq!(baz_entry.parent.unwrap(), ft.find_last_existing(Path::new("bar")).0);
        assert!(baz_entry.is_directory);

        let mov_path = Path::new("bar/baz/mov.mp4");
        let mov = ft.add(mov_path, false).unwrap();
        assert_eq!(ft.relative_path(&mov), mov_path);
        let mov_entry = ft.entry(&mov);
        assert_eq!(mov_entry.name, Path::new("mov.mp4"));
        assert_eq!(ft.find_last_existing(&mov_path).0, mov);

        let baz_entry = ft.entry(&baz);
        assert_eq!(baz_entry.name, Path::new("baz"));
        assert_eq!(baz_entry.children.len(), 2);
        assert_eq!(baz_entry.parent.unwrap(), ft.find_last_existing(Path::new("bar")).0);
        assert!(baz_entry.is_directory);

        let bin_path = Path::new("bar/file.bin");
        let bin = ft.add(bin_path, false).unwrap();
        assert_eq!(ft.relative_path(&bin), bin_path);
        let bin_entry = ft.entry(&bin);
        assert_eq!(bin_entry.name, Path::new("file.bin"));
        assert_eq!(ft.find_last_existing(&bin_path).0, bin);
    }

    #[test]
    #[should_panic]
    fn test_add_panic_on_absoulte_path() {
        let mut ft = FileTree::new();
        // NOTE: `is_absolute` is platform dependent, so e.g. `/tmp` is
        //       not absolute on Windows
        let txt_path = std::env::current_dir().unwrap().join(
            "foo/bar/baz/file.txt");
        let _ = ft.add(&txt_path, false);
    }

    #[test]
    fn test_add_ignores_curdir() {
        let mut ft = FileTree::new();
        let txt_path = Path::new("./bar/./baz/./file.txt");
        let txt = ft.add(txt_path, false).unwrap();

        for e in &ft.nodes {
            assert!(e.name != Path::new("."));
        }
        assert_eq!(ft.relative_path(&txt), Path::new("bar").join("baz").join("file.txt"));
    }

    #[test]
    fn test_add_adds_intermediate_dirs() {
        let mut ft = FileTree::new();
        let txt_path = Path::new("./bar/baz/file.txt");
        let txt = ft.add(txt_path, false).unwrap();
        assert_eq!(ft.relative_path(&txt), Path::new("bar").join("baz").join("file.txt"));

        let txt_entry = ft.entry(&txt);
        assert_eq!(txt_entry.name, Path::new("file.txt"));
        assert!(txt_entry.children.is_empty());
        assert_eq!(ft.find_last_existing(&txt_path).0, txt);

        let baz = ft.find_last_existing(Path::new("./bar/baz")).0;
        assert_eq!(txt_entry.parent.unwrap(), baz);
        let baz_entry = ft.entry(&baz);
        assert_eq!(baz_entry.name, Path::new("baz"));
        assert_eq!(baz_entry.children.len(), 1);
        assert_eq!(baz_entry.parent.unwrap(), ft.find_last_existing(Path::new("bar")).0);
        assert!(baz_entry.is_directory);
    }

    #[test]
    fn test_add_reuses_dir_entries() {
        let mut ft = FileTree::new();

        let txt = ft.add(
            Path::new("./bar/baz/file.txt"), false).unwrap();
        let txt_entry = ft.entry(&txt);

        let two = ft.add(
            Path::new("bar/baz/foo/xer.txt"), false).unwrap();
        let two_entry = ft.entry(&two);

        let foo = ft.find_last_existing(Path::new("bar/baz/foo")).0;
        let foo_entry = ft.entry(&foo);
        assert_eq!(two_entry.parent, Some(foo.clone()));

        let baz = ft.find_last_existing(Path::new("./bar/baz")).0;
        let baz_entry = ft.entry(&baz);
        assert!(baz_entry.is_directory);

        assert_eq!(baz_entry.children.len(), 2);
        assert!(baz_entry.children.contains(&txt));
        assert!(baz_entry.children.contains(&foo));

        assert_eq!(txt_entry.parent, Some(baz.clone()));
        assert_eq!(foo_entry.parent, Some(baz.clone()));
    }

    #[test]
    fn test_add_returns_entry_if_present() {
        let mut ft = FileTree::new();

        let txt = ft.add(
            Path::new("./bar/baz/file.txt"), false).unwrap();
        assert_eq!(txt, ft.add("bar/baz/file.txt", false).unwrap());
        assert_eq!(txt, ft.add("bar/baz/file.txt", false).unwrap());
    }

    #[test]
    fn test_add_child_returns_entry_if_present() {
        let mut ft = FileTree::new();

        let dir = ft.add("./bar/baz", true)
            .unwrap();

        let txt = ft.add_child(
            &dir, "file.txt", false);
        assert_eq!(txt, ft.add_child(&dir, "file.txt", false));
        assert_eq!(txt, ft.add_child(&dir, "file.txt", false));
    }

    #[test]
    fn test_add_errors_when_pardir_path() {
        let mut ft = FileTree::new();
        let txt_path = Path::new("bar/baz/../file.txt");
        assert_eq!(ft.add(txt_path, false), Err(ErrorKind::NonCanoncialPath));
    }
}
