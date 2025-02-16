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
}

fn is_valid(path: &impl AsRef<Path>) -> bool {
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

impl FileTree {
    /// `root` must be a canonical unicode-encodable path, which means that it cannot
    /// contain any `.` or `..` components
    /// `root` is not canonicalized by this method, since otherwise
    /// we could not represent roots that do not currently exist on the
    /// system
    pub fn new(root: &impl AsRef<Path>) -> Result<FileTree, ErrorKind> {
        if !is_valid(root) {
            return Err(ErrorKind::PathNotValid);
        }

        Ok(FileTree {
            nodes: vec!(Entry{
                name: root.as_ref().into(),
                parent: None,
                children: vec!(),
            }),
        })
    }

    pub fn entry(&self, entry: &EntryHandle) -> Entry {
        self.nodes[entry.0].clone()
    }

    pub fn path(&self, entry: &EntryHandle) -> PathBuf {
        let mut p = &self.nodes[entry.0];
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
    fn find_last_existing(&self, path: &Path) -> Option<EntryHandle> {
        let root = &self.nodes[0].name;
        if !path.starts_with(root) {
            return None;
        }

        let mut current = 0 as usize;
        for component_name in path.strip_prefix(root)
                .expect("BUG: `path` must have root as prefix").iter() {
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
                break;
            }
        }

        Some(EntryHandle{0: current})
    }

    pub fn add(&mut self, path: &Path) -> Result<EntryHandle, ErrorKind> {
        if let Some(last_existing) = self.find_last_existing(path) {
            let prefix = self.path(&last_existing);
            let remaining = path.strip_prefix(prefix)
                .expect("BUG: path must be prefixed by the path of the last existing node");
            let mut current_parent = last_existing;
            for component_name in remaining {
                self.nodes.push(Entry{
                    name: component_name.into(),
                    parent: Some(current_parent.clone()),
                    children: vec!(),
                });
                let index = self.nodes.len() - 1;

                self.nodes[current_parent.0].children.push(EntryHandle{0: index});

                current_parent = EntryHandle{0: index};
            }

            Ok(current_parent)
        } else {
            Err(ErrorKind::NotASubpathOfFileTreeRoot)
        }
    }

    pub fn add_child(&mut self, parent: &EntryHandle, child_name: &OsStr) -> EntryHandle {
        self.nodes.push(Entry{
            name: child_name.into(),
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
            write!(f, "  {:?}\n", self.path(&entry_handle))?;
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
                self.stack.push((child.clone(), 0));
            }

            return Some(child)
        }

        None
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EntryHandle(usize);

// TODO is_dir
#[derive(Debug, Clone)]
pub struct Entry {
    name: PathBuf,
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
    fn test_new_uncanonical_path() {
        assert_eq!(FileTree::new(&Path::new("/tmp/../other")).err().unwrap(), ErrorKind::PathNotValid);
        assert_eq!(FileTree::new(&Path::new("/tmp/./other")).err().unwrap(), ErrorKind::PathNotValid);
        assert_eq!(FileTree::new(&Path::new("/tmp/other/../foo")).err().unwrap(), ErrorKind::PathNotValid);
        unsafe {
            assert_eq!(FileTree::new(&Path::new(&OsStr::from_encoded_bytes_unchecked(b"\x80\xb8\xff"))).err().unwrap(), ErrorKind::PathNotValid);
        }
    }

    #[test]
    fn test_new_canonical_path() {
        assert!(FileTree::new(&Path::new("/tmp/foo/bar/baz/file.txt")).is_ok());
        assert!(FileTree::new(&Path::new("/tmp/.hidden/other")).is_ok());
        assert!(FileTree::new(&Path::new("/tmp/..other/foo")).is_ok());
    }

    #[test]
    fn test_add() {
        let mut ft = FileTree::new(&Path::new("/tmp/foo/")).unwrap();
        let txt_path = Path::new("/tmp/foo/bar/baz/file.txt");
        let txt = ft.add(txt_path).unwrap();
        assert_eq!(ft.path(&txt), txt_path);
        let txt_entry = ft.entry(&txt);
        assert_eq!(txt_entry.name, Path::new("file.txt"));
        assert!(txt_entry.children.is_empty());
        assert_eq!(ft.find_last_existing(&txt_path).unwrap(), txt);

        let baz = ft.find_last_existing(Path::new("/tmp/foo/bar/baz")).unwrap();
        assert_eq!(txt_entry.parent.unwrap(), baz);
        let baz_entry = ft.entry(&baz);
        assert_eq!(baz_entry.name, Path::new("baz"));
        assert_eq!(baz_entry.children.len(), 1);
        assert_eq!(baz_entry.parent.unwrap(), ft.find_last_existing(Path::new("/tmp/foo/bar")).unwrap());

        let mov_path = Path::new("/tmp/foo/bar/baz/mov.mp4");
        let mov = ft.add(mov_path).unwrap();
        assert_eq!(ft.path(&mov), mov_path);
        let mov_entry = ft.entry(&mov);
        assert_eq!(mov_entry.name, Path::new("mov.mp4"));
        assert_eq!(ft.find_last_existing(&mov_path).unwrap(), mov);

        let baz_entry = ft.entry(&baz);
        assert_eq!(baz_entry.name, Path::new("baz"));
        assert_eq!(baz_entry.children.len(), 2);
        assert_eq!(baz_entry.parent.unwrap(), ft.find_last_existing(Path::new("/tmp/foo/bar")).unwrap());

        let bin_path = Path::new("/tmp/foo/bar/file.bin");
        let bin = ft.add(bin_path).unwrap();
        assert_eq!(ft.path(&bin), bin_path);
        let bin_entry = ft.entry(&bin);
        assert_eq!(bin_entry.name, Path::new("file.bin"));
        assert_eq!(ft.find_last_existing(&bin_path).unwrap(), bin);
    }
}
