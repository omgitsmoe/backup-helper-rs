use std::path;
use std::fs;
use crate::file_tree::FileTree;

#[derive(Debug)]
pub struct GatherRes {
    pub errors: Vec<String>,
}

#[derive(Debug)]
pub enum Error {
    FileTree(String),
}

pub fn gather(start: &path::Path, file_tree: &mut FileTree, include_fn: fn(&fs::DirEntry) -> bool) -> Result<GatherRes, Error> {
    let mut errors = vec!();
    let mut directories =
        vec!((start.to_path_buf(), file_tree.root()));
    while !directories.is_empty() {
        let (directory, handle) = directories.pop()
            .expect("Directory must not be None, since it's the loop condition!");
        let iter_dir = match fs::read_dir(&directory) {
            Ok(iter) => iter,
            Err(e) => {
                errors.push(format!("Failed to read directory '{:?}': {}", directory, e));
                continue;
            },
        };
        for entry in iter_dir {
            match entry {
                Ok(e) => {
                    if include_fn(&e) {
                        if let Ok(file_type) = e.file_type() {
                            if file_type.is_dir() {
                                let new_handle =
                                    file_tree.add_child(&handle, &e.file_name(), true);
                                directories.push((e.path(), new_handle));
                            } else {
                                file_tree.add_child(
                                    &handle, &e.file_name(),
                                    false);
                            }
                        } else {
                            errors.push(format!("Failed to get file type for: {:?}", e.path()));
                        }
                    }
                },
                Err(e) => errors.push(format!("Error while iterating: {:?}: {}", directory, e)),
            }
        }
    }

    Ok(GatherRes {
        errors,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use testdir::testdir;
    use std::io::prelude::*;

    #[test]
    fn foo() {
        assert!(gather(path::Path::new("."), &mut FileTree::new(), |entry| {
            if entry.path().to_string_lossy().contains("src") { true } else { false }
        }).is_ok());
    }

    #[test]
    fn no_filter() {
        let test_path = setup_ftree();
        let mut file_tree = FileTree::new();
        let _ = gather(&test_path, &mut file_tree, |_| true).unwrap();
        let str = to_file_list(file_tree);
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
    }

    #[test]
    fn filter_extension() {
        let test_path = setup_ftree();
        let mut file_tree = FileTree::new();
        let _ = gather(&test_path, &mut file_tree, |p| {
            // NOTE: Path::ends_with matches the whole final component,
            //       so including the file name
            //       -> use exntension or str::ends_with
            p.metadata().unwrap().is_dir() || p.path().to_string_lossy().ends_with(".md5")
        }).unwrap();
        let str = to_file_list(file_tree);
        assert_eq!(
            str,
            "FileTree{
  subdir/chksum.md5
  subdir/nested/nested/chksum.md5
  subdir/other/chksms.md5
}"
        );
    }

    #[test]
    fn filter_dir() {
        let test_path = setup_ftree();
        let mut file_tree = FileTree::new();
        let _ = gather(&test_path, &mut file_tree, |p| {
            // NOTE: Path::ends_with matches the whole final component,
            //       so including the file name
            //       -> use exntension or str::ends_with
            !p.metadata().unwrap().is_dir() || !p.path().ends_with("other")
        }).unwrap();
        let str = to_file_list(file_tree);
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
    }

    fn to_file_list(ft: FileTree) -> String {
        format!("{}", ft)
            // always use / as separator
            .replace('\\', "/")
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
            subdir/other/file.txt"
        );

        test_path
    }

    fn create_ftree(root: &std::path::Path, file_list: &str) {
        file_list
            .split('\n')
            .for_each(|line| {
                let full_path = root.join(line.trim());
                std::fs::create_dir_all(
                    full_path.parent().expect("Must have a parent!"))
                        .expect("Failed to create parent directories");
                let mut file = std::fs::File::create(&full_path)
                    .expect("Failed to create file");
                file.write_all(full_path.to_string_lossy().as_bytes())
                    .expect("Failed to write to file");
            })
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
            subdir/nested/vid.mov");

        assert!(exists(test_path.join("file.txt")).unwrap());
        assert!(exists(test_path.join("vid.mp4")).unwrap());
        assert!(exists(test_path.join("subdir/foo.txt")).unwrap());
        assert!(exists(test_path.join("subdir/nested/bar.txt")).unwrap());
        assert!(exists(test_path.join("subdir/nested/vid.mov")).unwrap());
    }
}
