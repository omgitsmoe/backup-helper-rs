use crate::file_tree::{FileTree, EntryHandle};
use std::fs;
use std::path;

#[derive(Debug)]
pub struct GatherRes {
    pub errors: Vec<String>,
}

#[derive(Debug)]
pub enum Error {
    FileTree(String),
}

pub enum VisitType<'a> {
    ListDirStart(u32),
    ListDirStop(u32),
    Directory((u32, &'a fs::DirEntry)),
    File((u32, &'a fs::DirEntry)),
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
pub fn gather<F>(start: &path::Path, mut visit: F) -> Result<GatherRes, Error>
where
    F: FnMut(VisitType) -> bool,
{
    let mut errors = vec![];
    let mut directories = vec![(0u32, start.to_path_buf())];
    while let Some((depth, directory)) = directories.pop() {
        let iter_dir = match fs::read_dir(&directory) {
            Ok(iter) => iter,
            Err(e) => {
                errors.push(format!("Failed to read directory '{:?}': {}", directory, e));
                continue;
            }
        };
        visit(VisitType::ListDirStart(depth));
        for entry in iter_dir {
            match entry {
                Ok(e) => {
                    if let Ok(file_type) = e.file_type() {
                        if file_type.is_dir() {
                            if visit(VisitType::Directory((depth, &e))) {
                                directories.push((depth + 1, e.path()));
                            }
                        } else {
                            let _ = visit(VisitType::File((depth, &e)));
                        }
                    } else {
                        errors.push(format!("Failed to get file type for: {:?}", e.path()));
                    }
                }
                Err(e) => errors.push(format!("Error while iterating: {:?}: {}", directory, e)),
            }
        }
        visit(VisitType::ListDirStop(depth));
    }

    Ok(GatherRes { errors })
}

pub fn gather_into_file_tree<F>(
    start: &path::Path,
    file_tree: &mut FileTree,
    mut include_fn: F,
) -> Result<(Vec<EntryHandle>, GatherRes), Error>
where
    F: FnMut(&fs::DirEntry) -> bool,
{
    // in case the file_tree wasn't empty we need a way to just iterate the files
    // that were gathered into the file_tree, without the previously existing ones
    let mut result_handles = vec![];

    let mut directories = vec![file_tree.root()];
    let mut handle = file_tree.root();
    let gather_result = gather(
        start, |visit_type| {
        match visit_type {
            VisitType::ListDirStart(_) => {
                handle = directories
                    .pop()
                    .expect("there should be a directory queued");
            }
            VisitType::Directory((_, e)) => {
                if !include_fn(e) {
                    return false;
                }

                let new_handle = file_tree
                    .add_child(&handle, e.file_name(), true);
                directories.push(new_handle);
            }
            VisitType::File((_, e)) => {
                if !include_fn(e) {
                    return false;
                }

                let handle = file_tree
                    .add_child(&handle, e.file_name(), false);
                result_handles.push(handle);
            }
            _ => {}
        }

        true
    })?;

    Ok((result_handles, gather_result))
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;
    use crate::test_utils::*;

    #[test]
    fn gather_visit_no_filter() {
        let test_path = setup_ftree();
        create_ftree(
            test_path.as_ref(),
            "abc/other.txt
             abc/boo.txt");

        let mut visits = vec![];
        let _ = gather(&test_path, |v| {
            match v {
                VisitType::ListDirStart(d) => visits.push(format!("start d{}", d)),
                VisitType::ListDirStop(d) => visits.push(format!("stop d{}", d)),
                VisitType::File((d, e)) => visits.push(format!(
                    "file d{} {:?}",
                    d,
                    e.path()
                        .strip_prefix(&test_path)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace("\\", "/")
                )),
                VisitType::Directory((d, e)) => visits.push(format!(
                    "dir d{} {:?}",
                    d,
                    e.path()
                        .strip_prefix(&test_path)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace("\\", "/")
                )),
            }

            true
        })
        .unwrap();
        let actual = visits.join("\n");
        println!("actual:\n{}", actual);
        assert_eq!(
            actual,
            r#"start d0
dir d0 "abc"
file d0 "file.txt"
dir d0 "subdir"
file d0 "vid.mp4"
stop d0
start d1
file d1 "subdir/chksum.md5"
file d1 "subdir/foo.txt"
dir d1 "subdir/nested"
dir d1 "subdir/other"
stop d1
start d2
file d2 "subdir/other/chksms.md5"
file d2 "subdir/other/file.txt"
stop d2
start d2
file d2 "subdir/nested/bar.txt"
dir d2 "subdir/nested/nested"
file d2 "subdir/nested/vid.mov"
stop d2
start d3
file d3 "subdir/nested/nested/cgi.bin"
file d3 "subdir/nested/nested/chksum.md5"
stop d3
start d1
file d1 "abc/boo.txt"
file d1 "abc/other.txt"
stop d1"#
        );
    }

    #[test]
    fn no_filter() {
        let test_path = setup_ftree();
        let mut file_tree = FileTree::new(&test_path).unwrap();
        let (file_handles, _) = gather_into_file_tree(
            &test_path, &mut file_tree, |_| true).unwrap();
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
vid.mp4");
    }

    #[test]
    fn filter_extension() {
        let test_path = setup_ftree();
        let mut file_tree = FileTree::new(&test_path).unwrap();
        let (file_handles, _) = gather_into_file_tree(&test_path, &mut file_tree, |p| {
            // NOTE: Path::ends_with matches the whole final component,
            //       so including the file name
            //       -> use exntension or str::ends_with
            p.metadata().unwrap().is_dir() || p.path().to_string_lossy().ends_with(".md5")
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
subdir/other/chksms.md5");
    }

    #[test]
    fn filter_dir() {
        let test_path = setup_ftree();
        let mut file_tree = FileTree::new(&test_path).unwrap();
        let (file_handles, _) = gather_into_file_tree(&test_path, &mut file_tree, |p| {
            // NOTE: Path::ends_with matches the whole final component,
            //       so including the file name
            //       -> use exntension or str::ends_with
            !p.metadata().unwrap().is_dir() || !p.path().ends_with("other")
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
vid.mp4");
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
}
