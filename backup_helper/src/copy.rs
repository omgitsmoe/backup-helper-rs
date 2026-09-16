use std::{
    fs, io,
    path::{Path, PathBuf},
};

use crate::BackupHelperError;

pub fn copy_tree(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    mut on_progress: impl FnMut(CopyProgress),
) -> Result<(), BackupHelperError> {
    let source = source.as_ref();
    let destination = destination.as_ref();

    let source_meta = std::fs::metadata(source).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            BackupHelperError::CopyError(format!("Source at {:?} does not exist: {}", source, e))
        } else {
            BackupHelperError::CopyError(format!("Failed to get source path metadata: {}", e))
        }
    })?;

    if !source_meta.is_dir() {
        return Err(BackupHelperError::CopyError(format!(
            "Source at {:?} is not a directory!",
            source
        )));
    }

    reject_overlapping_paths(source, destination)?;
    fs::create_dir_all(destination)
        .map_err(|error| copy_io_error("create destination directory", destination, error))?;

    let iter =
        WalkTree::new(source).map_err(|error| copy_io_error("walk source", source, error))?;
    copy_tree_entries(source, destination, iter, &mut on_progress)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyProgress {
    pub relative_path: PathBuf,
}

fn copy_tree_entries(
    source: &Path,
    destination: &Path,
    mut iter: WalkTree,
    on_progress: &mut impl FnMut(CopyProgress),
) -> Result<(), BackupHelperError> {
    for entry in iter.by_ref() {
        let source_path = entry.entry.path();
        let meta = fs::symlink_metadata(&source_path)
            .map_err(|error| copy_io_error("read source metadata", &source_path, error))?;
        let relative = source_path
            .strip_prefix(source)
            .expect("walker yielded a path outside its root");
        let destination_path = destination.join(relative);

        if meta.is_dir() {
            fs::create_dir_all(&destination_path).map_err(|error| {
                copy_io_error("create destination directory", &destination_path, error)
            })?;
        } else if meta.file_type().is_symlink() {
            let target_meta = fs::metadata(&source_path).map_err(|error| {
                copy_io_error("read symlink target metadata", &source_path, error)
            })?;
            // Copy linked files as regular files, but do not follow linked directories.
            if target_meta.is_file() {
                fs::copy(&source_path, &destination_path)
                    .map_err(|error| copy_io_error("copy symlink target", &source_path, error))?;
            }
        } else {
            fs::copy(&source_path, &destination_path)
                .map_err(|error| copy_io_error("copy source file", &source_path, error))?;
        }

        on_progress(CopyProgress {
            relative_path: relative.to_path_buf(),
        });
    }

    if let Some(err) = iter.error() {
        return Err(BackupHelperError::CopyError(format!(
            "Iteration error: {err}"
        )));
    }

    Ok(())
}

fn copy_io_error(operation: &str, path: &Path, error: io::Error) -> BackupHelperError {
    BackupHelperError::CopyError(format!("Failed to {operation} {:?}: {error}", path))
}

fn reject_overlapping_paths(source: &Path, destination: &Path) -> Result<(), BackupHelperError> {
    let source_canonical = canonicalize_for_comparison(source).map_err(|error| {
        BackupHelperError::CopyError(format!("Failed to resolve source {:?}: {}", source, error))
    })?;
    let destination_canonical = canonicalize_for_comparison(destination).map_err(|error| {
        BackupHelperError::CopyError(format!(
            "Failed to resolve destination {:?}: {}",
            destination, error
        ))
    })?;

    if source_canonical == destination_canonical {
        return Err(BackupHelperError::CopyError(format!(
            "Source and destination refer to the same path: {:?}",
            source
        )));
    }

    if destination_canonical.starts_with(&source_canonical) {
        return Err(BackupHelperError::CopyError(format!(
            "Destination {:?} is inside source {:?}",
            destination, source
        )));
    }

    if source_canonical.starts_with(&destination_canonical) {
        return Err(BackupHelperError::CopyError(format!(
            "Source {:?} is inside destination {:?}",
            source, destination
        )));
    }

    Ok(())
}

fn canonicalize_for_comparison(path: &Path) -> std::io::Result<std::path::PathBuf> {
    if path.exists() {
        return fs::canonicalize(path);
    }

    let file_name = path
        .file_name()
        .expect("a non-empty path must have a file name");
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut result = canonicalize_for_comparison(parent)?;
    result.push(file_name);
    Ok(result)
}

pub struct WalkTree {
    stack: Vec<fs::ReadDir>,
    error: Option<io::Error>,
}

pub struct DirItem {
    pub entry: fs::DirEntry,
}

impl Iterator for WalkTree {
    type Item = DirItem;

    fn next(&mut self) -> Option<Self::Item> {
        if self.error.is_some() {
            return None;
        }

        while let Some(dir) = self.stack.last_mut() {
            match dir.next() {
                Some(Ok(entry)) => {
                    let file_type = match entry.file_type() {
                        Ok(file_type) => file_type,
                        Err(error) => {
                            self.error = Some(error);
                            return None;
                        }
                    };

                    if file_type.is_dir() {
                        match fs::read_dir(entry.path()) {
                            Ok(children) => self.stack.push(children),
                            Err(error) => {
                                self.error = Some(error);
                                return None;
                            }
                        }
                    }

                    return Some(DirItem { entry });
                }
                Some(Err(e)) => {
                    self.error = Some(e);
                    return None;
                }
                None => {
                    self.stack.pop();
                }
            }
        }

        None
    }
}

impl WalkTree {
    pub fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            stack: vec![fs::read_dir(root)?],
            error: None,
        })
    }

    pub fn error(&self) -> Option<&io::Error> {
        self.error.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use testdir::testdir;

    #[test]
    fn walk_tree_yields_nested_entries_depth_first() {
        let root = testdir!();
        fs::create_dir(root.join("nested")).unwrap();
        fs::write(root.join("nested/file.txt"), "content").unwrap();
        fs::write(root.join("file.txt"), "content").unwrap();

        let mut tree = WalkTree::new(&root).unwrap();
        let mut paths = Vec::new();
        for item in tree.by_ref() {
            paths.push(item.entry.path());
        }

        assert!(tree.error().is_none());
        assert_eq!(paths.len(), 3);
        assert!(paths.contains(&root.join("nested")));
        assert!(paths.contains(&root.join("nested/file.txt")));
        assert!(paths.contains(&root.join("file.txt")));
    }

    #[cfg(unix)]
    #[test]
    fn walk_tree_yields_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let root = testdir!();
        fs::create_dir(root.join("target")).unwrap();
        fs::write(root.join("target/file.txt"), "content").unwrap();
        symlink(root.join("target"), root.join("link")).unwrap();

        let mut tree = WalkTree::new(&root).unwrap();
        let paths: Vec<_> = tree.by_ref().map(|item| item.entry.path()).collect();

        assert!(tree.error().is_none());
        assert!(paths.contains(&root.join("link")));
        assert!(!paths.contains(&root.join("link/file.txt")));
    }

    #[test]
    fn walk_tree_reports_missing_root_from_constructor() {
        let root = testdir!().join("missing");

        let result = WalkTree::new(root);

        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::NotFound));
    }

    #[test]
    fn copy_tree_rejects_same_source_and_destination() {
        let root = testdir!();

        let result = copy_tree(&root, &root, |_| {});

        assert!(
            matches!(result, Err(BackupHelperError::CopyError(message)) if message.contains("same path"))
        );
    }

    #[test]
    fn copy_tree_rejects_missing_source() {
        let root = testdir!();
        let source = root.join("missing-source");

        let result = copy_tree(&source, root.join("destination"), |_| {});

        assert!(matches!(
            result,
            Err(BackupHelperError::CopyError(message))
                if message.contains("does not exist")
        ));
    }

    #[test]
    fn copy_tree_rejects_file_source() {
        let root = testdir!();
        let source = root.join("source");
        fs::write(&source, "not a directory").unwrap();

        let result = copy_tree(&source, root.join("destination"), |_| {});

        assert!(matches!(
            result,
            Err(BackupHelperError::CopyError(message))
                if message.contains("is not a directory")
        ));
    }

    #[test]
    fn copy_tree_rejects_file_destination() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        fs::write(&destination, "not a directory").unwrap();

        let result = copy_tree(&source, &destination, |_| {});

        assert!(matches!(
            result,
            Err(BackupHelperError::CopyError(message))
                if message.contains("create destination directory")
        ));
    }

    #[test]
    fn copy_tree_rejects_destination_below_file_parent() {
        let root = testdir!();
        let source = root.join("source");
        let file_parent = root.join("file-parent");
        let destination = file_parent.join("destination");
        fs::create_dir(&source).unwrap();
        fs::write(&file_parent, "not a directory").unwrap();

        let result = copy_tree(&source, &destination, |_| {});

        assert!(matches!(
            result,
            Err(BackupHelperError::CopyError(message))
                if message.contains("create destination directory")
        ));
    }

    #[test]
    fn copy_tree_rejects_destination_inside_source() {
        let root = testdir!();
        let destination = root.join("nested/destination");

        let result = copy_tree(&root, &destination, |_| {});

        assert!(
            matches!(result, Err(BackupHelperError::CopyError(message)) if message.contains("inside source"))
        );
        assert!(!destination.exists());
    }

    #[test]
    fn copy_tree_rejects_source_inside_destination() {
        let root = testdir!();
        let source = root.join("source");
        fs::create_dir(&source).unwrap();

        let result = copy_tree(&source, &root, |_| {});

        assert!(
            matches!(result, Err(BackupHelperError::CopyError(message)) if message.contains("inside destination"))
        );
    }

    #[test]
    fn copy_tree_allows_sibling_directories() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();

        let result = copy_tree(&source, &destination, |_| {});

        assert!(result.is_ok());
    }

    #[test]
    fn copy_tree_allows_existing_nested_destination_directory() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        let nested_source = source.join("nested");
        let nested_destination = destination.join("nested");
        fs::create_dir_all(&nested_source).unwrap();
        fs::create_dir_all(&nested_destination).unwrap();
        fs::write(nested_source.join("file.txt"), "content").unwrap();

        let result = copy_tree(&source, &destination, |_| {});

        assert!(result.is_ok());
        assert_eq!(
            fs::read_to_string(nested_destination.join("file.txt")).unwrap(),
            "content"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn copy_tree_copies_nested_files_and_handles_symlinks() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        let nested = source.join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("file.txt"), "nested content").unwrap();
        fs::write(source.join("regular.txt"), "regular content").unwrap();
        create_file_symlink(&nested.join("file.txt"), &source.join("file-link"));
        create_dir_symlink(&nested, &source.join("dir-link"));

        let mut progress = Vec::new();
        copy_tree(&source, &destination, |entry| {
            progress.push(entry.relative_path);
        })
        .unwrap();

        assert_eq!(
            fs::read_to_string(destination.join("nested/file.txt")).unwrap(),
            "nested content"
        );
        assert_eq!(
            fs::read_to_string(destination.join("regular.txt")).unwrap(),
            "regular content"
        );
        assert_eq!(
            fs::read_to_string(destination.join("file-link")).unwrap(),
            "nested content"
        );
        assert!(!destination.join("dir-link").exists());
        assert!(!destination.join("dir-link/file.txt").exists());
        assert!(progress.contains(&PathBuf::from("nested")));
        assert!(progress.contains(&PathBuf::from("nested/file.txt")));
        assert!(progress.contains(&PathBuf::from("regular.txt")));
    }

    #[test]
    fn copy_tree_returns_error_when_walker_fails() {
        let root = testdir!();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir(&source).unwrap();
        let iter = WalkTree {
            stack: vec![],
            error: Some(io::Error::other("forced iterator failure")),
        };

        let result = copy_tree_entries(&source, &destination, iter, &mut |_| {});

        assert!(matches!(
            result,
            Err(BackupHelperError::CopyError(message))
                if message.contains("forced iterator failure")
        ));
    }

    #[cfg(unix)]
    fn create_file_symlink(target: &std::path::Path, link: &std::path::Path) {
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    #[cfg(unix)]
    fn create_dir_symlink(target: &std::path::Path, link: &std::path::Path) {
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    #[cfg(windows)]
    fn create_file_symlink(target: &std::path::Path, link: &std::path::Path) {
        std::os::windows::fs::symlink_file(target, link).unwrap();
    }

    #[cfg(windows)]
    fn create_dir_symlink(target: &std::path::Path, link: &std::path::Path) {
        std::os::windows::fs::symlink_dir(target, link).unwrap();
    }
}
