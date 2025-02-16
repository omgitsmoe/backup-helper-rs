use std::path;
use std::fs;
use crate::file_tree::FileTree;

#[derive(Debug)]
pub struct GatherRes {
    pub file_tree: FileTree,
    pub errors: Vec<String>,
}

#[derive(Debug)]
pub enum Error {
    FileTree(String),
}

pub fn gather(start: &path::Path, include_fn: fn(&fs::DirEntry) -> bool) -> Result<GatherRes, Error> {
    let mut file_tree = FileTree::new(&start)
        .map_err(|_| Error::FileTree("Failed to create file tree!".to_owned()))?;
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
                                let dirpath = e.path();
                                let new_handle =
                                    file_tree.add_child(&handle, dirpath.as_ref());
                                directories.push((dirpath, new_handle));
                            } else {
                                file_tree.add_child(
                                    &handle, e.path().as_ref());
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
        file_tree,
        errors,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn foo() {
        assert!(gather(path::Path::new("."), |entry| {
            if entry.path().to_string_lossy().contains("src") { true } else { false }
        }).is_ok());
    }
}
