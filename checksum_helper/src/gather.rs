use std::path;
use std::fs;

#[derive(Debug)]
pub struct GatherRes {
    pub files: Vec<path::PathBuf>,
    pub errors: Vec<String>,
}

pub fn gather(start: &path::Path, include_fn: fn(&fs::DirEntry) -> bool) -> GatherRes {
    let mut files = vec!();
    let mut errors = vec!();
    let mut directories = vec!(start.to_path_buf());
    while !directories.is_empty() {
        let directory = directories.pop()
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
                                directories.push(e.path());
                            } else {
                                files.push(e.path());
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

    GatherRes {
        files,
        errors,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn foo() {
        println!("{:?}", gather(std::path::PathBuf::from(".").as_path(), |entry| {
            if entry.path().to_string_lossy().contains("src") { true } else { false }
        }));
    }
}
