use std::path;

use crate::target::Target;

#[derive(Debug, Clone)]
pub struct Source {
    path: path::PathBuf,
    hash_file: Option<path::PathBuf>,
    hash_log_file: Option<path::PathBuf>,
    targets: Vec<Target>,
    // TODO glob filters, separate for hash/all?
}

impl Source {
    pub fn new(path: impl AsRef<path::Path>, hash_file: Option<impl AsRef<path::Path>>) -> Source {
        Source {
            path: path.as_ref().to_path_buf(),
            hash_file: hash_file.map(|p| path::PathBuf::from(p.as_ref())),
            hash_log_file: None,
            targets: vec![],
        }
    }

    pub fn add_target(&mut self, target: Target) {
        self.targets.push(target);
    }
}
