use crate::file_tree::FileTree;

use std::io::Write;

pub use testdir::testdir;

pub fn to_file_list(ft: FileTree) -> String {
    format!("{}", ft)
        // always use / as separator
        .replace('\\', "/")
}

pub fn create_ftree(root: &std::path::Path, file_list: &str) {
    file_list.split('\n').for_each(|line| {
        let full_path = root.join(line.trim());
        std::fs::create_dir_all(full_path.parent().expect("Must have a parent!"))
            .expect("Failed to create parent directories");
        let mut file = std::fs::File::create(&full_path).expect("Failed to create file");
        file.write_all(full_path.to_string_lossy().as_bytes())
            .expect("Failed to write to file");
    })
}

