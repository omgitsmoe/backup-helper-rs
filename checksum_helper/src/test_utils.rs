use crate::file_tree::{FileTree, EntryHandle};

use std::io::Write;

pub use testdir::testdir;

pub fn to_file_list(ft: &FileTree) -> String {
    format!("{}", ft)
        // always use / as separator
        .replace('\\', "/")
}

pub fn file_handles_to_file_list(ft: &FileTree, handles: &Vec<EntryHandle>) -> String {
    let mut result = vec!();
    for fh in handles {
        result.push(ft.relative_path(fh)
            .to_str()
            .unwrap()
            .to_string()
            .replace('\\', "/"));
    }

    result.sort_unstable();

    result.join("\n")
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

