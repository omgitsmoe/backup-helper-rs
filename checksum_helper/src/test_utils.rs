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

pub fn cshd_str_paths_only_sorted(s: &str) -> String {
    let mut paths: Vec<&str> = s
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(' ').map(|(_, path)| path))
        .collect();

    paths.sort();

    paths.join("\n") + "\n"
}

pub fn create_ftree(root: &std::path::Path, file_list: &str) {
    file_list.split('\n').for_each(|line| {
        let relative_path = line.trim();
        let full_path = root.join(relative_path);
        std::fs::create_dir_all(full_path.parent().expect("Must have a parent!"))
            .expect("Failed to create parent directories");
        println!("creating file {}", relative_path);
        let mut file = std::fs::File::create(&full_path).expect("Failed to create file");
        file.write_all(relative_path.as_bytes())
            .expect("Failed to write to file");
    })
}

