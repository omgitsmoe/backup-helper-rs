use crate::file_tree::{EntryHandle, FileTree};

use std::io::Write;

pub use testdir::testdir;

pub fn to_file_list(ft: &FileTree) -> String {
    let mut paths: Vec<_> = ft.iter()
        .map(|handle| ft.relative_path(&handle))
        .collect();

    // Sort alphabetically for deterministic output
    paths.sort();

    let mut result = String::new();
    result.push_str("FileTree{\n");

    for path in paths {
        // Use display, replace \ with / for consistency
        result.push_str("  ");
        // NOTE: debug formatting {:?} will use escaping if chars would
        //       need it in a string literal,
        //       use .display directly, which is lossy if the path
        //       is not valid unicode
        result.push_str(&path.display().to_string().replace('\\', "/"));
        result.push('\n');
    }

    result.push('}');

    result
}


pub fn file_handles_to_file_list(ft: &FileTree, handles: &Vec<EntryHandle>) -> String {
    let mut result = vec![];
    for fh in handles {
        result.push(
            ft.relative_path(fh)
                .to_str()
                .unwrap()
                .to_string()
                .replace('\\', "/"),
        );
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
