use std::path;
use crate::collection::HashCollection;
use crate::file_tree::FileTree;

pub mod gather;
mod file_tree;
pub mod hashed_file;
pub mod collection;

pub struct ChecksumHelper<'a> {
    root: path::PathBuf,
    file_tree: FileTree,
    gathered_hash_files: bool,
    most_current: HashCollection<'a>,
}

// TODO: only ChecksumHelper should own a FileTree
//       -> everyone else should take it as a method argument or similar
//       -> then reading in a HashCollection would take FileTree and its
//          paths to it
//          (then you could refer to the same relative path with the same
//           handle, which simplifies lookup)
impl<'a> ChecksumHelper<'a> {
    pub fn new(root: &path::Path) -> ChecksumHelper {
        ChecksumHelper {
            root: root.to_path_buf(),
            gathered_hash_files: false,
            most_current: HashCollection::new(&root.join("most_current"))
                .expect("the path <root>/most_current should be a valid file path"),
            file_tree: FileTree::new(),
        }
    }

    // TODO should this modify most_current?
    pub fn incremental<'b>(&mut self) -> HashCollection<'b> {
        todo!();
    }
    pub fn update_most_current(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
}
