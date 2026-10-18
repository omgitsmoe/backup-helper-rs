use std::{
    fs, io,
    path::{Component, Path},
};

pub(crate) fn validate_relative_file(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty()
        || !path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(format!(
            "expected a nonempty relative file path without traversal: {}",
            path.display()
        ));
    }
    Ok(())
}

pub(crate) fn reject_symlinks(root: &Path, relative: &Path, include_leaf: bool) -> io::Result<()> {
    let mut current = root.to_path_buf();
    let components: Vec<_> = relative.components().collect();
    let count = components.len() - usize::from(!include_leaf);
    for component in &components[..count] {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "symlink below restore root is not allowed: {}",
                        current.display()
                    ),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
