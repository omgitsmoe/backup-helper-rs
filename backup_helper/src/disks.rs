use std::path;

#[derive(Debug, Clone)]
pub struct Disk {
    pub(crate) name: String,
    pub(crate) path: path::PathBuf,
}
