use std::path;

#[derive(Debug, Clone)]
pub struct VerifiedInfo {
    checked: u64,
    errors: u64,
    missing: u64,
    crc_errors: u64,
    log_file: path::PathBuf,
}

#[derive(Debug, Clone, Copy)]
pub enum TransferMode {
    Copy,
    // TODO settings?
    Sync,
}

#[derive(Debug, Clone)]
pub struct Target {
    path: path::PathBuf,
    transfer_mode: TransferMode,
    transfered: bool,
    verify: bool,
    verified: Option<VerifiedInfo>,
}

impl Target {
    pub fn new(path: impl AsRef<path::Path>, transfer_mode: TransferMode, verify: bool) -> Target {
        Target{
            path: path.as_ref().to_path_buf(),
            transfer_mode,
            transfered: false,
            verify,
            verified: None,
        }
    }
}
