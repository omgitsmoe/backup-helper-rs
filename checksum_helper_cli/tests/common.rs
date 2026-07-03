use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Run the CLI binary (built by cargo for integration tests) with the given args.
/// Returns (stdout, stderr, success).
pub fn run_cli(args: &[&str]) -> (String, String, bool) {
    let bin = std::env::var("CARGO_BIN_EXE_CHECKSUM_HELPER_CLI")
        .unwrap_or_else(|_| {
            // Fallback: locate the binary relative to the manifest dir
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            // Go up to workspace root, then into target/debug/
            manifest_dir
                .parent()
                .expect("workspace root")
                .join("target")
                .join("debug")
                .join("checksum_helper_cli")
                .to_string_lossy()
                .to_string()
        });
    let output = Command::new(bin)
        .args(args)
        .output()
        .expect("failed to run CLI");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

/// Create a unique temporary directory for a test.
/// Uses a counter and retries if the directory already exists (handles
/// parallel test execution).
pub fn testdir() -> PathBuf {
    let base = std::env::temp_dir().join("ch_e2e");
    for i in 0..10000u32 {
        let path = base.join(format!("test_{}", i));
        if std::fs::create_dir(&path).is_ok() {
            return path;
        }
    }
    panic!("could not create unique test directory");
}

/// Create a file tree from a string listing relative paths (one per line).
/// Each file gets its relative path as content (deterministic for hashing).
pub fn create_ftree(root: &Path, file_list: &str) {
    for line in file_list.lines() {
        let relative_path = line.trim();
        if relative_path.is_empty() {
            continue;
        }
        let full_path = root.join(relative_path);
        std::fs::create_dir_all(full_path.parent().unwrap()).unwrap();
        let mut file = std::fs::File::create(&full_path).unwrap();
        write!(file, "{}", relative_path).unwrap();
    }
}

/// Set file mtimes from a string spec "mtime relative_path" (one per line).
/// Uses filetime crate.
#[allow(dead_code)]
pub fn set_mtimes(root: &Path, spec: &str) {
    for line in spec.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (mtime_str, relpath) = line.split_once(' ').unwrap();
        let mtime: f64 = mtime_str.parse().unwrap();
        let full_path = root.join(relpath);
        let mtime = filetime::FileTime::from_unix_time(
            mtime as i64,
            ((mtime.fract() * 1_000_000_000.0) as u32).min(999_999_999),
        );
        filetime::set_file_mtime(&full_path, mtime).unwrap();
    }
}

/// Strip mtime (everything before the first comma) from .cshd lines,
/// so we can compare hash type + hash + path independently of timestamps.
pub fn cshd_strip_mtime(contents: &str) -> String {
    let mut result = String::new();
    for line in contents.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some(comma) = line.find(',') {
            result.push_str(&line[comma + 1..]);
            result.push('\n');
        }
    }
    result
}

/// Parse the collection path from "Wrote collection at: \"...\"" in stdout.
pub fn parse_collection_path(stdout: &str) -> Option<PathBuf> {
    let line = stdout.lines().find(|l| l.contains("Wrote collection at:"))?;
    let start = line.find('"')?;
    let after_quote = &line[start + 1..];
    let end = after_quote.find('"')?;
    Some(PathBuf::from(&after_quote[..end]))
}

/// Assert that a cshd file content has an entry for `path`
/// whose hash hex equals `expected_hash`.
///
/// Entry format:  mtime,size,algo,<128-hex-chars> path
pub fn assert_entry_hash(contents: &str, path: &str, expected_hash: &str) {
    for line in contents.lines() {
        if line.starts_with('#') {
            continue;
        }
        let (prefix, file_path) = line.rsplit_once(' ').unwrap_or(("", line));
        if file_path == path {
            let hash_hex = prefix.rsplit(',').next().unwrap();
            assert_eq!(hash_hex, expected_hash, "hash mismatch for {}", path);
            return;
        }
    }
    panic!("path '{}' not found in output:\n{}", path, contents);
}
