use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use testdir::testdir;

fn run_cli(args: &[OsString]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_backup_helper"))
        .args(args)
        .output()
        .expect("failed to run backup_helper")
}

fn arg(value: impl AsRef<Path>) -> OsString {
    value.as_ref().as_os_str().to_owned()
}

fn config(root: &Path) -> String {
    let source_disk = root.join("source-disk");
    let target_disk = root.join("target-disk");
    let source = source_disk.join("source");
    let target = target_disk.join("target");

    config_for_paths(&source_disk, &target_disk, &source, &target)
}

fn config_for_paths(
    source_disk: &Path,
    target_disk: &Path,
    source: &Path,
    target: &Path,
) -> String {
    format!(
        r#"
        disks {{
            disk "source" {{ path {:?} }}
            disk "target" {{ path {:?} }}
        }}
        source {:?} {{
            target {:?} {{ transfer_mode copy verify #true }}
        }}
        "#,
        source_disk, target_disk, source, target,
    )
}

fn write_config(root: &Path) -> (PathBuf, PathBuf) {
    let config_path = root.join("config.kdl");
    let state_path = root.join("state.json");
    std::fs::write(&config_path, config(root)).unwrap();
    (config_path, state_path)
}

#[test]
fn reconcile_creates_state_file() {
    let root = testdir!();
    let (config_path, state_path) = write_config(&root);

    let output = run_cli(&[
        "reconcile".into(),
        arg(&config_path),
        "--state".into(),
        arg(&state_path),
    ]);

    assert!(output.status.success(), "{output:?}");
    let state: Value = serde_json::from_str(&std::fs::read_to_string(state_path).unwrap()).unwrap();
    assert_eq!(state["version"], 1);
    assert_eq!(state["sources"][0]["targets"][0]["transferred"], false);
}

#[test]
fn invalid_config_returns_invalid_config_error() {
    let root = testdir!();
    let config_path = root.join("invalid.kdl");
    std::fs::write(&config_path, "source {").unwrap();

    let output = run_cli(&[
        "reconcile".into(),
        arg(&config_path),
        "--state".into(),
        arg(root.join("state.json")),
    ]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("InvalidConfig"));
}

#[test]
fn missing_config_returns_io_error() {
    let root = testdir!();
    let output = run_cli(&[
        "reconcile".into(),
        arg(root.join("missing.kdl")),
        "--state".into(),
        arg(root.join("state.json")),
    ]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("IoError"));
}

#[test]
fn missing_state_returns_io_error_for_start() {
    let root = testdir!();
    let output = run_cli(&[
        "start".into(),
        "--state".into(),
        arg(root.join("missing.json")),
    ]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("IoError"));
}

#[test]
fn start_loads_completed_state_and_is_idempotent() {
    let root = testdir!();
    let (config_path, state_path) = write_config(&root);

    let reconcile = run_cli(&[
        "reconcile".into(),
        arg(&config_path),
        "--state".into(),
        arg(&state_path),
    ]);
    assert!(reconcile.status.success(), "{reconcile:?}");

    let mut state: Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    state["sources"][0]["hash_file"] = arg(root.join("source.sha512"))
        .to_string_lossy()
        .to_string()
        .into();
    state["sources"][0]["targets"][0]["transferred"] = true.into();
    state["sources"][0]["targets"][0]["verified"] = serde_json::json!({
        "checked": 1,
        "errors": 0,
        "missing": 0,
        "crc_errors": 0,
        "log_file": root.join("verify.log"),
    });
    std::fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();

    let first_start = run_cli(&["start".into(), "--state".into(), arg(&state_path)]);
    assert!(first_start.status.success(), "{first_start:?}");

    let first_state = std::fs::read_to_string(&state_path).unwrap();

    let second_start = run_cli(&["start".into(), "--state".into(), arg(&state_path)]);
    assert!(second_start.status.success(), "{second_start:?}");
    assert_eq!(std::fs::read_to_string(state_path).unwrap(), first_state);
}
