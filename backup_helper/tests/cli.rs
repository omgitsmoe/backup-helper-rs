use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use testdir::testdir;

fn run_cli(args: &[OsString]) -> std::process::Output {
    run_cli_from(Path::new("."), args)
}

fn run_cli_from(root: &Path, args: &[OsString]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_backup_helper"))
        .current_dir(root)
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
            disk "source" {{
                path {:?}
                mounted #false
            }}
            disk "target" {{
                path {:?}
                mounted #false
            }}
        }}
        source {:?} {{
            target {:?} {{
                transfer_mode copy
                verify #true
            }}
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

fn mark_disks_mounted(state: &mut Value) {
    for disk in state["disks"].as_array_mut().unwrap() {
        disk["mounted"] = true.into();
    }
}

fn reconcile_with_mounted_disks(config_path: &Path, state_path: &Path) {
    let output = run_cli(&[
        "reconcile".into(),
        arg(config_path),
        "--state".into(),
        arg(state_path),
    ]);
    assert!(output.status.success(), "{output:?}");

    let mut state: Value =
        serde_json::from_str(&std::fs::read_to_string(state_path).unwrap()).unwrap();
    mark_disks_mounted(&mut state);
    std::fs::write(state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();
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
    assert_eq!(std::fs::read_to_string(&state_path).unwrap(), first_state);

    let force_start = run_cli(&[
        "start".into(),
        "--force-overwrite".into(),
        "--state".into(),
        arg(&state_path),
    ]);
    assert!(force_start.status.success(), "{force_start:?}");
    assert_eq!(std::fs::read_to_string(state_path).unwrap(), first_state);
}

#[test]
fn start_prints_task_verify_summaries_and_log_locations() {
    let root = testdir!();
    let (config_path, state_path) = write_config(&root);
    let source_path = root.join("source-disk/source");
    let target_path = root.join("target-disk/target");
    std::fs::create_dir_all(&source_path).unwrap();
    std::fs::create_dir_all(&target_path).unwrap();
    std::fs::write(source_path.join("file.txt"), "content").unwrap();
    reconcile_with_mounted_disks(&config_path, &state_path);

    let output = run_cli_from(&root, &["start".into(), "--state".into(), arg(&state_path)]);

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("========== TASK SUMMARY =========="));
    assert!(stdout.contains("Ran: 3 | Successful: 3 | Errored: 0"));
    assert!(stdout.contains("[OK] 0: hash"));
    assert!(stdout.contains("[OK] 1: copy"));
    assert!(stdout.contains("[OK] 2: verify"));
    assert_eq!(stdout.matches("Full log:").count(), 2);
    assert!(stdout.contains("SourceHash_"));
    assert!(stdout.contains("TargetVerify_"));
    assert!(stdout.contains("========== VERIFY SUMMARY =========="));
    assert!(stdout.contains("Total: 1 | OK: 1 | ERR: 0 | WARN: 0"));
    assert!(stdout.contains("ALL FILES VERIFIED SUCCESSFULLY"));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("========== VERIFY SUMMARY =========="));
    assert!(stderr.contains("Total: 1 | OK: 1 | ERR: 0 | WARN: 0"));
}

#[test]
fn start_prints_failed_task_summary_when_run_fails() {
    let root = testdir!();
    let (config_path, state_path) = write_config(&root);
    let source_path = root.join("source-disk/source");
    let target_path = root.join("target-disk/target");
    std::fs::create_dir_all(&source_path).unwrap();
    std::fs::create_dir_all(target_path.parent().unwrap()).unwrap();
    std::fs::write(source_path.join("file.txt"), "content").unwrap();
    std::fs::write(&target_path, "not a directory").unwrap();
    reconcile_with_mounted_disks(&config_path, &state_path);

    let output = run_cli_from(&root, &["start".into(), "--state".into(), arg(&state_path)]);

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Ran: 2 | Successful: 1 | Errored: 1"));
    assert!(stdout.contains("[OK] 0: hash"));
    assert!(stdout.contains("Full log:"));
    assert!(stdout.contains("SourceHash_"));
    assert!(stdout.contains("[ERR] 1: copy"));
    assert!(stdout.contains("CopyError:"));
    assert!(!stdout.contains("[ERR] 2: verify"));
    assert!(!stdout.contains("========== VERIFY SUMMARY =========="));
}
