use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

use testdir::testdir;

fn run_execute(root: &Path, mount: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_restore_helper"))
        .current_dir(root)
        .args([
            "execute",
            "plan.json",
            "--target",
            "restored",
            "--mount",
            mount,
            "--existing-file-policy",
            "skip-always",
        ])
        .output()
        .unwrap()
}

#[test]
fn execute_reports_missing_plan() {
    let root = testdir!();
    let output = run_execute(&root, "archive=source");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("IoError"));
}

#[test]
fn execute_reports_invalid_plan_json() {
    let root = testdir!();
    fs::write(root.join("plan.json"), "{").unwrap();
    let output = run_execute(&root, "archive=source");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("JsonError"));
}

#[test]
fn execute_reports_unknown_mount_id() {
    let root = testdir!();
    fs::write(
        root.join("plan.json"),
        r#"{"source_manifests":[],"contents":[],"files":[]}"#,
    )
    .unwrap();
    let output = run_execute(&root, "unknown=source");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ManifestIdDoesNotExist"));
    assert!(stderr.contains("unknown"));
}
