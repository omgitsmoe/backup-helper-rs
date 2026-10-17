use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

use restore_helper::Plan;
use testdir::testdir;

fn write_manifests(root: &Path) {
    let header = "# version 1\n";
    let hash = "ab".repeat(32);
    fs::write(
        root.join("target.cshd"),
        format!("{header}1234,42,sha256,{hash} desired.txt\n"),
    )
    .unwrap();
    fs::write(
        root.join("source.cshd"),
        format!("{header}5678,42,sha256,{hash} original.txt\n"),
    )
    .unwrap();
}

fn run_plan(root: &Path, target: &str, source: &str, output: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_restore_helper"));
    command
        .current_dir(root)
        .args(["plan", target, "--source", source]);
    if let Some(output) = output {
        command.arg(output);
    }
    command.output().unwrap()
}

#[test]
fn plan_command_writes_json_using_relative_manifest_paths() {
    let root = testdir!();
    write_manifests(&root);
    let result = run_plan(&root, "target.cshd", "archive=source.cshd", None);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bytes = fs::read(root.join("plan.json")).unwrap();
    let _: Plan = serde_json::from_slice(&bytes).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["files"][0]["relative_path"], "desired.txt");
    assert_eq!(
        json["contents"][0]["sources"][0]["relative_path"],
        "original.txt"
    );
    assert_eq!(json["source_manifests"][0]["id"], "archive");
    assert_eq!(json["files"][0]["mtime"]["seconds"], 1234);
}

#[test]
fn plan_command_uses_explicit_output_and_never_overwrites_it() {
    let root = testdir!();
    write_manifests(&root);
    let result = run_plan(
        &root,
        "target.cshd",
        "archive=source.cshd",
        Some("custom.json"),
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!root.join("plan.json").exists());
    fs::write(root.join("custom.json"), b"keep this").unwrap();
    let result = run_plan(
        &root,
        "target.cshd",
        "archive=source.cshd",
        Some("custom.json"),
    );
    assert!(!result.status.success());
    assert_eq!(fs::read(root.join("custom.json")).unwrap(), b"keep this");
}

#[test]
fn plan_command_build_failure_does_not_create_output() {
    let root = testdir!();
    write_manifests(&root);
    for (target, source) in [
        ("missing.cshd", "archive=source.cshd"),
        ("target.cshd", "archive=missing.cshd"),
    ] {
        let result = run_plan(&root, target, source, None);
        assert!(!result.status.success());
        assert!(!root.join("plan.json").exists());
    }
    fs::write(root.join("source.cshd"), "# version invalid\n").unwrap();
    let result = run_plan(&root, "target.cshd", "archive=source.cshd", None);
    assert!(!result.status.success());
    assert!(!root.join("plan.json").exists());
}

#[test]
fn plan_command_reports_output_creation_failure() {
    let root = testdir!();
    write_manifests(&root);
    let result = run_plan(
        &root,
        "target.cshd",
        "archive=source.cshd",
        Some("missing/plan.json"),
    );
    assert!(!result.status.success());
    assert!(!root.join("missing").exists());
}
