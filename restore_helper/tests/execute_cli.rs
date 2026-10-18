use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

use restore_helper::{Plan, Source};
use sha2::{Digest, Sha256};
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("open restore plan"));
    assert!(stderr.contains("plan.json"));
}

#[test]
fn execute_reports_invalid_plan_json() {
    let root = testdir!();
    fs::write(root.join("plan.json"), "{").unwrap();
    let output = run_execute(&root, "archive=source");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("plan JSON error"));
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
    assert!(stderr.contains("does not exist"));
    assert!(stderr.contains("unknown"));
}

fn progress_fixture(root: &Path) {
    let entry = |name: &str, data: &[u8]| {
        format!(
            "1234,{},sha256,{:x} {name}\n",
            data.len(),
            Sha256::digest(data)
        )
    };
    let copy = entry("copy.txt", b"copy");
    let skip = entry("skip.txt", b"skip");
    let offline = entry("offline.txt", b"offline");
    let absent = entry("absent.txt", b"absent");
    let target = root.join("target.cshd");
    let archive = root.join("archive.cshd");
    let other = root.join("offline.cshd");
    fs::write(
        &target,
        format!("# version 1\n{copy}{skip}{offline}{absent}"),
    )
    .unwrap();
    fs::write(&archive, format!("# version 1\n{copy}{skip}")).unwrap();
    fs::write(&other, format!("# version 1\n{offline}")).unwrap();
    let plan = Plan::build(
        &target,
        vec![
            Source::new("archive", &archive).unwrap(),
            Source::new("offline", &other).unwrap(),
        ],
    )
    .unwrap();
    fs::write(root.join("plan.json"), serde_json::to_vec(&plan).unwrap()).unwrap();
    fs::create_dir(root.join("source")).unwrap();
    fs::write(root.join("source/copy.txt"), b"copy").unwrap();
    fs::create_dir(root.join("restored")).unwrap();
    fs::write(root.join("restored/skip.txt"), b"keep").unwrap();
}

#[test]
fn redirected_execute_reports_selected_source_all_skips_and_summary() {
    let root = testdir!();
    progress_fixture(&root);
    let output = run_execute(&root, "archive=source");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains(['\r', '\x1b']));
    let copy_line = stdout
        .lines()
        .find(|line| line.starts_with("[COPY]"))
        .unwrap();
    assert!(copy_line.contains("copy.txt"));
    assert!(copy_line.contains("\"archive\" ->"));
    for (name, reason) in [
        ("skip.txt", "existing file (skip-always)"),
        ("absent.txt", "no matching source in plan"),
        ("offline.txt", "no candidate source mounted ([\"offline\"])"),
    ] {
        assert!(stdout.lines().any(|line| line.starts_with("[SKIP]")
            && line.contains(name)
            && line.contains(reason)));
    }
    assert!(stdout.contains("Summary: 1 copied (4 bytes), 3 skipped, 0 failed, 0 not processed"));
    assert!(stdout.contains("existing: 1, matching metadata: 0, no source: 1, unmounted: 1"));
    assert_eq!(fs::read(root.join("restored/copy.txt")).unwrap(), b"copy");
    assert_eq!(fs::read(root.join("restored/skip.txt")).unwrap(), b"keep");
}

#[test]
fn missing_source_diagnostic_identifies_operation_and_path() {
    let root = testdir!();
    progress_fixture(&root);
    fs::remove_file(root.join("source/copy.txt")).unwrap();
    let output = run_execute(&root, "archive=source");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to read source metadata"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&Path::new("source").join("copy.txt").display().to_string()),
        "{stderr}"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Summary (incomplete)"));
}

#[test]
fn failed_execute_reports_partial_summary_and_stops() {
    let root = testdir!();
    progress_fixture(&root);
    fs::write(root.join("source/copy.txt"), b"wrong size").unwrap();
    let output = run_execute(&root, "archive=source");
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Summary (incomplete): 0 copied (0 bytes)"));
    assert!(stdout.contains("1 failed"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Failed to copy"));
    assert!(!root.join("restored/copy.txt").exists());
}
