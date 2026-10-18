use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

use serde_json::json;
use testdir::testdir;

fn run(root: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_restore_helper"))
        .current_dir(root)
        .args(["check", "plan.json", "--target", "restored"])
        .output()
        .unwrap()
}

fn write_plan(root: &Path) {
    let file = |name, size| {
        json!({
            "hash_type": "sha256", "hash": "00", "size": size,
            "mtime": null, "content": 0, "relative_path": name
        })
    };
    fs::write(
        root.join("plan.json"),
        serde_json::to_vec(&json!({
            "source_manifests": [],
            "contents": [{"key": {"hash_type": "sha256", "hash": "00"}, "sources": []}],
            "files": [file("a", 3), file("b", 4)]
        }))
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn reports_problems_and_summary_with_failure_exit() {
    let root = testdir!();
    write_plan(&root);
    fs::create_dir(root.join("restored")).unwrap();
    fs::write(root.join("restored/b"), b"bad").unwrap();
    let output = run(&root);
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let missing = Path::new("restored").join("a");
    let mismatched = Path::new("restored").join("b");
    assert!(stdout.contains(&format!("MISSING {}", missing.display())));
    assert!(stdout.contains(&format!(
        "MISMATCH {} size: expected 4, actual 3",
        mismatched.display()
    )));
    assert!(stdout.contains("Matching: 0, missing: 1, mismatched: 1, not regular: 0, errors: 0"));
    assert!(!stdout.contains(['\r', '\x1b']));
}

#[test]
fn matching_files_succeed_without_per_file_output_or_mounts() {
    let root = testdir!();
    write_plan(&root);
    fs::create_dir(root.join("restored")).unwrap();
    fs::write(root.join("restored/a"), b"abc").unwrap();
    fs::write(root.join("restored/b"), b"abcd").unwrap();
    fs::write(root.join("restored/unrelated"), b"ignored").unwrap();
    let output = run(&root);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "Matching: 2, missing: 0, mismatched: 0, not regular: 0, errors: 0\n"
    );
}

#[test]
fn invalid_or_missing_plan_fails_before_summary() {
    let root = testdir!();
    let output = run(&root);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    fs::write(root.join("plan.json"), "{").unwrap();
    let output = run(&root);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}
