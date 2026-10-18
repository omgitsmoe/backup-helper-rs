use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use filetime::FileTime;
use sha2::{Digest, Sha256};
use testdir::testdir;

const POLICIES: [&str; 3] = ["skip-always", "skip-same-metadata", "overwrite"];
const SOURCE_MTIME: i64 = 5678;
const TARGET_MTIME: i64 = 1234;

struct Entry {
    path: &'static str,
    bytes: &'static [u8],
    mtime: Option<i64>,
}

const TARGETS: [Entry; 6] = [
    Entry {
        path: "root.txt",
        bytes: b"root",
        mtime: Some(TARGET_MTIME),
    },
    Entry {
        path: "docs/readme.txt",
        bytes: b"readme",
        mtime: Some(TARGET_MTIME),
    },
    Entry {
        path: "docs/deep/same.txt",
        bytes: b"same",
        mtime: Some(TARGET_MTIME),
    },
    Entry {
        path: "docs/deep/size.txt",
        bytes: b"size",
        mtime: Some(TARGET_MTIME),
    },
    Entry {
        path: "docs/deep/time.txt",
        bytes: b"time",
        mtime: Some(TARGET_MTIME),
    },
    Entry {
        path: "other/deep/duplicate.txt",
        bytes: b"root",
        mtime: None,
    },
];

fn write_file(path: &Path, bytes: &[u8], mtime: i64) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
    filetime::set_file_mtime(path, FileTime::from_unix_time(mtime, 0)).unwrap();
}

fn write_manifest(path: &Path, entries: &[Entry]) {
    let mut text = String::from("# version 1\n");
    for entry in entries {
        let mtime = entry.mtime.map(|time| time.to_string()).unwrap_or_default();
        text.push_str(&format!(
            "{mtime},{},sha256,{:x} {}\n",
            entry.bytes.len(),
            Sha256::digest(entry.bytes),
            entry.path,
        ));
    }
    fs::write(path, text).unwrap();
}

fn cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_restore_helper"))
        .current_dir(root)
        .args(args)
        .output()
        .unwrap()
}

fn success(output: Output) {
    assert!(
        output.status.success(),
        "status: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn failure(output: Output, diagnostic: &str) {
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(diagnostic),
        "expected {diagnostic:?}, got {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn execute(root: &Path, policy: &str, mounts: &[&str]) -> Output {
    let mut args = vec![
        "execute",
        "plan.json",
        "--target",
        "restored",
        "--existing-file-policy",
        policy,
    ];
    for mount in mounts {
        args.extend(["--mount", mount]);
    }
    cli(root, &args)
}

fn fixture(root: &Path) {
    write_manifest(&root.join("target.cshd"), &TARGETS);
    let a = [
        Entry {
            path: "renamed/root.bin",
            bytes: b"root",
            mtime: Some(SOURCE_MTIME),
        },
        Entry {
            path: "archive/readme.bin",
            bytes: b"readme",
            mtime: Some(SOURCE_MTIME),
        },
        Entry {
            path: "archive/deep/same.bin",
            bytes: b"same",
            mtime: Some(SOURCE_MTIME),
        },
    ];
    let b = [
        Entry {
            path: "backup/root.bin",
            bytes: b"root",
            mtime: Some(SOURCE_MTIME),
        },
        Entry {
            path: "backup/deep/size.bin",
            bytes: b"size",
            mtime: Some(SOURCE_MTIME),
        },
        Entry {
            path: "backup/deep/time.bin",
            bytes: b"time",
            mtime: Some(SOURCE_MTIME),
        },
    ];
    let unrelated = [Entry {
        path: "unrelated.txt",
        bytes: b"unrelated",
        mtime: Some(SOURCE_MTIME),
    }];
    for (name, entries) in [
        ("a", a.as_slice()),
        ("b", b.as_slice()),
        ("unrelated", unrelated.as_slice()),
    ] {
        write_manifest(&root.join(format!("{name}.cshd")), entries);
        for entry in entries {
            write_file(&root.join(name).join(entry.path), entry.bytes, SOURCE_MTIME);
        }
    }
    success(cli(
        root,
        &[
            "plan",
            "target.cshd",
            "--source",
            "a=a.cshd",
            "--source",
            "b=b.cshd",
            "--source",
            "unrelated=unrelated.cshd",
        ],
    ));
    let _: restore_helper::Plan =
        serde_json::from_slice(&fs::read(root.join("plan.json")).unwrap()).unwrap();
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, (Vec<u8>, FileTime)> {
    fn visit(base: &Path, path: &Path, result: &mut BTreeMap<PathBuf, (Vec<u8>, FileTime)>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            if metadata.is_dir() {
                visit(base, &entry.path(), result);
            } else {
                assert!(metadata.is_file(), "unexpected entry: {:?}", entry.path());
                result.insert(
                    entry.path().strip_prefix(base).unwrap().to_path_buf(),
                    (
                        fs::read(entry.path()).unwrap(),
                        FileTime::from_last_modification_time(&metadata),
                    ),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    if root.exists() {
        visit(root, root, &mut result);
    }
    result
}

fn expected_tree() -> BTreeMap<PathBuf, (Vec<u8>, FileTime)> {
    TARGETS
        .iter()
        .map(|entry| {
            (
                PathBuf::from(entry.path),
                (
                    entry.bytes.to_vec(),
                    FileTime::from_unix_time(entry.mtime.unwrap_or(SOURCE_MTIME), 0),
                ),
            )
        })
        .collect()
}

#[test]
fn plan_then_execute_restores_three_level_tree_under_every_policy() {
    for policy in POLICIES {
        let root = testdir!().join(policy);
        fs::create_dir_all(&root).unwrap();
        fixture(&root);
        success(execute(&root, policy, &["a=a", "b=b"]));
        assert_eq!(snapshot(&root.join("restored")), expected_tree());
        success(execute(&root, policy, &["a=a", "b=b"]));
        assert_eq!(snapshot(&root.join("restored")), expected_tree());
    }
}

#[test]
fn existing_policies_distinguish_matching_size_and_mtime() {
    for policy in POLICIES {
        let root = testdir!().join(policy);
        fs::create_dir_all(&root).unwrap();
        fixture(&root);
        let restored = root.join("restored");
        write_file(&restored.join("docs/deep/same.txt"), b"KEEP", TARGET_MTIME);
        write_file(
            &restored.join("docs/deep/size.txt"),
            b"wrong size",
            TARGET_MTIME,
        );
        write_file(&restored.join("docs/deep/time.txt"), b"KEEP", 999);
        write_file(&restored.join("unrelated/keep.txt"), b"untouched", 888);
        let before = snapshot(&restored);
        success(execute(&root, policy, &["a=a", "b=b"]));
        let mut expected = expected_tree();
        for (path, value) in before {
            if policy == "skip-always"
                || path == Path::new("unrelated/keep.txt")
                || (policy == "skip-same-metadata" && path == Path::new("docs/deep/same.txt"))
            {
                expected.insert(path, value);
            }
        }
        assert_eq!(snapshot(&restored), expected, "policy: {policy}");
    }
}

#[test]
fn partial_mounts_restore_only_available_content_and_can_resume() {
    for policy in POLICIES {
        let root = testdir!().join(policy);
        fs::create_dir_all(&root).unwrap();
        fixture(&root);
        success(execute(&root, policy, &["a=a"]));
        let mut partial = expected_tree();
        partial.remove(Path::new("docs/deep/size.txt"));
        partial.remove(Path::new("docs/deep/time.txt"));
        assert_eq!(snapshot(&root.join("restored")), partial);
        success(execute(&root, policy, &["a=a"]));
        assert_eq!(snapshot(&root.join("restored")), partial);
        success(execute(&root, policy, &["b=b"]));
        assert_eq!(snapshot(&root.join("restored")), expected_tree());
    }
}

#[test]
fn mounted_archive_with_no_matching_content_makes_no_progress() {
    let root = testdir!();
    fixture(&root);
    for policy in POLICIES {
        success(execute(&root, policy, &["unrelated=unrelated"]));
        assert!(!root.join("restored").exists());
    }
    write_file(&root.join("restored/keep.txt"), b"keep", 888);
    let before = snapshot(&root.join("restored"));
    for policy in POLICIES {
        success(execute(&root, policy, &["unrelated=unrelated"]));
        assert_eq!(snapshot(&root.join("restored")), before);
    }
}

#[test]
fn unavailable_content_is_reported_by_plan_and_skipped_by_execute() {
    let root = testdir!();
    fixture(&root);
    let output = cli(
        &root,
        &[
            "plan",
            "target.cshd",
            "--source",
            "a=a.cshd",
            "--output",
            "partial.json",
        ],
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("Files without matching content source: 2")
    );
    success(output);
    fs::rename(root.join("partial.json"), root.join("plan.json")).unwrap();
    success(execute(&root, "overwrite", &["a=a"]));
    let mut expected = expected_tree();
    expected.remove(Path::new("docs/deep/size.txt"));
    expected.remove(Path::new("docs/deep/time.txt"));
    assert_eq!(snapshot(&root.join("restored")), expected);
}

#[test]
fn source_failures_propagate_and_preserve_existing_destination() {
    for (case, diagnostic) in [
        ("missing", "read source metadata"),
        ("directory", "restore source is not a regular file"),
        ("size", "Failed to copy"),
    ] {
        let root = testdir!().join(case);
        fs::create_dir_all(&root).unwrap();
        fixture(&root);
        let source = root.join("a/archive/deep/same.bin");
        fs::remove_file(&source).unwrap();
        match case {
            "missing" => {}
            "directory" => fs::create_dir(&source).unwrap(),
            "size" => fs::write(&source, b"wrong length").unwrap(),
            _ => unreachable!(),
        }
        let target = root.join("restored/docs/deep/same.txt");
        write_file(&target, b"keep", 888);
        failure(execute(&root, "overwrite", &["a=a", "b=b"]), diagnostic);
        assert_eq!(fs::read(&target).unwrap(), b"keep");
        assert_eq!(
            FileTime::from_last_modification_time(&fs::metadata(&target).unwrap()),
            FileTime::from_unix_time(888, 0)
        );
        let names: Vec<_> = fs::read_dir(target.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(
            !names
                .iter()
                .any(|name| name.to_string_lossy().contains(".bh-tmp-"))
        );
    }
}

#[test]
fn directory_target_errors_under_every_policy() {
    for policy in POLICIES {
        let root = testdir!().join(policy);
        fs::create_dir_all(&root).unwrap();
        fixture(&root);
        let target = root.join("restored/docs/deep/same.txt");
        fs::create_dir_all(&target).unwrap();
        write_file(&target.join("keep.txt"), b"keep", 888);
        failure(
            execute(&root, policy, &["a=a", "b=b"]),
            "restore target is a directory",
        );
        assert_eq!(fs::read(target.join("keep.txt")).unwrap(), b"keep");
    }
}

#[cfg(unix)]
#[test]
fn symlink_target_is_skipped_or_rejected_without_touching_referent() {
    use std::os::unix::fs::symlink;
    for policy in POLICIES {
        let root = testdir!().join(policy);
        fs::create_dir_all(&root).unwrap();
        fixture(&root);
        let referent = root.join("outside.txt");
        write_file(&referent, b"keep", 888);
        let target = root.join("restored/docs/deep/same.txt");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        symlink(&referent, &target).unwrap();
        let output = execute(&root, policy, &["a=a", "b=b"]);
        if policy == "skip-always" {
            success(output);
        } else {
            failure(output, "restore target is not a regular file");
        }
        assert_eq!(fs::read_link(target).unwrap(), referent);
        assert_eq!(fs::read(referent).unwrap(), b"keep");
    }
}
