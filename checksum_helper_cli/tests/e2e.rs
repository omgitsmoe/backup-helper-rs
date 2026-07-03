mod common;

use filetime::FileTime;

// ============================================================
// Phase A: build
// ============================================================

#[test]
fn test_build_merges_hash_files() {
    let root = common::testdir();
    common::create_ftree(
        &root,
        "\
file1.txt
subdir/file2.txt",
    );

    let older = "\
# version 1
,,sha512,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa file1.txt
";
    std::fs::write(root.join("older.cshd"), older).unwrap();
    filetime::set_file_mtime(&root.join("older.cshd"), FileTime::from_unix_time(100, 0)).unwrap();

    let newer = "\
# version 1
,,sha512,bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb subdir/file2.txt
";
    std::fs::write(root.join("newer.cshd"), newer).unwrap();
    filetime::set_file_mtime(&root.join("newer.cshd"), FileTime::from_unix_time(200, 0)).unwrap();

    let (stdout, stderr, success) = common::run_cli(&["build", &root.to_string_lossy()]);
    assert!(success, "build failed: stderr={}", stderr);

    let output_path = common::parse_collection_path(&stdout)
        .unwrap_or_else(|| panic!("expected 'Wrote collection at:' in stdout: {}", stdout));
    assert!(
        output_path.exists(),
        "output file not found: {:?}",
        output_path
    );

    let contents = std::fs::read_to_string(&output_path).unwrap();
    assert!(contents.contains("file1.txt"), "contents: {}", contents);
    assert!(
        contents.contains("subdir/file2.txt"),
        "contents: {}",
        contents
    );
}

#[test]
fn test_build_merges_with_newer_mtime_winning() {
    let root = common::testdir();
    common::create_ftree(
        &root,
        "\
file1.txt
",
    );

    // Both hash files cover file1.txt, but with different hashes.
    // The file with the newer mtime should win.
    let older = "\
# version 1
,,md5,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa file1.txt
";
    std::fs::write(root.join("older.cshd"), older).unwrap();
    filetime::set_file_mtime(&root.join("older.cshd"), FileTime::from_unix_time(100, 0)).unwrap();

    let newer = "\
# version 1
,,sha256,bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb file1.txt
";
    std::fs::write(root.join("newer.cshd"), newer).unwrap();
    filetime::set_file_mtime(&root.join("newer.cshd"), FileTime::from_unix_time(200, 0)).unwrap();

    let (stdout, stderr, success) = common::run_cli(&["build", &root.to_string_lossy()]);
    assert!(success, "build failed: stderr={}", stderr);

    let output_path = common::parse_collection_path(&stdout)
        .unwrap_or_else(|| panic!("expected 'Wrote collection at:' in stdout: {}", stdout));
    let contents = std::fs::read_to_string(&output_path).unwrap();

    // The newer file's sha256 hash should win
    assert!(
        contents.contains("sha256"),
        "expected sha256 hash from newer file, got: {}",
        contents
    );
    assert!(
        !contents.contains("md5,aaaaaaaa"),
        "expected md5 hash from older file to be overwritten, got: {}",
        contents
    );
}

#[test]
fn test_build_discover_hash_files_depth() {
    let root = common::testdir();
    common::create_ftree(
        &root,
        "\
file1.txt
sub/file2.txt
sub/deep/file3.txt",
    );

    // Hash files at root, sub, and sub/deep levels
    let root_hf = "\
# version 1
,,sha512,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa file1.txt
";
    std::fs::write(root.join("root.cshd"), root_hf).unwrap();
    filetime::set_file_mtime(&root.join("root.cshd"), FileTime::from_unix_time(100, 0)).unwrap();

    let sub_hf = "\
# version 1
,,sha512,bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb file2.txt
";
    std::fs::write(root.join("sub").join("sub.cshd"), sub_hf).unwrap();
    filetime::set_file_mtime(&root.join("sub").join("sub.cshd"), FileTime::from_unix_time(101, 0))
        .unwrap();

    let deep_hf = "\
# version 1
,,sha512,cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc file3.txt
";
    std::fs::write(root.join("sub").join("deep").join("deep.cshd"), deep_hf).unwrap();
    filetime::set_file_mtime(
        &root.join("sub").join("deep").join("deep.cshd"),
        FileTime::from_unix_time(102, 0),
    )
    .unwrap();

    // depth=1 should find root.cshd and sub.cshd, but NOT deep.cshd
    let (stdout, stderr, success) = common::run_cli(&[
        "build",
        &root.to_string_lossy(),
        "--discover-hash-files-depth",
        "1",
    ]);
    assert!(success, "build failed: stderr={}", stderr);

    let output_path = common::parse_collection_path(&stdout)
        .unwrap_or_else(|| panic!("expected 'Wrote collection at:' in stdout: {}", stdout));
    let contents = std::fs::read_to_string(&output_path).unwrap();
    assert!(contents.contains("file1.txt"), "contents: {}", contents);
    assert!(
        contents.contains("file2.txt"),
        "contents: {}",
        contents
    );
    assert!(
        !contents.contains("file3.txt"),
        "file3 should not appear at depth=1, contents: {}",
        contents
    );
}

#[test]
fn test_build_with_hash_allow_filter() {
    let root = common::testdir();
    common::create_ftree(
        &root,
        "\
file1.txt",
    );

    let cshd = "\
# version 1
,,sha512,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa file1.txt
";
    std::fs::write(root.join("data.cshd"), cshd).unwrap();
    filetime::set_file_mtime(&root.join("data.cshd"), FileTime::from_unix_time(100, 0)).unwrap();

    let md5 = "\
aaaaaabbbbbbccccccddddddeeeeeeffffffff file1.txt
";
    std::fs::write(root.join("data.md5"), md5).unwrap();
    filetime::set_file_mtime(&root.join("data.md5"), FileTime::from_unix_time(200, 0)).unwrap();

    // Only allow .cshd files
    let (stdout, stderr, success) = common::run_cli(&[
        "build",
        &root.to_string_lossy(),
        "--hash-allow",
        "*.cshd",
    ]);
    assert!(success, "build failed: stderr={}", stderr);

    let output_path = common::parse_collection_path(&stdout)
        .unwrap_or_else(|| panic!("expected 'Wrote collection at:' in stdout: {}", stdout));
    let contents = std::fs::read_to_string(&output_path).unwrap();
    let stripped = common::cshd_strip_mtime(&contents);
    // Should have the .cshd entry, not the .md5 one
    assert!(
        stripped.contains("sha512,aaaaaaaa"),
        "expected sha512 from .cshd file, got: {}",
        stripped
    );
}

#[test]
fn test_build_with_keep_deleted() {
    let root = common::testdir();
    common::create_ftree(
        &root,
        "\
existing.txt",
    );

    let cshd = "\
# version 1
,,sha512,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa existing.txt
,,sha512,bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb deleted.txt
";
    std::fs::write(root.join("data.cshd"), cshd).unwrap();
    filetime::set_file_mtime(&root.join("data.cshd"), FileTime::from_unix_time(100, 0)).unwrap();

    // Without --keep-deleted, deleted.txt should be filtered out
    let (stdout, stderr, success) = common::run_cli(&["build", &root.to_string_lossy()]);
    assert!(success, "build failed: stderr={}", stderr);
    let output_path = common::parse_collection_path(&stdout)
        .unwrap_or_else(|| panic!("expected 'Wrote collection at:' in stdout: {}", stdout));
    let contents = std::fs::read_to_string(&output_path).unwrap();
    assert!(
        contents.contains("existing.txt"),
        "contents: {}",
        contents
    );
    assert!(
        !contents.contains("deleted.txt"),
        "deleted.txt should be filtered out by default, contents: {}",
        contents
    );

    // With --keep-deleted, deleted.txt should remain
    let root2 = common::testdir();
    // copy the same .cshd
    std::fs::write(root2.join("data.cshd"), cshd).unwrap();
    filetime::set_file_mtime(&root2.join("data.cshd"), FileTime::from_unix_time(100, 0)).unwrap();
    // create existing.txt too (but not deleted.txt)
    std::fs::write(root2.join("existing.txt"), "existing.txt").unwrap();

    let (stdout2, stderr2, success2) =
        common::run_cli(&["build", &root2.to_string_lossy(), "--keep-deleted"]);
    assert!(success2, "build failed: stderr={}", stderr2);
    let output_path2 = common::parse_collection_path(&stdout2)
        .unwrap_or_else(|| panic!("expected 'Wrote collection at:' in stdout: {}", stdout2));
    let contents2 = std::fs::read_to_string(&output_path2).unwrap();
    assert!(
        contents2.contains("existing.txt"),
        "contents: {}",
        contents2
    );
    assert!(
        contents2.contains("deleted.txt"),
        "deleted.txt should be kept with --keep-deleted, contents: {}",
        contents2
    );
}

// ============================================================
// Phase B: verify
// ============================================================

#[test]
fn test_verify_file_ok() {
    let root = common::testdir();
    let relpath = "hello.txt";
    common::create_ftree(&root, relpath);
    let cshd = format!(
        "\
# version 1
,,sha512,{} {}
",
        "acec329f80cc50edbab0dfbc2283d427ac673f84e6d8b949101791867b9b7771a53d2ffb1f8386189227beed4395b9a78171a1349700e2885c70ae14358d72ff",
        relpath
    );
    let cshd_path = root.join("test.cshd");
    std::fs::write(&cshd_path, &cshd).unwrap();

    let (stdout, stderr, success) =
        common::run_cli(&["verify", "file", &cshd_path.to_string_lossy()]);
    assert!(success, "verify file failed: stderr={}", stderr);
    assert!(
        stdout.contains("[OK        ]"),
        "expected OK in output: {}",
        stdout
    );
    assert!(
        stdout.contains("SUCCESSFULLY"),
        "expected success summary: {}",
        stdout
    );
}

#[test]
fn test_verify_file_missing() {
    let root = common::testdir();
    let cshd = "\
# version 1
,,sha512,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa nonexistent.txt
";
    let cshd_path = root.join("test.cshd");
    std::fs::write(&cshd_path, cshd).unwrap();

    let (stdout, _stderr, success) =
        common::run_cli(&["verify", "file", &cshd_path.to_string_lossy()]);
    assert!(!success, "verify should fail when file is missing");
    assert!(
        stdout.contains("[ERR MISS  ]"),
        "expected MISS in output: {}",
        stdout
    );
}

#[test]
fn test_verify_file_corrupted() {
    let root = common::testdir();
    let relpath = "data.bin";
    common::create_ftree(&root, relpath);
    // Use a wrong hash to simulate corruption
    let wrong_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let cshd = format!(
        "\
# version 1
,,sha512,{} {}
",
        wrong_hash, relpath
    );
    let cshd_path = root.join("test.cshd");
    std::fs::write(&cshd_path, &cshd).unwrap();

    let (stdout, _stderr, success) =
        common::run_cli(&["verify", "file", &cshd_path.to_string_lossy()]);
    assert!(!success, "verify should fail on hash mismatch");

    if stdout.contains("[ERR SIZE  ]") {
        // Size mismatch is also acceptable
    } else if stdout.contains("[ERR HASH  ]") {
        // Hash mismatch is also acceptable
    } else {
        panic!(
            "expected ERR SIZE or ERR HASH in output, got: {}",
            stdout
        );
    }
}

#[test]
fn test_verify_file_with_filter() {
    let root = common::testdir();
    common::create_ftree(
        &root,
        "\
keep.txt
skip.txt",
    );

    let cshd = format!(
        "\
# version 1
,,sha512,{} keep.txt
,,sha512,{} skip.txt
",
        "45b8c7cb621057989f000d254b0b31e0aec2063e5796962ead702b9f756fbbdad56260821e6cef50bbff014155fa26424ed5e8426f619b9db8a8857e76fb81d5",
        "50e3bc7a4c158a13d06d6db520363151677519bbe9a51ee97bcd83fdc838e1f55f9fa756592526a601fc7252d20e9b13bbf2813d4f888349ee3ac2271db74da5",
    );
    let cshd_path = root.join("test.cshd");
    std::fs::write(&cshd_path, &cshd).unwrap();

    // Only verify keep.txt — skip.txt entries still exist but only keep.txt is verified
    let (stdout, stderr, success) = common::run_cli(&[
        "verify",
        "file",
        &cshd_path.to_string_lossy(),
        "--verify-allow",
        "keep.txt",
    ]);
    assert!(success, "verify file with filter failed: stderr={}", stderr);
    assert!(
        stdout.contains("OK:"),
        "expected OK count in summary: {}",
        stdout
    );
}

#[test]
fn test_verify_root_merges_and_verifies() {
    let root = common::testdir();
    common::create_ftree(
        &root,
        "\
good.txt",
    );

    let cshd = format!(
        "\
# version 1
,,sha512,{} good.txt
",
        "8ab6060ca8a175c695ff1e2e8a116570e37f0bb2c8f939610d9a0d96b669134c292ec1fa48b235a055dcdc4f4fe233fbecc71048d71d6dac2d27fb1a1f5f2c02"
    );
    // File content matches hash — OK
    let cshd_path = root.join("ok.cshd");
    std::fs::write(&cshd_path, &cshd).unwrap();
    filetime::set_file_mtime(&cshd_path, FileTime::from_unix_time(100, 0)).unwrap();

    let (stdout, stderr, success) =
        common::run_cli(&["verify", "root", &root.to_string_lossy()]);
    assert!(success, "verify root failed: stderr={}", stderr);
    assert!(
        stdout.contains("SUCCESSFULLY"),
        "expected success summary: {}",
        stdout
    );
}

#[test]
fn test_verify_root_with_corrupted_file() {
    let root = common::testdir();
    common::create_ftree(
        &root,
        "\
good.txt
bad.txt",
    );

    let hash_bad = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let cshd = format!(
        "\
# version 1
,,sha512,{} good.txt
,,sha512,{} bad.txt
",
        "8ab6060ca8a175c695ff1e2e8a116570e37f0bb2c8f939610d9a0d96b669134c292ec1fa48b235a055dcdc4f4fe233fbecc71048d71d6dac2d27fb1a1f5f2c02",
        hash_bad
    );
    let cshd_path = root.join("data.cshd");
    std::fs::write(&cshd_path, &cshd).unwrap();
    filetime::set_file_mtime(&cshd_path, FileTime::from_unix_time(100, 0)).unwrap();

    let (stdout, _stderr, success) =
        common::run_cli(&["verify", "root", &root.to_string_lossy()]);
    assert!(!success, "verify root should fail when files are corrupted");
    assert!(
        stdout.contains("VERIFICATION FAILED"),
        "expected failure message: {}",
        stdout
    );
}

// ============================================================
// Phase C: incremental + fill
// ============================================================

#[test]
fn test_incremental_basic() {
    let root = common::testdir();
    common::create_ftree(
        &root,
        "\
file1.txt",
    );

    let (stdout, stderr, success) = common::run_cli(&[
        "incremental",
        &root.to_string_lossy(),
    ]);
    assert!(success, "incremental failed: stderr={}", stderr);

    let output_path = common::parse_collection_path(&stdout)
        .unwrap_or_else(|| panic!("expected 'Wrote collection at:' in stdout: {}", stdout));
    assert!(output_path.exists(), "output file not found: {:?}", output_path);

    let contents = std::fs::read_to_string(&output_path).unwrap();
    assert!(
        contents.contains(" file1.txt"),
        "expected file1.txt in output: {}",
        contents
    );
    common::assert_entry_hash(&contents, "file1.txt",
        "055dc805570eecebad4270774054ee4375ef9a7248d981cfa8155dc884817df31e8497684dd26addd018a30565c3ccf87eeb70445f2e76587af84ed6ce1e0302");
}

#[test]
fn test_incremental_with_existing_hash() {
    let root = common::testdir();
    common::create_ftree(
        &root,
        "\
file1.txt
file2.txt",
    );

    let cshd = format!(
        "\
# version 1
,,sha512,{} file1.txt
",
        "055dc805570eecebad4270774054ee4375ef9a7248d981cfa8155dc884817df31e8497684dd26addd018a30565c3ccf87eeb70445f2e76587af84ed6ce1e0302"
    );
    let cshd_path = root.join("existing.cshd");
    std::fs::write(&cshd_path, &cshd).unwrap();
    filetime::set_file_mtime(&cshd_path, FileTime::from_unix_time(100, 0)).unwrap();

    // file1.txt already has a hash — incremental should only add file2.txt
    // (by default include_unchanged=True, so file1.txt should appear too)
    let (stdout, stderr, success) = common::run_cli(&[
        "incremental",
        &root.to_string_lossy(),
    ]);
    assert!(success, "incremental failed: stderr={}", stderr);

    let output_path = common::parse_collection_path(&stdout)
        .unwrap_or_else(|| panic!("expected 'Wrote collection at:' in stdout: {}", stdout));
    let contents = std::fs::read_to_string(&output_path).unwrap();
    assert!(
        contents.contains(" file1.txt"),
        "expected file1.txt (unchanged but included by default): {}",
        contents
    );
    assert!(
        contents.contains(" file2.txt"),
        "expected file2.txt (new file): {}",
        contents
    );
    common::assert_entry_hash(&contents, "file1.txt",
        "055dc805570eecebad4270774054ee4375ef9a7248d981cfa8155dc884817df31e8497684dd26addd018a30565c3ccf87eeb70445f2e76587af84ed6ce1e0302");
    common::assert_entry_hash(&contents, "file2.txt",
        "2b85daf030ebc94d302822da4fd50216dc56f90c9bb60a95b272aa5b11fe81cd9b192b1a860896d6a8241d1a42cc97b6015d42100c9b46432a32db4b13a11c58");
}

#[test]
fn test_incremental_no_include_unchanged() {
    let root = common::testdir();
    common::create_ftree(
        &root,
        "\
existing.txt
new.txt",
    );

    // Set a known mtime so the hash entry can reference it.
    // Without a matching mtime in the hash entry, the incremental command
    // always includes the file (to seed mtime-based skipping for future runs).
    let known_mtime = FileTime::from_unix_time(100, 0);
    filetime::set_file_mtime(root.join("existing.txt"), known_mtime).unwrap();

    let cshd = format!(
        "\
# version 1
100,12,sha512,{} existing.txt
",
        "1305473c35428e9ede0589b43ca9fb05ed31df4343ca8aba4036e20445f42718fcd9d3e575e0b04cfeb2d2c20298359858d5891a2d530ec0ffd532a0fef42126"
    );
    let cshd_path = root.join("existing.cshd");
    std::fs::write(&cshd_path, &cshd).unwrap();
    filetime::set_file_mtime(&cshd_path, FileTime::from_unix_time(100, 0)).unwrap();

    let (stdout, stderr, success) = common::run_cli(&[
        "incremental",
        &root.to_string_lossy(),
        "--no-include-unchanged",
    ]);
    assert!(success, "incremental failed: stderr={}", stderr);

    let output_path = common::parse_collection_path(&stdout)
        .unwrap_or_else(|| panic!("expected 'Wrote collection at:' in stdout: {}", stdout));
    let contents = std::fs::read_to_string(&output_path).unwrap();
    assert!(
        !contents.contains(" existing.txt"),
        "existing.txt should NOT appear with --no-include-unchanged: {}",
        contents
    );
    assert!(
        contents.contains(" new.txt"),
        "new.txt should appear: {}",
        contents
    );
    common::assert_entry_hash(&contents, "new.txt",
        "d3d67bc3e3848925892de9b132c9ff4054a05c9dbc7b4366d16b5c6b87c898df60da162e9ec415d4dc16470128ef52c11c44fc06da2841543ddeb351b10e9fb2");
}

#[test]
fn test_fill_basic() {
    let root = common::testdir();
    common::create_ftree(
        &root,
        "\
protected.txt
unprotected.txt",
    );

    // protect protected.txt with a hash file
    let cshd = format!(
        "\
# version 1
,,sha512,{} protected.txt
",
        "a5717e2c691af2dbc0ba8a753f1198cd8ff573592f4a73d26e5589bf24de7cc146a96289f813bc9f654b497bb385fc523a5fcca4c6b1c34058f1b34f75dfba70"
    );
    let cshd_path = root.join("existing.cshd");
    std::fs::write(&cshd_path, &cshd).unwrap();
    filetime::set_file_mtime(&cshd_path, FileTime::from_unix_time(100, 0)).unwrap();

    let (stdout, stderr, success) = common::run_cli(&[
        "fill",
        &root.to_string_lossy(),
    ]);
    assert!(success, "fill failed: stderr={}", stderr);

    let output_path = common::parse_collection_path(&stdout)
        .unwrap_or_else(|| panic!("expected 'Wrote collection at:' in stdout: {}", stdout));
    let contents = std::fs::read_to_string(&output_path).unwrap();
    // unprotected.txt should be in the fill output
    assert!(
        contents.contains("unprotected.txt"),
        "expected unprotected.txt in fill output: {}",
        contents
    );
    // protected.txt should NOT be in the fill output (it already has a hash)
    // NB: use " protected.txt" to avoid matching "unprotected.txt"
    assert!(
        !contents.contains(" protected.txt"),
        "protected.txt should not appear in fill output: {}",
        contents
    );
}

#[test]
fn test_fill_with_allowlist() {
    let root = common::testdir();
    common::create_ftree(
        &root,
        "\
keep.txt
skip.txt",
    );

    let (stdout, stderr, success) = common::run_cli(&[
        "fill",
        &root.to_string_lossy(),
        "--all-allow",
        "keep.txt",
    ]);
    assert!(success, "fill failed: stderr={}", stderr);

    let output_path = common::parse_collection_path(&stdout)
        .unwrap_or_else(|| panic!("expected 'Wrote collection at:' in stdout: {}", stdout));
    let contents = std::fs::read_to_string(&output_path).unwrap();
    assert!(
        contents.contains("keep.txt"),
        "expected keep.txt: {}",
        contents
    );
    assert!(
        !contents.contains("skip.txt"),
        "skip.txt should be excluded by filter: {}",
        contents
    );
}

// ============================================================
// Phase D: move
// ============================================================

#[test]
#[ignore = "move_hash_file is not yet implemented (todo!())"]
fn test_move_file() {
    let root = common::testdir();
    common::create_ftree(
        &root,
        "\
sub/file.txt",
    );

    let cshd = format!(
        "\
# version 1
,,sha512,{} sub/file.txt
",
        "276e5a2207153c071671cd03bf6af11ec342b056538434e185bc1ce1f45a6420f8220bcd2d60eb7ef35f9b8d28f09ae79f7eb51887c73be2c48ef200ebc41b55"
    );
    let src_path = root.join("test.cshd");
    std::fs::write(&src_path, &cshd).unwrap();
    filetime::set_file_mtime(&src_path, FileTime::from_unix_time(100, 0)).unwrap();
    let original_mtime =
        filetime::FileTime::from_last_modification_time(&std::fs::metadata(&src_path).unwrap());

    let dst_path = root.join("moved.cshd");
    let (_stdout, stderr, success) = common::run_cli(&[
        "move",
        &src_path.to_string_lossy(),
        &dst_path.to_string_lossy(),
    ]);
    assert!(success, "move failed: stderr={}", stderr);

    // Source file should be gone, destination should exist
    assert!(!src_path.exists(), "source should not exist after move");
    assert!(dst_path.exists(), "destination should exist after move");

    // mtime should be preserved (best effort comparison)
    let dst_mtime =
        filetime::FileTime::from_last_modification_time(&std::fs::metadata(&dst_path).unwrap());
    assert_eq!(
        original_mtime, dst_mtime,
        "mtime should be preserved on move"
    );

    // The internal paths should be unchanged since we moved within same dir
    let contents = std::fs::read_to_string(&dst_path).unwrap();
    assert!(
        contents.contains("file.txt"),
        "expected file.txt in moved hash file: {}",
        contents
    );
}

#[test]
fn test_move_file_error_no_source() {
    let root = common::testdir();
    let (_stdout, _stderr, success) = common::run_cli(&[
        "move",
        &root.join("nonexistent.cshd").to_string_lossy(),
        &root.join("dest.cshd").to_string_lossy(),
    ]);
    assert!(!success, "move should fail when source doesn't exist");
}
