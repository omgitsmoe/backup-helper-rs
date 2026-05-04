use crate::{MostCurrentArgs, VerifyMatcherArgs};

use std::path::Path;


pub fn verify_root(root: impl AsRef<Path>, _most_current_args: MostCurrentArgs, _matcher: VerifyMatcherArgs) -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::absolute(root)?;
    let mut ch = checksum_helper::ChecksumHelper::new(&root)?;

    let mut files_found = 0usize;
    let mut files_ignored = 0usize;

    let mut ok = Vec::new();
    let mut missing = Vec::new();
    let mut mismatch = Vec::new();
    let mut mismatch_size = Vec::new();
    let mut corrupted = Vec::new();
    let mut outdated = Vec::new();

    // track current file + last printed progress
    let mut current_file: Option<std::path::PathBuf> = None;

    let verify = ch.verify_root(
        |_path| true,
        |p| {
            match p {
                checksum_helper::checksum_helper::VerifyRootProgress::BuildMostCurrent(
                    most_current_progress,
                ) => match most_current_progress {
                    checksum_helper::checksum_helper::MostCurrentProgress::FoundFile(_path_buf) => {
                        files_found += 1;
                        print!(
                            "\r[BUILD] found {:03} (+ {:03} ignored)",
                            files_found, files_ignored
                        );
                    }

                    checksum_helper::checksum_helper::MostCurrentProgress::IgnoredPath(
                        _path_buf,
                    ) => {
                        files_ignored += 1;
                    }

                    checksum_helper::checksum_helper::MostCurrentProgress::MergeHashFile(
                        path_buf,
                    ) => {
                        println!("\n[MERGE] {:?}", path_buf);
                    }
                },

                checksum_helper::checksum_helper::VerifyRootProgress::Verify(verify_progress) => {
                    match verify_progress {
                        checksum_helper::collection::VerifyProgress::Pre(common) => {
                            let path = common.tree_root.join(common.relative_path);
                            current_file = Some(path.clone());

                            println!(
                                "\n[VERIFY] ({:>4}/{:>4}) {:?}",
                                common.file_number_processed, common.file_number_total, path
                            );

                            println!(
                                "[PROG ] bytes {:>10} / {:>10}",
                                common.size_processed_bytes, common.size_total_bytes
                            );
                        }

                        checksum_helper::collection::VerifyProgress::During(hash_progress) => {
                            if let Some(path) = &current_file {
                                let percent = if hash_progress.bytes_total > 0 {
                                    (hash_progress.bytes_read as f64
                                        / hash_progress.bytes_total as f64)
                                        * 100.0
                                } else {
                                    0.0
                                };

                                print!(
                                    "\r[HASH ] {:<30} {:>8}/{:>8} bytes ({:5.1}%)",
                                    path.file_name().unwrap_or_default().to_string_lossy(),
                                    hash_progress.bytes_read,
                                    hash_progress.bytes_total,
                                    percent
                                );
                            } else {
                                print!(
                                    "\r[HASH ] {:>8}/{:>8} bytes",
                                    hash_progress.bytes_read, hash_progress.bytes_total
                                );
                            }
                        }

                        checksum_helper::collection::VerifyProgress::Post(post) => {
                            let path = post.progress.tree_root.join(post.progress.relative_path);

                            print!("\r");

                            let status = match post.result {
                                checksum_helper::hashed_file::VerifyResult::Ok => {
                                    ok.push(path.clone());
                                    "[OK      ]"
                                }

                                checksum_helper::hashed_file::VerifyResult::FileMissing(_error_kind) => {
                                    missing.push(path.clone());
                                    "[ERR MISS]"
                                }

                                checksum_helper::hashed_file::VerifyResult::Mismatch => {
                                    mismatch.push(path.clone());
                                    "[ERR HASH]"
                                }

                                checksum_helper::hashed_file::VerifyResult::MismatchSize => {
                                    mismatch_size.push(path.clone());
                                    "[ERR SIZE]"
                                }

                                checksum_helper::hashed_file::VerifyResult::MismatchCorrupted => {
                                    corrupted.push(path.clone());
                                    "[ERR CORR]"
                                }

                                checksum_helper::hashed_file::VerifyResult::MismatchOutdatedHash => {
                                    outdated.push(path.clone());
                                    "[WARN OLD]" // not strictly an error
                                }
                            };

                            println!("{} {:?}", status, path);
                        }
                    }
                }
            }
        },
    );

    println!("\n========== VERIFY SUMMARY ==========");

    let total = ok.len()
        + missing.len()
        + mismatch.len()
        + mismatch_size.len()
        + corrupted.len()
        + outdated.len();

    println!(
        "Total: {} | OK: {} | ERR: {} | WARN: {}",
        total,
        ok.len(),
        missing.len() + mismatch.len() + mismatch_size.len() + corrupted.len(),
        outdated.len()
    );

    if missing.is_empty() && mismatch.is_empty() && mismatch_size.is_empty() && corrupted.is_empty()
    {
        println!("✅ ALL FILES VERIFIED SUCCESSFULLY");
    } else {
        println!("❌ VERIFICATION FAILED\n");

        if !missing.is_empty() {
            println!("--- Missing files ({}) ---", missing.len());
            for p in &missing {
                println!("[ERR MISS] {:?}", p);
            }
            println!();
        }

        if !mismatch.is_empty() {
            println!("--- Hash mismatches ({}) ---", mismatch.len());
            for p in &mismatch {
                println!("[ERR HASH] {:?}", p);
            }
            println!();
        }

        if !mismatch_size.is_empty() {
            println!("--- Size mismatches ({}) ---", mismatch_size.len());
            for p in &mismatch_size {
                println!("[ERR SIZE] {:?}", p);
            }
            println!();
        }

        if !corrupted.is_empty() {
            println!("--- Corrupted files ({}) ---", corrupted.len());
            for p in &corrupted {
                println!("[ERR CORR] {:?}", p);
            }
            println!();
        }
    }

    // Warnings separately (less alarming)
    if !outdated.is_empty() {
        println!("--- Outdated hashes ({}) ---", outdated.len());
        for p in &outdated {
            println!("[WARN OLD] {:?}", p);
        }
    }

    if let Err(err) = verify {
        println!("ERR: {}", err);
        std::process::exit(-1);
    } else {
        println!("Success! Verified all files!")
    }

    Ok(())
}

pub fn verify_file(_root: impl AsRef<Path>, _matcher: VerifyMatcherArgs) -> Result<(), Box<dyn std::error::Error>> {
    todo!()
}
