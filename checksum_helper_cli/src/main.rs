use checksum_helper;

use std::path::Path;

use std::io::prelude::*;

fn pause() {
    let mut stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    // We want the cursor to stay at the end of the line, so we print without a newline and flush manually.
    write!(stdout, "Press any key to continue...").unwrap();
    stdout.flush().unwrap();

    // Read a single byte and discard
    let _ = stdin.read(&mut [0u8]).unwrap();
}

fn main() {
    // use std::time::Instant;
    // let now = Instant::now();

    // let _gathered =
    //     checksum_helper::gather::gather(&Path::new("L:\\"), |_| true)
    //     .unwrap();

    // let elapsed = now.elapsed();
    // println!("Elapsed: {:.2?}", elapsed);
    // println!("Items {}", _gathered.file_tree.len());
    // let mem_overhead =
    //     std::mem::size_of::<checksum_helper::file_tree::Entry>()
    //     * (_gathered.file_tree.cap() - _gathered.file_tree.len());
    // println!("MemOverhead {}", mem_overhead);
    // println!("{}", _gathered.file_tree);
    // // pause();
    // // vec 61 mb = 64126K - 1468192
    // // FT add 22 mb = 25664K - 2757744

    // let mut ch = checksum_helper::ChecksumHelper::new(
    //     std::env::current_dir().as_ref().unwrap());
    // let discover = ch.discover_hash_files(None).unwrap();
    // for p in discover.hash_file_paths {
    //     println!("Found {:?}", p);
    // }
    // for e in discover.errors {
    //     println!("ERR: {:?}", e);
    // }
    // let inc = ch.incremental();
    // inc.write(&Path::new("hash.cshd"));
    // let ser = std::fs::read_to_string("obsidian_2024-09-28.cshd").unwrap();
    // let sorted = checksum_helper::collection::sort_serialized(&ser).unwrap();
    // println!("{}", sorted);
    // std::hint::black_box(sorted);

    // Get first CLI argument as the path
    let arg_path = std::env::args().nth(1).expect("Usage: program <path>");
    let abs_path = Path::new(&arg_path).canonicalize().unwrap();

    verify_root(abs_path);
}

fn incremental(abs_path: impl AsRef<Path>) {
    let mut ch = checksum_helper::ChecksumHelper::new(abs_path.as_ref())
        .expect("Failed to create ChecksumHelper");

    let mut files_found = 0;
    let mut files_ignored = 0;

    // track current file for nicer read output
    let mut current_file: Option<std::path::PathBuf> = None;

    let inc = ch
        .incremental(|p| {
            match p {
                checksum_helper::checksum_helper::IncrementalProgress::BuildMostCurrent(
                    most_current_progress,
                ) => {
                    if let checksum_helper::checksum_helper::MostCurrentProgress::MergeHashFile(
                        path_buf,
                    ) = most_current_progress
                    {
                        println!("Merging hash file {:?} into most current", path_buf);
                    }
                }

                checksum_helper::checksum_helper::IncrementalProgress::DiscoverFilesFound(
                    found,
                ) => {
                    files_found = found;
                    print!(
                        "\rFound files: {:003} (+ {:003} ignored)",
                        files_found, files_ignored
                    );
                }

                checksum_helper::checksum_helper::IncrementalProgress::DiscoverFilesIgnored(
                    _path_buf,
                ) => {
                    files_ignored += 1;
                }

                checksum_helper::checksum_helper::IncrementalProgress::DiscoverFilesDone(
                    to_hash,
                    num_ignored,
                ) => {
                    println!(
                        "\nIncremental: Discovering done, found {} (+ {} ignored)",
                        to_hash, num_ignored
                    );
                }

                checksum_helper::checksum_helper::IncrementalProgress::PreRead(path_buf) => {
                    current_file = Some(path_buf.clone());
                    println!("\n[READ ] {:?}", path_buf);
                }

                // assuming (bytes_read, total_bytes) or similar
                checksum_helper::checksum_helper::IncrementalProgress::Read(read, total) => {
                    if let Some(path) = &current_file {
                        print!(
                            "\r[READ ] {:?} {:>8} / {:>8} bytes",
                            path.file_name().unwrap_or_default(),
                            read,
                            total
                        );
                    } else {
                        print!("\r[READ ] {:>8} / {:>8} bytes", read, total);
                    }
                }

                checksum_helper::checksum_helper::IncrementalProgress::FileMatch(path_buf) => {
                    println!("\r[OK   ] {:?} unchanged", path_buf);
                }

                checksum_helper::checksum_helper::IncrementalProgress::FileUnchangedSkipped(
                    path_buf,
                ) => {
                    println!("\r[SKIP ] {:?} (unchanged, skipped)", path_buf);
                }

                checksum_helper::checksum_helper::IncrementalProgress::FileChanged(path_buf) => {
                    println!("\r[CHG  ] {:?} modified", path_buf);
                }

                checksum_helper::checksum_helper::IncrementalProgress::FileChangedCorrupted(
                    path_buf,
                ) => {
                    println!("\r[CORR ] {:?} corrupted", path_buf);
                }

                checksum_helper::checksum_helper::IncrementalProgress::FileChangedOlder(
                    path_buf,
                ) => {
                    println!("\r[OLD  ] {:?} local newer than hash", path_buf);
                }

                checksum_helper::checksum_helper::IncrementalProgress::FileNew(path_buf) => {
                    println!("\r[NEW  ] {:?}", path_buf);
                }

                checksum_helper::checksum_helper::IncrementalProgress::FileRemoved(path_buf) => {
                    println!("\r[DEL  ] {:?}", path_buf);
                }

                checksum_helper::checksum_helper::IncrementalProgress::Finished => {
                    println!("\nDone.");
                }
            }
        })
        .unwrap();

    ch.write_collection(&inc).unwrap();
}

fn verify_root(abs_path: impl AsRef<Path>) {
    let mut ch = checksum_helper::ChecksumHelper::new(abs_path.as_ref())
        .expect("Failed to create ChecksumHelper");

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
                    checksum_helper::checksum_helper::MostCurrentProgress::FoundFile(path_buf) => {
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
}
