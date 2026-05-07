use std::path::PathBuf;

use checksum_helper::{
    checksum_helper::{IncrementalProgress, MostCurrentProgress, VerifyRootProgress},
    collection::VerifyProgress,
};

pub struct ProgressReporter {
    checksum_files_found: u64,
    checksum_files_ignored: u64,
    files_found: u64,
    files_ignored: u64,
    current_file: Option<PathBuf>,
}

impl ProgressReporter {
    pub fn new() -> Self {
        Self {
            checksum_files_found: 0,
            checksum_files_ignored: 0,
            files_found: 0,
            files_ignored: 0,
            current_file: None,
        }
    }

    pub fn report_most_current(&mut self, progress: MostCurrentProgress) {
        match progress {
            MostCurrentProgress::MergeHashFile(path_buf) => {
                println!("\n[MERGE] {:?}", path_buf);
            }

            MostCurrentProgress::FoundFile(_path_buf) => {
                self.checksum_files_found += 1;

                print!(
                    "\rMost current: {:003} files (+ {:003} ignored)",
                    self.checksum_files_found, self.checksum_files_ignored
                );
            }

            MostCurrentProgress::IgnoredPath(path_buf) => {
                self.checksum_files_ignored += 1;
                println!("\n[IGN  ] {:?}", path_buf);
            }
        }
    }

    pub fn report_incremental(&mut self, progress: IncrementalProgress) {
        match progress {
            checksum_helper::checksum_helper::IncrementalProgress::BuildMostCurrent(
                most_current_progress,
            ) => self.report_most_current(most_current_progress),

            checksum_helper::checksum_helper::IncrementalProgress::DiscoverFilesFound(found) => {
                self.files_found = found;
                print!(
                    "\rFound files: {:003} (+ {:003} ignored)",
                    self.files_found, self.files_ignored
                );
            }

            checksum_helper::checksum_helper::IncrementalProgress::DiscoverFilesIgnored(
                _path_buf,
            ) => {
                self.files_ignored += 1;
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
                self.current_file = Some(path_buf.clone());
                println!("\n[READ ] {:?}", path_buf);
            }

            // assuming (bytes_read, total_bytes) or similar
            checksum_helper::checksum_helper::IncrementalProgress::Read(read, total) => {
                if let Some(path) = &self.current_file {
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

            checksum_helper::checksum_helper::IncrementalProgress::FileChangedOlder(path_buf) => {
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
    }

    pub fn report_verify(&mut self, progress: VerifyProgress) {
        match progress {
            VerifyProgress::Pre(common) => {
                let path = common.tree_root.join(common.relative_path);
                self.current_file = Some(path.clone());

                println!(
                    "\n[VERIFY] ({:>4}/{:>4}) {:?}",
                    common.file_number_processed, common.file_number_total, path
                );

                println!(
                    "[PROG ] bytes {:>10} / {:>10}",
                    common.size_processed_bytes, common.size_total_bytes
                );
            }

            VerifyProgress::During(hash_progress) => {
                if let Some(path) = &self.current_file {
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

            VerifyProgress::Post(post) => {
                let path = post.progress.tree_root.join(post.progress.relative_path);

                print!("\r");

                let status = match post.result {
                    checksum_helper::hashed_file::VerifyResult::Ok => {
                        "[OK        ]"
                    }

                    checksum_helper::hashed_file::VerifyResult::FileMissing(_error_kind) => {
                        "[ERR MISS  ]"
                    }

                    checksum_helper::hashed_file::VerifyResult::Mismatch => {
                        "[ERR HASH  ]"
                    }

                    checksum_helper::hashed_file::VerifyResult::MismatchSize => {
                        "[ERR SIZE  ]"
                    }

                    checksum_helper::hashed_file::VerifyResult::MismatchCorrupted => {
                        "[ERR CORR  ]"
                    }

                    checksum_helper::hashed_file::VerifyResult::MismatchOutdatedHash => {
                        "[WARN STALE]" // not strictly an error
                    }
                };

                println!("{} {:?}", status, path);
            }
        }
    }

    pub fn report_verify_root(&mut self, progress: VerifyRootProgress) {
        match progress {
            VerifyRootProgress::BuildMostCurrent(p) => self.report_most_current(p),
            VerifyRootProgress::Verify(p) => self.report_verify(p),
        }
    }
}
