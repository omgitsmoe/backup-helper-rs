use crate::IncrementalArgs;

pub fn incremental(args: IncrementalArgs) -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::absolute(args.root)?;
    let mut ch = checksum_helper::ChecksumHelper::new(&root)?;

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
        })?;

    ch.write_collection(&inc)?;

    Ok(())
}

pub fn fill(args: IncrementalArgs) -> Result<(), Box<dyn std::error::Error>> {
    todo!();

    Ok(())
}
