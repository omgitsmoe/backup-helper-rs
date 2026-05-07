use checksum_helper::ChecksumHelperOptions;

use crate::{progress::ProgressReporter, MostCurrentArgs};

use std::path::Path;

pub fn build(
    root: impl AsRef<Path>,
    args: MostCurrentArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::absolute(root)?;
    let options = args.apply(ChecksumHelperOptions::default())?;
    let mut ch = checksum_helper::ChecksumHelper::with_options(&root, options)?;

    let mut reporter = ProgressReporter::new();
    ch.with_most_current(
        |p| reporter.report_most_current(p),
        |ch, c| {
            ch.write_collection(c)?;
            println!("Wrote collection at: {:?}", c.full_path()?);

            Ok(())
        }
    )?;

    Ok(())
}

pub fn missing(
    root: impl AsRef<Path>,
    args: MostCurrentArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::absolute(root)?;
    let options = args.apply(ChecksumHelperOptions::default())?;
    let mut ch = checksum_helper::ChecksumHelper::with_options(&root, options)?;

    let mut reporter = ProgressReporter::new();
    let result = ch.check_missing(|p| reporter.report_incremental(p))?;

    if result.directories.is_empty() && result.files.is_empty() {
        println!("Success! All files have checksums!");
        return Ok(());
    }

    println!("\n\nThere were files without checksums!");

    println!("\nDirectories without any checksums:");
    for dir in result.directories {
        println!("\t{:?}", dir);
    }

    println!("\nFiles without any checksums:");
    for file in result.files {
        println!("\t{:?}", file);
    }

    Err("Fail! There were files that do not have a checksum yet!".into())
}
