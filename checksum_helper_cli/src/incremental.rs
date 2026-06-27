use checksum_helper::ChecksumHelperOptions;

use crate::{IncrementalArgs, progress::ProgressReporter};

pub fn incremental(
    args: IncrementalArgs,
    verbose: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::absolute(args.root.clone())?;
    let options = args.apply(ChecksumHelperOptions::default())?;
    let mut ch = checksum_helper::ChecksumHelper::with_options(&root, options)?;

    let mut reporter = ProgressReporter::new();
    reporter.set_verbose(verbose);
    let inc = ch.incremental(|p| reporter.report_incremental(p))?;

    ch.write_collection(&inc)?;
    println!("\nWrote collection at: {:?}", inc.full_path()?);

    Ok(())
}

pub fn fill(
    args: IncrementalArgs,
    verbose: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::absolute(args.root.clone())?;
    let options = args.apply(ChecksumHelperOptions::default())?;
    let mut ch = checksum_helper::ChecksumHelper::with_options(&root, options)?;

    let mut reporter = ProgressReporter::new();
    reporter.set_verbose(verbose);
    let hc = ch.fill_missing(|p| reporter.report_incremental(p))?;
    ch.write_collection(&hc)?;

    println!("\nWrote collection at: {:?}", hc.full_path()?);

    Ok(())
}
