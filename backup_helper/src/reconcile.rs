use crate::ReconcileArgs;
use crate::parse;

use std::fs;

type Result<T> = std::result::Result<T, crate::BackupHelperError>;

pub fn reconcile(args: ReconcileArgs) -> Result<()> {
    let contents = fs::read_to_string(&args.config)?;
    let parsed = parse::parse(&contents)?;
    println!("{:?}", parsed);

    Ok(())
}
