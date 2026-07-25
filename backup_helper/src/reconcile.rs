use crate::ReconcileArgs;
use crate::backup_helper::BackupHelper;
use crate::parse;
use crate::BackupHelperError;

use std::fs;

type Result<T> = std::result::Result<T, BackupHelperError>;

pub fn reconcile(args: ReconcileArgs) -> Result<()> {
    let contents = fs::read_to_string(&args.config)?;
    let parsed = parse::parse(&contents)?;

    let mut bh = BackupHelper::from_file(&args.common.state)?;
    bh.reconcile(parsed)?;
    bh.persist(&args.common.state)?;

    println!("after reconcile:\n{}", bh.serialize()?);

    Ok(())
}

pub(crate) trait Reconcile {
    fn reconcile(&mut self, other: Self) -> std::result::Result<(), BackupHelperError>;
}
