use crate::BackupHelperError;
use crate::ReconcileArgs;

use kdl::KdlDocument;
use std::fs;

type Result<T> = std::result::Result<T, crate::BackupHelperError>;

fn span_to_line_number(input: &str, offset_bytes: usize) -> u32 {
    input
        .bytes()
        .take(offset_bytes)
        .fold(0, |acc, c| acc + (c == b'\n') as u32)
        + 1
}

pub fn reconcile(args: ReconcileArgs) -> Result<()> {
    let contents = fs::read_to_string(&args.config)?;
    let doc: KdlDocument = contents.parse()?;

    for node in doc.nodes() {
        if node.name().value() != "source" {
            return Err(BackupHelperError::InvalidConfig(format!(
                "Invalid top-level node. Expected 'source', got '{}'",
                node.name().value()
            )));
        }

        let path = node.get(0);
        if path.is_none() {
            let line_nr = span_to_line_number(&contents, node.span().offset());
            return Err(BackupHelperError::InvalidConfig(format!(
                "Missing positional argument path on `source` on line {}",
                line_nr
            )));
        }

        println!("node {}", node);
    }

    Ok(())
}
