use std::path;
use kdl::{KdlDocument, KdlNode};

use crate::{
    BackupHelperError, disks::Disk, source::Source, target::{Target, TransferMode}
};

type Result<T> = std::result::Result<T, crate::BackupHelperError>;

#[derive(Debug, Clone)]
pub struct Parsed {
    pub sources: Vec<Source>,
    pub disks: Vec<Disk>,
}

pub fn parse(contents: &str) -> Result<Parsed> {
    let doc: KdlDocument = contents.parse()?;

    let mut result = Parsed{
        sources: vec![],
        disks: vec![],
    };
    for node in doc.nodes() {
        match node.name().value() {
            "source" => {
                let source = parse_source(contents, node)?;
                result.sources.push(source);
            },
            "disks" => {
                for child in node.iter_children() {
                    let name = child.name().value();
                    match name {
                        "disk" => {
                            let disk = parse_disk(child, contents)?;
                            result.disks.push(disk);
                        },
                        _ => {
                            return Err(BackupHelperError::InvalidConfig(format!(
                                "Expected `disk` as child nodes of `disks`, got `{}`",
                                name
                            )));
                        },
                    }
                }
            },
            _ => return Err(BackupHelperError::InvalidConfig(format!(
                "Invalid top-level node. Expected `source` or `disk`, got '{}'",
                node.name().value()
            ))),
        }
    }

    Ok(result)
}

fn parse_source(contents: &str, node: &KdlNode) -> Result<Source> {
    let path = node.get(0);
    if path.is_none() {
        let line_nr = span_to_line_number(contents, node.span().offset());
        return Err(BackupHelperError::InvalidConfig(format!(
            "Missing positional argument path on `source` on line {}",
            line_nr
        )));
    }

    let path = path.expect("checked above");
    if !path.is_string() {
        let line_nr = span_to_line_number(contents, node.span().offset());
        return Err(BackupHelperError::InvalidConfig(format!(
            "Expected positional string argument `path`, got `{}` in `source` on line {}",
            path, line_nr
        )));
    }

    let path = path.as_string().expect("checked above");

    let mut hash_file = None;
    let mut targets = vec![];
    for child in node.iter_children() {
        let name = child.name().value();
        match name {
            "hash_file" => {
                let path = child.get(0).and_then(|a| a.as_string());
                if let Some(p) = path {
                    hash_file = Some(p);
                } else {
                    let line_nr = span_to_line_number(contents, child.span().offset());
                    return Err(BackupHelperError::InvalidConfig(format!(
                        "Expected positional string argument `path`, got `{:?}` for `hash_file` on line {}",
                        child.get(0),
                        line_nr
                    )));
                }
            }
            "target" => {
                targets.push(parse_target(child, contents)?);
            }
            _ => {
                return Err(BackupHelperError::InvalidConfig(format!(
                    "Expected `hash_file` or `target` as child nodes of `source`, got `{}`",
                    name
                )));
            }
        }
    }

    let mut source = Source::new(path, hash_file);
    for target in targets {
        source.add_target(target);
    }

    Ok(source)
}

fn parse_target(node: &KdlNode, contents: &str) -> Result<Target> {
    let path = node.get(0).and_then(|a| a.as_string());
    if path.is_none() {
        let line_nr = span_to_line_number(contents, node.span().offset());
        return Err(BackupHelperError::InvalidConfig(format!(
            "Expected positional string argument `path`, got `{:?}` for `target` on line {}",
            node.get(0),
            line_nr
        )));
    }
    let path = path.expect("checked above");

    let mut transfer_mode = None;
    let mut verify = true;

    for child in node.iter_children() {
        let name = child.name().value();
        match name {
            "transfer_mode" => {
                let mode_str = child.get(0).and_then(|a| a.as_string());
                if let Some(s) = mode_str {
                    transfer_mode = Some(match s {
                        "copy" => TransferMode::Copy,
                        "sync" => TransferMode::Sync,
                        _ => {
                            let line_nr = span_to_line_number(contents, child.span().offset());
                            return Err(BackupHelperError::InvalidConfig(format!(
                                "Invalid transfer_mode `{}`, expected `copy` or `sync` on line {}",
                                s, line_nr
                            )));
                        }
                    });
                } else {
                    let line_nr = span_to_line_number(contents, child.span().offset());
                    return Err(BackupHelperError::InvalidConfig(format!(
                        "Expected positional string argument for `transfer_mode`, got `{:?}` on line {}",
                        child.get(0),
                        line_nr
                    )));
                }
            }
            "verify" => match child.get(0).and_then(|a| a.as_bool()) {
                Some(b) => verify = b,
                None => {
                    let line_nr = span_to_line_number(contents, child.span().offset());
                    return Err(BackupHelperError::InvalidConfig(format!(
                        "Expected boolean argument for `verify`, got `{:?}` on line {}",
                        child.get(0),
                        line_nr
                    )));
                }
            },
            _ => {
                let line_nr = span_to_line_number(contents, child.span().offset());
                return Err(BackupHelperError::InvalidConfig(format!(
                    "Expected `transfer_mode` or `verify` as child nodes of `target`, got `{}` on line {}",
                    name, line_nr
                )));
            }
        }
    }

    let transfer_mode = match transfer_mode {
        Some(tm) => tm,
        None => {
            let line_nr = span_to_line_number(contents, node.span().offset());
            return Err(BackupHelperError::InvalidConfig(format!(
                "Missing mandatory child node `transfer_mode` for `target` on line {}",
                line_nr
            )));
        }
    };

    Ok(Target::new(path, transfer_mode, verify))
}

fn parse_disk(node: &KdlNode, contents: &str) -> Result<Disk> {
    let name = node.get(0).and_then(|a| a.as_string());
    if name.is_none() {
        let line_nr = span_to_line_number(contents, node.span().offset());
        return Err(BackupHelperError::InvalidConfig(format!(
            "Expected positional string argument `name`, got `{:?}` for `disk` on line {}",
            node.get(0),
            line_nr
        )));
    }
    let name = name.expect("checked above");

    let mut path = None;
    for child in node.iter_children() {
        let name = child.name().value();
        match name {
            "path" => {
                path = child.get(0).and_then(|a| a.as_string());
                if path.is_none() {
                    let line_nr = span_to_line_number(contents, child.span().offset());
                    return Err(BackupHelperError::InvalidConfig(format!(
                        "Expected positional string argument for `path`, got `{:?}` on line {}",
                        child.get(0),
                        line_nr
                    )));
                }
            }
            _ => {
                let line_nr = span_to_line_number(contents, child.span().offset());
                return Err(BackupHelperError::InvalidConfig(format!(
                    "Expected `path` as child node of `disk`, got `{}` on line {}",
                    name, line_nr
                )));
            }
        }
    }

    if path.is_none() {
        let line_nr = span_to_line_number(contents, node.span().offset());
        return Err(BackupHelperError::InvalidConfig(format!(
            "Missing mandatory child node `path` for `disk` on line {}",
            line_nr
        )));
    }
    let path = path.expect("we exit early above if none");

    Ok(Disk{
        name: name.to_string(),
        path: path::PathBuf::from(path),
    })
}

fn span_to_line_number(input: &str, offset_bytes: usize) -> u32 {
    input
        .bytes()
        .take(offset_bytes)
        .fold(0, |acc, c| acc + (c == b'\n') as u32)
        + 1
}
