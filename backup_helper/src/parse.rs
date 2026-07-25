use std::path;
use kdl::{KdlDocument, KdlNode};

use crate::{
    BackupHelperError, disks::Disk, source, source::{ChecksumOptions, Source}, target::{Target, TransferMode}
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

    let mut source = Source::new(path, None::<&str>);
    let mut targets = vec![];
    for child in node.iter_children() {
        let name = child.name().value();
        match name {
            "checksums" => {
                *source.checksum_options_mut() = parse_checksum_options(child, contents)?;
            },
            "hash_file" => {
                let path = child.get(0).and_then(|a| a.as_string());
                if let Some(p) = path {
                    source.set_hash_file(p);
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
                    "Expected `checksums`, `hash_file` or `target` as child nodes of `source`, got `{}`",
                    name
                )));
            }
        }
    }

    for target in targets {
        source.add_target(target);
    }

    Ok(source)
}

fn parse_checksum_options(node: &KdlNode, contents: &str) -> Result<ChecksumOptions> {
    let mut result = ChecksumOptions::default();

    for child in node.iter_children() {
        let name = child.name().value();
        match name {
            "files" => result.all_files = parse_checksums_child(child, contents, name)?,
            "checksum_files" => {
                result.checksum_files = parse_checksums_child(child, contents, name)?
            }
            _ => {
                return Err(BackupHelperError::InvalidConfig(format!(
                    "Expected `files` or `checksum_files` as child nodes of `source.checksums`, got `{}`",
                    name
                )));
            }
        }
    }

    Ok(result)
}

fn parse_checksums_child(node: &KdlNode, contents: &str, child_name: &str) -> Result<source::GlobFilter> {
    let mut result = source::GlobFilter::default();

    for child in node.iter_children() {
        let name = child.name().value();
        match name {
            "allow" => {
                result.allow = parse_string_nodes(
                    child,
                    contents,
                    &format!("source.checksums.{}.allow", child_name),
                )?;
            }
            "block" => {
                result.block = parse_string_nodes(
                    child,
                    contents,
                    &format!("source.checksums.{}.block", child_name),
                )?;
            }
            _ => {
                return Err(BackupHelperError::InvalidConfig(format!(
                    "Expected `allow` or `block` as child nodes of `source.checksums.{}`, got `{}`",
                    child_name,
                    name
                )));
            }
        }
    }

    Ok(result)
}

fn parse_string_nodes(node: &KdlNode, contents: &str, node_name: &str) -> Result<Vec<String>> {
    let mut result = vec![];

    for child in node.iter_children() {
        if child.children().is_some() || !child.entries().is_empty() {
            let line_nr = span_to_line_number(contents, child.span().offset());
            return Err(BackupHelperError::InvalidConfig(format!(
                "Expected only strings as child nodes of `{}`, got `{}` on line {}",
                node_name,
                child,
                line_nr,
            )));
        }

        result.push(child.name().value().to_string());
    }

    Ok(result)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_config_err(result: Result<Parsed>, expected_substring: &str) {
        match result {
            Err(crate::BackupHelperError::InvalidConfig(msg)) => {
                assert!(
                    msg.contains(expected_substring),
                    "Expected error containing '{}', got: {}",
                    expected_substring,
                    msg
                );
            }
            Err(e) => panic!("Expected InvalidConfig error, got: {:?}", e),
            Ok(_) => panic!("Expected error containing '{}', but got Ok", expected_substring),
        }
    }

    #[test]
    fn test_parse_full_config() {
        let input = r#"
            disks {
                disk "main" {
                    path "/mnt/main"
                }
            }

            source "/mnt/main/photos" {
                hash_file "/mnt/main/photos.hsh"

                checksums {
                    files {
                        allow {
                            "**/*.zip"
                            "**/*.bin"
                        }
                        block {
                            "**/*.tmp"
                        }
                    }
                    checksum_files {
                        allow {
                            "**/*.cshd"
                        }
                        block {
                            "**/*.md5"
                        }
                    }
                }

                target "/mnt/backup/photos" {
                    transfer_mode copy
                    verify #true
                }

                target "/mnt/remote/photos" {
                    transfer_mode sync
                    verify #false
                }
            }
        "#;
        let parsed = parse(input).expect("should parse successfully");

        assert_eq!(parsed.disks.len(), 1);
        assert_eq!(parsed.disks[0].name, "main");
        assert_eq!(parsed.disks[0].path, path::PathBuf::from("/mnt/main"));

        assert_eq!(parsed.sources.len(), 1);
        let source = &parsed.sources[0];
        assert_eq!(source.path(), &path::PathBuf::from("/mnt/main/photos"));

        let opts = source.checksum_options();
        assert_eq!(opts.all_files.allow, vec!["**/*.zip", "**/*.bin"]);
        assert_eq!(opts.all_files.block, vec!["**/*.tmp"]);
        assert_eq!(opts.checksum_files.allow, vec!["**/*.cshd"]);
        assert_eq!(opts.checksum_files.block, vec!["**/*.md5"]);

        let v = serde_json::to_value(source).unwrap();
        let targets = v.get("targets").unwrap().as_array().unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].get("path").unwrap().as_str().unwrap(), "/mnt/backup/photos");
        assert_eq!(targets[0].get("transfer_mode").unwrap().as_str().unwrap(), "Copy");
        assert!(targets[0].get("verify").unwrap().as_bool().unwrap());
        assert_eq!(targets[1].get("path").unwrap().as_str().unwrap(), "/mnt/remote/photos");
        assert_eq!(targets[1].get("transfer_mode").unwrap().as_str().unwrap(), "Sync");
        assert!(!targets[1].get("verify").unwrap().as_bool().unwrap());
    }

    #[test]
    fn test_parse_minimal_source() {
        let input = r#"
            source "/data" {
                target "/backup/data" {
                    transfer_mode copy
                }
            }
        "#;
        let parsed = parse(input).expect("should parse successfully");

        assert_eq!(parsed.sources.len(), 1);
        assert_eq!(parsed.disks.len(), 0);
        let source = &parsed.sources[0];
        assert_eq!(source.path(), &path::PathBuf::from("/data"));

        let v = serde_json::to_value(source).unwrap();
        let targets = v.get("targets").unwrap().as_array().unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].get("transfer_mode").unwrap().as_str().unwrap(), "Copy");
        assert!(targets[0].get("verify").unwrap().as_bool().unwrap());
    }

    #[test]
    fn test_parse_sync_transfer_mode() {
        let input = r#"
            source "/data" {
                target "/backup/data" {
                    transfer_mode sync
                }
            }
        "#;
        let parsed = parse(input).expect("should parse successfully");

        let v = serde_json::to_value(&parsed.sources[0]).unwrap();
        let targets = v.get("targets").unwrap().as_array().unwrap();
        assert_eq!(targets[0].get("transfer_mode").unwrap().as_str().unwrap(), "Sync");
    }

    // parse() errors

    #[test]
    fn test_parse_invalid_kdl_syntax() {
        let input = "this is not valid kdl {{{{";
        let result = parse(input);
        assert_config_err(result, "");
    }

    #[test]
    fn test_parse_unknown_top_level_node() {
        let input = r#"foo "bar""#;
        let result = parse(input);
        assert_config_err(result, "Invalid top-level node");
    }

    #[test]
    fn test_parse_unknown_child_of_disks() {
        let input = r#"
            disks {
                thing "hello"
            }
        "#;
        let result = parse(input);
        assert_config_err(result, "Expected `disk` as child nodes of `disks`");
    }

    // parse_source() errors

    #[test]
    fn test_parse_source_missing_path() {
        let input = r#"source {
            target "/backup" {
                transfer_mode copy
            }
        }"#;
        let result = parse(input);
        assert_config_err(result, "Missing positional argument path on `source`");
    }

    #[test]
    fn test_parse_source_non_string_path() {
        let input = r#"source 42 {
            target "/backup" {
                transfer_mode copy
            }
        }"#;
        let result = parse(input);
        assert_config_err(result, "Expected positional string argument `path`");
    }

    #[test]
    fn test_parse_source_unknown_child() {
        let input = r#"
            source "/data" {
                foo "bar"
            }
        "#;
        let result = parse(input);
        assert_config_err(result, "Expected `checksums`, `hash_file` or `target` as child nodes of `source`");
    }

    #[test]
    fn test_parse_source_hash_file_missing_path() {
        let input = r#"
            source "/data" {
                hash_file 42
            }
        "#;
        let result = parse(input);
        assert_config_err(result, "Expected positional string argument `path`, got");
    }

    // checksums parsing

    #[test]
    fn test_parse_checksums_default_empty() {
        let input = r#"
            source "/data" {
                target "/backup" {
                    transfer_mode copy
                }
            }
        "#;
        let parsed = parse(input).expect("should parse successfully");
        let opts = parsed.sources[0].checksum_options();
        assert!(opts.all_files.allow.is_empty());
        assert!(opts.all_files.block.is_empty());
        assert!(opts.checksum_files.allow.is_empty());
        assert!(opts.checksum_files.block.is_empty());
    }

    #[test]
    fn test_parse_checksums_files_only() {
        let input = r#"
            source "/data" {
                checksums {
                    files {
                        allow {
                            "**/*.zip"
                            "**/*.bin"
                        }
                        block {
                            "**/*.tmp"
                        }
                    }
                }
                target "/backup" {
                    transfer_mode copy
                }
            }
        "#;
        let parsed = parse(input).expect("should parse successfully");
        let opts = parsed.sources[0].checksum_options();
        assert_eq!(opts.all_files.allow, vec!["**/*.zip", "**/*.bin"]);
        assert_eq!(opts.all_files.block, vec!["**/*.tmp"]);
        assert!(opts.checksum_files.allow.is_empty());
        assert!(opts.checksum_files.block.is_empty());
    }

    #[test]
    fn test_parse_checksums_checksum_files_only() {
        let input = r#"
            source "/data" {
                checksums {
                    checksum_files {
                        allow {
                            "**/*.cshd"
                        }
                        block {
                            "**/*.md5"
                            "**/*.sha1"
                        }
                    }
                }
                target "/backup" {
                    transfer_mode copy
                }
            }
        "#;
        let parsed = parse(input).expect("should parse successfully");
        let opts = parsed.sources[0].checksum_options();
        assert!(opts.all_files.allow.is_empty());
        assert!(opts.all_files.block.is_empty());
        assert_eq!(opts.checksum_files.allow, vec!["**/*.cshd"]);
        assert_eq!(opts.checksum_files.block, vec!["**/*.md5", "**/*.sha1"]);
    }

    #[test]
    fn test_parse_checksums_unknown_child() {
        let input = r#"
            source "/data" {
                checksums {
                    unknown_node {
                    }
                }
                target "/backup" {
                    transfer_mode copy
                }
            }
        "#;
        let result = parse(input);
        assert_config_err(result, "Expected `files` or `checksum_files` as child nodes of `source.checksums`");
    }

    #[test]
    fn test_parse_checksums_files_unknown_grandchild() {
        let input = r#"
            source "/data" {
                checksums {
                    files {
                        bad_node {
                        }
                    }
                }
                target "/backup" {
                    transfer_mode copy
                }
            }
        "#;
        let result = parse(input);
        assert_config_err(result, "Expected `allow` or `block` as child nodes of `source.checksums.files`");
    }

    #[test]
    fn test_parse_string_nodes_rejects_argued_node() {
        let input = r#"
            source "/data" {
                checksums {
                    files {
                        allow {
                            node_with_arg "value"
                        }
                    }
                }
                target "/backup" {
                    transfer_mode copy
                }
            }
        "#;
        let result = parse(input);
        assert_config_err(result, "Expected only strings as child nodes of `source.checksums.files.allow`");
    }

    // parse_target() errors

    #[test]
    fn test_parse_target_missing_path() {
        let input = r#"
            source "/data" {
                target {
                    transfer_mode copy
                }
            }
        "#;
        let result = parse(input);
        assert_config_err(result, "Expected positional string argument `path`, got");
    }

    #[test]
    fn test_parse_target_transfer_mode_missing_value() {
        let input = r#"
            source "/data" {
                target "/backup" {
                    transfer_mode
                }
            }
        "#;
        let result = parse(input);
        assert_config_err(result, "Expected positional string argument for `transfer_mode`");
    }

    #[test]
    fn test_parse_target_transfer_mode_invalid_value() {
        let input = r#"
            source "/data" {
                target "/backup" {
                    transfer_mode "invalid"
                }
            }
        "#;
        let result = parse(input);
        assert_config_err(result, "Invalid transfer_mode `invalid`, expected `copy` or `sync`");
    }

    #[test]
    fn test_parse_target_verify_not_bool() {
        let input = r#"
            source "/data" {
                target "/backup" {
                    transfer_mode copy
                    verify "notbool"
                }
            }
        "#;
        let result = parse(input);
        assert_config_err(result, "Expected boolean argument for `verify`");
    }

    #[test]
    fn test_parse_target_unknown_child() {
        let input = r#"
            source "/data" {
                target "/backup" {
                    transfer_mode copy
                    foobar "baz"
                }
            }
        "#;
        let result = parse(input);
        assert_config_err(result, "Expected `transfer_mode` or `verify` as child nodes of `target`");
    }

    #[test]
    fn test_parse_target_missing_transfer_mode() {
        let input = r#"
            source "/data" {
                target "/backup" {
                    verify #true
                }
            }
        "#;
        let result = parse(input);
        assert_config_err(result, "Missing mandatory child node `transfer_mode` for `target`");
    }

    // parse_disk() errors

    #[test]
    fn test_parse_disk_missing_name() {
        let input = r#"
            disks {
                disk {
                    path "/mnt/disk"
                }
            }
        "#;
        let result = parse(input);
        assert_config_err(result, "Expected positional string argument `name`, got");
    }

    #[test]
    fn test_parse_disk_path_missing_value() {
        let input = r#"
            disks {
                disk "mydisk" {
                    path
                }
            }
        "#;
        let result = parse(input);
        assert_config_err(result, "Expected positional string argument for `path`");
    }

    #[test]
    fn test_parse_disk_unknown_child() {
        let input = r#"
            disks {
                disk "mydisk" {
                    foo "bar"
                }
            }
        "#;
        let result = parse(input);
        assert_config_err(result, "Expected `path` as child node of `disk`");
    }

    #[test]
    fn test_parse_disk_missing_path() {
        let input = r#"
            disks {
                disk "mydisk" {
                }
            }
        "#;
        let result = parse(input);
        assert_config_err(result, "Missing mandatory child node `path` for `disk`");
    }
}
