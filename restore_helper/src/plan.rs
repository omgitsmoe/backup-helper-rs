use std::{collections::HashMap, fs, path};

use checksum_helper::{ChecksumHelper, hash_type::HashType};
use filetime::FileTime;
use serde::{Deserialize, Serialize};

use crate::{RestoreHelperError, Source};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManifestHandle(usize);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FileSource {
    // Source manifest the file belongs to.
    manifest_handle: ManifestHandle,
    // Relative path to the file.
    relative_path: path::PathBuf,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ContentHandle(usize);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RestoreFile {
    #[serde(with = "hash_type_serde")]
    hash_type: HashType,
    // hex-encoded hash
    hash: String,
    size: Option<u64>,
    #[serde(with = "optional_filetime_serde")]
    mtime: Option<FileTime>,

    content: ContentHandle,

    // Original path in the manifest to restore.
    relative_path: path::PathBuf,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SourceManifest {
    id: String,
    path: path::PathBuf,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
struct ContentKey {
    #[serde(with = "hash_type_serde")]
    hash_type: HashType,
    hash: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ContentRecord {
    key: ContentKey,
    // ordered by number of files the originating source manifest can provide
    sources: Vec<FileSource>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PlanData")]
pub struct Plan {
    source_manifests: Vec<SourceManifest>,
    contents: Vec<ContentRecord>,
    files: Vec<RestoreFile>,
}

#[derive(Deserialize)]
struct PlanData {
    source_manifests: Vec<SourceManifest>,
    contents: Vec<ContentRecord>,
    files: Vec<RestoreFile>,
}

impl TryFrom<PlanData> for Plan {
    type Error = String;

    fn try_from(data: PlanData) -> Result<Self, Self::Error> {
        for content in &data.contents {
            for source in &content.sources {
                if source.manifest_handle.0 >= data.source_manifests.len() {
                    return Err(format!(
                        "invalid manifest handle: {}",
                        source.manifest_handle.0
                    ));
                }
            }
        }
        for file in &data.files {
            if file.content.0 >= data.contents.len() {
                return Err(format!("invalid content handle: {}", file.content.0));
            }
        }
        Ok(Self {
            source_manifests: data.source_manifests,
            contents: data.contents,
            files: data.files,
        })
    }
}

mod hash_type_serde {
    use super::*;
    use serde::{Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(value: &HashType, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value.to_str())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<HashType, D::Error> {
        let value = String::deserialize(deserializer)?;
        HashType::try_from(value.as_str()).map_err(D::Error::custom)
    }
}

mod optional_filetime_serde {
    use super::*;
    use serde::{Deserializer, Serializer, de::Error};

    #[derive(Serialize, Deserialize)]
    struct Timestamp {
        seconds: i64,
        nanoseconds: u32,
    }

    pub fn serialize<S: Serializer>(
        value: &Option<FileTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .map(|time| Timestamp {
                seconds: time.unix_seconds(),
                nanoseconds: time.nanoseconds(),
            })
            .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<FileTime>, D::Error> {
        Option::<Timestamp>::deserialize(deserializer)?
            .map(|time| {
                if time.nanoseconds >= 1_000_000_000 {
                    return Err(D::Error::custom(
                        "timestamp nanoseconds must be less than 1000000000",
                    ));
                }
                Ok(FileTime::from_unix_time(time.seconds, time.nanoseconds))
            })
            .transpose()
    }
}

impl Plan {
    pub fn build(
        restore_manifest: impl AsRef<path::Path>,
        sources: Vec<Source>,
    ) -> Result<Plan, RestoreHelperError> {
        let restore_manifest = restore_manifest.as_ref();
        if !fs::exists(restore_manifest)? {
            return Err(RestoreHelperError::ManifestDoesNotExist(
                restore_manifest.to_path_buf(),
            ));
        }

        let mut plan = Plan {
            source_manifests: vec![],
            contents: vec![],
            files: vec![],
        };
        let mut lookup: HashMap<ContentKey, ContentHandle> = HashMap::new();

        let restore_parent = restore_manifest
            .parent()
            .expect("restore_manifest is a file and must have a parent");
        let mut ch = ChecksumHelper::new(restore_parent)?;
        let restore_collection = ch.read_collection(restore_manifest)?;

        for (_, file) in ch.iter_collection(&restore_collection)? {
            let relative_path = file.relative_path();
            let key = ContentKey {
                hash_type: file.hash_type(),
                hash: file.hash_hex(),
            };

            let content_handle = if let Some(content_handle) = lookup.get(&key) {
                *content_handle
            } else {
                let content_handle = ContentHandle(plan.contents.len());
                plan.contents.push(ContentRecord {
                    key: key.clone(),
                    sources: vec![],
                });

                let _ = lookup.insert(key.clone(), content_handle);
                content_handle
            };

            plan.files.push(RestoreFile {
                hash_type: key.hash_type,
                hash: key.hash.clone(),
                size: file.size(),
                mtime: file.mtime(),
                content: content_handle,
                relative_path,
            });
        }

        for source in sources {
            if !fs::exists(&source.manifest)? {
                return Err(RestoreHelperError::ManifestDoesNotExist(source.manifest));
            }
            let source_handle = ManifestHandle(plan.source_manifests.len());
            plan.source_manifests.push(SourceManifest {
                id: source.id,
                path: source.manifest.clone(),
            });
            let source_parent = source
                .manifest
                .parent()
                .expect("source manifest is a file and must have a parent");
            let mut ch = ChecksumHelper::new(source_parent)?;
            let source_collection = ch.read_collection(&source.manifest)?;

            for (_, file) in ch.iter_collection(&source_collection)? {
                let relative_path = file.relative_path();
                let key = ContentKey {
                    hash_type: file.hash_type(),
                    hash: file.hash_hex(),
                };

                if let Some(content_handle) = lookup.get(&key) {
                    let content = &mut plan.contents[content_handle.0];
                    content.sources.push(FileSource {
                        manifest_handle: source_handle,
                        relative_path,
                    });
                }
            }
        }

        plan.prioritize_manifests();
        Ok(plan)
    }

    fn prioritize_manifests(&mut self) {
        let mut source_to_supplied_file_count = vec![0; self.source_manifests.len()];
        for content in &self.contents {
            let mut source_counted = vec![false; self.source_manifests.len()];
            for file_source in &content.sources {
                if source_counted[file_source.manifest_handle.0] {
                    // only count once so multiple distinct paths having the
                    // same hash in a source don't bias the manifest priority
                    continue;
                }
                source_to_supplied_file_count[file_source.manifest_handle.0] += 1;
                source_counted[file_source.manifest_handle.0] = true;
            }
        }

        for content in &mut self.contents {
            content.sources.sort_by(|a, b| {
                let freq_a = source_to_supplied_file_count[a.manifest_handle.0];
                let freq_b = source_to_supplied_file_count[b.manifest_handle.0];
                // reversed so it sorts by descending nr of files contributed
                // by the source manifest
                freq_b.cmp(&freq_a)
            });
        }
    }

    pub fn content_without_source(&self) -> Vec<path::PathBuf> {
        let mut result = vec![];
        for file in &self.files {
            let content = &self.contents[file.content.0];
            if content.sources.is_empty() {
                result.push(file.relative_path.clone());
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use checksum_helper::{ChecksumHelperError, collection::HashCollectionError};
    use serde_json::{Value, json};
    use testdir::testdir;

    fn write_manifest(root: &path::Path, name: &str, entries: &[(&str, u8)]) -> path::PathBuf {
        let manifest = root.join(name);
        let mut text = String::from("# version 1\n");
        for (relative_path, hash_byte) in entries {
            text.push_str(&format!(
                "1234.5,42,sha256,{} {relative_path}\n",
                format!("{hash_byte:02x}").repeat(32)
            ));
        }
        fs::write(&manifest, text).unwrap();
        manifest
    }

    fn source(id: &str, manifest: &path::Path) -> Source {
        Source::new(id, manifest).unwrap()
    }

    fn source_handles(content: &ContentRecord) -> Vec<usize> {
        content
            .sources
            .iter()
            .map(|source| source.manifest_handle.0)
            .collect()
    }

    #[test]
    fn build_matches_content_across_paths_and_prioritizes_manifests() {
        let root = testdir!();
        let target = write_manifest(
            &root,
            "target.cshd",
            &[("a.txt", 1), ("b.txt", 2), ("c.txt", 3), ("missing.txt", 4)],
        );
        let small = write_manifest(
            &root,
            "small.cshd",
            &[
                ("copies/a1.txt", 1),
                ("copies/a2.txt", 1),
                ("copies/a3.txt", 1),
                ("copies/a4.txt", 1),
                ("unneeded.txt", 99),
            ],
        );
        let medium = write_manifest(
            &root,
            "medium.cshd",
            &[("other/a.txt", 1), ("other/b.txt", 2)],
        );
        let large = write_manifest(
            &root,
            "large.cshd",
            &[
                ("renamed/a.txt", 1),
                ("renamed/b.txt", 2),
                ("renamed/c.txt", 3),
            ],
        );

        let plan = Plan::build(
            &target,
            vec![
                source("small", &small),
                source("medium", &medium),
                source("large", &large),
            ],
        )
        .unwrap();

        assert_eq!(
            plan.source_manifests,
            vec![
                SourceManifest {
                    id: "small".into(),
                    path: small
                },
                SourceManifest {
                    id: "medium".into(),
                    path: medium
                },
                SourceManifest {
                    id: "large".into(),
                    path: large
                },
            ]
        );
        assert_eq!(plan.files.len(), 4);
        assert_eq!(plan.contents.len(), 4);
        for (index, name) in ["a.txt", "b.txt", "c.txt", "missing.txt"]
            .iter()
            .enumerate()
        {
            let file = &plan.files[index];
            assert_eq!(file.relative_path, path::Path::new(name));
            assert_eq!(file.content, ContentHandle(index));
            assert_eq!(file.hash_type, HashType::Sha256);
            assert_eq!(file.hash, format!("{:02x}", index + 1).repeat(32));
            assert_eq!(file.size, Some(42));
            assert_eq!(
                file.mtime,
                Some(FileTime::from_unix_time(1234, 500_000_000))
            );
            assert_eq!(
                plan.contents[index].key,
                ContentKey {
                    hash_type: file.hash_type,
                    hash: file.hash.clone(),
                }
            );
        }
        assert_eq!(source_handles(&plan.contents[0]), vec![2, 1, 0, 0, 0, 0]);
        assert_eq!(source_handles(&plan.contents[1]), vec![2, 1]);
        assert_eq!(source_handles(&plan.contents[2]), vec![2]);
        assert!(plan.contents[3].sources.is_empty());
        assert_eq!(
            plan.contents[0]
                .sources
                .iter()
                .map(|s| s.relative_path.as_path())
                .collect::<Vec<_>>(),
            vec![
                path::Path::new("renamed/a.txt"),
                path::Path::new("other/a.txt"),
                path::Path::new("copies/a1.txt"),
                path::Path::new("copies/a2.txt"),
                path::Path::new("copies/a3.txt"),
                path::Path::new("copies/a4.txt"),
            ]
        );
    }

    #[test]
    fn build_without_sources_keeps_unavailable_content() {
        let root = testdir!();
        let target = write_manifest(&root, "target.cshd", &[("a.txt", 1)]);
        let plan = Plan::build(target, vec![]).unwrap();
        assert!(plan.source_manifests.is_empty());
        assert_eq!(plan.files.len(), 1);
        assert_eq!(plan.contents.len(), 1);
        assert!(plan.contents[0].sources.is_empty());
    }

    #[test]
    fn build_empty_manifests() {
        let root = testdir!();
        let target = write_manifest(&root, "target.cshd", &[]);
        let empty = write_manifest(&root, "empty.cshd", &[]);
        let plan = Plan::build(target, vec![source("empty", &empty)]).unwrap();
        assert_eq!(plan.source_manifests.len(), 1);
        assert!(plan.files.is_empty());
        assert!(plan.contents.is_empty());
    }

    #[test]
    fn build_does_not_match_digest_with_a_different_algorithm() {
        let root = testdir!();
        let target = write_manifest(&root, "target.cshd", &[("a.txt", 1)]);
        let other = root.join("other.cshd");
        fs::write(
            &other,
            format!(
                "# version 1\n1234.5,42,sha3_256,{} a.txt\n",
                "01".repeat(32)
            ),
        )
        .unwrap();
        let plan = Plan::build(target, vec![source("other", &other)]).unwrap();
        assert!(plan.contents[0].sources.is_empty());
    }

    #[test]
    fn build_reports_missing_target_manifest() {
        let root = testdir!();
        let missing = root.join("missing.cshd");
        assert!(matches!(Plan::build(&missing, vec![]),
            Err(RestoreHelperError::ManifestDoesNotExist(p)) if p == missing));
    }

    #[test]
    fn build_reports_missing_source_manifest() {
        let root = testdir!();
        let target = write_manifest(&root, "target.cshd", &[]);
        let missing = root.join("missing.cshd");
        assert!(
            matches!(Plan::build(target, vec![source("missing", &missing)]),
            Err(RestoreHelperError::ManifestDoesNotExist(p)) if p == missing)
        );
    }

    #[test]
    fn build_propagates_manifest_parse_and_read_errors() {
        let root = testdir!();
        let valid = write_manifest(&root, "valid.cshd", &[("a.txt", 1)]);
        let cases: &[(&str, &[u8])] = &[
            ("version.cshd", b"# version invalid\n"),
            ("mtime.cshd", b"# version 1\ninvalid,42,sha256,01 a.txt\n"),
            ("size.cshd", b"# version 1\n1234,invalid,sha256,01 a.txt\n"),
            ("algorithm.cshd", b"# version 1\n1234,42,unknown,01 a.txt\n"),
            ("hex.cshd", b"# version 1\n1234,42,sha256,zz a.txt\n"),
            ("utf8.cshd", b"\xff\n"),
            ("extension.unknown", b""),
        ];
        for (name, bytes) in cases {
            let invalid = root.join(name);
            fs::write(&invalid, bytes).unwrap();
            for result in [
                Plan::build(&invalid, vec![]),
                Plan::build(&valid, vec![source("invalid", &invalid)]),
            ] {
                let Err(RestoreHelperError::ChecksumHelperError(
                    ChecksumHelperError::HashCollectionError(error),
                )) = result
                else {
                    panic!("expected collection error for {name}, got {result:?}");
                };
                match *name {
                    "version.cshd" => assert!(matches!(
                        *error,
                        HashCollectionError::InvalidVersionHeader(_)
                    )),
                    "algorithm.cshd" => assert!(matches!(
                        *error,
                        HashCollectionError::UnsupportedHashType(_)
                    )),
                    "utf8.cshd" => assert!(matches!(
                        *error,
                        HashCollectionError::IOError(std::io::ErrorKind::InvalidData)
                    )),
                    "extension.unknown" => {
                        assert!(matches!(*error, HashCollectionError::InvalidExtension(_)))
                    }
                    _ => assert!(matches!(*error, HashCollectionError::InvalidHashLine(_))),
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn build_propagates_directory_read_errors() {
        let root = testdir!();
        let valid = write_manifest(&root, "valid.cshd", &[]);
        let directory = root.join("directory.cshd");
        fs::create_dir(&directory).unwrap();
        for result in [
            Plan::build(&directory, vec![]),
            Plan::build(&valid, vec![source("directory", &directory)]),
        ] {
            assert!(
                matches!(result, Err(RestoreHelperError::ChecksumHelperError(
                ChecksumHelperError::HashCollectionError(error)))
                if matches!(*error, HashCollectionError::IOError(_)))
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn build_propagates_existence_check_io_errors() {
        let root = testdir!();
        let valid = write_manifest(&root, "valid.cshd", &[]);
        let looping = root.join("loop.cshd");
        std::os::unix::fs::symlink(&looping, &looping).unwrap();
        let expected_kind = fs::exists(&looping).unwrap_err().kind();
        for result in [
            Plan::build(&looping, vec![]),
            Plan::build(&valid, vec![source("loop", &looping)]),
        ] {
            assert!(
                matches!(result, Err(RestoreHelperError::IoError(kind)) if kind == expected_kind)
            );
        }
    }

    #[test]
    fn build_rejects_relative_manifest_parents() {
        let root = testdir!();
        let valid = write_manifest(&root, "valid.cshd", &[]);
        let cwd = std::env::current_dir().unwrap();
        let mut relative = path::PathBuf::new();
        for _ in cwd.ancestors().skip(1) {
            relative.push("..");
        }
        relative.push(valid.strip_prefix(cwd.ancestors().last().unwrap()).unwrap());
        assert!(relative.is_relative());
        for result in [
            Plan::build(&relative, vec![]),
            Plan::build(&valid, vec![source("relative", &relative)]),
        ] {
            assert!(
                matches!(result, Err(RestoreHelperError::ChecksumHelperError(
                ChecksumHelperError::RootIsRelative(p))) if p == relative.parent().unwrap())
            );
        }
    }

    #[test]
    fn build_shares_content_between_duplicate_target_hashes() {
        let root = testdir!();
        let target = write_manifest(
            &root,
            "target.cshd",
            &[("a.txt", 1), ("b.txt", 2), ("c.txt", 1)],
        );
        let replica = write_manifest(&root, "replica.cshd", &[("original.txt", 1)]);
        let plan = Plan::build(target, vec![source("replica", &replica)]).unwrap();

        assert_eq!(plan.files.len(), 3);
        assert_eq!(plan.contents.len(), 2);
        for (index, (name, handle)) in [
            ("a.txt", ContentHandle(0)),
            ("b.txt", ContentHandle(1)),
            ("c.txt", ContentHandle(0)),
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(plan.files[index].relative_path, path::Path::new(name));
            assert_eq!(plan.files[index].content, *handle);
            assert_eq!(plan.files[index].hash, plan.contents[handle.0].key.hash);
        }
        assert_eq!(
            plan.contents[0].sources,
            vec![FileSource {
                manifest_handle: ManifestHandle(0),
                relative_path: "original.txt".into(),
            }]
        );
        assert!(plan.contents[1].sources.is_empty());
    }

    #[test]
    fn prioritize_manifests_sorts_by_descending_distinct_content_coverage() {
        let mut input = plan_json();
        input["source_manifests"] = json!([
            {"id": "small", "path": "small.cshd"},
            {"id": "large", "path": "large.cshd"}
        ]);
        input["contents"][0]["sources"] = json!([
            {"manifest_handle": 0, "relative_path": "a1.txt"},
            {"manifest_handle": 0, "relative_path": "a2.txt"},
            {"manifest_handle": 0, "relative_path": "a3.txt"},
            {"manifest_handle": 1, "relative_path": "a.txt"}
        ]);
        let mut second = input["contents"][0].clone();
        second["key"]["hash"] = json!("cd".repeat(64));
        second["sources"] = json!([{"manifest_handle": 1, "relative_path": "b.txt"}]);
        input["contents"].as_array_mut().unwrap().push(second);
        let mut plan: Plan = serde_json::from_value(input).unwrap();

        plan.prioritize_manifests();

        assert_eq!(source_handles(&plan.contents[0]), vec![1, 0, 0, 0]);
        assert_eq!(source_handles(&plan.contents[1]), vec![1]);
        let prioritized = serde_json::to_value(&plan).unwrap();
        plan.prioritize_manifests();
        assert_eq!(serde_json::to_value(&plan).unwrap(), prioritized);
    }

    #[test]
    fn prioritize_manifests_preserves_ties_and_is_idempotent() {
        let mut input = plan_json();
        input["source_manifests"] = json!([
            {"id": "a", "path": "a.cshd"},
            {"id": "b", "path": "b.cshd"},
            {"id": "unused", "path": "unused.cshd"}
        ]);
        input["contents"][0]["sources"] = json!([
            {"manifest_handle": 1, "relative_path": "b.txt"},
            {"manifest_handle": 0, "relative_path": "a1.txt"},
            {"manifest_handle": 0, "relative_path": "a2.txt"}
        ]);
        let mut plan: Plan = serde_json::from_value(input).unwrap();
        let original = serde_json::to_value(&plan).unwrap();
        plan.prioritize_manifests();
        assert_eq!(serde_json::to_value(&plan).unwrap(), original);
        plan.prioritize_manifests();
        assert_eq!(serde_json::to_value(&plan).unwrap(), original);
    }

    fn plan_json() -> Value {
        json!({
            "source_manifests": [{"id": "archive-a", "path": "archive-a.cshd"}],
            "contents": [{
                "key": {"hash_type": "sha512", "hash": "ab".repeat(64)},
                "sources": [{"manifest_handle": 0, "relative_path": "original/file.txt"}]
            }],
            "files": [{
                "hash_type": "sha512",
                "hash": "ab".repeat(64),
                "size": 42,
                "mtime": {"seconds": -1, "nanoseconds": 123456789},
                "content": 0,
                "relative_path": "restored/file.txt"
            }]
        })
    }

    #[test]
    fn json_round_trip_preserves_plan_and_timestamp_precision() {
        let input = plan_json();
        let plan: Plan = serde_json::from_value(input.clone()).unwrap();
        assert_eq!(
            plan.files[0].mtime,
            Some(FileTime::from_unix_time(-1, 123456789))
        );
        assert_eq!(serde_json::to_value(&plan).unwrap(), input);
        let encoded = serde_json::to_string_pretty(&plan).unwrap();
        assert_eq!(serde_json::from_str::<Plan>(&encoded).unwrap(), plan);
    }

    #[test]
    fn json_round_trip_preserves_missing_metadata_and_sources() {
        let mut input = plan_json();
        input["files"][0]["size"] = Value::Null;
        input["files"][0]["mtime"] = Value::Null;
        input["contents"][0]["sources"] = json!([]);
        let plan: Plan = serde_json::from_value(input.clone()).unwrap();
        assert_eq!(serde_json::to_value(plan).unwrap(), input);
    }

    #[test]
    fn empty_plan_round_trips() {
        let plan = Plan {
            source_manifests: vec![],
            contents: vec![],
            files: vec![],
        };
        let encoded = serde_json::to_string(&plan).unwrap();
        assert_eq!(serde_json::from_str::<Plan>(&encoded).unwrap(), plan);
    }

    #[test]
    fn invalid_handles_are_rejected() {
        let mut input = plan_json();
        input["files"][0]["content"] = json!(1);
        assert!(
            serde_json::from_value::<Plan>(input)
                .unwrap_err()
                .to_string()
                .contains("invalid content handle")
        );

        let mut input = plan_json();
        input["contents"][0]["sources"][0]["manifest_handle"] = json!(1);
        assert!(
            serde_json::from_value::<Plan>(input)
                .unwrap_err()
                .to_string()
                .contains("invalid manifest handle")
        );
    }

    #[test]
    fn invalid_timestamp_is_rejected() {
        let mut input = plan_json();
        input["files"][0]["mtime"]["nanoseconds"] = json!(1_000_000_000);
        assert!(serde_json::from_value::<Plan>(input).is_err());
    }

    #[test]
    fn all_hash_algorithms_round_trip() {
        for algorithm in [
            "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256",
            "sha3_384", "sha3_512",
        ] {
            let mut input = plan_json();
            input["files"][0]["hash_type"] = json!(algorithm);
            input["contents"][0]["key"]["hash_type"] = json!(algorithm);
            let plan: Plan = serde_json::from_value(input.clone()).unwrap();
            assert_eq!(serde_json::to_value(plan).unwrap(), input);
        }
    }

    #[test]
    fn unknown_hash_algorithm_is_rejected() {
        let mut input = plan_json();
        input["contents"][0]["key"]["hash_type"] = json!("unknown");
        assert!(serde_json::from_value::<Plan>(input).is_err());
    }
}
