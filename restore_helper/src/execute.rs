use std::{fs, io, path};

use filetime::FileTime;

use crate::{
    Mount, Plan, RestoreHelperError,
    plan::{FileSource, RestoreFile},
};

#[derive(Debug, Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
pub enum ExistingFilePolicy {
    /// Skip if a file that already exists.
    SkipAlways,
    /// Skip a file that already exists and has the same mtime/size,
    /// otherwise overwrite the file.
    SkipSameMetadata,
    // Always overwrite the file.
    Overwrite,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SkipReason {
    Existing,
    SameMetadata,
    NoSource,
    NoMountedSource,
}

#[derive(Debug)]
pub enum ExecuteProgress<'a> {
    Begin {
        files: usize,
    },
    CopyStarted {
        target: &'a path::Path,
        source: &'a path::Path,
        source_id: &'a str,
        total: u64,
    },
    CopyBytes {
        copied: u64,
        total: u64,
    },
    Copied {
        bytes: u64,
    },
    Skipped {
        target: &'a path::Path,
        reason: SkipReason,
        source_ids: Vec<&'a str>,
    },
}

pub struct RestoreState {
    plan: Plan,
    // indexed by ManifestHandle, which corresponds to the index in plan.source_manifests
    mounts: Vec<Option<path::PathBuf>>,
    target: path::PathBuf,
}

impl RestoreState {
    pub fn new(
        plan: Plan,
        mounts: Vec<Mount>,
        target: impl AsRef<path::Path>,
    ) -> Result<RestoreState, RestoreHelperError> {
        let mut handle_to_mount = vec![None; plan.source_manifests.len()];
        for mount in mounts {
            let handle = plan
                .source_manifests
                .iter()
                .position(|s| s.id == mount.id)
                .ok_or(RestoreHelperError::ManifestIdDoesNotExist(mount.id))?;

            handle_to_mount[handle] = Some(mount.mount);
        }

        Ok(RestoreState {
            plan,
            mounts: handle_to_mount,
            target: target.as_ref().to_path_buf(),
        })
    }

    pub fn from_json(
        plan: impl AsRef<path::Path>,
        mounts: Vec<Mount>,
        target: impl AsRef<path::Path>,
    ) -> Result<RestoreState, RestoreHelperError> {
        let plan = Plan::from_json(plan)?;
        Self::new(plan, mounts, target)
    }

    pub fn execute(
        &mut self,
        existing_policy: ExistingFilePolicy,
    ) -> Result<(), RestoreHelperError> {
        self.execute_with_progress(existing_policy, |_| Ok(()))
    }

    pub fn execute_with_progress(
        &mut self,
        existing_policy: ExistingFilePolicy,
        mut progress: impl FnMut(ExecuteProgress<'_>) -> io::Result<()>,
    ) -> Result<(), RestoreHelperError> {
        progress(ExecuteProgress::Begin {
            files: self.plan.files.len(),
        })?;
        for file in &self.plan.files {
            let content = &self.plan.contents[file.content.0];
            let target_path = self.target.join(&file.relative_path);
            crate::paths::reject_symlinks(&self.target, &file.relative_path, false).map_err(
                |error| {
                    RestoreHelperError::path_io(
                        "validate destination parents for",
                        &target_path,
                        error,
                    )
                },
            )?;
            let Some((source, source_path)) = self.select_source(&content.sources) else {
                progress(ExecuteProgress::Skipped {
                    target: &target_path,
                    reason: if content.sources.is_empty() {
                        SkipReason::NoSource
                    } else {
                        SkipReason::NoMountedSource
                    },
                    source_ids: content
                        .sources
                        .iter()
                        .map(|source| {
                            self.plan.source_manifests[source.manifest_handle.0]
                                .id
                                .as_str()
                        })
                        .collect(),
                })?;
                continue;
            };

            let write_file = self.should_write_file(&target_path, file, existing_policy)?;
            if !write_file {
                progress(ExecuteProgress::Skipped {
                    target: &target_path,
                    reason: if existing_policy == ExistingFilePolicy::SkipAlways {
                        SkipReason::Existing
                    } else {
                        SkipReason::SameMetadata
                    },
                    source_ids: Vec::new(),
                })?;
                continue;
            }

            let source_id = &self.plan.source_manifests[source.manifest_handle.0].id;
            let mount = self.mounts[source.manifest_handle.0]
                .as_ref()
                .expect("selected source is mounted");
            crate::paths::reject_symlinks(mount, &source.relative_path, true).map_err(|error| {
                RestoreHelperError::path_io("validate source", &source_path, error)
            })?;
            let source_metadata = fs::metadata(&source_path).map_err(|error| {
                RestoreHelperError::path_io("read source metadata", &source_path, error)
            })?;
            if !source_metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "restore source is not a regular file: {}",
                        source_path.display()
                    ),
                )
                .into());
            }
            let mut metadata =
                copy_helper::preserved_metadata(&source_metadata).map_err(|error| {
                    RestoreHelperError::path_io("read source timestamps", &source_path, error)
                })?;
            if let Some(mtime) = file.mtime {
                metadata.modified = mtime;
            }

            let parent = target_path.parent().expect("restore target has a parent");
            fs::create_dir_all(parent).map_err(|error| {
                RestoreHelperError::path_io("create destination directory", parent, error)
            })?;
            let total = file.size.unwrap_or(source_metadata.len());
            progress(ExecuteProgress::CopyStarted {
                target: &target_path,
                source: &source_path,
                source_id,
                total,
            })?;
            let bytes = copy_helper::copy_file_with_progress(
                &source_path,
                &target_path,
                &metadata,
                Some(total),
                "restore file",
                |copied| progress(ExecuteProgress::CopyBytes { copied, total }),
            )?;
            copy_helper::sync_parent_directory(parent).map_err(|error| {
                RestoreHelperError::path_io("synchronize destination directory", parent, error)
            })?;
            progress(ExecuteProgress::Copied { bytes })?;
        }

        Ok(())
    }

    /// Selects the highest priority (first, since sources is sorted by descending
    /// priority) mounted source and its absolute path.
    /// If no source is mounted None is returned.
    fn select_source<'a>(
        &self,
        sources: &'a [FileSource],
    ) -> Option<(&'a FileSource, path::PathBuf)> {
        for source in sources {
            let mount = &self.mounts[source.manifest_handle.0];
            if mount.is_none() {
                continue;
            }

            return Some((
                source,
                mount
                    .as_ref()
                    .expect("checked above")
                    .join(&source.relative_path),
            ));
        }

        None
    }

    fn should_write_file(
        &self,
        target: impl AsRef<path::Path>,
        file: &RestoreFile,
        existing_policy: ExistingFilePolicy,
    ) -> Result<bool, RestoreHelperError> {
        let target = target.as_ref();
        let meta = match fs::symlink_metadata(target) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(true),
            Err(error) => {
                return Err(RestoreHelperError::path_io(
                    "read destination metadata",
                    target,
                    error,
                ));
            }
        };

        if meta.is_dir() {
            return Err(RestoreHelperError::TargetIsDirectory(target.to_path_buf()));
        }

        if existing_policy == ExistingFilePolicy::SkipAlways {
            return Ok(false);
        }

        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("restore target is not a regular file: {}", target.display()),
            )
            .into());
        }

        if existing_policy == ExistingFilePolicy::SkipSameMetadata
            && let (Some(size), Some(mtime)) = (file.size, file.mtime)
            && meta.len() == size
            && FileTime::from(meta.modified().map_err(|error| {
                RestoreHelperError::path_io("read destination timestamp", target, error)
            })?) == mtime
        {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        io::ErrorKind,
    };

    use testdir::testdir;

    use super::*;

    fn plan_with_sources(ids: &[&str]) -> Plan {
        let sources: Vec<_> = ids
            .iter()
            .map(|id| serde_json::json!({ "id": id, "path": format!("{id}.cshd") }))
            .collect();
        serde_json::from_value(serde_json::json!({
            "source_manifests": sources,
            "contents": [],
            "files": [],
        }))
        .unwrap()
    }

    const POLICIES: [ExistingFilePolicy; 3] = [
        ExistingFilePolicy::SkipAlways,
        ExistingFilePolicy::SkipSameMetadata,
        ExistingFilePolicy::Overwrite,
    ];

    fn restore_file() -> RestoreFile {
        RestoreFile {
            hash_type: checksum_helper::hash_type::HashType::Sha256,
            hash: String::new(),
            size: Some(4),
            mtime: Some(FileTime::from_unix_time(1234, 500_000_000)),
            content: crate::plan::ContentHandle(0),
            relative_path: "file.txt".into(),
        }
    }

    fn state_with_file(root: &path::Path) -> RestoreState {
        let manifest = root.join("target.cshd");
        fs::write(&manifest, "# version 1\n1234.5,4,sha256,0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef nested/file.txt\n").unwrap();
        let plan = Plan::build(
            &manifest,
            vec![crate::Source::new("source", &manifest).unwrap()],
        )
        .unwrap();
        RestoreState::new(
            plan,
            vec![Mount::new("source", root.join("source")).unwrap()],
            root.join("target"),
        )
        .unwrap()
    }

    #[test]
    #[cfg(unix)]
    fn execute_rejects_parent_and_source_symlinks() {
        use std::os::unix::fs::symlink;
        for source_link in [false, true] {
            let root = testdir!().join(if source_link { "source" } else { "target" });
            fs::create_dir_all(&root).unwrap();
            let mut state = state_with_file(&root);
            let outside = root.join("outside");
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("file.txt"), b"keep").unwrap();
            fs::create_dir_all(root.join("source/nested")).unwrap();
            fs::write(root.join("source/nested/file.txt"), b"data").unwrap();
            fs::create_dir_all(root.join("target")).unwrap();
            if source_link {
                fs::remove_file(root.join("source/nested/file.txt")).unwrap();
                symlink(
                    outside.join("file.txt"),
                    root.join("source/nested/file.txt"),
                )
                .unwrap();
            } else {
                symlink(&outside, root.join("target/nested")).unwrap();
            }
            for policy in POLICIES {
                assert!(state.execute(policy).is_err());
                assert_eq!(fs::read(outside.join("file.txt")).unwrap(), b"keep");
            }
            if source_link {
                assert!(!root.join("target/nested/file.txt").exists());
            }
        }
    }

    #[test]
    fn execute_copies_nested_files_and_preserves_planned_mtime() {
        let root = testdir!();
        let mut state = state_with_file(&root);
        let source = root.join("source/nested/file.txt");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(&source, b"data").unwrap();
        let source_mtime = FileTime::from_unix_time(5678, 0);
        filetime::set_file_mtime(&source, source_mtime).unwrap();
        assert_ne!(Some(source_mtime), state.plan.files[0].mtime);
        for policy in POLICIES {
            state.execute(policy).unwrap();
            let target = root.join("target/nested/file.txt");
            assert_eq!(fs::read(&target).unwrap(), b"data");
            assert_eq!(
                FileTime::from_last_modification_time(&fs::metadata(&target).unwrap()),
                state.plan.files[0].mtime.unwrap(),
            );
            fs::remove_file(target).unwrap();
        }
    }

    #[test]
    fn progress_reports_selected_source_bytes_and_completion() {
        let root = testdir!();
        let mut state = state_with_file(&root);
        let source = root.join("source/nested/file.txt");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(&source, b"data").unwrap();
        let mut events = Vec::new();
        state
            .execute_with_progress(ExistingFilePolicy::Overwrite, |event| {
                match event {
                    ExecuteProgress::Begin { files } => assert_eq!(files, 1),
                    ExecuteProgress::CopyStarted {
                        target,
                        source: selected,
                        source_id,
                        total,
                    } => {
                        assert_eq!(selected, source);
                        assert_eq!(target, root.join("target/nested/file.txt"));
                        assert_eq!(source_id, "source");
                        assert_eq!(total, 4);
                        events.push("started");
                    }
                    ExecuteProgress::CopyBytes { copied, total } => {
                        assert!(copied <= total);
                        events.push(if copied == 0 { "zero" } else { "bytes" });
                    }
                    ExecuteProgress::Copied { bytes } => {
                        assert_eq!(bytes, 4);
                        assert_eq!(fs::read(root.join("target/nested/file.txt"))?, b"data");
                        events.push("copied");
                    }
                    ExecuteProgress::Skipped { .. } => panic!("unexpected skip"),
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(events, ["started", "zero", "bytes", "copied"]);
    }

    #[test]
    fn progress_distinguishes_all_skip_reasons() {
        let root = testdir!();
        let mut state = state_with_file(&root);
        let target = root.join("target/nested/file.txt");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"data").unwrap();
        filetime::set_file_mtime(&target, state.plan.files[0].mtime.unwrap()).unwrap();
        for (policy, expected) in [
            (ExistingFilePolicy::SkipAlways, SkipReason::Existing),
            (
                ExistingFilePolicy::SkipSameMetadata,
                SkipReason::SameMetadata,
            ),
        ] {
            let mut reasons = Vec::new();
            state
                .execute_with_progress(policy, |event| {
                    if let ExecuteProgress::Skipped { reason, .. } = event {
                        reasons.push(reason);
                    }
                    Ok(())
                })
                .unwrap();
            assert_eq!(reasons, [expected]);
        }
        state.mounts[0] = None;
        for expected in [SkipReason::NoMountedSource, SkipReason::NoSource] {
            let mut reasons = Vec::new();
            state
                .execute_with_progress(ExistingFilePolicy::Overwrite, |event| {
                    if let ExecuteProgress::Skipped {
                        reason, source_ids, ..
                    } = event
                    {
                        reasons.push(reason);
                        if reason == SkipReason::NoMountedSource {
                            assert_eq!(source_ids, ["source"]);
                        }
                    }
                    Ok(())
                })
                .unwrap();
            assert_eq!(reasons, [expected]);
            state.plan.contents[0].sources.clear();
        }
    }

    #[test]
    fn failed_copy_never_reports_completion() {
        let root = testdir!();
        let mut state = state_with_file(&root);
        let source = root.join("source/nested/file.txt");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(source, b"wrong size").unwrap();
        let mut completed = false;
        let result = state.execute_with_progress(ExistingFilePolicy::Overwrite, |event| {
            completed |= matches!(event, ExecuteProgress::Copied { .. });
            Ok(())
        });
        assert!(result.is_err());
        assert!(!completed);
        assert!(!root.join("target/nested/file.txt").exists());
    }

    #[test]
    fn execute_preserves_source_mtime_when_manifest_has_none() {
        let root = testdir!();
        let mut state = state_with_file(&root);
        state.plan.files[0].mtime = None;
        let source = root.join("source/nested/file.txt");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(&source, b"data").unwrap();
        let source_mtime = FileTime::from_unix_time(5678, 0);
        filetime::set_file_mtime(&source, source_mtime).unwrap();

        for policy in POLICIES {
            state.execute(policy).unwrap();
            let target = root.join("target/nested/file.txt");
            assert_eq!(fs::read(&target).unwrap(), b"data");
            assert_eq!(
                FileTime::from_last_modification_time(&fs::metadata(&target).unwrap()),
                source_mtime,
            );
            fs::remove_file(target).unwrap();
        }
    }

    #[test]
    fn execute_propagates_missing_source_error() {
        let root = testdir!();
        let mut state = state_with_file(&root);
        fs::create_dir_all(root.join("source/nested")).unwrap();
        for policy in POLICIES {
            assert!(matches!(
                state.execute(policy),
                Err(RestoreHelperError::PathIoError { source, .. }) if source.kind() == ErrorKind::NotFound
            ));
            assert!(!root.join("target").exists());
        }
    }

    #[test]
    fn execute_rejects_directory_source() {
        let root = testdir!();
        let mut state = state_with_file(&root);
        fs::create_dir_all(root.join("source/nested/file.txt")).unwrap();
        for policy in POLICIES {
            assert!(matches!(
                state.execute(policy),
                Err(RestoreHelperError::IoError(error)) if error.kind() == ErrorKind::InvalidInput
            ));
            assert!(!root.join("target").exists());
        }
    }

    #[test]
    fn execute_obeys_existing_file_policy() {
        let root = testdir!();
        let mut state = state_with_file(&root);
        let source = root.join("source/nested/file.txt");
        let target = root.join("target/nested/file.txt");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(source, b"data").unwrap();
        for policy in POLICIES {
            for same_metadata in [true, false] {
                fs::write(&target, b"keep").unwrap();
                let mtime = if same_metadata {
                    state.plan.files[0].mtime.unwrap()
                } else {
                    FileTime::from_unix_time(1, 0)
                };
                filetime::set_file_mtime(&target, mtime).unwrap();
                state.execute(policy).unwrap();
                let skipped = policy == ExistingFilePolicy::SkipAlways
                    || (policy == ExistingFilePolicy::SkipSameMetadata && same_metadata);
                assert_eq!(
                    fs::read(&target).unwrap(),
                    if skipped { b"keep" } else { b"data" }
                );
            }
        }
    }

    #[test]
    fn execute_propagates_copy_failure_without_replacing_existing_file() {
        let root = testdir!();
        let mut state = state_with_file(&root);
        let source = root.join("source/nested/file.txt");
        let target = root.join("target/nested/file.txt");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(source, b"wrong size").unwrap();
        fs::write(&target, b"keep").unwrap();
        assert!(matches!(
            state.execute(ExistingFilePolicy::Overwrite),
            Err(RestoreHelperError::CopyError(_))
        ));
        assert_eq!(fs::read(target).unwrap(), b"keep");
    }

    #[test]
    fn missing_targets_are_writable_under_every_policy() {
        let root = testdir!();
        let state = RestoreState::new(plan_with_sources(&[]), vec![], &root).unwrap();
        for target in [root.join("missing"), root.join("missing-parent/file")] {
            for policy in POLICIES {
                assert!(
                    state
                        .should_write_file(&target, &restore_file(), policy)
                        .unwrap()
                );
            }
        }
    }

    #[test]
    fn existing_regular_file_obeys_policy_and_requires_complete_matching_metadata() {
        let root = testdir!();
        let target = root.join("file.txt");
        fs::write(&target, b"data").unwrap();
        let state = RestoreState::new(plan_with_sources(&[]), vec![], &root).unwrap();
        let mut file = restore_file();
        filetime::set_file_mtime(&target, file.mtime.unwrap()).unwrap();

        for (size, mtime, matches) in [
            (file.size, file.mtime, true),
            (Some(5), file.mtime, false),
            (
                file.size,
                Some(FileTime::from_unix_time(1234, 500_000_001)),
                false,
            ),
            (None, file.mtime, false),
            (file.size, None, false),
            (None, None, false),
        ] {
            file.size = size;
            file.mtime = mtime;
            for policy in POLICIES {
                let expected = match policy {
                    ExistingFilePolicy::SkipAlways => false,
                    ExistingFilePolicy::SkipSameMetadata => !matches,
                    ExistingFilePolicy::Overwrite => true,
                };
                assert_eq!(
                    state.should_write_file(&target, &file, policy).unwrap(),
                    expected
                );
            }
        }
    }

    #[test]
    fn directory_is_rejected_under_every_policy() {
        let root = testdir!();
        let state = RestoreState::new(plan_with_sources(&[]), vec![], &root).unwrap();
        for policy in POLICIES {
            let result = state.should_write_file(&root, &restore_file(), policy);
            assert!(matches!(
                result,
                Err(RestoreHelperError::TargetIsDirectory(path)) if path == root
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_skipped_or_rejected_without_following_them() {
        use std::os::unix::fs::symlink;

        let root = testdir!();
        let state = RestoreState::new(plan_with_sources(&[]), vec![], &root).unwrap();
        let regular = root.join("regular");
        fs::write(&regular, b"data").unwrap();
        let link = root.join("link");
        for destination in [&regular, &root, &root.join("missing"), &link] {
            symlink(destination, &link).unwrap();
            for policy in POLICIES {
                let result = state.should_write_file(&link, &restore_file(), policy);
                if policy == ExistingFilePolicy::SkipAlways {
                    assert!(!result.unwrap());
                } else {
                    assert!(matches!(
                        result,
                        Err(RestoreHelperError::IoError(error)) if error.kind() == ErrorKind::InvalidInput
                    ));
                }
            }
            fs::remove_file(&link).unwrap();
        }
        assert_eq!(fs::read(&regular).unwrap(), b"data");
    }

    #[test]
    fn metadata_errors_are_propagated_under_every_policy() {
        let root = testdir!();
        let target = root.join("invalid\0path");
        let state = RestoreState::new(plan_with_sources(&[]), vec![], &root).unwrap();
        for policy in POLICIES {
            assert!(matches!(
                state.should_write_file(&target, &restore_file(), policy),
                Err(RestoreHelperError::PathIoError { source, .. }) if source.kind() == ErrorKind::InvalidInput
            ));
        }
    }

    #[test]
    fn loads_plan_from_json_file() {
        let root = testdir!();
        let manifest = root.join("target.cshd");
        fs::write(&manifest, "# version 1\n1234.5,42,sha256,0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef file.txt\n").unwrap();
        let plan = Plan::build(
            &manifest,
            vec![crate::Source::new("source", &manifest).unwrap()],
        )
        .unwrap();
        let path = root.join("plan.json");
        serde_json::to_writer(File::create(&path).unwrap(), &plan).unwrap();

        let target = root.join("restored");
        let mount = root.join("source-mount");
        let state =
            RestoreState::from_json(&path, vec![Mount::new("source", &mount).unwrap()], &target)
                .unwrap();

        assert_eq!(state.plan, plan);
        assert_eq!(state.mounts, vec![Some(mount)]);
        assert_eq!(state.target, target);
    }

    #[test]
    fn new_matches_mounts_by_id_in_manifest_order() {
        let root = testdir!();
        let plan = plan_with_sources(&["first", "second", "third"]);
        let first = root.join("first-mount");
        let third = root.join("third-mount");
        let target = root.join("restored");

        let state = RestoreState::new(
            plan,
            vec![
                Mount::new("third", &third).unwrap(),
                Mount::new("first", &first).unwrap(),
            ],
            &target,
        )
        .unwrap();

        assert_eq!(state.plan, plan_with_sources(&["first", "second", "third"]));
        assert_eq!(state.mounts, vec![Some(first), None, Some(third)]);
        assert_eq!(state.target, target);
    }

    #[test]
    fn new_without_mounts_leaves_all_sources_unmounted() {
        let root = testdir!();
        let state =
            RestoreState::new(plan_with_sources(&["first", "second"]), vec![], &root).unwrap();

        assert_eq!(state.mounts, vec![None, None]);
    }

    #[test]
    fn new_with_no_sources_or_mounts_succeeds() {
        let root = testdir!();
        let state = RestoreState::new(plan_with_sources(&[]), vec![], &root).unwrap();

        assert!(state.mounts.is_empty());
    }

    #[test]
    fn new_uses_last_mount_for_duplicate_ids() {
        let root = testdir!();
        let last = root.join("last");
        let state = RestoreState::new(
            plan_with_sources(&["source"]),
            vec![
                Mount::new("source", root.join("first")).unwrap(),
                Mount::new("source", &last).unwrap(),
            ],
            &root,
        )
        .unwrap();

        assert_eq!(state.mounts, vec![Some(last)]);
    }

    #[test]
    fn new_rejects_unknown_mount_ids() {
        let root = testdir!();
        for ids in [&[][..], &["source"][..]] {
            let result = RestoreState::new(
                plan_with_sources(ids),
                vec![Mount::new("unknown", &root).unwrap()],
                &root,
            );

            assert!(matches!(
                result,
                Err(RestoreHelperError::ManifestIdDoesNotExist(id)) if id == "unknown"
            ));
        }
    }

    #[test]
    fn from_json_propagates_unknown_mount_id_error() {
        let root = testdir!();
        let path = root.join("plan.json");
        serde_json::to_writer(
            File::create(&path).unwrap(),
            &plan_with_sources(&["source"]),
        )
        .unwrap();

        assert!(matches!(
            RestoreState::from_json(
                &path,
                vec![Mount::new("unknown", &root).unwrap()],
                &root,
            ),
            Err(RestoreHelperError::ManifestIdDoesNotExist(id)) if id == "unknown"
        ));
    }

    #[test]
    fn missing_file_returns_io_error() {
        let root = testdir!();

        assert!(matches!(
            RestoreState::from_json(root.join("missing.json"), vec![], &root),
            Err(RestoreHelperError::PathIoError { source, .. }) if source.kind() == ErrorKind::NotFound
        ));
    }

    #[test]
    fn malformed_json_returns_json_error() {
        let root = testdir!();
        let path = root.join("plan.json");
        fs::write(&path, "{").unwrap();

        assert!(matches!(
            RestoreState::from_json(&path, vec![], &root),
            Err(RestoreHelperError::JsonError(_))
        ));
    }

    #[test]
    fn trailing_data_returns_json_error() {
        let root = testdir!();
        let path = root.join("plan.json");
        fs::write(
            &path,
            r#"{"source_manifests":[],"contents":[],"files":[]} {}"#,
        )
        .unwrap();

        assert!(matches!(
            RestoreState::from_json(&path, vec![], &root),
            Err(RestoreHelperError::JsonError(_))
        ));
    }
}
