use std::{fs::File, io::BufReader, path};

use crate::{Mount, Plan, RestoreHelperError, plan::FileSource};

#[derive(Debug, Clone, PartialEq, Eq, clap::ValueEnum)]
pub enum ExistingFilePolicy {
    /// Skip if a file that already exists.
    SkipAlways,
    /// Skip a file that already exists and has the same mtime/size,
    /// otherwise overwrite the file.
    SkipSameMetadata,
    // Always overwrite the file.
    Overwrite,
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
        let reader = BufReader::new(File::open(plan)?);
        let plan: Plan = serde_json::from_reader(reader)?;
        Self::new(plan, mounts, target)
    }

    pub fn execute(
        &mut self,
        existing_policy: ExistingFilePolicy,
    ) -> Result<(), RestoreHelperError> {
        Ok(())
    }

    /// Selects the highest priority (first, since sources is sorted by descending
    /// priority) mounted source returning the absolute path to the source file.
    /// If no source is mounted None is returned.
    fn select_source(&self, sources: &Vec<FileSource>) -> Option<path::PathBuf> {
        for source in sources {
            let mount = &self.mounts[source.manifest_handle.0];
            if mount.is_none() {
                continue;
            }

            return Some(
                mount
                    .as_ref()
                    .expect("checked above")
                    .join(&source.relative_path),
            );
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io::ErrorKind};

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
            Err(RestoreHelperError::IoError(ErrorKind::NotFound))
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
