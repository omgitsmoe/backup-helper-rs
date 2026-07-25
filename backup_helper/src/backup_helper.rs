use serde::{Serialize, Deserialize};
use std::path;

use crate::{BackupHelperError, disks::Disk, parse::Parsed, reconcile::Reconcile, source::Source};

type Result<T> = std::result::Result<T, crate::BackupHelperError>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct DiskHandle(pub(crate) usize);

#[derive(Default, Debug, Clone)]
pub struct BackupHelper {
    disks: Vec<Disk>,
    sources: Vec<Source>,
}

impl BackupHelper {
    pub fn from_file(path: impl AsRef<path::Path>) -> Result<Self> {
        let path = path.as_ref();
        if !std::fs::exists(path)? {
            return Ok(Self::default())
        }

        let json = std::fs::read_to_string(path)?;
        Self::from_state(&json)
    }

    pub fn from_state(json: &str) -> Result<Self> {
        let header: BackupHeader = serde_json::from_str(json)?;

        match header.version {
            1 => {
                let state: BackupStateV1Owned = serde_json::from_str(json)?;
                Ok(Self {
                    disks: state.disks,
                    sources: state.sources,
                })
            },
            v => Err(BackupHelperError::InvalidState(format!("unsupported version {v}"))),
        }
    }

    pub fn serialize(&self) -> Result<String> {
        let state = BackupStateV1Ref{
            version: 1,
            disks: &self.disks,
            sources: &self.sources,
        };

        Ok(serde_json::to_string_pretty(&state)?)
    }

    pub fn persist(&self, path: impl AsRef<path::Path>) -> Result<()> {
        Ok(std::fs::write(path, self.serialize()?)?)
    }

    pub fn reconcile(&mut self, config: Parsed) -> Result<()> {
        if self.disks.is_empty() {
            self.disks = config.disks;
        } else {
            let mut seen = vec![];
            for incoming_disk in config.disks {
                seen.push(incoming_disk.name.clone());
                if !self.has_disk(&incoming_disk.name) {
                    self.disks.push(incoming_disk);
                    continue;
                }

                let existing_disk = self.get_disk_mut(&incoming_disk.name)
                    .expect("checked above");
                existing_disk.reconcile(incoming_disk)?;
            }

            self.disks = std::mem::take(&mut self.disks)
                .into_iter()
                .filter(|d| seen.contains(&d.name))
                .collect();
        }

        if self.sources.is_empty() {
            self.sources = config.sources;
        } else {
            let mut seen = vec![];
            for incoming_source in config.sources {
                seen.push(incoming_source.path().clone());
                if let Some(existing_source) = self.get_source_mut(&incoming_source.path()) {
                    existing_source.reconcile(incoming_source)?;
                } else {
                    self.sources.push(incoming_source);
                }
            }

            for existing_source in &self.sources {
                if !seen.contains(existing_source.path()) && existing_source.has_transferred_target() {
                    return Err(BackupHelperError::ReconcileConflict(format!(
                        "reconciliation would drop source {:?} with transferred targets",
                        existing_source.path()
                    )));
                }
            }

            self.sources.retain(|s| seen.contains(s.path()));
        }

        self.assign_disks()?;

        Ok(())
    }

    fn has_disk(&self, name: &str) -> bool {
        self.disks.iter().any(|d| d.name == name)
    }

    fn get_disk_mut(&mut self, name: &str) -> Option<&mut Disk> {
        self.disks.iter_mut().find(|d| d.name == name)
    }

    fn get_source_mut(&mut self, source_path: &path::Path) -> Option<&mut Source> {
        self.sources.iter_mut().find(|s| s.path() == source_path)
    }

    fn assign_disks(&mut self) -> Result<()> {
        for source in &mut self.sources {
            source.assign_disk(&self.disks)?;
        }

        Ok(())
    }
}

#[derive(Deserialize)]
struct BackupHeader {
    version: u32,
}

#[derive(Serialize)]
struct BackupStateV1Ref<'a> {
    version: u32,
    disks: &'a [Disk],
    sources: &'a [Source],
}

#[derive(Deserialize)]
struct BackupStateV1Owned {
    disks: Vec<Disk>,
    sources: Vec<Source>,
}
