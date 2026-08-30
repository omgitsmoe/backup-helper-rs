use crate::{backup_helper::DiskHandle, source::ChecksumOptions};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Task {
    SourceHash(SourceHash),
    SourceToTargetCopy(SourceToTargetCopy),
    SourceToTargetSync(SourceToTargetSync),
    TargetVerify(TargetVerify),
}

impl Task {
    pub fn involved_disks(&self) -> &[DiskHandle] {
        match self {
            Task::SourceHash(t) => &t.common.involved_disks[..],
            Task::SourceToTargetCopy(t) => &t.common.involved_disks[..],
            Task::SourceToTargetSync(t) => &t.common.involved_disks[..],
            Task::TargetVerify(t) => &t.common.involved_disks[..],
        }
    }

    pub fn execute(&self) {
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("<unnamed>");
        match self {
            Task::SourceHash(t) => println!("{name}: Executing SourceHash"),
            Task::SourceToTargetCopy(t) => println!("{name}: Executing SourceToTargetCopy"),
            Task::SourceToTargetSync(t) => println!("{name}: Executing SourceToTargetSync"),
            Task::TargetVerify(t) => println!("{name}: Executing TargetVerify"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommonData {
    pub(crate) involved_disks: Box<[DiskHandle]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceHash{
    pub(crate) common: CommonData,
    pub(crate) source_idx: usize,
    pub(crate) options: ChecksumOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceToTargetCopy {
    pub(crate) common: CommonData,
    pub(crate) source_idx: usize,
    pub(crate) target_idx: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceToTargetSync {
    pub(crate) common: CommonData,
    pub(crate) source_idx: usize,
    pub(crate) target_idx: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetVerify {
    pub(crate) common: CommonData,
    pub(crate) source_idx: usize,
    pub(crate) target_idx: usize,
}
