use std::fmt::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use crate::task::{TaskContext, TaskOutcome};
use crate::{
    BackupHelperError,
    backup_helper::{BackupHelper, DiskHandle},
    source::Source,
    target::Target,
    task::{CommonData, SourceHash, SourceToTargetCopy, TargetVerify, Task},
};

type Result<T> = std::result::Result<T, BackupHelperError>;

pub struct SchedulerCore {
    state: BackupHelper,
    // all tasks
    // indexed by TaskId
    tasks: Vec<TaskEntry>,
    // dependents indexed by TaskId
    // e.g. dependents[1] lists the TaskIds that depend on TaskId 1
    dependents: Vec<Vec<TaskId>>,
    errors: Vec<BackupHelperError>,
    fatal_error: Option<BackupHelperError>,
    running: usize,
    done: usize,
    // DiskHandle -> busy bool
    disks_busy: Vec<bool>,
}

pub struct SchedulerShared {
    core: Mutex<SchedulerCore>,
    // notified when a task becomes ready
    runnable: Condvar,
    cancel_requested: AtomicBool,
}

pub type Scheduler = Arc<SchedulerShared>;

type TaskId = usize;

pub struct TaskEntry {
    task: Task,
    state: TaskState,
    // tasks that this task depends on
    dependencies: Vec<TaskId>,
    remaining_deps: usize,
    priority: u8,
}

impl TaskEntry {
    pub fn involved_disks(&self) -> &[DiskHandle] {
        self.task.involved_disks()
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum TaskState {
    Pending,
    Ready,
    Running,
    Done,
    Failed,
}

impl SchedulerShared {
    pub fn new(state: BackupHelper) -> Result<Self> {
        Ok(Self {
            core: Mutex::new(SchedulerCore::new(state)?),
            runnable: Condvar::new(),
            cancel_requested: AtomicBool::new(false),
        })
    }

    pub fn worker_count(&self) -> usize {
        let guard = self.core.lock().unwrap();
        guard.disks_total()
    }

    pub fn close(self: Arc<Self>) -> Result<BackupHelper> {
        let shared = Arc::try_unwrap(self).map_err(|_| {
            BackupHelperError::SchedulerError(
                "Tried to close the scheduler while more than one reference was alive!".to_string(),
            )
        })?;

        Ok(shared.core.into_inner()
            .expect("worker panicked")
            .close())
    }

    pub fn request_cancel(&self) {
        self.cancel_requested.store(true, Ordering::Release);
        // so waiting workers can see the cancel request
        self.runnable.notify_all();
    }

    pub fn cancel_requested(&self) -> bool {
        self.cancel_requested.load(Ordering::Acquire)
    }
}

impl SchedulerCore {
    pub fn new(state: BackupHelper) -> Result<Self> {
        let disks_busy = state.disks().iter().map(|_| false).collect();
        let mut s = Self {
            state,
            tasks: vec![],
            dependents: vec![],
            errors: vec![],
            fatal_error: None,
            disks_busy,
            running: 0,
            done: 0,
        };

        s.make_tasks()?;

        Ok(s)
    }

    pub fn disks_total(&self) -> usize {
        self.disks_busy.len()
    }

    fn make_tasks(&mut self) -> Result<()> {
        let check_source_disk = |source: &Source| match source.disk() {
            Some(_) => Ok(()),
            _ => Err(BackupHelperError::SchedulerError(format!(
                "Source at {:?} has no disk assigned!",
                source.path()
            ))),
        };
        let check_target_disk = |target: &Target| match target.disk() {
            Some(_) => Ok(()),
            _ => Err(BackupHelperError::SchedulerError(format!(
                "Target at {:?} has no disk assigned!",
                target.path()
            ))),
        };

        for (source_index, source) in self.state.sources().iter().enumerate() {
            check_source_disk(source)?;
            let source_disk = source.disk().expect("bug: source disk checked above");

            let mut source_task_id = None;
            if source.hash_file().is_none() {
                source_task_id = Some(self.tasks.len());
                self.tasks.push(TaskEntry {
                    task: Task::SourceHash(SourceHash {
                        common: CommonData {
                            involved_disks: Box::<[DiskHandle; 1]>::new([source_disk]),
                        },
                        source_idx: source_index,
                        options: source.checksum_options().clone(),
                    }),
                    state: TaskState::Ready,
                    dependencies: vec![],
                    remaining_deps: 0,
                    priority: 0,
                });
            }

            for (target_index, target) in source.targets().iter().enumerate() {
                check_target_disk(target)?;
                let target_disk = target.disk().expect("bug: target disk checked above");

                let mut target_copy_task_id = None;
                if !target.is_transferred() {
                    target_copy_task_id = Some(self.tasks.len());
                    let dependencies = match source_task_id {
                            None => vec![],
                            Some(source_task_id) => vec![source_task_id],
                    };

                    self.tasks.push(TaskEntry {
                        task: Task::SourceToTargetCopy(SourceToTargetCopy{
                            common: CommonData {
                                involved_disks: Box::<[DiskHandle; 2]>::new([source_disk, target_disk]),
                            },
                            source_idx: source_index,
                            target_idx: target_index,
                        }),
                        state: match dependencies.len() {
                            0 => TaskState::Ready,
                            _ => TaskState::Pending,
                        },
                        remaining_deps: dependencies.len(),
                        dependencies,
                        priority: 1,
                    });
                }

                if target.verify() && !target.is_verified() {
                    let dependencies = match (source_task_id, target_copy_task_id) {
                            (None, None) => vec![],
                            (Some(_), None) => {
                                unreachable!("source must be done before target copy can be done")
                            }
                            (None, Some(target_copy_task_id)) => vec![target_copy_task_id],
                            (Some(source_task_id), Some(target_copy_task_id)) => {
                                vec![source_task_id, target_copy_task_id]
                            }
                        };
                    self.tasks.push(TaskEntry {
                        task: Task::TargetVerify(TargetVerify {
                            common: CommonData {
                                involved_disks: Box::<[DiskHandle; 1]>::new([target_disk]),
                            },
                            source_idx: source_index,
                            target_idx: target_index,
                        }),
                        state: match dependencies.len() {
                            0 => TaskState::Ready,
                            _ => TaskState::Pending,
                        },
                        remaining_deps: dependencies.len(),
                        dependencies,
                        priority: 0,
                    });
                }
            }
        }

        self.dependents = vec![vec![]; self.tasks.len()];
        for (i, entry) in self.tasks.iter().enumerate() {
            for &dep in &entry.dependencies {
                self.dependents[dep].push(i);
            }
        }

        Ok(())
    }

    pub fn pick_next(&self) -> Result<Option<TaskId>> {
        let mut selected: Option<TaskId> = None;

        for (task_id, task) in self.tasks.iter().enumerate() {
            if task.state != TaskState::Ready {
                continue;
            }

            let can_run = task.involved_disks().iter().try_fold(
                true,
                |can_run, disk| {
                    if !can_run || self.disks_busy[disk.0] {
                        return Ok(false);
                    }

                    self.state.disks()[disk.0].is_mounted()
                })?;

            if can_run &&
                selected
                    .map(|id| task.priority > self.tasks[id].priority)
                    .unwrap_or(true)
            {
                selected = Some(task_id);
            }
        }

        Ok(selected)
    }

    pub fn start_task(&mut self, task: TaskId) -> Task {
        let task = &mut self.tasks[task];
        for disk_id in task.involved_disks() {
            let busy = self.disks_busy[disk_id.0];
            assert!(!busy, "all disks of a ready task must be idle!");
            self.disks_busy[disk_id.0] = true;
        }

        self.running += 1;
        task.state = TaskState::Running;

        task.task.clone()
    }

    pub fn finish_task(&mut self, task_id: TaskId, outcome: Result<TaskOutcome>) {
        let task = &mut self.tasks[task_id];
        for disk_id in task.involved_disks() {
            let busy = self.disks_busy[disk_id.0];
            assert!(busy, "all disks of a running task must be busy!");
            self.disks_busy[disk_id.0] = false;
        }

        self.running -= 1;

        match outcome {
            Ok(o) => {
                self.done += 1;
                task.state = TaskState::Done;

                self.update_state(task_id, o);

                // update other tasks that might have become ready
                for &dependent in &self.dependents[task_id] {
                    let entry = &mut self.tasks[dependent];
                    if entry.state != TaskState::Pending { continue; }

                    entry.remaining_deps -= 1;
                    if entry.remaining_deps == 0 {
                        entry.state = TaskState::Ready;
                    }
                }
            },
            Err(e) => {
                task.state = TaskState::Failed;
                self.errors.push(e);
                self.mark_failed_dependents(task_id);
            },
        }
    }

    fn update_state(&mut self, task_id: TaskId, outcome: TaskOutcome) {
        let task = &mut self.tasks[task_id].task;
        match outcome {
            TaskOutcome::SourceHash { hash_file, hash_log_file } => {
                let Task::SourceHash(task) = task else {
                    unreachable!("outcome doesn't match task");
                };

                let source = self.state.source_mut(task.source_idx);
                source.set_hash_file(hash_file);
                source.set_hash_log_file(hash_log_file);
            },
            TaskOutcome::SourceToTargetCopy => {
                let Task::SourceToTargetCopy(task) = task else {
                    unreachable!("outcome doesn't match task");
                };

                let source = self.state.source_mut(task.source_idx);
                let target = source.target_mut(task.target_idx);
                target.transferred();
            },
            TaskOutcome::SourceToTargetSync => {
                let Task::SourceToTargetSync(task) = task else {
                    unreachable!("outcome doesn't match task");
                };

                let source = self.state.source_mut(task.source_idx);
                let target = source.target_mut(task.target_idx);
                target.transferred();
            },
            TaskOutcome::TargetVerify(verified_info) => {
                let Task::TargetVerify(task) = task else {
                    unreachable!("outcome doesn't match task");
                };

                let source = self.state.source_mut(task.source_idx);
                let target = source.target_mut(task.target_idx);
                target.verified(verified_info);
            },
        }
    }

    fn mark_failed_dependents(&mut self, task_id: TaskId) {
        for i in 0..self.dependents[task_id].len() {
            let dependent = self.dependents[task_id][i];
            if self.tasks[dependent].state != TaskState::Pending { continue; }

            self.tasks[dependent].state = TaskState::Failed;
            self.mark_failed_dependents(dependent);
        }
    }

    pub fn context(&self, task: &Task) -> TaskContext {
        match task {
            Task::SourceHash(t) => TaskContext {
                source_path: Some(self.state.sources()[t.source_idx].path().to_path_buf()),
                target_path: None,
                hash_file: None,
                checksum_options: Some(
                    self.state.sources()[t.source_idx]
                        .checksum_options()
                        .clone(),
                ),
                log_directory: None,
            },
            Task::SourceToTargetCopy(t) => {
                let source = &self.state.sources()[t.source_idx];
                TaskContext {
                    source_path: Some(source.path().to_path_buf()),
                    target_path: Some(source.targets()[t.target_idx].path().to_path_buf()),
                    hash_file: None,
                    checksum_options: None,
                    log_directory: None,
                }
            }
            Task::SourceToTargetSync(t) => {
                let source = &self.state.sources()[t.source_idx];
                TaskContext {
                    source_path: Some(source.path().to_path_buf()),
                    target_path: Some(source.targets()[t.target_idx].path().to_path_buf()),
                    hash_file: None,
                    checksum_options: None,
                    log_directory: None,
                }
            }
            Task::TargetVerify(t) => {
                let source = &self.state.sources()[t.source_idx];
                TaskContext {
                    source_path: Some(source.path().to_path_buf()),
                    target_path: Some(source.targets()[t.target_idx].path().to_path_buf()),
                    hash_file: source.hash_file().to_owned(),
                    checksum_options: None,
                    log_directory: None,
                }
            }
        }
    }

    pub fn finished(&self) -> bool {
        self.running == 0 && self.tasks.iter().all(|t| t.state != TaskState::Ready)
    }

    fn has_ready_tasks(&self) -> bool {
        self.tasks.iter().any(|task| task.state == TaskState::Ready)
    }

    pub fn close(self) -> BackupHelper {
        self.state
    }
}

fn worker(scheduler: &Scheduler) {
    loop {
        let guard = scheduler.core.lock().unwrap();
        let mut core = guard;
        let task_id = loop {
            if scheduler.cancel_requested() {
                return;
            }

            match core.pick_next() {
                Ok(Some(id)) => break id,

                Ok(None) if core.finished() => {
                    return;
                }

                Ok(None) if core.running == 0 && core.has_ready_tasks() => {
                    core.fatal_error = Some(BackupHelperError::SchedulerError(
                        "ready tasks cannot run because their disks are unavailable".to_string(),
                    ));

                    drop(core);
                    scheduler.runnable.notify_all();
                    return;
                }

                Ok(None) => {
                    core = scheduler.runnable.wait(core).unwrap();
                }

                Err(error) => {
                    core.fatal_error = Some(error);

                    drop(core);
                    scheduler.runnable.notify_all();
                    return;
                }
            }
        };

        let task = core.start_task(task_id);
        let ctx = core.context(&task);

        drop(core);

        let outcome = task.execute(&ctx);

        let guard = scheduler.core.lock().unwrap();
        let mut core = guard;
        core.finish_task(task_id, outcome);
        let done = core.finished();
        drop(core);

        // task is done, others might become runnable
        scheduler.runnable.notify_all();

        if done { break; }
    }
}

pub fn run(scheduler: &Scheduler) -> Result<()> {
    let handles = (0..scheduler.worker_count())
        .map(|i| {
            let sched = Arc::clone(scheduler);
            thread::Builder::new()
                .name(format!("worker-{i}"))
                .spawn(move || worker(&sched))
                .expect("failed to spawn worker")
        })
        .collect::<Vec<_>>();

    for h in handles {
        h.join().expect("worker panicked");
    }

    if scheduler.cancel_requested() {
        return Err(BackupHelperError::Interrupted);
    }

    let guard = scheduler.core.lock().unwrap();
    if guard.errors.is_empty() && guard.fatal_error.is_none() {
        Ok(())
    } else {
        let mut combined = String::new();
        let mut first = true;
        for err in &guard.errors {
            if !first {
                combined.push('\n');
            }
            write!(combined, "Task failed: {}", err).unwrap();

            first = false;
        }

        match &guard.fatal_error {
            None => {},
            Some(e) => {
                if !first {
                    combined.push('\n');
                }

                write!(combined, "Fatal error: {}", e).unwrap();
            },
        }

        Err(BackupHelperError::SchedulerError(combined))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse, target::VerifiedInfo};
    use serde_json::Value;
    use std::path::Path;
    use testdir::testdir;

    fn state(config: &str) -> BackupHelper {
        let mut state = BackupHelper::default();
        state.reconcile(parse::parse(config).unwrap()).unwrap();
        state
    }

    fn completed_state(config: &str, transferred: bool, verified: bool) -> BackupHelper {
        let serialized = state(config).serialize().unwrap();
        let mut json: Value = serde_json::from_str(&serialized).unwrap();
        let target = &mut json["sources"][0]["targets"][0];
        target["transferred"] = transferred.into();
        target["verified"] = if verified {
            serde_json::json!({
                "checked": 1,
                "errors": 0,
                "missing": 0,
                "crc_errors": 0,
                "log_file": ""
            })
        } else {
            Value::Null
        };

        BackupHelper::from_state(&serde_json::to_string(&json).unwrap()).unwrap()
    }

    fn state_with_verify(config: &str, verify: bool) -> BackupHelper {
        let serialized = state(config).serialize().unwrap();
        let mut json: Value = serde_json::from_str(&serialized).unwrap();
        for target in json["sources"][0]["targets"].as_array_mut().unwrap() {
            target["verify"] = verify.into();
        }

        BackupHelper::from_state(&serde_json::to_string(&json).unwrap()).unwrap()
    }

    fn path_literal(path: &Path) -> String {
        serde_json::to_string(&path.to_string_lossy().to_string()).unwrap()
    }

    fn normal_config(root: &Path) -> String {
        let source_disk = path_literal(&root.join("source-disk"));
        let target_disk = path_literal(&root.join("target-disk"));
        let source = path_literal(&root.join("source-disk/source"));
        let target = path_literal(&root.join("target-disk/target"));

        format!(
            r#"
            disks {{
                disk "source" {{ path {source_disk} }}
                disk "target" {{ path {target_disk} }}
            }}
            source {source} {{
                target {target} {{ transfer_mode copy verify #true }}
            }}
        "#
        )
    }

    fn two_target_config(root: &Path, verify: bool) -> String {
        let source_disk = path_literal(&root.join("source-disk"));
        let target_disk = path_literal(&root.join("target-disk"));
        let source = path_literal(&root.join("source-disk/source"));
        let first_target = path_literal(&root.join("target-disk/first"));
        let second_target = path_literal(&root.join("target-disk/second"));
        let verify = if verify { "#true" } else { "#false" };

        format!(
            r#"
            disks {{
                disk "source" {{ path {source_disk} }}
                disk "target" {{ path {target_disk} }}
            }}
            source {source} {{
                target {first_target} {{ transfer_mode copy verify {verify} }}
                target {second_target} {{ transfer_mode copy verify {verify} }}
            }}
        "#
        )
    }

    fn source_hash_outcome(root: &Path) -> TaskOutcome {
        TaskOutcome::SourceHash {
            hash_file: root.join("source.sha512"),
            hash_log_file: root.join("source.log"),
        }
    }

    fn verify_outcome(root: &Path) -> TaskOutcome {
        TaskOutcome::TargetVerify(VerifiedInfo {
            checked: 1,
            errors: 0,
            missing: 0,
            crc_errors: 0,
            log_file: root.join("verify.log"),
        })
    }

    #[test]
    fn dependencies_are_released_in_order() {
        let root = testdir!();
        let mut core = SchedulerCore::new(state(&normal_config(&root))).unwrap();

        assert_eq!(core.tasks.len(), 3);
        assert_eq!(core.tasks[0].state, TaskState::Ready);
        assert_eq!(core.tasks[1].dependencies, vec![0]);
        assert_eq!(core.tasks[1].state, TaskState::Pending);
        assert_eq!(core.tasks[2].dependencies, vec![0, 1]);
        assert_eq!(core.tasks[2].state, TaskState::Pending);

        core.start_task(0);
        core.finish_task(0, Ok(source_hash_outcome(&root)));
        assert_eq!(core.tasks[0].state, TaskState::Done);
        assert_eq!(core.tasks[1].state, TaskState::Ready);
        assert_eq!(core.tasks[2].state, TaskState::Pending);

        core.start_task(1);
        core.finish_task(1, Ok(TaskOutcome::SourceToTargetCopy));
        assert!(core.state.sources()[0].targets()[0].is_transferred());
        assert_eq!(core.tasks[2].state, TaskState::Ready);

        core.start_task(2);
        core.finish_task(2, Ok(verify_outcome(&root)));
        assert!(core.tasks.iter().all(|task| task.state == TaskState::Done));
        assert!(core.finished());
    }

    #[test]
    fn finish_target_verify_persists_verified_info() {
        let root = testdir!();
        let mut core = SchedulerCore::new(state(&normal_config(&root))).unwrap();

        core.start_task(0);
        core.finish_task(0, Ok(source_hash_outcome(&root)));
        core.start_task(1);
        core.finish_task(1, Ok(TaskOutcome::SourceToTargetCopy));

        let verified = VerifiedInfo {
            checked: 4,
            errors: 2,
            missing: 1,
            crc_errors: 1,
            log_file: root.join("verification.log"),
        };
        core.start_task(2);
        core.finish_task(2, Ok(TaskOutcome::TargetVerify(verified.clone())));

        assert!(core.state.sources()[0].targets()[0].is_verified());

        let state = core.close();
        let json: Value = serde_json::from_str(&state.serialize().unwrap()).unwrap();
        assert_eq!(
            json["sources"][0]["targets"][0]["verified"],
            serde_json::json!({
                "checked": verified.checked,
                "errors": verified.errors,
                "missing": verified.missing,
                "crc_errors": verified.crc_errors,
                "log_file": verified.log_file,
            })
        );
    }

    #[test]
    fn failed_source_marks_all_dependents_failed() {
        let root = testdir!();
        let mut core = SchedulerCore::new(state(&normal_config(&root))).unwrap();
        core.start_task(0);
        core.finish_task(
            0,
            Err(BackupHelperError::TaskError("source failed".into())),
        );

        assert_eq!(core.tasks[0].state, TaskState::Failed);
        assert_eq!(core.tasks[1].state, TaskState::Failed);
        assert_eq!(core.tasks[2].state, TaskState::Failed);
        assert_eq!(core.errors.len(), 1);
        assert!(core.finished());
    }

    #[test]
    fn failed_copy_marks_verification_failed() {
        let root = testdir!();
        let mut core = SchedulerCore::new(state(&normal_config(&root))).unwrap();
        core.start_task(0);
        core.finish_task(0, Ok(source_hash_outcome(&root)));
        core.start_task(1);
        core.finish_task(1, Err(BackupHelperError::CopyError("copy failed".into())));

        assert_eq!(core.tasks[0].state, TaskState::Done);
        assert_eq!(core.tasks[1].state, TaskState::Failed);
        assert_eq!(core.tasks[2].state, TaskState::Failed);
        assert!(!core.state.sources()[0].targets()[0].is_transferred());
        assert_eq!(core.errors.len(), 1);
    }

    #[test]
    fn completed_work_is_not_added_to_the_task_graph() {
        let root = testdir!();
        let source_disk = path_literal(&root.join("source-disk"));
        let target_disk = path_literal(&root.join("target-disk"));
        let source = path_literal(&root.join("source-disk/source"));
        let hash_file = path_literal(&root.join("source.sha512"));
        let target = path_literal(&root.join("target-disk/target"));
        let config = format!(
            r#"
            disks {{
                disk "source" {{ path {source_disk} }}
                disk "target" {{ path {target_disk} }}
            }}
            source {source} {{
                hash_file {hash_file}
                target {target} {{ transfer_mode copy verify #true }}
            }}
        "#
        );
        let core = SchedulerCore::new(completed_state(&config, true, true)).unwrap();

        assert!(core.tasks.is_empty());
    }

    #[test]
    fn reloaded_transferred_target_only_schedules_verification() {
        let root = testdir!();
        let source_disk = path_literal(&root.join("source-disk"));
        let target_disk = path_literal(&root.join("target-disk"));
        let source = path_literal(&root.join("source-disk/source"));
        let hash_file = path_literal(&root.join("source.sha512"));
        let target = path_literal(&root.join("target-disk/target"));
        let config = format!(
            r#"
            disks {{
                disk "source" {{ path {source_disk} }}
                disk "target" {{ path {target_disk} }}
            }}
            source {source} {{
                hash_file {hash_file}
                target {target} {{ transfer_mode copy verify #true }}
            }}
        "#
        );
        let core = SchedulerCore::new(completed_state(&config, true, false)).unwrap();

        assert_eq!(core.tasks.len(), 1);
        assert!(matches!(core.tasks[0].task, Task::TargetVerify(_)));
        assert!(core.tasks[0].dependencies.is_empty());
    }

    #[test]
    fn existing_source_hash_makes_copy_ready_without_a_dependency() {
        let root = testdir!();
        let source_disk = path_literal(&root.join("source-disk"));
        let target_disk = path_literal(&root.join("target-disk"));
        let source = path_literal(&root.join("source-disk/source"));
        let hash_file = path_literal(&root.join("source.sha512"));
        let target = path_literal(&root.join("target-disk/target"));
        let config = format!(
            r#"
            disks {{
                disk "source" {{ path {source_disk} }}
                disk "target" {{ path {target_disk} }}
            }}
            source {source} {{
                hash_file {hash_file}
                target {target} {{ transfer_mode copy verify #true }}
            }}
        "#
        );
        let core = SchedulerCore::new(state(&config)).unwrap();

        assert_eq!(core.tasks.len(), 2);
        assert_eq!(core.tasks[0].state, TaskState::Ready);
        assert!(matches!(core.tasks[0].task, Task::SourceToTargetCopy(_)));
        assert!(core.tasks[0].dependencies.is_empty());
        assert_eq!(core.tasks[1].dependencies, vec![0]);
    }

    #[test]
    fn verification_is_not_scheduled_when_disabled() {
        let root = testdir!();
        let config = normal_config(&root).replace("verify #true", "verify #false");
        let core = SchedulerCore::new(state_with_verify(&config, false)).unwrap();

        assert_eq!(core.tasks.len(), 2);
        assert!(matches!(core.tasks[0].task, Task::SourceHash(_)));
        assert!(matches!(core.tasks[1].task, Task::SourceToTargetCopy(_)));
        assert_eq!(core.tasks[1].dependencies, vec![0]);
    }

    #[test]
    fn verification_is_not_scheduled_when_target_is_already_verified() {
        let root = testdir!();
        let config = normal_config(&root);
        let mut helper = state(&config);
        helper.source_mut(0).target_mut(0).verified(VerifiedInfo {
            checked: 1,
            errors: 0,
            missing: 0,
            crc_errors: 0,
            log_file: root.join("verify.log"),
        });

        let core = SchedulerCore::new(helper).unwrap();

        assert_eq!(core.tasks.len(), 2);
        assert!(matches!(core.tasks[0].task, Task::SourceHash(_)));
        assert!(matches!(core.tasks[1].task, Task::SourceToTargetCopy(_)));
    }

    #[test]
    fn copy_is_not_scheduled_when_target_is_already_transferred() {
        let root = testdir!();
        let source_disk = path_literal(&root.join("source-disk"));
        let target_disk = path_literal(&root.join("target-disk"));
        let source = path_literal(&root.join("source-disk/source"));
        let hash_file = path_literal(&root.join("source.sha512"));
        let target = path_literal(&root.join("target-disk/target"));
        let config = format!(
            r#"
            disks {{
                disk "source" {{ path {source_disk} }}
                disk "target" {{ path {target_disk} }}
            }}
            source {source} {{
                hash_file {hash_file}
                target {target} {{ transfer_mode copy verify #true }}
            }}
        "#
        );
        let mut helper = state(&config);
        helper.source_mut(0).target_mut(0).transferred();

        let core = SchedulerCore::new(helper).unwrap();

        assert_eq!(core.tasks.len(), 1);
        assert!(matches!(core.tasks[0].task, Task::TargetVerify(_)));
        assert!(core.tasks[0].dependencies.is_empty());
    }

    #[test]
    fn multiple_targets_have_independent_copy_and_verify_tasks() {
        let root = testdir!();
        let core = SchedulerCore::new(state(&two_target_config(&root, true))).unwrap();

        assert_eq!(core.tasks.len(), 5);
        assert_eq!(core.tasks[1].dependencies, vec![0]);
        assert_eq!(core.tasks[2].dependencies, vec![0, 1]);
        assert_eq!(core.tasks[3].dependencies, vec![0]);
        assert_eq!(core.tasks[4].dependencies, vec![0, 3]);
    }

    #[test]
    fn failed_copy_does_not_mark_unrelated_target_transferred() {
        let root = testdir!();
        let mut core =
            SchedulerCore::new(state_with_verify(&two_target_config(&root, true), false)).unwrap();

        core.start_task(0);
        core.finish_task(0, Ok(source_hash_outcome(&root)));
        core.start_task(1);
        core.finish_task(1, Err(BackupHelperError::CopyError("copy failed".into())));

        assert_eq!(core.tasks[1].state, TaskState::Failed);
        assert_eq!(core.tasks[2].state, TaskState::Ready);
        assert!(!core.state.sources()[0].targets()[0].is_transferred());
        assert!(!core.state.sources()[0].targets()[1].is_transferred());

        core.start_task(2);
        core.finish_task(2, Ok(TaskOutcome::SourceToTargetCopy));

        assert!(core.state.sources()[0].targets()[1].is_transferred());
        assert!(!core.state.sources()[0].targets()[0].is_transferred());
    }

    #[test]
    fn failed_task_marks_all_dependent_tasks_failed() {
        let root = testdir!();
        let mut core = SchedulerCore::new(state(&normal_config(&root))).unwrap();

        core.start_task(0);
        core.finish_task(
            0,
            Err(BackupHelperError::TaskError("source failed".into())),
        );

        assert!(core
            .tasks
            .iter()
            .all(|task| task.state == TaskState::Failed));
        assert!(core.finished());
    }

    #[test]
    fn filesystem_tasks_update_and_persist_scheduler_state() {
        let root = testdir!();
        let source_path = root.join("source-disk/source");
        let target_path = root.join("target-disk/target");
        std::fs::create_dir_all(&source_path).unwrap();
        std::fs::write(source_path.join("file.txt"), "content").unwrap();

        let mut core = SchedulerCore::new(state(&normal_config(&root))).unwrap();

        let source_task = core.start_task(0);
        let mut source_context = core.context(&source_task);
        source_context.log_directory = Some(root.clone());
        let source_outcome = source_task.execute(&source_context).unwrap();
        let hash_file = match &source_outcome {
            TaskOutcome::SourceHash { hash_file, .. } => hash_file.clone(),
            _ => panic!("source task returned the wrong outcome"),
        };
        core.finish_task(0, Ok(source_outcome));
        assert_eq!(core.state.sources()[0].hash_file(), &Some(hash_file.clone()));

        let copy_task = core.start_task(1);
        let copy_context = core.context(&copy_task);
        let copy_outcome = copy_task.execute(&copy_context).unwrap();
        std::fs::copy(&hash_file, target_path.join(hash_file.file_name().unwrap())).unwrap();
        core.finish_task(1, Ok(copy_outcome));
        assert!(core.state.sources()[0].targets()[0].is_transferred());

        let verify_task = core.start_task(2);
        let mut verify_context = core.context(&verify_task);
        verify_context.log_directory = Some(root.clone());
        let verify_outcome = verify_task.execute(&verify_context).unwrap();
        core.finish_task(2, Ok(verify_outcome));
        assert!(core.state.sources()[0].targets()[0].is_verified());

        let state = core.close();
        let serialized = state.serialize().unwrap();
        let reloaded = BackupHelper::from_state(&serialized).unwrap();
        assert_eq!(reloaded.sources()[0].hash_file(), &Some(hash_file));
        assert!(reloaded.sources()[0].targets()[0].is_transferred());
        assert!(reloaded.sources()[0].targets()[0].is_verified());
        let reloaded_core = SchedulerCore::new(reloaded).unwrap();
        assert!(reloaded_core.tasks.is_empty());
    }

    #[test]
    fn run_reports_task_failures_and_exits() {
        let root = testdir!();
        let mut core = SchedulerCore::new(state(&normal_config(&root))).unwrap();
        core.start_task(0);
        core.finish_task(
            0,
            Err(BackupHelperError::TaskError("source failed".into())),
        );
        let scheduler = Arc::new(SchedulerShared {
            core: Mutex::new(core),
            runnable: Condvar::new(),
            cancel_requested: AtomicBool::new(false),
        });

        let error = run(&scheduler).unwrap_err();
        let BackupHelperError::SchedulerError(message) = error else {
            panic!("expected a scheduler error");
        };
        assert!(message.contains("Task failed: TaskError: source failed"));
    }

    #[test]
    fn cancellation_prevents_workers_from_starting_tasks() {
        let root = testdir!();
        let scheduler = Arc::new(SchedulerShared::new(state(&normal_config(&root))).unwrap());

        scheduler.request_cancel();
        assert!(scheduler.cancel_requested());

        assert!(matches!(run(&scheduler), Err(BackupHelperError::Interrupted)));

        let core = scheduler.core.lock().unwrap();
        assert!(core
            .tasks
            .iter()
            .all(|task| matches!(task.state, TaskState::Pending | TaskState::Ready)));
    }

    #[test]
    fn run_reports_fatal_unavailable_disk_errors() {
        let root = testdir!();
        let missing_disk = path_literal(&root.join("missing-disk"));
        let source = path_literal(&root.join("missing-disk/source"));
        let target = path_literal(&root.join("missing-disk/target"));
        let config = format!(
            r#"
            disks {{ disk "missing" {{ path {missing_disk} }} }}
            source {source} {{
                target {target} {{ transfer_mode copy }}
            }}
        "#
        );
        let scheduler = Arc::new(SchedulerShared::new(state(&config)).unwrap());

        let error = run(&scheduler).unwrap_err();
        let BackupHelperError::SchedulerError(message) = error else {
            panic!("expected a scheduler error");
        };
        assert!(message.contains("Fatal error: Scheduler: ready tasks cannot run"));
    }
}
