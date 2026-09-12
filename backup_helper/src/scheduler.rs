use std::fmt::Write;
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
    running: usize,
    done: usize,
    // DiskHandle -> busy bool
    disks_busy: Vec<bool>,
}

pub struct SchedulerShared {
    core: Mutex<SchedulerCore>,
    // notified when a task becomes ready
    runnable: Condvar,
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
}

impl SchedulerCore {
    pub fn new(state: BackupHelper) -> Result<Self> {
        let disks_busy = state.disks().iter().map(|_| false).collect();
        let mut s = Self {
            state,
            tasks: vec![],
            dependents: vec![],
            errors: vec![],
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

        // TODO: don't add task if already finished, e.g. source already has hash_file
        for (source_index, source) in self.state.sources().iter().enumerate() {
            check_source_disk(source)?;
            let source_task_id = self.tasks.len();
            let source_disk = source.disk().expect("bug: source disk checked above");
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

            for (target_index, target) in source.targets().iter().enumerate() {
                check_target_disk(target)?;
                let target_disk = target.disk().expect("bug: target disk checked above");
                let target_copy_task_id = self.tasks.len();
                self.tasks.push(TaskEntry {
                    task: Task::SourceToTargetCopy(SourceToTargetCopy{
                        common: CommonData {
                            involved_disks: Box::<[DiskHandle; 2]>::new([source_disk, target_disk]),
                        },
                        source_idx: source_index,
                        target_idx: target_index,
                    }),
                    state: TaskState::Pending,
                    dependencies: vec![source_task_id],
                    remaining_deps: 1,
                    priority: 1,
                });

                if target.verify() {
                    self.tasks.push(TaskEntry {
                        task: Task::TargetVerify(TargetVerify{
                            common: CommonData {
                                involved_disks: Box::<[DiskHandle; 1]>::new([target_disk]),
                            },
                            source_idx: source_index,
                            target_idx: target_index,
                        }),
                        state: TaskState::Pending,
                        dependencies: vec![source_task_id, target_copy_task_id],
                        remaining_deps: 2,
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

    // TODO needs more conditions, e.g. for copy both source needs to exist and
    //      the target disk must be present
    pub fn pick_next(&self) -> Option<TaskId> {
        self.tasks.iter().enumerate()
            .filter(|(_, t)| t.state == TaskState::Ready)
            .filter(|(_, t)| t.involved_disks().iter().all(|d| !self.disks_busy[d.0]))
            .max_by_key(|(_, t)| t.priority)
            .map(|(id, _)| id)
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
            },
            Task::SourceToTargetCopy(t) => {
                let source = &self.state.sources()[t.source_idx];
                TaskContext {
                    source_path: Some(source.path().to_path_buf()),
                    target_path: Some(source.targets()[t.target_idx].path().to_path_buf()),
                    hash_file: None,
                }
            }
            Task::SourceToTargetSync(t) => {
                let source = &self.state.sources()[t.source_idx];
                TaskContext {
                    source_path: Some(source.path().to_path_buf()),
                    target_path: Some(source.targets()[t.target_idx].path().to_path_buf()),
                    hash_file: None,
                }
            }
            Task::TargetVerify(t) => {
                let source = &self.state.sources()[t.source_idx];
                TaskContext {
                    source_path: Some(source.path().to_path_buf()),
                    target_path: Some(source.targets()[t.target_idx].path().to_path_buf()),
                    hash_file: source.hash_file().to_owned(),
                }
            }
        }
    }

    pub fn finished(&self) -> bool {
        self.running == 0 && self.tasks.iter().all(|t| t.state != TaskState::Ready)
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
            if let Some(id) = core.pick_next() {
                break id;
            }

            if core.finished() {
                return;
            }

            core = scheduler.runnable.wait(core).unwrap();
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

    let guard = scheduler.core.lock().unwrap();
    if guard.errors.is_empty() {
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
        Err(BackupHelperError::SchedulerError(combined))
    }
}
