use std::{
    collections::BTreeMap,
    io::{self, IsTerminal, Write},
    sync::mpsc,
};

use crossterm::{
    cursor, execute,
    terminal::{self, ClearType},
};

#[derive(Debug, PartialEq, Eq)]
pub enum ProgressEvent {
    Started { task_id: usize, description: String },
    Updated { task_id: usize, message: String },
    Finished { task_id: usize },
    Failed { task_id: usize, message: String },
}

pub fn report(sender: &mpsc::Sender<ProgressEvent>, event: ProgressEvent) {
    let _ = sender.send(event);
}

pub fn progress_reporter(receiver: mpsc::Receiver<ProgressEvent>) {
    let interactive = io::stderr().is_terminal();
    let mut lines = BTreeMap::new();
    let mut rendered_lines = 0;

    while let Ok(event) = receiver.recv() {
        let task_id = event.task_id();
        update_lines(&mut lines, event);

        if interactive {
            render_interactive(&lines, &mut rendered_lines);
        } else if let Some(line) = lines.get(&task_id) {
            eprintln!("{}", line.render(task_id));
        }
    }

    if interactive && rendered_lines > 0 {
        let _ = io::stderr().write_all(b"\n");
    }
}

impl ProgressEvent {
    fn task_id(&self) -> usize {
        match self {
            Self::Started { task_id, .. }
            | Self::Updated { task_id, .. }
            | Self::Finished { task_id }
            | Self::Failed { task_id, .. } => *task_id,
        }
    }
}

#[derive(Debug, Default)]
struct TaskLine {
    description: String,
    message: String,
}

impl TaskLine {
    fn render(&self, task_id: usize) -> String {
        format!("{task_id}: {} | {}", self.description, self.message)
    }
}

fn update_lines(lines: &mut BTreeMap<usize, TaskLine>, event: ProgressEvent) {
    match event {
        ProgressEvent::Started {
            task_id,
            description,
        } => {
            lines.insert(
                task_id,
                TaskLine {
                    description,
                    message: "starting".into(),
                },
            );
        }
        ProgressEvent::Updated { task_id, message } => {
            lines.entry(task_id).or_default().message = message;
        }
        ProgressEvent::Finished { task_id } => {
            lines.entry(task_id).or_default().message = "done".into();
        }
        ProgressEvent::Failed { task_id, message } => {
            lines.entry(task_id).or_default().message = format!("failed: {message}");
        }
    }
}

fn render_interactive(lines: &BTreeMap<usize, TaskLine>, rendered_lines: &mut usize) {
    let mut stderr = io::stderr();
    let new_lines = lines.len();

    let _ = execute!(stderr, cursor::MoveUp(*rendered_lines as u16));

    for (task_id, line) in lines {
        let _ = execute!(
            stderr,
            terminal::Clear(ClearType::CurrentLine),
            cursor::MoveToColumn(0)
        );
        let _ = writeln!(stderr, "{}", line.render(*task_id));
    }

    for _ in new_lines..*rendered_lines {
        let _ = execute!(
            stderr,
            terminal::Clear(ClearType::CurrentLine),
            cursor::MoveToColumn(0)
        );
        let _ = writeln!(stderr);
    }

    let _ = stderr.flush();
    *rendered_lines = new_lines;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updates_keep_one_line_per_task() {
        let mut lines = BTreeMap::new();

        update_lines(
            &mut lines,
            ProgressEvent::Started {
                task_id: 2,
                description: "copy".into(),
            },
        );
        update_lines(
            &mut lines,
            ProgressEvent::Updated {
                task_id: 2,
                message: "file.txt".into(),
            },
        );

        assert_eq!(lines.len(), 1);
        assert_eq!(lines[&2].description, "copy");
        assert_eq!(lines[&2].message, "file.txt");
    }

    #[test]
    fn tasks_are_rendered_in_task_id_order() {
        let mut lines = BTreeMap::new();
        update_lines(
            &mut lines,
            ProgressEvent::Started {
                task_id: 4,
                description: "four".into(),
            },
        );
        update_lines(
            &mut lines,
            ProgressEvent::Started {
                task_id: 1,
                description: "one".into(),
            },
        );

        assert_eq!(lines.keys().copied().collect::<Vec<_>>(), vec![1, 4]);
    }
}
