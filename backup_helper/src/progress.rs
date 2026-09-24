use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, IsTerminal, Write},
    sync::mpsc,
};

use crossterm::{
    cursor, execute,
    terminal::{self, ClearType},
};
use unicode_width::UnicodeWidthChar;

use crate::task_log::VerifySummary;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TaskDisplay {
    pub(crate) operation: String,
    pub(crate) source: Option<String>,
    pub(crate) target: Option<String>,
}

impl TaskDisplay {
    pub(crate) fn new(operation: &str, source: Option<String>, target: Option<String>) -> Self {
        Self {
            operation: operation.to_owned(),
            source,
            target,
        }
    }

    fn one_line(&self) -> String {
        let mut result = self.operation.clone();

        if let Some(source) = &self.source {
            result.push(' ');
            result.push_str(source);
        }

        if let Some(target) = &self.target {
            if self.source.is_some() {
                result.push_str(" -> ");
            } else {
                result.push(' ');
            }
            result.push_str(target);
        }

        result
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProgressEvent {
    Started {
        task_id: usize,
        display: TaskDisplay,
    },
    Updated {
        task_id: usize,
        message: String,
    },
    Finished {
        task_id: usize,
        verify_summary: Option<VerifySummary>,
    },
    Failed {
        task_id: usize,
        message: String,
    },
}

pub fn report(sender: &mpsc::Sender<ProgressEvent>, event: ProgressEvent) {
    let _ = sender.send(event);
}

pub fn progress_reporter(receiver: mpsc::Receiver<ProgressEvent>) -> io::Result<()> {
    let interactive = io::stderr().is_terminal();
    let mut lines = BTreeMap::new();
    let mut active_lines = BTreeMap::new();
    let mut completed_lines = BTreeSet::new();
    let mut rendered_rows = 0;

    while let Ok(event) = receiver.recv() {
        let task_id = event.task_id();

        if interactive {
            let completed = update_active_lines(&mut active_lines, &mut completed_lines, event);
            let width = terminal_width()?;
            render_interactive(&active_lines, completed, &mut rendered_rows, width)?;
        } else {
            let verify_summary = match &event {
                ProgressEvent::Finished { verify_summary, .. } => verify_summary.clone(),
                _ => None,
            };
            update_lines(&mut lines, event);
            if let Some(line) = lines.get(&task_id) {
                eprintln!("{}", line.render_flat(task_id));
            }
            if let Some(summary) = verify_summary {
                eprint!("{summary}");
            }
        }
    }

    if interactive && rendered_rows > 0 {
        let mut stderr = io::stderr();
        stderr.write_all(b"\n")?;
    }

    Ok(())
}

impl ProgressEvent {
    fn task_id(&self) -> usize {
        match self {
            Self::Started { task_id, .. }
            | Self::Updated { task_id, .. }
            | Self::Finished { task_id, .. }
            | Self::Failed { task_id, .. } => *task_id,
        }
    }
}

#[derive(Debug, Default)]
struct TaskLine {
    display: TaskDisplay,
    message: String,
}

impl TaskLine {
    fn render_flat(&self, task_id: usize) -> String {
        format!("{task_id}: {} | {}", self.display.one_line(), self.message)
    }

    fn layout(&self, task_id: usize, width: usize) -> Vec<String> {
        let width = width.max(1);
        let mut rows = Vec::new();

        let first_row = match (&self.display.source, &self.display.target) {
            (Some(source), Some(_)) => {
                format!("{task_id}: {} {source}", self.display.operation)
            }
            (Some(source), None) => {
                format!("{task_id}: {} {source}", self.display.operation)
            }
            (None, Some(target)) => {
                format!("{task_id}: {} {target}", self.display.operation)
            }
            (None, None) => format!("{task_id}: {}", self.display.operation),
        };
        rows.extend(wrap_display_line(&first_row, width, "       "));

        if self.display.source.is_some()
            && let Some(target) = &self.display.target
        {
            let target_row = format!("   -> {target}");
            rows.extend(wrap_display_line(&target_row, width, "      "));
        }

        let message_row = format!("      {}", self.message);
        rows.extend(wrap_display_line(&message_row, width, "      "));
        rows
    }
}

fn update_lines(lines: &mut BTreeMap<usize, TaskLine>, event: ProgressEvent) {
    match event {
        ProgressEvent::Started { task_id, display } => {
            lines.insert(
                task_id,
                TaskLine {
                    display,
                    message: "starting".into(),
                },
            );
        }
        ProgressEvent::Updated { task_id, message } => {
            lines.entry(task_id).or_default().message = message;
        }
        ProgressEvent::Finished { task_id, .. } => {
            lines.entry(task_id).or_default().message = "done".into();
        }
        ProgressEvent::Failed { task_id, message } => {
            lines.entry(task_id).or_default().message = format!("failed: {message}");
        }
    }
}

#[derive(Debug)]
struct CompletedTask {
    task_id: usize,
    line: TaskLine,
    verify_summary: Option<VerifySummary>,
}

fn update_active_lines(
    lines: &mut BTreeMap<usize, TaskLine>,
    completed: &mut BTreeSet<usize>,
    event: ProgressEvent,
) -> Option<CompletedTask> {
    match event {
        ProgressEvent::Started { task_id, display } => {
            if !completed.contains(&task_id) {
                lines.insert(
                    task_id,
                    TaskLine {
                        display,
                        message: "starting".into(),
                    },
                );
            }
            None
        }
        ProgressEvent::Updated { task_id, message } => {
            if !completed.contains(&task_id)
                && let Some(line) = lines.get_mut(&task_id)
            {
                line.message = message;
            }
            None
        }
        ProgressEvent::Finished {
            task_id,
            verify_summary,
        } => finish_active_line(lines, completed, task_id, "done".into(), verify_summary),
        ProgressEvent::Failed { task_id, message } => finish_active_line(
            lines,
            completed,
            task_id,
            format!("failed: {message}"),
            None,
        ),
    }
}

fn finish_active_line(
    lines: &mut BTreeMap<usize, TaskLine>,
    completed: &mut BTreeSet<usize>,
    task_id: usize,
    message: String,
    verify_summary: Option<VerifySummary>,
) -> Option<CompletedTask> {
    if completed.contains(&task_id) {
        return None;
    }

    let Some(mut line) = lines.remove(&task_id) else {
        completed.insert(task_id);
        return None;
    };

    line.message = message;
    completed.insert(task_id);
    Some(CompletedTask {
        task_id,
        line,
        verify_summary,
    })
}

fn render_interactive(
    lines: &BTreeMap<usize, TaskLine>,
    completed: Option<CompletedTask>,
    rendered_rows: &mut usize,
    width: usize,
) -> io::Result<()> {
    let mut stderr = io::stderr();
    clear_rendered(&mut stderr, *rendered_rows)?;

    if let Some(completed) = completed.as_ref() {
        write_rows(
            &mut stderr,
            &completed.line.layout(completed.task_id, width),
        )?;
        if let Some(summary) = &completed.verify_summary {
            write!(stderr, "{summary}")?;
        }
    }

    let mut new_rows = 0;
    for (task_id, line) in lines {
        let rows = line.layout(*task_id, width);
        new_rows += rows.len();
        write_rows(&mut stderr, &rows)?;
    }

    stderr.flush()?;
    *rendered_rows = new_rows;
    Ok(())
}

fn clear_rendered(stderr: &mut io::Stderr, rows: usize) -> io::Result<()> {
    if rows == 0 {
        return Ok(());
    }

    let rows_to_move = u16::try_from(rows).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "progress display is taller than the terminal cursor range",
        )
    })?;
    execute!(stderr, cursor::MoveUp(rows_to_move))?;

    for row in 0..rows {
        execute!(
            stderr,
            cursor::MoveToColumn(0),
            terminal::Clear(ClearType::CurrentLine)
        )?;
        if row + 1 < rows {
            execute!(stderr, cursor::MoveDown(1))?;
        }
    }

    if rows > 1 {
        execute!(stderr, cursor::MoveUp((rows_to_move - 1) as u16))?;
    }

    Ok(())
}

fn write_rows<W: Write>(writer: &mut W, rows: &[String]) -> io::Result<()> {
    for row in rows {
        writeln!(writer, "{row}")?;
    }
    Ok(())
}

fn terminal_width() -> io::Result<usize> {
    let (columns, _) = terminal::size()?;
    if columns == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "terminal has zero width",
        ));
    }

    // Keep one column unused so a terminal's delayed automatic-wrap state cannot
    // add an unaccounted-for physical row.
    Ok((usize::from(columns) - 1).max(1))
}

fn wrap_display_line(line: &str, width: usize, continuation: &str) -> Vec<String> {
    let width = width.max(1);
    // Leave room for a two-column character after the continuation indent.
    let continuation = truncate_to_width(continuation, width.saturating_sub(2));
    let mut rows = Vec::new();

    for segment in line.split('\n') {
        let mut current = String::new();
        let mut current_width = 0;

        for character in segment.chars() {
            let character_width = character_width(character);
            if current_width + character_width > width && !current.is_empty() {
                rows.push(std::mem::take(&mut current));
                current.push_str(&continuation);
                current_width = display_width(&continuation);
            }

            current.push(character);
            current_width += character_width;
        }

        rows.push(current);
    }

    if rows.is_empty() {
        rows.push(String::new());
    }
    rows
}

fn truncate_to_width(value: &str, width: usize) -> String {
    let mut result = String::new();
    let mut result_width = 0;

    for character in value.chars() {
        let character_width = character_width(character);
        if result_width + character_width > width {
            break;
        }
        result.push(character);
        result_width += character_width;
    }

    result
}

fn display_width(value: &str) -> usize {
    value.chars().map(character_width).sum()
}

fn character_width(character: char) -> usize {
    UnicodeWidthChar::width(character).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn copy_line(message: &str) -> TaskLine {
        TaskLine {
            display: TaskDisplay::new("copy", Some("/mnt/src".into()), Some("/mnt/target".into())),
            message: message.into(),
        }
    }

    #[test]
    fn active_tasks_are_rendered_as_multiple_rows() {
        let rows = copy_line("copied file \"foo.txt\"").layout(0, 80);

        assert_eq!(
            rows,
            [
                "0: copy /mnt/src",
                "   -> /mnt/target",
                "      copied file \"foo.txt\"",
            ]
        );
    }

    #[test]
    fn active_task_layout_wraps_to_the_available_width() {
        let rows = copy_line("copied file with a very long name.txt").layout(0, 24);

        assert!(rows.len() > 3);
        assert!(rows.iter().all(|row| display_width(row) <= 24));
    }

    #[test]
    fn active_task_layout_accounts_for_wide_characters() {
        let line = TaskLine {
            display: TaskDisplay::new("copy", Some("源".into()), Some("目标".into())),
            message: "文件".into(),
        };

        let rows = line.layout(0, 8);

        assert!(rows.iter().all(|row| display_width(row) <= 8), "{rows:?}");
    }

    #[test]
    fn finished_task_is_returned_only_once() {
        let mut lines = BTreeMap::new();
        let mut completed = BTreeSet::new();

        update_active_lines(
            &mut lines,
            &mut completed,
            ProgressEvent::Started {
                task_id: 2,
                display: TaskDisplay::new("copy", Some("/src".into()), Some("/dst".into())),
            },
        );
        update_active_lines(
            &mut lines,
            &mut completed,
            ProgressEvent::Updated {
                task_id: 2,
                message: "copied file.txt".into(),
            },
        );

        let finished = update_active_lines(
            &mut lines,
            &mut completed,
            ProgressEvent::Finished {
                task_id: 2,
                verify_summary: None,
            },
        );

        assert!(lines.is_empty());
        assert_eq!(finished.as_ref().unwrap().task_id, 2);
        assert_eq!(finished.as_ref().unwrap().line.message, "done");
        assert!(
            update_active_lines(
                &mut lines,
                &mut completed,
                ProgressEvent::Finished {
                    task_id: 2,
                    verify_summary: None,
                },
            )
            .is_none()
        );
    }

    #[test]
    fn verify_completion_keeps_its_summary() {
        let mut lines = BTreeMap::new();
        let mut completed = BTreeSet::new();
        let summary = VerifySummary::default();

        update_active_lines(
            &mut lines,
            &mut completed,
            ProgressEvent::Started {
                task_id: 2,
                display: TaskDisplay::new("verify", None, Some("/target".into())),
            },
        );
        let finished = update_active_lines(
            &mut lines,
            &mut completed,
            ProgressEvent::Finished {
                task_id: 2,
                verify_summary: Some(summary.clone()),
            },
        );

        assert_eq!(finished.unwrap().verify_summary, Some(summary));
    }

    #[test]
    fn noninteractive_tasks_keep_the_flat_format() {
        let mut lines = BTreeMap::new();

        update_lines(
            &mut lines,
            ProgressEvent::Started {
                task_id: 2,
                display: TaskDisplay::new(
                    "copy",
                    Some("/mnt/src".into()),
                    Some("/mnt/target".into()),
                ),
            },
        );
        update_lines(
            &mut lines,
            ProgressEvent::Updated {
                task_id: 2,
                message: "copied file.txt".into(),
            },
        );

        assert_eq!(
            lines[&2].render_flat(2),
            "2: copy /mnt/src -> /mnt/target | copied file.txt"
        );
    }

    #[test]
    fn tasks_are_rendered_in_task_id_order() {
        let mut lines = BTreeMap::new();

        update_lines(
            &mut lines,
            ProgressEvent::Started {
                task_id: 4,
                display: TaskDisplay::new("four", None, None),
            },
        );
        update_lines(
            &mut lines,
            ProgressEvent::Started {
                task_id: 1,
                display: TaskDisplay::new("one", None, None),
            },
        );

        assert_eq!(lines.keys().copied().collect::<Vec<_>>(), vec![1, 4]);
    }
}
