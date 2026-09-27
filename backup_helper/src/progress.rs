use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, IsTerminal, Write},
    path::PathBuf,
    sync::mpsc,
    time::{Duration, Instant},
};

use crossterm::{
    cursor, execute,
    terminal::{self, ClearType},
};
use unicode_width::UnicodeWidthChar;

use crate::{
    copy::{CopyStats, format_bytes},
    task_log::VerifySummary,
};

/// Upper bound for how often the active block is redrawn.
///
/// A copy reports one event per walked entry, and a redraw rewrites every row of
/// every active task. The CLI renderer throttles its single status line for the
/// same reason; see `checksum_helper_cli/src/progress.rs`.
const REDRAW_INTERVAL: Duration = Duration::from_millis(100);

/// Below this the running average is one entry wide and says nothing, so the
/// rate is left out rather than shown wildly high.
const RATE_AFTER: Duration = Duration::from_secs(1);

/// What a finished task reports about itself, next to its log file. Rendered
/// once the task leaves the active block, in both output modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TaskSummary {
    Verify(VerifySummary),
    Copy(CopyStats),
}

impl fmt::Display for TaskSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaskSummary::Verify(summary) => write!(f, "{summary}"),
            TaskSummary::Copy(stats) => write!(f, "{stats}"),
        }
    }
}

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
    /// One walked entry of a copy, with the totals as they stand after it. Typed
    /// rather than preformatted, so the renderer decides whether to build the
    /// text: a copy emits one of these per entry, including every directory.
    Copying {
        task_id: usize,
        stats: CopyStats,
        current: PathBuf,
    },
    Finished {
        task_id: usize,
        summary: Option<TaskSummary>,
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
    let mut active_lines = BTreeMap::new();
    let mut completed_lines = BTreeSet::new();
    let mut rendered_rows = 0;
    let mut last_redraw = None;

    while let Ok(event) = receiver.recv() {
        // A started task has to appear at once, whatever the throttle says.
        let phase_start = matches!(event, ProgressEvent::Started { .. });

        if interactive {
            let completed = update_active_lines(&mut active_lines, &mut completed_lines, event);
            // A completed line has left the active set, so it is drawn even when
            // the throttle would drop this event.
            if completed.is_some() || phase_start || redraw_due(&mut last_redraw) {
                last_redraw = Some(Instant::now());
                let width = terminal_width()?;
                render_interactive(&active_lines, completed, &mut rendered_rows, width)?;
            }
        } else if let Some(summary) = totals_of(&event) {
            eprint!("{summary}");
        }
    }

    if interactive && rendered_rows > 0 {
        let mut stderr = io::stderr();
        stderr.write_all(b"\n")?;
    }

    Ok(())
}

/// The totals of a finished task, which is all a run without a terminal reports.
///
/// There is no row to redraw, and the per-file detail is not lost with it: a
/// hash and a verification write every result to their task log. A copy has no
/// log and needs none, because its progress is the block the terminal shows.
fn totals_of(event: &ProgressEvent) -> Option<&TaskSummary> {
    match event {
        ProgressEvent::Finished { summary, .. } => summary.as_ref(),
        _ => None,
    }
}

fn redraw_due(last_redraw: &mut Option<Instant>) -> bool {
    match last_redraw {
        Some(last) => last.elapsed() >= REDRAW_INTERVAL,
        None => true,
    }
}

#[derive(Debug, Default)]
struct TaskLine {
    display: TaskDisplay,
    message: String,
    /// Present while a copy walks its source. The counters and the entry being
    /// worked on take the place of the message, which for a copy would repeat
    /// the same path.
    copy: Option<CopyLine>,
}

#[derive(Debug)]
struct CopyLine {
    stats: CopyStats,
    /// The entry being worked on, which for a copy replaces the message: it
    /// would otherwise repeat the same path on a row of its own.
    current: PathBuf,
    /// When the first entry was reported, so the rate is measured over the copy
    /// rather than over the whole session.
    started: Instant,
}

impl CopyLine {
    /// Counters, throughput and elapsed time. There is no total to divide by:
    /// the source is not walked twice to obtain one, so no percentage and no
    /// remaining time is shown.
    fn counters_line(&self) -> String {
        let elapsed = self.started.elapsed();
        let mut line = self.stats.progress_line();

        if elapsed >= RATE_AFTER {
            let rate = self.stats.copied_bytes as f64 / elapsed.as_secs_f64();
            line.push_str(&format!(" | {}/s", format_bytes(rate as u64)));
        }
        line.push_str(&format!(" | elapsed {}", format_elapsed(elapsed)));
        line
    }
}

fn format_elapsed(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    let minutes = seconds / 60;
    if minutes >= 60 {
        format!("{}:{:02}:{:02}", minutes / 60, minutes % 60, seconds % 60)
    } else {
        format!("{minutes}:{:02}", seconds % 60)
    }
}

impl TaskLine {
    /// Closes the live rows. The counters belong to the running phase; the
    /// outcome takes their place and the totals are reported once, below.
    fn close(&mut self, message: String) {
        self.message = message;
        self.copy = None;
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

        match &self.copy {
            Some(copy) => {
                let counters_row = format!("      {}", copy.counters_line());
                rows.extend(wrap_display_line(&counters_row, width, "      "));
                let current_row = format!("      {}", copy.current.display());
                rows.extend(wrap_display_line(&current_row, width, "      "));
            }
            None => {
                let message_row = format!("      {}", self.message);
                rows.extend(wrap_display_line(&message_row, width, "      "));
            }
        }
        rows
    }
}

#[derive(Debug)]
struct CompletedTask {
    task_id: usize,
    line: TaskLine,
    summary: Option<TaskSummary>,
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
                        copy: None,
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
        ProgressEvent::Copying {
            task_id,
            stats,
            current,
        } => {
            if !completed.contains(&task_id)
                && let Some(line) = lines.get_mut(&task_id)
            {
                let copy = line.copy.get_or_insert_with(|| CopyLine {
                    stats: CopyStats::default(),
                    current: PathBuf::new(),
                    started: Instant::now(),
                });
                copy.stats = stats;
                copy.current = current;
            }
            None
        }
        ProgressEvent::Finished { task_id, summary } => {
            finish_active_line(lines, completed, task_id, "done".into(), summary)
        }
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
    summary: Option<TaskSummary>,
) -> Option<CompletedTask> {
    if completed.contains(&task_id) {
        return None;
    }

    let Some(mut line) = lines.remove(&task_id) else {
        completed.insert(task_id);
        return None;
    };

    line.close(message);
    completed.insert(task_id);
    Some(CompletedTask {
        task_id,
        line,
        summary,
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
        if let Some(summary) = &completed.summary {
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
    use std::path::Path;

    fn copy_line(message: &str) -> TaskLine {
        TaskLine {
            display: TaskDisplay::new("copy", Some("/mnt/src".into()), Some("/mnt/target".into())),
            message: message.into(),
            copy: None,
        }
    }

    fn stats(copied_files: u64, copied_bytes: u64, skipped_files: u64) -> CopyStats {
        CopyStats {
            entries: copied_files + skipped_files,
            copied_files,
            copied_bytes,
            skipped_files,
            ..CopyStats::default()
        }
    }

    /// A copy line part way through: counters plus the entry being worked on.
    fn walking_copy(stats: CopyStats, current: &str, started: Instant) -> TaskLine {
        TaskLine {
            display: TaskDisplay::new("copy", Some("/mnt/src".into()), Some("/mnt/target".into())),
            message: String::new(),
            copy: Some(CopyLine {
                stats,
                current: PathBuf::from(current),
                started,
            }),
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
    fn a_walking_copy_shows_counters_and_the_current_entry() {
        let line = walking_copy(
            stats(2, 5 * 1024 * 1024, 1),
            "photos/raw/IMG_0042.CR3",
            Instant::now() - Duration::from_secs(90),
        );

        let rows = line.layout(0, 80);

        assert_eq!(
            rows[2],
            "      2 copied (5.0 MiB) | 1 skipped | 56.9 KiB/s | elapsed 1:30"
        );
        assert_eq!(rows[3], "      photos/raw/IMG_0042.CR3");
    }

    #[test]
    fn the_rate_is_left_out_until_the_copy_has_been_running_for_a_second() {
        let line = walking_copy(stats(1, 4096, 0), "file.txt", Instant::now());

        let rows = line.layout(0, 80);

        assert_eq!(
            rows[2],
            "      1 copied (4.0 KiB) | 0 skipped | elapsed 0:00"
        );
    }

    #[test]
    fn a_finished_copy_reports_its_outcome_and_leaves_the_counters_to_the_summary() {
        let mut line = walking_copy(stats(2, 2048, 1), "file.txt", Instant::now());
        line.close("done".into());

        let rows = line.layout(0, 80);

        assert_eq!(
            rows,
            ["0: copy /mnt/src", "   -> /mnt/target", "      done"]
        );
    }

    #[test]
    fn a_walking_copy_layout_wraps_to_the_available_width() {
        let line = walking_copy(
            stats(2, 5 * 1024 * 1024, 1),
            "a-very-long-directory-name/another-long-name/IMG_0042.CR3",
            Instant::now() - Duration::from_secs(90),
        );

        let rows = line.layout(0, 40);

        assert!(rows.len() > 4);
        assert!(rows.iter().all(|row| display_width(row) <= 40), "{rows:?}");
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
            copy: None,
        };

        let rows = line.layout(0, 8);

        assert!(rows.iter().all(|row| display_width(row) <= 8), "{rows:?}");
    }

    #[test]
    fn a_copy_event_opens_the_counters_and_the_current_entry() {
        let mut lines = BTreeMap::new();
        update_active_lines(
            &mut lines,
            &mut BTreeSet::new(),
            ProgressEvent::Started {
                task_id: 1,
                display: TaskDisplay::new("copy", Some("/src".into()), Some("/dst".into())),
            },
        );
        update_active_lines(
            &mut lines,
            &mut BTreeSet::new(),
            ProgressEvent::Copying {
                task_id: 1,
                stats: stats(1, 100, 0),
                current: PathBuf::from("file.txt"),
            },
        );

        let copy = lines[&1].copy.as_ref().expect("a copy reports counters");
        assert_eq!(copy.stats, stats(1, 100, 0));
        assert_eq!(copy.current, Path::new("file.txt"));
    }

    #[test]
    fn a_hash_task_reports_its_result_in_the_message_row() {
        let mut lines = BTreeMap::new();
        let mut completed = BTreeSet::new();
        update_active_lines(
            &mut lines,
            &mut completed,
            ProgressEvent::Started {
                task_id: 1,
                display: TaskDisplay::new("hash", Some("/src".into()), None),
            },
        );
        update_active_lines(
            &mut lines,
            &mut completed,
            ProgressEvent::Updated {
                task_id: 1,
                message: "[NEW  ] \"file.txt\"".into(),
            },
        );

        assert!(lines[&1].copy.is_none());
        assert_eq!(lines[&1].layout(1, 80)[1], "      [NEW  ] \"file.txt\"");
    }

    #[test]
    fn the_redraw_throttle_allows_the_first_event_and_holds_the_next_ones() {
        let mut last_redraw = None;
        assert!(redraw_due(&mut last_redraw));

        last_redraw = Some(Instant::now());
        assert!(!redraw_due(&mut last_redraw));

        last_redraw = Some(Instant::now() - REDRAW_INTERVAL);
        assert!(redraw_due(&mut last_redraw));
    }

    #[test]
    fn elapsed_time_is_reported_in_hours_only_when_it_is_needed() {
        assert_eq!(format_elapsed(Duration::from_secs(0)), "0:00");
        assert_eq!(format_elapsed(Duration::from_secs(75)), "1:15");
        assert_eq!(format_elapsed(Duration::from_secs(3599)), "59:59");
        assert_eq!(format_elapsed(Duration::from_secs(3600)), "1:00:00");
        assert_eq!(format_elapsed(Duration::from_secs(7384)), "2:03:04");
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
                summary: None,
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
                    summary: None,
                },
            )
            .is_none()
        );
    }

    #[test]
    fn verify_completion_keeps_its_summary() {
        let mut lines = BTreeMap::new();
        let mut completed = BTreeSet::new();

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
                summary: Some(TaskSummary::Verify(VerifySummary::default())),
            },
        );

        assert_eq!(
            finished.unwrap().summary,
            Some(TaskSummary::Verify(VerifySummary::default()))
        );
    }

    #[test]
    fn the_copy_summary_reports_its_totals() {
        let summary = TaskSummary::Copy(stats(2, 3 * 1024 * 1024, 1));

        assert_eq!(
            summary.to_string(),
            "Totals: 3 entries | 2 copied (3.0 MiB) | 1 skipped (0 B) | 0 directories | 0 ignored\n"
        );
    }

    #[test]
    fn a_run_without_a_terminal_reports_only_the_totals_of_a_finished_task() {
        let events = [
            ProgressEvent::Started {
                task_id: 1,
                display: TaskDisplay::new("copy", Some("/src".into()), Some("/dst".into())),
            },
            ProgressEvent::Copying {
                task_id: 1,
                stats: stats(1, 100, 0),
                current: PathBuf::from("a.txt"),
            },
            ProgressEvent::Updated {
                task_id: 1,
                message: "[NEW  ] \"b.txt\"".into(),
            },
            ProgressEvent::Failed {
                task_id: 1,
                message: "Failed to copy \"c.txt\"".into(),
            },
            ProgressEvent::Finished {
                task_id: 1,
                summary: Some(TaskSummary::Copy(stats(1, 100, 0))),
            },
            ProgressEvent::Finished {
                task_id: 2,
                summary: None,
            },
        ];

        let reported: Vec<_> = events.iter().filter_map(totals_of).cloned().collect();

        assert_eq!(reported, [TaskSummary::Copy(stats(1, 100, 0))]);
    }

    #[test]
    fn tasks_are_rendered_in_task_id_order() {
        let mut lines = BTreeMap::new();
        let mut completed = BTreeSet::new();

        update_active_lines(
            &mut lines,
            &mut completed,
            ProgressEvent::Started {
                task_id: 4,
                display: TaskDisplay::new("four", None, None),
            },
        );
        update_active_lines(
            &mut lines,
            &mut completed,
            ProgressEvent::Started {
                task_id: 1,
                display: TaskDisplay::new("one", None, None),
            },
        );

        assert_eq!(lines.keys().copied().collect::<Vec<_>>(), vec![1, 4]);
    }
}
