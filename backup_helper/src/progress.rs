use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, IsTerminal, Write},
    path::PathBuf,
    sync::mpsc,
    time::{Duration, Instant},
};

use crossterm::{
    Command, cursor,
    terminal::{self, BeginSynchronizedUpdate, ClearType, EndSynchronizedUpdate},
};
use unicode_width::UnicodeWidthChar;

use crate::{
    copy::{CopyStats, format_bytes},
    scan_stats::{ScanPhase, ScanStats},
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
    Hash(ScanStats),
}

impl fmt::Display for TaskSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaskSummary::Verify(summary) => write!(f, "{summary}"),
            TaskSummary::Copy(stats) => write!(f, "{stats}"),
            TaskSummary::Hash(stats) => write!(f, "{stats}"),
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
    /// The totals of a hash or a verification as they stand. Typed for the same
    /// reason, and emitted once per 64 KiB read, which on a whole-disk hash is
    /// six figures.
    Counting {
        task_id: usize,
        stats: ScanStats,
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
    let mut cursor = Cursor::default();

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
                render_interactive(
                    &active_lines,
                    completed,
                    &mut rendered_rows,
                    width,
                    &mut cursor,
                    &mut io::stderr(),
                )?;
            }
        } else if let Some(summary) = totals_of(&event) {
            eprint!("{summary}");
        }
    }

    if interactive && rendered_rows > 0 {
        let mut tail = String::new();
        tail.push('\n');
        cursor.show(&mut tail);
        io::stderr().write_all(tail.as_bytes())?;
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
    /// Present while a task reports counters instead of a message per event. A
    /// copy shows the entry being worked on in place of the message, which for a
    /// copy would repeat the same path; a hash and a verification keep the
    /// message, which carries the per-file status.
    counters: Option<CountersLine>,
}

/// The live counters of a running task, with the time the current phase started
/// so the rate is measured over that phase.
#[derive(Debug)]
struct CountersLine {
    counters: TaskCounters,
    started: Instant,
}

/// What a task is counting, which decides the counter line and the row below it.
#[derive(Debug, PartialEq, Eq)]
enum TaskCounters {
    Copy {
        stats: CopyStats,
        /// The entry being worked on, which for a copy replaces the message: it
        /// would otherwise repeat the same path on a row of its own.
        current: PathBuf,
    },
    Scan(ScanStats),
}

impl TaskCounters {
    fn bytes_done(&self) -> u64 {
        match self {
            TaskCounters::Copy { stats, .. } => stats.copied_bytes,
            TaskCounters::Scan(stats) => stats.bytes_done(),
        }
    }

    fn progress_line(&self) -> String {
        match self {
            TaskCounters::Copy { stats, .. } => stats.progress_line(),
            TaskCounters::Scan(stats) => stats.progress_line(),
        }
    }

    /// The phase the counters are in, whose change restarts the rate. A copy
    /// counts one thing for its whole run and has no phase to change.
    fn phase(&self) -> Option<ScanPhase> {
        match self {
            TaskCounters::Copy { .. } => None,
            TaskCounters::Scan(stats) => Some(stats.phase),
        }
    }
}

impl CountersLine {
    fn new(counters: TaskCounters) -> Self {
        CountersLine {
            counters,
            started: Instant::now(),
        }
    }

    /// Counters, throughput and elapsed time. A copy has no total to divide by:
    /// the source is not walked twice to obtain one, so no percentage and no
    /// remaining time is shown.
    fn counters_line(&self) -> String {
        let elapsed = self.started.elapsed();
        let mut line = self.counters.progress_line();

        if elapsed >= RATE_AFTER && self.counters.bytes_done() > 0 {
            let rate = self.counters.bytes_done() as f64 / elapsed.as_secs_f64();
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
        self.counters = None;
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

        if let Some(counters) = &self.counters {
            let counters_row = format!("      {}", counters.counters_line());
            rows.extend(wrap_display_line(&counters_row, width, "      "));
        }

        // A copy replaces the message with the entry it is walking, so that the
        // counters row is not followed by the same path on a row of its own.
        let detail = match &self.counters {
            Some(counters) => match &counters.counters {
                TaskCounters::Copy { current, .. } => current.display().to_string(),
                TaskCounters::Scan(_) => self.message.clone(),
            },
            None => self.message.clone(),
        };
        let detail_row = format!("      {detail}");
        rows.extend(wrap_display_line(&detail_row, width, "      "));

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
                        counters: None,
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
                line.counters
                    .get_or_insert_with(|| {
                        CountersLine::new(TaskCounters::Copy {
                            stats: CopyStats::default(),
                            current: PathBuf::new(),
                        })
                    })
                    .counters = TaskCounters::Copy { stats, current };
            }
            None
        }
        ProgressEvent::Counting { task_id, stats } => {
            if !completed.contains(&task_id)
                && let Some(line) = lines.get_mut(&task_id)
            {
                let counters = line
                    .counters
                    .get_or_insert_with(|| CountersLine::new(TaskCounters::Scan(stats)));

                // A hash walks its source before it reads any of it, and a rate
                // averaged over both says nothing about either.
                if counters.counters.phase() != Some(stats.phase) {
                    counters.started = Instant::now();
                }

                counters.counters = TaskCounters::Scan(stats);
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

/// Assembles one redraw in memory and hands it over in a single write.
///
/// Erasing the block and drawing it again is what the terminal paints, so every
/// step in between is a frame the user sees: the block gone, the cursor walking
/// over the empty rows, the block back. Assembling the whole redraw into one
/// buffer means the terminal is handed it in one call, and between the
/// synchronized-update markers it paints the result of that call and nothing
/// else. Each row is also cleared and refilled before the cursor leaves it, so a
/// terminal that ignores the markers never shows a blank block either.
struct Frame {
    bytes: String,
    /// The rows the next redraw has to take back, which excludes the rows a
    /// finished task left behind: those stay on the screen.
    rows: usize,
}

impl fmt::Write for Frame {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.bytes.push_str(value);
        Ok(())
    }
}

impl Frame {
    /// The redraw of the active block, replacing the `rendered` rows the
    /// previous frame left on the screen.
    fn new(
        lines: &BTreeMap<usize, TaskLine>,
        completed: Option<&CompletedTask>,
        rendered: usize,
        width: usize,
        cursor: &mut Cursor,
    ) -> io::Result<Frame> {
        let mut frame = Frame {
            bytes: String::new(),
            rows: 0,
        };

        frame.write(BeginSynchronizedUpdate)?;
        // In the frame that draws the first block, so that the cursor is not
        // painted between moving it and moving it back.
        cursor.hide(&mut frame.bytes);

        if rendered > 0 {
            frame.up(rendered)?;
        }

        // A finished task is written once, above the rows that are redrawn, and
        // is never taken back by a later frame.
        if let Some(completed) = completed {
            for row in completed.line.layout(completed.task_id, width) {
                frame.row(&row)?;
            }
            if let Some(summary) = &completed.summary {
                for line in summary_lines(&summary.to_string()) {
                    frame.row(line)?;
                }
            }
        }

        for (task_id, line) in lines {
            for row in line.layout(*task_id, width) {
                frame.row(&row)?;
                frame.rows += 1;
            }
        }

        // A block that shrank leaves rows of the previous frame below the new
        // one, which are cleared and stepped back over.
        if let Some(leftover) = rendered.checked_sub(frame.rows).filter(|rows| *rows > 0) {
            for _ in 0..leftover {
                frame.row("")?;
            }
            frame.up(leftover)?;
        }

        frame.write(EndSynchronizedUpdate)?;
        Ok(frame)
    }

    /// One row, from the first column and with whatever the previous frame left
    /// on it gone.
    fn row(&mut self, text: &str) -> io::Result<()> {
        self.write(cursor::MoveToColumn(0))?;
        self.write(terminal::Clear(ClearType::CurrentLine))?;
        self.bytes.push_str(text);
        self.bytes.push('\n');
        Ok(())
    }

    fn up(&mut self, rows: usize) -> io::Result<()> {
        let rows = u16::try_from(rows).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "progress display is taller than the terminal cursor range",
            )
        })?;

        self.write(cursor::MoveUp(rows))
    }

    fn write(&mut self, command: impl Command) -> io::Result<()> {
        // A command written into a buffer in memory cannot fail; the errors a
        // frame reports are the ones it raises itself.
        command.write_ansi(self).map_err(|error| {
            io::Error::other(format!("failed to assemble a progress frame: {error}"))
        })
    }
}

/// The lines of a summary, without the newline its last line ends in: a frame
/// puts a newline after every row it writes.
fn summary_lines(summary: &str) -> Vec<&str> {
    match summary.strip_suffix('\n') {
        Some(stripped) => stripped.split('\n').collect(),
        None => summary.split('\n').collect(),
    }
}

/// A command as the bytes a terminal reads, for one written on its own rather
/// than as part of a frame.
fn command_bytes(command: impl Command) -> String {
    let mut bytes = String::new();
    let _ = command.write_ansi(&mut bytes);
    bytes
}

/// Whether the terminal cursor is hidden, so that it is shown again on the way
/// out of the reporter however it is left.
#[derive(Default)]
struct Cursor {
    hidden: bool,
}

impl Cursor {
    /// Appends the escape that hides the cursor, once: the cursor is never
    /// painted inside a block that is being rewritten.
    fn hide(&mut self, buffer: &mut String) {
        if self.hidden {
            return;
        }

        buffer.push_str(&command_bytes(cursor::Hide));
        self.hidden = true;
    }

    /// Appends the escape that shows the cursor again, once.
    fn show(&mut self, buffer: &mut String) {
        if !self.hidden {
            return;
        }

        buffer.push_str(&command_bytes(cursor::Show));
        self.hidden = false;
    }
}

impl Drop for Cursor {
    fn drop(&mut self) {
        if self.hidden {
            let mut buffer = String::new();
            self.show(&mut buffer);
            let _ = io::stderr().write_all(buffer.as_bytes());
        }
    }
}

/// Draws one frame in a single write, and leaves `rendered_rows` holding what the
/// next frame has to take back.
fn render_interactive<W: Write>(
    lines: &BTreeMap<usize, TaskLine>,
    completed: Option<CompletedTask>,
    rendered_rows: &mut usize,
    width: usize,
    cursor: &mut Cursor,
    writer: &mut W,
) -> io::Result<()> {
    let frame = Frame::new(lines, completed.as_ref(), *rendered_rows, width, cursor)?;
    writer.write_all(frame.bytes.as_bytes())?;
    writer.flush()?;

    *rendered_rows = frame.rows;
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
    use checksum_helper::{
        checksum_helper::IncrementalProgress, collection::HashProgress, collection::VerifyProgress,
        collection::VerifyProgressCommon, collection::VerifyProgressPost,
        hashed_file::VerifyResult,
    };
    use pretty_assertions::assert_eq;

    use super::*;
    use std::path::Path;

    fn copy_line(message: &str) -> TaskLine {
        TaskLine {
            display: TaskDisplay::new("copy", Some("/mnt/src".into()), Some("/mnt/target".into())),
            message: message.into(),
            counters: None,
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
            counters: Some(CountersLine {
                counters: TaskCounters::Copy {
                    stats,
                    current: PathBuf::from(current),
                },
                started,
            }),
        }
    }

    /// A hash or a verification line part way through: the counters of the scan
    /// plus the per-file status the counters do not carry.
    fn walking_scan(
        operation: &str,
        source: Option<&str>,
        target: Option<&str>,
        stats: ScanStats,
        message: &str,
        started: Instant,
    ) -> TaskLine {
        TaskLine {
            display: TaskDisplay::new(
                operation,
                source.map(str::to_owned),
                target.map(str::to_owned),
            ),
            message: message.into(),
            counters: Some(CountersLine {
                counters: TaskCounters::Scan(stats),
                started,
            }),
        }
    }

    /// A verification that has 1234 of 50000 files done and is 300 MiB into the
    /// next one, which leaves 12.3 of 98.7 GiB read.
    fn verifying_stats() -> ScanStats {
        let mut stats = ScanStats::default();
        let total = 98 * 1024 * 1024 * 1024 + 700 * 1024 * 1024;
        let finished = VerifyProgressCommon {
            tree_root: Path::new("/mnt/backup"),
            relative_path: Path::new("raw/IMG_0041.CR3"),
            file_number_processed: 1233,
            file_number_total: 50000,
            size_processed_bytes: 12 * 1024 * 1024 * 1024,
            size_total_bytes: total,
        };

        stats.record_verify(&VerifyProgress::Pre(finished));
        stats.record_verify(&VerifyProgress::During(HashProgress {
            bytes_read: 12 * 1024 * 1024 * 1024,
            bytes_total: 12 * 1024 * 1024 * 1024,
        }));
        stats.record_verify(&VerifyProgress::Post(VerifyProgressPost {
            progress: finished,
            result: VerifyResult::Ok,
        }));
        stats.record_verify(&VerifyProgress::Pre(VerifyProgressCommon {
            tree_root: Path::new("/mnt/backup"),
            relative_path: Path::new("raw/IMG_0042.CR3"),
            file_number_processed: 1234,
            file_number_total: 50000,
            size_processed_bytes: 12 * 1024 * 1024 * 1024,
            size_total_bytes: total,
        }));
        stats.record_verify(&VerifyProgress::During(HashProgress {
            bytes_read: 300 * 1024 * 1024,
            bytes_total: 4 * 1024 * 1024 * 1024,
        }));

        stats
    }

    /// A hash that has read 12.3 GiB of a 50000 file tree, 300 MiB into the file
    /// it is working on.
    fn hashing_stats() -> ScanStats {
        let mut stats = ScanStats::default();

        stats.record_incremental(&IncrementalProgress::DiscoverFilesDone(50000, 1234));
        stats.record_incremental(&IncrementalProgress::PreRead(PathBuf::from(
            "raw/IMG_0042.CR3",
        )));
        stats.record_incremental(&IncrementalProgress::Read(
            12 * 1024 * 1024 * 1024 + 300 * 1024 * 1024,
            4 * 1024 * 1024 * 1024,
        ));

        stats
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
            counters: None,
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

        let counters = lines[&1]
            .counters
            .as_ref()
            .expect("a copy reports counters");
        assert_eq!(
            counters.counters,
            TaskCounters::Copy {
                stats: stats(1, 100, 0),
                current: PathBuf::from("file.txt"),
            }
        );
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

        assert!(lines[&1].counters.is_none());
        assert_eq!(lines[&1].layout(1, 80)[1], "      [NEW  ] \"file.txt\"");
    }

    #[test]
    fn a_hashing_task_shows_its_counters_above_the_file_it_is_working_on() {
        let line = walking_scan(
            "hash",
            Some("/mnt/src"),
            None,
            hashing_stats(),
            "[NEW  ] \"photos/raw/IMG_0042.CR3\"",
            Instant::now() - Duration::from_secs(90),
        );

        let rows = line.layout(0, 80);

        assert_eq!(rows[0], "0: hash /mnt/src");
        assert_eq!(
            rows[1],
            "      files 1/50000 | 12.3 GiB | 139.9 MiB/s | elapsed 1:30"
        );
        assert_eq!(rows[2], "      [NEW  ] \"photos/raw/IMG_0042.CR3\"");
    }

    #[test]
    fn a_verification_shows_a_percentage_for_files_and_for_bytes() {
        let line = walking_scan(
            "verify",
            None,
            Some("/mnt/target"),
            verifying_stats(),
            "[OK        ] \"photos/raw/IMG_0042.CR3\"",
            Instant::now() - Duration::from_secs(90),
        );

        let rows = line.layout(2, 200);

        assert_eq!(rows[0], "2: verify /mnt/target");
        assert_eq!(
            rows[1],
            "      files 1234/50000 (2.5%) | bytes 12.3 GiB/98.7 GiB (12.5%) | 139.9 MiB/s | elapsed 1:30"
        );
        assert_eq!(rows[2], "      [OK        ] \"photos/raw/IMG_0042.CR3\"");
    }

    #[test]
    fn a_discovery_walk_reports_the_files_it_found_and_no_rate() {
        let mut stats = ScanStats::default();
        stats.record_incremental(&IncrementalProgress::DiscoverFilesFound(1234));

        let line = walking_scan(
            "hash",
            Some("/mnt/src"),
            None,
            stats,
            "starting",
            Instant::now() - Duration::from_secs(90),
        );

        let rows = line.layout(0, 80);

        assert_eq!(rows[1], "      discovered 1234 | elapsed 1:30");
    }

    #[test]
    fn the_rate_is_left_out_until_a_scan_has_read_something() {
        let mut stats = ScanStats::default();
        stats.record_incremental(&IncrementalProgress::DiscoverFilesDone(2, 0));
        stats.record_incremental(&IncrementalProgress::PreRead(PathBuf::from("file.txt")));

        let line = walking_scan(
            "hash",
            Some("/mnt/src"),
            None,
            stats,
            "[SKIP ] \"file.txt\"",
            Instant::now() - Duration::from_secs(90),
        );

        let rows = line.layout(0, 80);

        assert_eq!(rows[1], "      files 1/2 | 0 B | elapsed 1:30");
    }

    #[test]
    fn a_phase_change_restarts_the_rate_so_a_walk_does_not_lower_it() {
        let mut lines = BTreeMap::new();
        let mut completed = BTreeSet::new();
        update_active_lines(
            &mut lines,
            &mut completed,
            ProgressEvent::Started {
                task_id: 0,
                display: TaskDisplay::new("hash", Some("/mnt/src".into()), None),
            },
        );

        let mut discovered = ScanStats::default();
        discovered.record_incremental(&IncrementalProgress::DiscoverFilesFound(50000));
        update_active_lines(
            &mut lines,
            &mut completed,
            ProgressEvent::Counting {
                task_id: 0,
                stats: discovered,
            },
        );
        let after_discovery = lines[&0].counters.as_ref().unwrap().started;

        std::thread::sleep(Duration::from_millis(10));
        update_active_lines(
            &mut lines,
            &mut completed,
            ProgressEvent::Counting {
                task_id: 0,
                stats: hashing_stats(),
            },
        );
        let counters = lines[&0].counters.as_ref().unwrap();

        assert!(
            counters.started > after_discovery,
            "the rate keeps its own start"
        );
        assert_ne!(counters.counters.phase(), Some(ScanPhase::Discover));
    }

    #[test]
    fn a_finished_scan_leaves_the_counters_to_its_totals() {
        let mut line = walking_scan(
            "hash",
            Some("/mnt/src"),
            None,
            hashing_stats(),
            "[NEW  ] \"file.txt\"",
            Instant::now() - Duration::from_secs(90),
        );
        line.close("done".into());

        let rows = line.layout(0, 80);

        assert_eq!(rows, ["0: hash /mnt/src", "      done"]);
    }

    #[test]
    fn the_hash_summary_reports_its_totals() {
        let summary = TaskSummary::Hash(hashing_stats());

        assert_eq!(
            summary.to_string(),
            "Totals: 1 files (12.3 GiB read) | 1234 ignored\n"
        );
    }

    /// A row from the first column, with whatever the previous frame left on it
    /// gone.
    fn erased_row(text: &str) -> String {
        format!(
            "{}{}{text}\n",
            command_bytes(cursor::MoveToColumn(0)),
            command_bytes(terminal::Clear(ClearType::CurrentLine)),
        )
    }

    /// The bytes of a frame that takes back `rendered` rows and writes `rows` in
    /// their place, after `prefix`.
    fn frame_bytes(prefix: &str, rendered: usize, rows: &[&str]) -> String {
        let mut bytes = command_bytes(BeginSynchronizedUpdate);
        bytes.push_str(prefix);
        if rendered > 0 {
            bytes.push_str(&command_bytes(cursor::MoveUp(rendered as u16)));
        }
        for row in rows {
            bytes.push_str(&erased_row(row));
        }
        bytes.push_str(&command_bytes(EndSynchronizedUpdate));
        bytes
    }

    /// One active task with a counters row and the entry it is walking, which is
    /// the tallest block a task draws.
    fn walking_lines() -> BTreeMap<usize, TaskLine> {
        let mut lines = BTreeMap::new();
        lines.insert(
            0,
            walking_copy(
                stats(1, 4096, 0),
                "file.txt",
                Instant::now() - Duration::from_secs(90),
            ),
        );
        lines
    }

    /// The same task without counters, which is a shorter block.
    fn message_lines() -> BTreeMap<usize, TaskLine> {
        let mut lines = BTreeMap::new();
        lines.insert(0, copy_line("copied file.txt"));
        lines
    }

    const WALKING_ROWS: [&str; 4] = [
        "0: copy /mnt/src",
        "   -> /mnt/target",
        "      1 copied (4.0 KiB) | 0 skipped | 45 B/s | elapsed 1:30",
        "      file.txt",
    ];

    const MESSAGE_ROWS: [&str; 3] = [
        "0: copy /mnt/src",
        "   -> /mnt/target",
        "      copied file.txt",
    ];

    #[test]
    fn the_first_frame_draws_the_block_and_takes_back_nothing() {
        let mut cursor = Cursor::default();
        let lines = walking_lines();

        let frame = Frame::new(&lines, None, 0, 80, &mut cursor).unwrap();

        assert_eq!(frame.rows, WALKING_ROWS.len());
        assert_eq!(
            frame.bytes,
            frame_bytes(&command_bytes(cursor::Hide), 0, &WALKING_ROWS)
        );
        assert!(cursor.hidden);
    }

    #[test]
    fn a_redraw_takes_back_the_rows_of_the_previous_frame() {
        let mut cursor = Cursor::default();
        let lines = walking_lines();
        let first = Frame::new(&lines, None, 0, 80, &mut cursor).unwrap();

        let second = Frame::new(&lines, None, first.rows, 80, &mut cursor).unwrap();

        assert_eq!(second.rows, first.rows);
        assert_eq!(second.bytes, frame_bytes("", 4, &WALKING_ROWS));
        // The cursor is hidden once for the whole run, not once per frame.
        assert!(!second.bytes.contains(&command_bytes(cursor::Hide)));
    }

    #[test]
    fn a_block_that_shrank_clears_the_rows_it_no_longer_uses() {
        let mut cursor = Cursor::default();
        let first = Frame::new(&walking_lines(), None, 0, 80, &mut cursor).unwrap();

        let second = Frame::new(&message_lines(), None, first.rows, 80, &mut cursor).unwrap();

        assert_eq!(second.rows, MESSAGE_ROWS.len());

        let mut expected = frame_bytes("", 4, &MESSAGE_ROWS);
        expected.truncate(expected.len() - command_bytes(EndSynchronizedUpdate).len());
        expected.push_str(&erased_row(""));
        expected.push_str(&command_bytes(cursor::MoveUp(1)));
        expected.push_str(&command_bytes(EndSynchronizedUpdate));

        assert_eq!(second.bytes, expected);
    }

    #[test]
    fn a_finished_block_is_written_above_the_rows_that_are_redrawn() {
        let mut cursor = Cursor::default();
        let completed = CompletedTask {
            task_id: 1,
            line: copy_line("done"),
            summary: Some(TaskSummary::Copy(stats(2, 2048, 1))),
        };
        let finished_rows = [
            "1: copy /mnt/src",
            "   -> /mnt/target",
            "      done",
            "Totals: 3 entries | 2 copied (2.0 KiB) | 1 skipped (0 B) | 0 directories | 0 ignored",
        ];
        let mut expected_rows = finished_rows.to_vec();
        expected_rows.extend_from_slice(&MESSAGE_ROWS);

        let frame = Frame::new(&message_lines(), Some(&completed), 0, 80, &mut cursor).unwrap();

        // Only the rows of the task that is still running are taken back: the
        // finished block and its totals stay on the screen.
        assert_eq!(frame.rows, MESSAGE_ROWS.len());
        assert_eq!(
            frame.bytes,
            frame_bytes(&command_bytes(cursor::Hide), 0, &expected_rows)
        );

        let next = Frame::new(&message_lines(), None, frame.rows, 80, &mut cursor).unwrap();
        assert_eq!(next.bytes, frame_bytes("", 3, &MESSAGE_ROWS));
    }

    /// A writer that counts the calls made to it, to pin that a frame is handed
    /// over in one piece: a frame written in pieces is a frame the terminal
    /// paints in pieces.
    #[derive(Default)]
    struct WriteCounter {
        writes: usize,
        bytes: Vec<u8>,
    }

    impl Write for WriteCounter {
        fn write(&mut self, value: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            self.bytes.extend_from_slice(value);
            Ok(value.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_frame_is_handed_to_the_terminal_in_one_write() {
        let mut cursor = Cursor::default();
        let mut lines = walking_lines();
        let mut rendered_rows = 0;
        let mut writer = WriteCounter::default();

        render_interactive(
            &lines,
            None,
            &mut rendered_rows,
            80,
            &mut cursor,
            &mut writer,
        )
        .unwrap();
        lines.insert(0, copy_line("copied file.txt"));
        render_interactive(
            &lines,
            None,
            &mut rendered_rows,
            80,
            &mut cursor,
            &mut writer,
        )
        .unwrap();

        assert_eq!(writer.writes, 2, "one write per frame, not one per row");
        assert_eq!(rendered_rows, MESSAGE_ROWS.len());
        assert_eq!(
            String::from_utf8_lossy(&writer.bytes)
                .matches(&command_bytes(BeginSynchronizedUpdate))
                .count(),
            2
        );
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
