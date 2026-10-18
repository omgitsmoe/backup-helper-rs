use std::{
    io::{self, Write},
    time::{Duration, Instant},
};

use crossterm::{
    cursor, queue,
    terminal::{Clear, ClearType},
};
use restore_helper::{ExecuteProgress, SkipReason};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

const REDRAW_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Default)]
struct Counters {
    planned: usize,
    copied: usize,
    bytes: u64,
    existing: usize,
    same_metadata: usize,
    no_source: usize,
    unmounted: usize,
}

impl Counters {
    fn processed(&self) -> usize {
        self.copied + self.skipped()
    }

    fn skipped(&self) -> usize {
        self.existing + self.same_metadata + self.no_source + self.unmounted
    }
}

pub struct ProgressReporter<W> {
    output: W,
    interactive: bool,
    width: usize,
    rows: usize,
    last_render: Option<Instant>,
    target: String,
    source: String,
    counters: Counters,
    started: Option<Instant>,
    active: bool,
    active_bytes: u64,
}

impl<W: Write> ProgressReporter<W> {
    pub fn new(output: W, interactive: bool, width: usize) -> Self {
        Self {
            output,
            interactive,
            width: width.min(80),
            rows: 0,
            last_render: None,
            target: String::new(),
            source: String::new(),
            counters: Counters::default(),
            started: None,
            active: false,
            active_bytes: 0,
        }
    }

    fn clear(&mut self) -> io::Result<()> {
        while self.rows > 0 {
            queue!(
                self.output,
                cursor::MoveUp(1),
                cursor::MoveToColumn(0),
                Clear(ClearType::CurrentLine)
            )?;
            self.rows -= 1;
        }
        Ok(())
    }

    fn render(&mut self, copied: u64, total: u64, now: Instant) -> io::Result<()> {
        if !self.interactive
            || self
                .last_render
                .is_some_and(|last| now.duration_since(last) < REDRAW_INTERVAL)
        {
            return Ok(());
        }
        self.last_render = Some(now);
        self.clear()?;
        let percent = if total == 0 {
            100.0
        } else {
            copied as f64 / total as f64 * 100.0
        };
        let mut lines = vec![
            format!(
                "Files: {}/{} processed ({} copied, {} skipped)",
                self.counters.processed(),
                self.counters.planned,
                self.counters.copied,
                self.counters.skipped()
            ),
            self.timing_line(now, true),
        ];
        if self.active {
            lines.extend([
                format!("Copy: {}", self.target),
                format!("Source: {}", self.source),
                format!("{copied} / {total} bytes ({percent:.1}%)"),
            ]);
        }
        for line in lines {
            // Leave the last column unused to avoid the terminal's automatic wrap.
            write!(
                self.output,
                "\r{}\r\n",
                truncate(&line, self.width.saturating_sub(1))
            )?;
            self.rows += 1;
        }
        self.output.flush()
    }

    pub fn report(&mut self, event: ExecuteProgress<'_>) -> io::Result<()> {
        self.report_at(event, Instant::now())
    }

    fn report_at(&mut self, event: ExecuteProgress<'_>, now: Instant) -> io::Result<()> {
        match event {
            ExecuteProgress::Begin { files } => {
                self.counters.planned = files;
                self.started = Some(now);
            }
            ExecuteProgress::CopyStarted {
                target,
                source,
                source_id,
                total,
            } => {
                self.active = true;
                self.active_bytes = 0;
                self.target = format!("{target:?}");
                self.source = format!("{source_id:?} -> {source:?}");
                if !self.interactive {
                    writeln!(self.output, "[COPY] {} <- {}", self.target, self.source)?;
                }
                self.render(0, total, now)?;
            }
            ExecuteProgress::CopyBytes { copied, total } => {
                self.active_bytes = copied;
                self.render(copied, total, now)?
            }
            ExecuteProgress::Copied { bytes } => {
                self.counters.copied += 1;
                self.counters.bytes += bytes;
                self.active = false;
                self.active_bytes = 0;
                self.render(0, 0, now)?;
            }
            ExecuteProgress::Skipped {
                target,
                reason,
                source_ids,
            } => {
                self.clear()?;
                let reason = match reason {
                    SkipReason::Existing => {
                        self.counters.existing += 1;
                        "existing file (skip-always)".to_owned()
                    }
                    SkipReason::SameMetadata => {
                        self.counters.same_metadata += 1;
                        "matching size and mtime".to_owned()
                    }
                    SkipReason::NoSource => {
                        self.counters.no_source += 1;
                        "no matching source in plan".to_owned()
                    }
                    SkipReason::NoMountedSource => {
                        self.counters.unmounted += 1;
                        format!("no candidate source mounted ({source_ids:?})")
                    }
                };
                writeln!(self.output, "[SKIP] {target:?} — {reason}")?;
                self.output.flush()?;
                self.render(0, 0, now)?;
            }
        }
        Ok(())
    }

    pub fn finish(&mut self, failed: bool) -> io::Result<()> {
        self.finish_at(failed, Instant::now())
    }

    fn finish_at(&mut self, failed: bool, now: Instant) -> io::Result<()> {
        self.clear()?;
        let counts = &self.counters;
        let skipped = counts.skipped();
        let failed_count = usize::from(failed);
        let remaining = counts
            .planned
            .saturating_sub(counts.copied + skipped + failed_count);
        writeln!(
            self.output,
            "Summary{}: {} copied ({} bytes), {skipped} skipped, {failed_count} failed, {remaining} not processed",
            if failed { " (incomplete)" } else { "" },
            counts.copied,
            counts.bytes
        )?;
        writeln!(
            self.output,
            "  existing: {}, matching metadata: {}, no source: {}, unmounted: {}",
            counts.existing, counts.same_metadata, counts.no_source, counts.unmounted
        )?;
        writeln!(self.output, "{}", self.timing_line(now, false))?;
        self.output.flush()
    }

    fn timing_line(&self, now: Instant, include_eta: bool) -> String {
        let elapsed = self
            .started
            .map(|start| now.duration_since(start))
            .unwrap_or_default();
        let rate = if elapsed.is_zero() {
            "—".to_owned()
        } else {
            let bytes = self.counters.bytes.saturating_add(self.active_bytes);
            format!(
                "{:.1} MiB/s",
                bytes as f64 / elapsed.as_secs_f64() / 1_048_576.0
            )
        };
        let mut line = format!("Elapsed: {} | Rate: {rate}", duration_text(elapsed));
        if include_eta {
            let processed = self.counters.processed();
            let remaining = self.counters.planned.saturating_sub(processed);
            let eta = if remaining == 0 {
                "0s".to_owned()
            } else if processed == 0 || elapsed.is_zero() {
                "—".to_owned()
            } else {
                Duration::try_from_secs_f64(
                    elapsed.as_secs_f64() * remaining as f64 / processed as f64,
                )
                .map(|duration| format!("~{}", duration_text(duration)))
                .unwrap_or_else(|_| "—".to_owned())
            };
            line.push_str(&format!(" | ETA: {eta}"));
        }
        line
    }
}

fn duration_text(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds >= 3600 {
        format!(
            "{}h {}m {}s",
            seconds / 3600,
            seconds / 60 % 60,
            seconds % 60
        )
    } else if seconds >= 60 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else {
        format!("{seconds}s")
    }
}

fn truncate(text: &str, width: usize) -> String {
    if text.width() <= width {
        return text.to_owned();
    }
    if width == 0 {
        return String::new();
    }
    let head_budget = (width - 1) / 2;
    let mut used = 0;
    let mut result = String::new();
    for ch in text.chars() {
        let next = ch.width().unwrap_or(0);
        if used + next > head_budget {
            break;
        }
        result.push(ch);
        used += next;
    }
    result.push('…');
    let tail_budget = width - 1 - used;
    let mut tail_width = 0;
    let mut tail_start = text.len();
    for (index, ch) in text.char_indices().rev() {
        let next = ch.width().unwrap_or(0);
        if tail_width + next > tail_budget {
            break;
        }
        tail_start = index;
        tail_width += next;
    }
    result.push_str(&text[tail_start..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn start(reporter: &mut ProgressReporter<Vec<u8>>) {
        reporter
            .report(ExecuteProgress::Begin { files: 3 })
            .unwrap();
        reporter
            .report(ExecuteProgress::CopyStarted {
                target: Path::new("target/file.txt"),
                source: Path::new("mount/other.txt"),
                source_id: "archive",
                total: 8,
            })
            .unwrap();
    }

    #[test]
    fn redirected_output_has_source_skips_and_exact_totals_without_controls() {
        let mut reporter = ProgressReporter::new(Vec::new(), false, 80);
        start(&mut reporter);
        for copied in 0..=8 {
            reporter
                .report(ExecuteProgress::CopyBytes { copied, total: 8 })
                .unwrap();
        }
        reporter
            .report(ExecuteProgress::Copied { bytes: 8 })
            .unwrap();
        for reason in [SkipReason::Existing, SkipReason::NoMountedSource] {
            reporter
                .report(ExecuteProgress::Skipped {
                    target: Path::new("target/skipped.txt"),
                    reason,
                    source_ids: vec!["offline"],
                })
                .unwrap();
        }
        reporter.finish(false).unwrap();
        let output = String::from_utf8(reporter.output).unwrap();
        assert!(!output.contains(['\r', '\x1b']));
        assert!(output.contains("archive"));
        assert!(output.contains("mount/other.txt"));
        assert!(output.contains("existing file (skip-always)"));
        assert!(output.contains("no candidate source mounted"));
        assert!(output.contains("offline"));
        assert!(output.contains("1 copied (8 bytes), 2 skipped, 0 failed, 0 not processed"));
        assert!(output.contains("Elapsed:"));
        assert!(output.contains("MiB/s"));
        assert!(!output.contains("ETA:"));
        assert_eq!(output.lines().count(), 6);
    }

    #[test]
    fn interactive_progress_is_throttled_and_cleared_before_permanent_lines() {
        let mut reporter = ProgressReporter::new(Vec::new(), true, 80);
        start(&mut reporter);
        let now = reporter.last_render.unwrap();
        let first = reporter.output.len();
        for _ in 0..100_000 {
            reporter
                .render(1, 8, now + Duration::from_millis(1))
                .unwrap();
        }
        assert_eq!(reporter.output.len(), first);
        reporter.render(4, 8, now + REDRAW_INTERVAL).unwrap();
        assert_eq!(reporter.rows, 5);
        reporter
            .report(ExecuteProgress::Skipped {
                target: Path::new("skipped"),
                reason: SkipReason::NoSource,
                source_ids: vec![],
            })
            .unwrap();
        assert_eq!(reporter.rows, 0);
        let output = String::from_utf8(reporter.output).unwrap();
        assert!(output.contains("4 / 8 bytes (50.0%)"));
        assert!(output.contains("\x1b[2K[SKIP]"));
    }

    #[test]
    fn failure_clears_progress_and_reports_partial_counts() {
        let mut reporter = ProgressReporter::new(Vec::new(), true, 80);
        start(&mut reporter);
        reporter.finish(true).unwrap();
        assert_eq!(reporter.rows, 0);
        let output = String::from_utf8(reporter.output).unwrap();
        assert!(output.contains(
            "Summary (incomplete): 0 copied (0 bytes), 0 skipped, 1 failed, 2 not processed"
        ));
    }

    #[test]
    fn changing_files_does_not_bypass_the_redraw_throttle() {
        let mut reporter = ProgressReporter::new(Vec::new(), true, 80);
        start(&mut reporter);
        let before = reporter.output.len();
        reporter.last_render = Some(Instant::now());
        reporter
            .report(ExecuteProgress::Copied { bytes: 8 })
            .unwrap();
        reporter
            .report(ExecuteProgress::CopyStarted {
                target: Path::new("next.txt"),
                source: Path::new("next-source.txt"),
                source_id: "archive",
                total: 4,
            })
            .unwrap();
        assert_eq!(reporter.output.len(), before);
    }

    #[test]
    fn empty_run_still_has_a_summary() {
        let mut reporter = ProgressReporter::new(Vec::new(), false, 80);
        reporter
            .report(ExecuteProgress::Begin { files: 0 })
            .unwrap();
        reporter.finish(false).unwrap();
        assert!(
            String::from_utf8(reporter.output)
                .unwrap()
                .contains("0 copied (0 bytes), 0 skipped, 0 failed, 0 not processed")
        );
    }

    #[test]
    fn whole_run_timing_counts_completed_files_and_active_bytes_once() {
        let mut reporter = ProgressReporter::new(Vec::new(), true, 80);
        let start = Instant::now();
        reporter
            .report_at(ExecuteProgress::Begin { files: 3 }, start)
            .unwrap();
        assert!(reporter.timing_line(start, true).contains("ETA: —"));
        assert!(reporter.timing_line(start, true).contains("Rate: —"));
        reporter
            .report_at(ExecuteProgress::Copied { bytes: 1_048_576 }, start)
            .unwrap();
        reporter
            .report_at(
                ExecuteProgress::CopyStarted {
                    target: Path::new("next"),
                    source: Path::new("source"),
                    source_id: "archive",
                    total: 4 * 1_048_576,
                },
                start,
            )
            .unwrap();
        let now = start + Duration::from_secs(2);
        reporter
            .report_at(
                ExecuteProgress::CopyBytes {
                    copied: 1_048_576,
                    total: 4 * 1_048_576,
                },
                now,
            )
            .unwrap();
        assert_eq!(
            reporter.timing_line(now, true),
            "Elapsed: 2s | Rate: 1.0 MiB/s | ETA: ~4s"
        );
        assert!(
            String::from_utf8_lossy(&reporter.output)
                .contains("Files: 1/3 processed (1 copied, 0 skipped)")
        );
        reporter
            .report_at(
                ExecuteProgress::CopyBytes {
                    copied: 0,
                    total: 4 * 1_048_576,
                },
                now,
            )
            .unwrap();
        assert!(reporter.timing_line(now, true).contains("Rate: 0.5 MiB/s"));
        reporter
            .report_at(ExecuteProgress::Copied { bytes: 1_048_576 }, now)
            .unwrap();
        assert!(reporter.timing_line(now, true).contains("Rate: 1.0 MiB/s"));
        assert_eq!(reporter.active_bytes, 0);
        reporter
            .report_at(
                ExecuteProgress::Skipped {
                    target: Path::new("skipped"),
                    reason: SkipReason::Existing,
                    source_ids: vec![],
                },
                now + REDRAW_INTERVAL,
            )
            .unwrap();
        assert!(reporter.timing_line(now, true).contains("ETA: 0s"));
        let output = String::from_utf8_lossy(&reporter.output);
        assert!(output.contains("Files: 3/3 processed (2 copied, 1 skipped)"));
        assert_eq!(reporter.rows, 2);
    }

    #[test]
    fn failure_summary_includes_active_rate_but_only_completed_byte_totals() {
        let mut reporter = ProgressReporter::new(Vec::new(), false, 80);
        let start = Instant::now();
        reporter
            .report_at(ExecuteProgress::Begin { files: 1 }, start)
            .unwrap();
        reporter
            .report_at(
                ExecuteProgress::CopyBytes {
                    copied: 2 * 1_048_576,
                    total: 4 * 1_048_576,
                },
                start,
            )
            .unwrap();
        reporter
            .finish_at(true, start + Duration::from_secs(2))
            .unwrap();
        let output = String::from_utf8(reporter.output).unwrap();
        assert!(output.contains("0 copied (0 bytes), 0 skipped, 1 failed"));
        assert!(output.contains("Elapsed: 2s | Rate: 1.0 MiB/s"));
        assert!(!output.contains("ETA:"));
    }

    #[test]
    fn empty_run_and_long_durations_have_defined_timing() {
        let mut reporter = ProgressReporter::new(Vec::new(), false, 80);
        let start = Instant::now();
        reporter
            .report_at(ExecuteProgress::Begin { files: 0 }, start)
            .unwrap();
        assert_eq!(
            reporter.timing_line(start, true),
            "Elapsed: 0s | Rate: — | ETA: 0s"
        );
        reporter.finish_at(false, start).unwrap();
        assert!(
            String::from_utf8(reporter.output)
                .unwrap()
                .contains("Elapsed: 0s | Rate: —")
        );
        assert_eq!(duration_text(Duration::from_secs(133)), "2m 13s");
        assert_eq!(duration_text(Duration::from_secs(3661)), "1h 1m 1s");
    }

    #[test]
    fn truncation_obeys_terminal_columns_and_preserves_unicode() {
        for text in [
            "long ascii path",
            "目录/文件.txt",
            "e\u{301}e\u{301}e\u{301}",
        ] {
            for width in 0..20 {
                let shortened = truncate(text, width);
                assert!(shortened.width() <= width, "{shortened:?}, width={width}");
                if text.width() <= width {
                    assert_eq!(shortened, text);
                }
            }
        }
    }
}
