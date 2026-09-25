use std::ffi::{OsStr, OsString};
use std::io::{self, IsTerminal};
use std::time::{Duration, Instant};

use checksum_helper::{
    checksum_helper::{IncrementalProgress, MostCurrentProgress, VerifyRootProgress},
    collection::VerifyProgress,
    hashed_file::VerifyResult,
};

/// Upper bound for how often an in-place status line is redrawn.
///
/// A run reports one event per file, and one event per 64 KiB chunk while
/// hashing. Redrawing on every event would emit one write and one `format!`
/// per event, which is unreadable and needlessly slow on a tree holding
/// hundreds of thousands of entries.
const REDRAW_INTERVAL: Duration = Duration::from_millis(100);

/// A status line stays below this width, since `\r` returns to column zero of
/// the current row only and cannot return from a wrapped row.
const STATUS_LINE_WIDTH: usize = 80;

/// Totals shown both on the in-place status line and, with exact numbers, once
/// a phase is done.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Counters {
    hash_files_found: u64,
    hash_files_ignored: u64,
    files_found: u64,
    files_ignored: u64,
    files_missing: u64,
}

impl Counters {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    fn line(&self) -> String {
        let line = format!(
            "hash files: {} | missing: {} | files: {}",
            with_ignored(self.hash_files_found, self.hash_files_ignored),
            self.files_missing,
            with_ignored(self.files_found, self.files_ignored),
        );

        debug_assert!(
            line.chars().count() <= STATUS_LINE_WIDTH,
            "a wrapped status line cannot be redrawn with a carriage return: {line}"
        );

        line
    }

    fn totals(&self) -> String {
        format!(
            "hash files: {}, filtered missing: {}, files: {}",
            with_ignored(self.hash_files_found, self.hash_files_ignored),
            self.files_missing,
            with_ignored(self.files_found, self.files_ignored),
        )
    }
}

fn with_ignored(count: u64, ignored: u64) -> String {
    if ignored == 0 {
        count.to_string()
    } else {
        format!("{count} (+{ignored} ign)")
    }
}

/// A single terminal row, redrawn in place for as long as no full line is
/// printed on top of it.
#[derive(Debug, Default)]
struct StatusLine {
    last_render: Option<Instant>,
    last_text: Option<String>,
    last_width: usize,
    /// Whether the cursor still sits at the end of the last rendered status.
    open: bool,
}

impl StatusLine {
    /// Whether the throttle allows another redraw.
    ///
    /// Separate from [`Self::render`], so the text of a suppressed redraw is
    /// never built.
    fn should_render(&mut self, now: Instant) -> bool {
        if let Some(last) = self.last_render {
            if now.duration_since(last) < REDRAW_INTERVAL {
                return false;
            }
        }

        self.last_render = Some(now);
        true
    }

    /// Returns the payload erasing the previous status line and writing
    /// `text`, or `None` if `text` is already on screen.
    fn render(&mut self, text: String) -> Option<String> {
        if self.open && self.last_text.as_deref() == Some(text.as_str()) {
            return None;
        }

        // The previous width, since that is what is on screen and therefore
        // what has to be erased: a shorter status line would leave the tail of
        // the longer one behind.
        let erased_width = self.last_width;
        self.last_width = text.chars().count();
        self.last_text = Some(text.clone());

        // A row is only erased while it is still ours; a full line in between
        // moved the cursor onto a new row.
        let mut line = String::from("\r");
        if self.open {
            line.push_str(&" ".repeat(erased_width));
            line.push('\r');
        }
        self.open = true;
        line.push_str(&text);

        Some(line)
    }

    /// Closes the status line, returning whether a row was still open.
    ///
    /// The throttle is reset as well, so a status line for the next file is
    /// drawn right away instead of waiting out the interval of the previous
    /// one. Full lines are printed per file, so their output is bounded by the
    /// work and does not need throttling.
    fn finish(&mut self) -> bool {
        self.last_render = None;
        std::mem::take(&mut self.open)
    }

    /// Closes the status line and returns the payload erasing its row.
    fn close(&mut self) -> String {
        if !self.finish() {
            return String::new();
        }

        format!("\r{}\r", " ".repeat(self.last_width))
    }
}

pub struct ProgressReporter {
    counters: Counters,
    verbose: u8,
    /// Name of the file currently being read or verified, for the status line.
    current_name: Option<OsString>,
    status: StatusLine,
    /// Whether status lines are redrawn in place. Without a terminal there is
    /// no row to redraw, so only the totals of a finished phase are reported.
    interactive: bool,
    /// Whether a most current collection is being built, so that it is
    /// reported as soon as verification starts.
    building_most_current: bool,
}

impl Default for ProgressReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressReporter {
    pub fn new() -> Self {
        Self {
            counters: Counters::default(),
            verbose: 0,
            current_name: None,
            status: StatusLine::default(),
            interactive: io::stdout().is_terminal(),
            building_most_current: false,
        }
    }

    pub fn set_verbose(&mut self, verbose: u8) {
        self.verbose = verbose;
    }

    /// Closes the in-place status line, so following output starts on its own
    /// row.
    pub fn finish(&mut self) {
        if self.status.finish() {
            println!();
        }
    }

    /// Reports the exact totals of a finished phase.
    ///
    /// The in-place status line is throttled, so it can be missing the last
    /// increments of a phase.
    pub fn report_totals(&mut self) {
        self.finish();

        if self.counters.is_empty() {
            return;
        }

        println!("Totals: {}", self.counters.totals());
    }

    /// Whether a status line may be redrawn right now.
    fn status_allowed(&mut self) -> bool {
        self.interactive && self.status.should_render(Instant::now())
    }

    /// Writes `text` as the status line, replacing the previous one.
    fn render_status(&mut self, text: String) {
        if let Some(line) = self.status.render(text) {
            print!("{line}");
        }
    }

    /// Redraws the counter status line.
    fn update_status(&mut self) {
        if self.status_allowed() {
            self.render_status(self.counters.line());
        }
    }

    /// Prints a full line, erasing an in-place status line first.
    fn print_line(&mut self, line: impl AsRef<str>) {
        let erase = self.status.close();

        if !erase.is_empty() {
            print!("{erase}");
        }

        println!("{}", line.as_ref());
    }

    pub fn report_most_current(&mut self, progress: MostCurrentProgress) {
        match progress {
            MostCurrentProgress::MergeHashFile(path_buf) => {
                self.print_line(format!("[MERGE] {:?}", path_buf));
            }

            MostCurrentProgress::FoundFile(_path_buf) => {
                self.counters.hash_files_found += 1;
                self.update_status();
            }

            MostCurrentProgress::IgnoredPath(path_buf) => {
                self.counters.hash_files_ignored += 1;
                self.print_line(format!("[IGN  ] {:?}", path_buf));
            }

            MostCurrentProgress::FilteredMissingFile(path_buf) => {
                self.counters.files_missing += 1;
                if self.verbose > 0 {
                    self.print_line(format!("[MISS ] {:?}", path_buf));
                }
                self.update_status();
            }
        }
    }

    pub fn report_incremental(&mut self, progress: IncrementalProgress) {
        match progress {
            IncrementalProgress::BuildMostCurrent(most_current_progress) => {
                self.report_most_current(most_current_progress)
            }

            IncrementalProgress::DiscoverFilesFound(found) => {
                self.counters.files_found = found;
                self.update_status();
            }

            IncrementalProgress::DiscoverFilesIgnored(_path_buf) => {
                self.counters.files_ignored += 1;
            }

            IncrementalProgress::DiscoverFilesDone(to_hash, num_ignored) => {
                self.print_line(format!(
                    "Incremental: Discovering done, found {to_hash} (+ {num_ignored} ignored)"
                ));
            }

            IncrementalProgress::PreRead(path_buf) => {
                self.current_name = path_buf.file_name().map(OsStr::to_owned);
                self.print_line(format!("[READ ] {:?}", path_buf));
            }

            IncrementalProgress::Read(read, total) => {
                if self.status_allowed() {
                    self.render_status(read_line(self.current_name.as_deref(), read, total));
                }
            }

            IncrementalProgress::FileMatch(path_buf) => {
                self.print_line(format!("[OK   ] {:?} unchanged", path_buf));
            }

            IncrementalProgress::FileUnchangedSkipped(path_buf) => {
                self.print_line(format!("[SKIP ] {:?} (unchanged, skipped)", path_buf));
            }

            IncrementalProgress::FileChanged(path_buf) => {
                self.print_line(format!("[CHG  ] {:?} modified", path_buf));
            }

            IncrementalProgress::FileChangedCorrupted(path_buf) => {
                self.print_line(format!("[CORR ] {:?} corrupted", path_buf));
            }

            IncrementalProgress::FileChangedOlder(path_buf) => {
                self.print_line(format!("[OLD  ] {:?} local newer than hash", path_buf));
            }

            IncrementalProgress::FileNew(path_buf) => {
                self.print_line(format!("[NEW  ] {:?}", path_buf));
            }

            IncrementalProgress::FileRemoved(path_buf) => {
                self.print_line(format!("[DEL  ] {:?}", path_buf));
            }

            IncrementalProgress::Finished => {
                self.print_line("Done.");
            }
        }
    }

    pub fn report_verify(&mut self, progress: VerifyProgress) {
        match progress {
            VerifyProgress::Pre(common) => {
                let path = common.tree_root.join(common.relative_path);
                self.current_name = path.file_name().map(OsStr::to_owned);

                self.print_line(format!(
                    "[VERIFY] ({:>4}/{:>4}) {:?}",
                    common.file_number_processed, common.file_number_total, path
                ));

                self.print_line(format!(
                    "[PROG ] bytes {:>10} / {:>10}",
                    common.size_processed_bytes, common.size_total_bytes
                ));
            }

            VerifyProgress::During(hash_progress) => {
                if self.status_allowed() {
                    self.render_status(hash_line(
                        self.current_name.as_deref(),
                        hash_progress.bytes_read,
                        hash_progress.bytes_total,
                    ));
                }
            }

            VerifyProgress::Post(post) => {
                let path = post.progress.tree_root.join(post.progress.relative_path);

                let status = match post.result {
                    VerifyResult::Ok => "[OK        ]",

                    VerifyResult::FileMissing(_error_kind) => "[ERR MISS  ]",

                    VerifyResult::Mismatch => "[ERR HASH  ]",

                    VerifyResult::MismatchSize => "[ERR SIZE  ]",

                    VerifyResult::MismatchCorrupted => "[ERR CORR  ]",

                    VerifyResult::MismatchOutdatedHash => "[WARN STALE]", // not strictly an error
                };

                self.print_line(format!("{status} {path:?}"));
            }
        }
    }

    pub fn report_verify_root(&mut self, progress: VerifyRootProgress) {
        match progress {
            VerifyRootProgress::BuildMostCurrent(p) => {
                self.building_most_current = true;
                self.report_most_current(p);
            }

            VerifyRootProgress::Verify(p) => {
                if std::mem::take(&mut self.building_most_current) {
                    self.report_totals();
                }
                self.report_verify(p);
            }
        }
    }
}

fn read_line(name: Option<&OsStr>, read: u64, total: u64) -> String {
    match name {
        Some(name) => format!("[READ ] {name:?} {read:>8} / {total:>8} bytes"),
        None => format!("[READ ] {read:>8} / {total:>8} bytes"),
    }
}

fn hash_line(name: Option<&OsStr>, bytes_read: u64, bytes_total: u64) -> String {
    let Some(name) = name else {
        return format!("[HASH ] {bytes_read:>8}/{bytes_total:>8} bytes");
    };

    let percent = if bytes_total > 0 {
        (bytes_read as f64 / bytes_total as f64) * 100.0
    } else {
        0.0
    };

    format!(
        "[HASH ] {:<30} {:>8}/{bytes_total:>8} bytes ({percent:5.1}%)",
        name.to_string_lossy(),
        bytes_read
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_line_redraws_at_most_once_per_interval() {
        let start = Instant::now();
        let mut status = StatusLine::default();

        assert!(status.should_render(start));
        assert!(!status.should_render(start + Duration::from_millis(1)));
        assert!(!status.should_render(start + REDRAW_INTERVAL - Duration::from_millis(1)));
        assert!(status.should_render(start + REDRAW_INTERVAL));
    }

    #[test]
    fn status_line_erases_the_previous_row() {
        let start = Instant::now();
        let mut status = StatusLine::default();

        status.should_render(start);
        assert_eq!(
            status.render("a longer line".to_owned()).as_deref(),
            Some("\ra longer line")
        );

        // A shorter status line erases the width of the longer one before it,
        // so no trailing characters are left behind.
        status.should_render(start + REDRAW_INTERVAL);
        assert_eq!(
            status.render("ab".to_owned()).as_deref(),
            Some("\r             \rab")
        );
    }

    #[test]
    fn status_line_is_not_redrawn_with_unchanged_text() {
        let start = Instant::now();
        let mut status = StatusLine::default();

        status.should_render(start);
        assert!(status.render("same".to_owned()).is_some());

        status.should_render(start + REDRAW_INTERVAL);
        assert!(status.render("same".to_owned()).is_none());

        status.should_render(start + 2 * REDRAW_INTERVAL);
        assert!(status.render("other".to_owned()).is_some());
    }

    #[test]
    fn status_line_is_not_erased_again_after_a_full_line() {
        let start = Instant::now();
        let mut status = StatusLine::default();

        status.should_render(start);
        status.render("status".to_owned());

        assert_eq!(status.close(), "\r      \r");
        assert!(status.close().is_empty());

        // The status row is gone, so the next one starts on a fresh row.
        assert_eq!(
            status.render("again".to_owned()).as_deref(),
            Some("\ragain")
        );
    }

    #[test]
    fn a_full_line_resets_the_throttle() {
        let start = Instant::now();
        let mut status = StatusLine::default();

        status.should_render(start);
        status.render("status".to_owned());

        // A full line printed right after the status line, well within the
        // interval, still lets the next file report progress immediately.
        status.close();
        assert!(status.should_render(start + Duration::from_millis(1)));
    }

    #[test]
    fn finishing_reports_whether_a_status_row_was_open() {
        let start = Instant::now();
        let mut status = StatusLine::default();

        assert!(!status.finish());

        status.should_render(start);
        status.render("status".to_owned());
        assert!(status.finish());
        assert!(!status.finish());
    }

    #[test]
    fn a_hundred_thousand_events_redraw_once_per_interval() {
        let start = Instant::now();
        let mut status = StatusLine::default();
        let mut redraws = 0;

        for event in 0..100_000u64 {
            if status.should_render(start + Duration::from_millis(event))
                && status.render(format!("event {event}")).is_some()
            {
                redraws += 1;
            }
        }

        // One event per millisecond spans 100 s, so at most one redraw per
        // 100 ms, no matter how many events arrive.
        assert_eq!(redraws, 1_000);
    }

    #[test]
    fn counters_show_ignored_paths_only_when_there_are_some() {
        assert_eq!(with_ignored(3, 0), "3");
        assert_eq!(with_ignored(3, 5), "3 (+5 ign)");
    }

    #[test]
    fn counters_line_carries_all_three_groups() {
        let counters = Counters {
            hash_files_found: 12,
            hash_files_ignored: 1,
            files_found: 34,
            files_ignored: 2,
            files_missing: 56,
        };

        assert_eq!(
            counters.line(),
            "hash files: 12 (+1 ign) | missing: 56 | files: 34 (+2 ign)"
        );
    }

    #[test]
    fn counters_line_fits_a_narrow_terminal() {
        let counters = Counters {
            hash_files_found: 9_999_999,
            hash_files_ignored: 9_999,
            files_found: 9_999_999,
            files_ignored: 9_999,
            files_missing: 9_999_999,
        };

        let line = counters.line();
        assert!(line.chars().count() <= STATUS_LINE_WIDTH, "{line}");
    }

    #[test]
    fn totals_report_the_exact_counts_of_a_phase() {
        let counters = Counters {
            hash_files_found: 12,
            files_found: 34,
            files_missing: 56,
            ..Counters::default()
        };

        assert_eq!(
            counters.totals(),
            "hash files: 12, filtered missing: 56, files: 34"
        );
    }

    #[test]
    fn read_line_carries_the_file_name_when_known() {
        assert_eq!(
            read_line(Some(OsStr::new("file.txt")), 12, 34),
            "[READ ] \"file.txt\"       12 /       34 bytes"
        );
        assert_eq!(read_line(None, 12, 34), "[READ ]       12 /       34 bytes");
    }

    #[test]
    fn hash_line_reports_a_percentage_and_falls_back_to_bytes() {
        assert_eq!(
            hash_line(Some(OsStr::new("file.txt")), 1, 8),
            "[HASH ] file.txt                              1/       8 bytes ( 12.5%)"
        );
        assert_eq!(
            hash_line(Some(OsStr::new("file.txt")), 8, 0),
            "[HASH ] file.txt                              8/       0 bytes (  0.0%)"
        );
        assert_eq!(hash_line(None, 1, 8), "[HASH ]        1/       8 bytes");
    }
}
