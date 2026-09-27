//! The totals of a hash or a verification, folded from the progress events the
//! library reports.
//!
//! A hash and a verification walk a tree, so both can say how far they are along
//! the same way a copy does. What they can say depends on the totals their phase
//! already knows: a verification reads them out of the collection it verifies
//! against, a hash only learns the number of files to hash when its discovery
//! walk is over. Neither is ever asked to walk a tree twice to obtain a total it
//! does not have.

use std::fmt;

use checksum_helper::{
    checksum_helper::IncrementalProgress, collection::VerifyProgress,
    collection::VerifyProgressCommon,
};

use crate::copy::format_bytes;

/// Which part of a hash is running, so the counters say what they count and the
/// rate is measured over the part that reads bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ScanPhase {
    /// The discovery walk, which counts files as it finds them and has no total
    /// to count against.
    #[default]
    Discover,
    /// Hashing the files the walk found.
    Hash,
    /// Verifying a collection.
    Verify,
}

/// Running totals of a hash or a verification.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ScanStats {
    pub(crate) phase: ScanPhase,
    /// Files the discovery walk has found, counted while it runs.
    pub(crate) discovered: u64,
    /// Files hashed or verified so far.
    pub(crate) files_done: u64,
    /// The number of files to hash, once discovery is over; the size of the
    /// collection, for a verification.
    pub(crate) files_total: Option<u64>,
    /// Bytes read in the files that are finished, counted as they were read: a
    /// collection that records no size for a file would count as no bytes for it,
    /// and one whose size is out of date would not count what was read from it.
    pub(crate) bytes_completed: u64,
    /// Bytes read in the file being worked on. Added to the finished files when
    /// the next one starts, so that the last file of a run is not lost.
    pub(crate) bytes_in_file: u64,
    /// Bytes to read, for a verification only: a hash has no total to divide by.
    /// A collection's total counts only the files whose size it records, so it
    /// is only shown while the read has not passed it.
    pub(crate) bytes_total: Option<u64>,
    /// Paths the discovery walk skipped, as reported by `DiscoverFilesDone`.
    pub(crate) ignored: u64,
}

impl ScanStats {
    /// Folds one hash event into the totals.
    ///
    /// Returns whether the counters moved, so a caller reports progress only
    /// when there is something new to draw.
    pub(crate) fn record_incremental(&mut self, progress: &IncrementalProgress) -> bool {
        match progress {
            IncrementalProgress::DiscoverFilesFound(found) => {
                self.phase = ScanPhase::Discover;
                self.discovered = *found;
                true
            }
            IncrementalProgress::DiscoverFilesDone(to_hash, ignored) => {
                self.phase = ScanPhase::Hash;
                self.files_total = Some(*to_hash as u64);
                self.ignored = *ignored as u64;
                true
            }
            IncrementalProgress::PreRead(_) => {
                self.phase = ScanPhase::Hash;
                self.files_done += 1;
                self.bytes_completed += self.bytes_in_file;
                self.bytes_in_file = 0;
                true
            }
            IncrementalProgress::Read(read, _) => {
                self.bytes_in_file = *read;
                true
            }
            _ => false,
        }
    }

    /// Folds one verification event into the totals.
    pub(crate) fn record_verify(&mut self, progress: &VerifyProgress) -> bool {
        match progress {
            VerifyProgress::Pre(common) => {
                self.record_common(common);
                true
            }
            VerifyProgress::During(hash_progress) => {
                self.bytes_in_file = hash_progress.bytes_read;
                true
            }
            VerifyProgress::Post(post) => {
                // The bytes the finished file was read at, before the running
                // total is reset for the next one.
                self.bytes_completed += self.bytes_in_file;
                self.record_common(&post.progress);
                true
            }
        }
    }

    fn record_common(&mut self, common: &VerifyProgressCommon<'_>) {
        self.phase = ScanPhase::Verify;
        self.files_done = common.file_number_processed;
        self.files_total = Some(common.file_number_total);
        self.bytes_total = Some(common.size_total_bytes);
        self.bytes_in_file = 0;
    }

    /// Bytes read so far, over all files.
    pub(crate) fn bytes_done(&self) -> u64 {
        self.bytes_completed + self.bytes_in_file
    }

    /// The compact form for an in-place status line.
    pub(crate) fn progress_line(&self) -> String {
        match self.phase {
            ScanPhase::Discover => {
                // Nothing has been read yet, so there is nothing to divide by a
                // total and no rate that would say anything.
                format!("discovered {}", self.discovered)
            }
            ScanPhase::Hash => {
                let files = match self.files_total {
                    Some(total) => format!("{}/{}", self.files_done, total),
                    None => format!("{}/?", self.files_done),
                };

                format!("files {files} | {}", format_bytes(self.bytes_done()))
            }
            ScanPhase::Verify => {
                let files = match self.files_total {
                    Some(total) => format!(
                        "{}/{} ({:.1}%)",
                        self.files_done,
                        total,
                        percent(self.files_done, total)
                    ),
                    None => format!("{}/?", self.files_done),
                };

                // A collection counts towards its byte total only the files whose
                // size it records, so the total is smaller than the bytes read
                // whenever one of them is missing, and a file that grew since the
                // collection was written adds up to more than its recorded size
                // again. Either way the read passing the total is what shows that
                // it is not a total, and from then on the row reports the bytes
                // read without one.
                let bytes = match self.bytes_total.filter(|total| self.bytes_done() <= *total) {
                    Some(total) => format!(
                        "{}/{} ({:.1}%)",
                        format_bytes(self.bytes_done()),
                        format_bytes(total),
                        percent(self.bytes_done(), total)
                    ),
                    None => format!("{} read", format_bytes(self.bytes_done())),
                };

                format!("files {files} | bytes {bytes}")
            }
        }
    }

    /// The totals of a finished hash, where the bytes are the ones read: a file
    /// skipped for an unchanged `mtime` was never opened.
    pub(crate) fn totals(&self) -> String {
        format!(
            "{} files ({} read) | {} ignored",
            self.files_done,
            format_bytes(self.bytes_done()),
            self.ignored,
        )
    }
}

impl fmt::Display for ScanStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Totals: {}", self.totals())
    }
}

/// A share of a total, with an empty or unrecorded total counted as no progress
/// rather than as a division by zero.
fn percent(done: u64, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }

    (done as f64 / total as f64) * 100.0
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use checksum_helper::{
        checksum_helper::MostCurrentProgress, collection::HashProgress,
        collection::VerifyProgressPost, hashed_file::VerifyResult,
    };
    use pretty_assertions::assert_eq;

    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn path(name: &str) -> PathBuf {
        Path::new(name).to_path_buf()
    }

    fn discover(found: u64) -> IncrementalProgress {
        IncrementalProgress::DiscoverFilesFound(found)
    }

    fn preread() -> IncrementalProgress {
        IncrementalProgress::PreRead(path("raw/x.NEF"))
    }

    /// A hash that found 3 files, hashed one of them and is half way through
    /// the second.
    fn hashing_hash() -> ScanStats {
        let mut stats = ScanStats::default();

        for progress in [
            discover(1),
            discover(2),
            discover(3),
            IncrementalProgress::DiscoverFilesDone(3, 2),
            preread(),
            IncrementalProgress::Read(4 * MIB, 4 * MIB),
            IncrementalProgress::FileNew(path("raw/a.NEF")),
            preread(),
            IncrementalProgress::Read(MIB, 8 * MIB),
        ] {
            stats.record_incremental(&progress);
        }

        stats
    }

    fn common<'a>(
        root: &'a Path,
        relative: &'a Path,
        file_number_processed: u64,
        file_number_total: u64,
        size_processed_bytes: u64,
        size_total_bytes: u64,
    ) -> VerifyProgressCommon<'a> {
        VerifyProgressCommon {
            tree_root: root,
            relative_path: relative,
            file_number_processed,
            file_number_total,
            size_processed_bytes,
            size_total_bytes,
        }
    }

    fn pre(
        file_number_processed: u64,
        file_number_total: u64,
        size_total_bytes: u64,
    ) -> VerifyProgress<'static> {
        VerifyProgress::Pre(common(
            Path::new("/mnt/backup"),
            Path::new("raw/x.NEF"),
            file_number_processed,
            file_number_total,
            0,
            size_total_bytes,
        ))
    }

    fn during(bytes_read: u64) -> VerifyProgress<'static> {
        VerifyProgress::During(HashProgress {
            bytes_read,
            bytes_total: 4 * MIB,
        })
    }

    fn post(
        file_number_processed: u64,
        file_number_total: u64,
        size_total_bytes: u64,
    ) -> VerifyProgress<'static> {
        VerifyProgress::Post(VerifyProgressPost {
            progress: common(
                Path::new("/mnt/backup"),
                Path::new("raw/x.NEF"),
                file_number_processed,
                file_number_total,
                0,
                size_total_bytes,
            ),
            result: VerifyResult::Ok,
        })
    }

    #[test]
    fn discovery_counts_the_files_it_finds_and_has_no_total_yet() {
        let mut stats = ScanStats::default();
        assert!(stats.record_incremental(&discover(1234)));

        assert_eq!(stats.progress_line(), "discovered 1234");
        assert_eq!(stats.phase, ScanPhase::Discover);
    }

    #[test]
    fn a_hash_counts_every_file_it_takes_on_and_only_the_bytes_it_reads() {
        let mut stats = hashing_hash();

        assert_eq!(stats.phase, ScanPhase::Hash);
        assert_eq!(stats.progress_line(), "files 2/3 | 5.0 MiB");

        // The bytes of the last file are counted before the run is over, or a
        // finished hash would report one file short of what it read.
        stats.record_incremental(&preread());
        stats.record_incremental(&IncrementalProgress::Read(4 * MIB, 4 * MIB));

        assert_eq!(stats.progress_line(), "files 3/3 | 9.0 MiB");
        assert_eq!(stats.totals(), "3 files (9.0 MiB read) | 2 ignored");
    }

    #[test]
    fn a_skipped_file_counts_as_a_file_but_contributes_no_bytes() {
        let mut stats = ScanStats::default();
        stats.record_incremental(&IncrementalProgress::DiscoverFilesDone(1, 0));
        stats.record_incremental(&preread());
        stats.record_incremental(&IncrementalProgress::FileUnchangedSkipped(path(
            "raw/a.NEF",
        )));

        assert_eq!(stats.totals(), "1 files (0 B read) | 0 ignored");
    }

    #[test]
    fn a_verification_reports_a_percentage_for_files_and_for_bytes() {
        let mut stats = ScanStats::default();

        for progress in [
            pre(0, 2, 8 * MIB),
            during(4 * MIB),
            post(1, 2, 8 * MIB),
            pre(1, 2, 8 * MIB),
            during(MIB),
        ] {
            assert!(stats.record_verify(&progress));
        }

        assert_eq!(stats.phase, ScanPhase::Verify);
        assert_eq!(
            stats.progress_line(),
            "files 1/2 (50.0%) | bytes 5.0 MiB/8.0 MiB (62.5%)"
        );
    }

    #[test]
    fn the_bytes_of_a_finished_file_are_counted_as_they_were_read() {
        let mut stats = ScanStats::default();

        // A collection that records the size of the first file and none for the
        // second: a total that counts the second as nothing, and a run that reads
        // more of it than the first file held.
        for progress in [
            pre(0, 2, 4 * MIB),
            during(4 * MIB),
            post(1, 2, 4 * MIB),
            pre(1, 2, 4 * MIB),
            during(2 * MIB),
        ] {
            stats.record_verify(&progress);
        }

        // The total the collection reports is smaller than what has been read, so
        // the row reports the bytes read and leaves out a total it has been shown
        // not to be one.
        assert_eq!(
            stats.progress_line(),
            "files 1/2 (50.0%) | bytes 6.0 MiB read"
        );
    }

    #[test]
    fn a_read_that_stays_under_the_total_keeps_it() {
        let mut stats = ScanStats::default();

        for progress in [pre(0, 2, 8 * MIB), during(2 * MIB)] {
            stats.record_verify(&progress);
        }

        assert_eq!(
            stats.progress_line(),
            "files 0/2 (0.0%) | bytes 2.0 MiB/8.0 MiB (25.0%)"
        );
    }

    #[test]
    fn a_collection_without_recorded_sizes_reports_bytes_read() {
        let mut stats = ScanStats::default();
        stats.record_verify(&pre(1, 2, 0));
        stats.record_verify(&during(3 * MIB));

        assert_eq!(
            stats.progress_line(),
            "files 1/2 (50.0%) | bytes 3.0 MiB read"
        );
    }

    #[test]
    fn an_empty_collection_is_no_progress_rather_than_a_division_by_zero() {
        assert_eq!(percent(0, 0), 0.0);
    }

    #[test]
    fn events_that_move_no_counter_report_no_change() {
        let mut stats = ScanStats::default();

        for progress in [
            IncrementalProgress::BuildMostCurrent(MostCurrentProgress::IgnoredPath(path("raw/a"))),
            IncrementalProgress::DiscoverFilesIgnored(path("raw/a.NEF")),
            IncrementalProgress::FileNew(path("raw/a.NEF")),
            IncrementalProgress::Finished,
        ] {
            assert!(!stats.record_incremental(&progress));
        }
    }
}
