# restore_helper

Build a restore plan from checksum manifests, then execute it using mounted
sources. Source manifest IDs associate the plan's content with mount paths.
Source IDs must be nonempty and unique within a plan. Repeating a source ID
in `plan`, in saved JSON, or a mount ID in `execute` is an error, even when
the repeated arguments use the same path.

```sh
restore_helper plan target.cshd --source archive=/path/archive.cshd --output plan.json
restore_helper execute plan.json --target restored --mount archive=/mnt/archive --existing-file-policy skip-same-metadata
restore_helper check plan.json --target restored
```

## Checking destinations

`check` loads the saved plan and checks every planned destination, including
files without a usable restore source. It needs no mounts or source manifests
and does not write files or hash their contents. Unrelated destination files
are ignored.

Each destination must be a regular file (symlinks are reported as problems).
Size and mtime are compared independently when recorded in the plan. Size must
match exactly; mtime allows an absolute difference of up to 1 µs, using the
same comparison as `checksum_helper`. If neither is recorded, only existence
and file type are checked.

Missing files, metadata mismatches (expected and actual values), wrong file
types, and metadata access errors are printed as permanent lines. Checking
continues after per-file problems and ends with totals. A problem produces a
nonzero exit status; matching files produce no per-file output.

The library exposes `Plan::from_json`, `Plan::check`, and
`Plan::check_with_progress`. The latter emits a `CheckProgress` result for each
destination. Both checking methods return a `CheckSummary`; findings are not
library errors, so callers should inspect `CheckSummary::has_problems()`.
Callback errors stop the check and are returned to the caller.

## Execution

Plan paths must be nonempty relative file paths without parent traversal
or absolute prefixes, and cannot name `.`. Loading a saved plan validates destination and source
paths. Execution and checking reject symlinked parent directories below the
configured target; execution also rejects symlinks below source mounts,
including source files. The explicitly configured roots are trusted.
These checks do not protect against another process concurrently replacing
directories during a restore; keep roots and their ancestors stable while running.

`--existing-file-policy` is required:

- `skip-always`: leave existing destination files alone.
- `skip-same-metadata`: skip files with matching planned size and mtime;
  otherwise replace them.
- `overwrite`: replace existing regular files.

For each file, execution selects the highest-priority mounted candidate in the
plan. It skips files without a matching content source or a mounted candidate.
It does not reopen source manifests. Missing or unreadable files on a selected
mount remain errors and stop execution.

On a terminal, a temporary section shows the destination, selected source ID
and source path, and bytes copied with a percentage. Redraws are throttled to
100 ms, and long paths are shortened to fit. Successful copies leave no
permanent per-file lines. Skips always leave a permanent line with their reason.

Redirected output has no terminal controls or per-chunk updates. It prints one
source-selection line per copy attempt, skip lines, and the final summary.

The summary includes copied files and bytes, skips by reason, failed files,
and files not processed. Execution errors produce an incomplete summary before
the error is returned. Plan-loading or CLI argument errors happen before
execution and do not produce execution totals.

File I/O diagnostics include the operation, affected path, and original OS error.
The library retains the underlying `std::io::Error` in `IoError` or `PathIoError`
and exposes it through `std::error::Error::source`.

## Library progress

`RestoreState::execute_with_progress(policy, callback)` emits `ExecuteProgress`
events for the planned file count, selected copy source, bytes written,
completed copies, and skips with a `SkipReason`. The callback returns
`std::io::Result<()>`. A copy counts as completed only after publication and
parent-directory synchronization succeed. Bytes may restart at zero on a
transfer retry; they are not a cumulative byte total for the whole run.
