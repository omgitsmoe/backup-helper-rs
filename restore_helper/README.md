# restore_helper

Build a restore plan from checksum manifests, then execute it using mounted
sources. Source manifest IDs associate the plan's content with mount paths.

```sh
restore_helper plan target.cshd --source archive=/path/archive.cshd --output plan.json
restore_helper execute plan.json --target restored --mount archive=/mnt/archive --existing-file-policy skip-same-metadata
```

## Execution

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

## Library progress

`RestoreState::execute_with_progress(policy, callback)` emits `ExecuteProgress`
events for the planned file count, selected copy source, bytes written,
completed copies, and skips with a `SkipReason`. The callback returns
`std::io::Result<()>`. A copy counts as completed only after publication and
parent-directory synchronization succeed. Bytes may restart at zero on a
transfer retry; they are not a cumulative byte total for the whole run.
