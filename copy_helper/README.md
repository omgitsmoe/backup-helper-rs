# copy_helper

Low-level file transfer primitives shared by workspace tools. Tree traversal,
source selection, skip policies, and progress rendering belong to callers.

## API

- `preserved_metadata` captures a file's mtime and Unix permissions.
  `PreservedMetadata` has public fields so a caller can explicitly choose a
  different destination mtime, for example from a restore manifest.
- `copy_file(source, destination, metadata, expected_len, operation)` copies to
  a sibling temp file, validates the byte count when `expected_len` is `Some`,
  flushes, applies the supplied metadata, and renames onto the destination.
  It replaces existing files and returns the copied byte count, or `CopyError`.
  `operation` supplies context for transfer errors. Use `Some(length)` for
  regular files, including followed file symlinks, and `None` for special files.
- `copy_file_with_progress` takes the same arguments plus a fallible callback
  receiving the bytes written so far, starting at zero. It copies in 64 KiB
  chunks and uses the same validation, flushing, metadata and publication path.
  A retried transfer starts its progress at zero again. Callback errors abort
  the attempt and are subject to the same retry policy as transfer errors.
- `sync_parent_directory` flushes a directory after publication. Callers can
  batch this once per touched directory; `copy_file` does not flush it itself.
- `sweep_stale_temps` performs best-effort cleanup of recognized `.bh-tmp-`
  files at least 24 hours old. Call it once per directory before transfers,
  not while that directory contains an active transfer's temp file.
- `retry_io` and `is_retryable_io_error` provide the same short retry backoff
  for associated filesystem operations.

The caller must create parent directories and validate paths, symlinks, and
source/destination overlap before copying. These primitives do not enforce a
destination root or provide race-free path confinement. Failed transfers clean
up their temp files without publishing partial contents.

`copy_file` retains `std::fs::copy` and its platform optimizations.
`copy_file_with_progress` uses buffered reads and writes instead; the callback
does not imply completion until the function successfully returns.

File flushing must precede metadata restoration: a writable flush handle can
reset the mtime on CIFS. The existing rationale and real-share regression check
are in [stamp_after_flush.md](../backup_helper/doc/adr/stamp_after_flush.md).
