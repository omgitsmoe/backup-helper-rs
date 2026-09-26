# Publish copied files atomically

## Context

`copy_file` wrote straight to the final destination path with `fs::copy`, discarded
the byte count that `fs::copy` returns, and then stamped the source mtime onto
whatever the filesystem accepted.

That left the `SkipUnchanged` fast path resting on an assumption the code never
established. `metadata_matches` treats a destination file as complete when its
size and mtime match the source, which is only sound if a file under the final
name is never a partial transfer. A copy that failed part-way through left a
short file with the source mtime already applied, so the next run compared a
truncated file against a matching size and skipped it.

The order made this worse. `restore_metadata` ran after the copy, so metadata was
applied to a file whose content might never have been complete, turning a failed
transfer into a file that looks pristine. A real case: a 705 MiB file on an SMB
share whose size and mtime both matched the manifest while its content did not.

A destination is also not necessarily a local disk. The deployment this was
written for copies to a NAS over CIFS, where `fs::copy` cannot assume the write
reaches stable storage before the call returns.

## Decision

A copy is written to a temporary file in the destination directory and published
with `rename`:

1. Reserve `.{name}.bh-tmp-{pid}-{attempt}` in the destination directory with
   `create_new`, so the name is known to be unused.
2. `fs::copy` into it, asserting the returned byte count equals the source length.
3. `restore_metadata` on the temp file, so it is published already final.
   `rename` does not touch the mtime of the inode it moves.
4. `sync_all()` on the temp file. On POSIX that is a read-only open followed by
   `fsync`. On Windows `sync_all` is `FlushFileBuffers`, which requires
   `GENERIC_WRITE` and rejects a read-only handle with `ERROR_ACCESS_DENIED`, so
   the file is opened for writing instead.
5. `fs::rename(temp, destination)`.
6. On POSIX, `fsync` each destination directory that received a file, once, after
   the walk.

The temp file is removed on drop unless it was published, so a failure at any
step leaves the previous destination file untouched. The temp file lives in the
destination directory because `rename` is only atomic within a filesystem.

Directory flushes are batched per directory rather than per file. A whole-tree
copy would otherwise pay one extra round trip per file, and a crash mid-run can
lose a rename, which resurfaces as a temp file the sweep cleans up.

`sync_parent_directory` tolerates only the errors that mean the filesystem cannot
flush a directory handle (`ENOTSUP`, `EINVAL`, `EBADF`, `EISDIR`,
`ErrorKind::Unsupported`); anything else fails the copy. Verified to work on both
CIFS and NTFS-3g.

On Windows the flush has a second consequence: `fs::copy` propagates
`FILE_ATTRIBUTE_READONLY` from source to destination, so a read-only source
produces a read-only temp that cannot be opened for writing. The same
clear-then-restore guard already used for the read-only destination is applied
around the flush, and generalised to serve both.

Temp files older than 24 hours are swept when a destination directory is entered.
The sweep matches the exact generated name shape, because the destination is a
share that is browsed by hand and a file that merely looks similar belongs to the
user. It is best-effort: a temp file we may not delete must not abort a backup.

## Alternatives considered

### Verify the copy against the source hash as it is written

Hash the bytes while copying and compare against the source manifest. This was
rejected: it validates the source-to-userspace path, not the server's storage. The
data can be read from a cache that is masking the loss, so a copy-time check
would pass on exactly the failure it is meant to catch. This is the reason
verification is a separate, later task rather than an assertion inside the copy.

### Re-copy and re-verify files that verification reports as corrupted

A repair loop would make the tool self-healing. Rejected for now: the read-back
is unavoidable, so it doubles the I/O of an already expensive operation, and the
re-verification has to be deferred to be meaningful anyway. Periodic full
verification plus manual repair is the current operating model.

### Per-file directory flush

Stronger guarantee: every rename is durable before the next file starts. Rejected
on cost — one extra round trip per file across a 132k-entry collection.

### A hand-rolled `io::copy` loop instead of `fs::copy`

Would give direct control of the destination handle. Rejected: `fs::copy` can use
a server-side copy when source and destination share a mount, and replacing it
means reimplementing permission propagation and the sparse-file handling that
comes with it.

### Treat a failed verification as unverified

Making `is_verified()` false when `errors > 0` would re-run verification on the
next start instead of latching a failure. Not part of this decision: it turns a
single failure into a full re-hash of the collection on every subsequent run,
which is a policy change rather than a copy-correctness fix.

## Consequences

- A file under its final name is complete and carries its final metadata, which
  is what the `SkipUnchanged` fast path already assumed.
- A failed copy no longer destroys the destination file it was replacing.
- A short `fs::copy` is reported instead of silently accepted.
- Each file costs one extra `create`, one extra `fsync`, and one `rename` against
  the destination, plus one directory `fsync` per directory.
- A run that dies mid-copy leaves a `.bh-tmp-` file behind. It is invisible to
  the walker and is swept after 24 hours.
- A source that is neither a regular file nor a symlink to one (a FIFO, a socket)
  still reaches `fs::copy`, which blocks on open for a FIFO. The length assertion
  is skipped for those rather than papering over the hang; this is pre-existing
  and unchanged.
- Correctness against a filesystem that acknowledges writes it never made is
  still the server's responsibility. This change makes a partial transfer
  impossible to mistake for a complete one; it cannot detect data the server lost
  after acknowledging it.
