# Stamp the destination after flushing it

Amends steps 3 to 5 of [atomic_destination_publish.md](atomic_destination_publish.md).
The temp file, the rename and the directory flushes are unchanged; only the order
of the file flush and the metadata stamp changes.

## Context

The atomic publish stamps the source mtime onto the temp file, flushes it, and
renames it onto the final name. On a CIFS destination that order does not hold.

Every file copied to the NAS came out with `mtime == ctime` equal to the moment
its last write completed, instead of the source mtime. The content was correct, so
nothing was reported: `metadata_matches` never matched, so the next run copied the
file again, and the hash pass could not skip it either, so the next run hashed it
again. A run against the collection reported `[READ ]` followed by `[OK   ]
unchanged` for files that had not changed at all.

Bisected to the commit range: `b1851cf3` is fine, `4c6c6c0` ("publish copied files
by renaming a complete temp file") breaks it. That commit added the temp file, the
file flush and the rename, so the stamp is no longer the last thing that happens
to the file. The only new operations between the stamp and the end of the copy are
the flush and the rename.

No local test can see this. On ext4, btrfs and tmpfs neither a flush nor a rename
touches the mtime of the file, so `copy_tree_preserves_file_mtime` passed against
the same code that lost every mtime on the share.

### What the probes showed

Both probes ran on the CIFS mount of the NAS (`//192.168.178.30/data`, mounted with
`actimeo=1`, `cache=strict`, `nounix`), in the `data` dataset. Each case writes
1 MiB, stamps the file to 2020-01-01 with `touch -d` (the same syscall as
`filetime::set_file_mtime`), applies the operations under test, and stats the
result.

```
A stamp                        -> 2020-01-01  kept
B stamp + fsync                -> 2020-01-01  kept
C stamp + rename               -> 2020-01-01  kept
D stamp + fsync + rename       -> 2026-09-26 21:37:04  lost
```

Neither operation alone loses the stamp; the combination does. That reading is
misleading, because the mount has `actimeo=1`: a `stat` that follows our own
`setattr` within the attribute-cache window is answered from the client cache,
which holds the value that was just set. A second probe with a two second pause
before every `stat`, so the cache is stale and the client has to ask the server:

```
1 fsync, then stat:            2020-01-01     client cache, lying
1 same file after 2s:          2026-09-26     server truth
2 stamp after fsync:           2020-01-01
3 fsync -> stamp -> rename:    2020-01-01
4 stamp -> rename:             2020-01-01
```

The flush loses the stamp and the rename does not. The flush is the server's doing:
a flush needs write access, so the client re-opens the file for writing, and the
server updates LastWrite when that handle closes. The probes pin that effect, not
the exact code path in either the client or the server. The client does not see
it, because its attribute cache still holds the value we set until `actimeo`
expires, which is why the loss only showed up in a later run. `rename` opens the
file for delete access only and preserves the mtime (cases 3 and 4).

This is not platform-specific. The Windows flush opens the file for writing by
construction, because `FlushFileBuffers` rejects a read-only handle, so a Windows
client against the same share should hit the same server behaviour. That has not
been verified from Windows.

## Decision

Flush first, stamp second, rename third:

1. `fs::copy` into the temp file, asserting the returned byte count (unchanged).
2. `sync_file` on the temp file (unchanged, just earlier).
3. `restore_metadata` on the temp file.
4. `fs::rename` onto the final name (unchanged).
5. `fsync` on every destination directory that received a file, after the walk
   (unchanged).

The stamp is the last attribute set on the inode before the name points at it, and
nothing after it opens the file for writing.

No read-back assertion was added. It would have to stat the destination after the
rename and compare the mtime, but on a share with an attribute cache that
comparison reads the client's own cache rather than the server. In the failing
case a stat on the freshly renamed name happened to revalidate, but that is a
property of the client cache, not a guarantee, so the check would be a net for a
failure it cannot reliably see. The order is the guarantee; a destination that
drops the stamp outright is caught by the next run copying the file again.

## Alternatives considered

### Stamp after the rename

Rejected: it moves the stamp past the only operation that could still lose it, but
it also reintroduces the window that `atomic_destination_publish.md` exists to
close. A crash between the rename and the stamp leaves a complete file under the
final name whose mtime is not the source's. Since the rename is innocent
(probe cases 3 and 4), the window buys nothing.

### Revert to writing the final destination path

Rejected: that gives up the guarantee of the previous ADR. A partial transfer
under the final name is indistinguishable from a complete one.

### Drop the file flush on network destinations

Rejected: the flush is what makes the write acknowledgement mean something, which
is the reason for publishing through a temp file at all. Its side effect on the
mtime is a consequence of the server, not of the flush's purpose.

### Verify the stamp and fail the copy when it did not stick

Rejected: see above. A check that cannot see the failure is worse than none,
because it invites trusting it.

### Warn and keep the file when the stamp did not stick

Rejected: that is the silent failure mode this decision exists to end. The
destination looks fine and the only symptom is a backup that re-copies and
re-hashes everything on every run.

### Pin the call order with a test

Rejected: the invariant, that nothing which opens the file for writing may follow
the stamp, is not observable without injecting a seam into the copy path. The seam
would assert the order of two adjacent calls rather than any behaviour, which is
why the existing suite passed while the backup lost every mtime. The regression
test is the share: copy a file, then compare the destination's mtime against the
source's.

## Consequences

- Files copied to a CIFS destination keep the source mtime, so `metadata_matches`
  matches on the next run and the hash pass can skip the file instead of reading
  it again.
- The stamp is no longer covered by the file flush. The flush is what makes the
  content durable before the name points at it; the stamp is a `SET_INFO` that the
  server commits before it returns, so a crash in the next instant can lose the
  stamp. That costs one re-copy of that file and nothing else.
- A step added after the stamp must not open the file for writing, on any
  destination. This is the whole content of the decision.
- On a share with an attribute cache, the destination's mtime is not trustworthy
  for up to `actimeo` after the copy. A concurrent run comparing mtimes can see the
  pre-stamp value in that window and copy the file unnecessarily.
- Files copied by a build with the previous order keep the wrong mtime until they
  are copied again or their metadata is restored out of band; the hash file records
  whatever it read, so one extra hashing pass follows.
