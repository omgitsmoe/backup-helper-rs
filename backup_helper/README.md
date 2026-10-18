# backup_helper

A runner for reliable backups, which is particularly suited
for archiving to cold-storage: a declarative KDL
configuration describes which directories to protect and where to put them, and
each run hashes, copies and verifies the outstanding work.

The hashing, hash-file merging and verification come from the
[`checksum_helper`](../checksum_helper/README.md) crate; this crate is the
configuration, scheduling and copying layer on top of it.

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Configuration reference](#configuration-reference)
- [State file reference](#state-file-reference)
- [Reconcile semantics](#reconcile-semantics)
- [Tasks and scheduling](#tasks-and-scheduling)
- [Copy semantics](#copy-semantics)
- [Verification](#verification)
- [Log files](#log-files)
- [Progress output](#progress-output)
- [Interrupting a run](#interrupting-a-run)
- [Errors and exit codes](#errors-and-exit-codes)
- [Architecture decision records](#architecture-decision-records)
- [Development](#development)

## Install

The workspace is not published to crates.io; build or install it from the
checkout.

```bash
# build everything
cargo build --release

# run without installing
cargo run -p backup_helper -- --help

# install into ~/.cargo/bin
cargo install --path backup_helper
```

## Quick start

`backup_helper` has exactly two subcommands, and they are used in order.

1. `reconcile` merges a KDL configuration file into a state file (creating the
   state file on the first run). It copies nothing.
2. `start` runs the work the state file still lists as outstanding.

`backup.kdl`:

```kdl
disks {
    disk "main" {
        path "/mnt/main"
        mounted #true
    }
    disk "backup" {
        path "/mnt/backup"
        mounted #true
    }
}

source "/mnt/main/photos" {
    target "/mnt/backup/photos" {
        transfer_mode copy
        verify #true
    }
}
```

```bash
backup_helper reconcile backup.kdl --state state.json
backup_helper start --state state.json
```

For the source above, `start` performs three tasks and prints a summary:

```
========== TASK SUMMARY ==========
Ran: 3 | Successful: 3 | Errored: 0

Successful (3):
  [OK] 0: hash /mnt/main/photos
         Full log: "mnt_main_photos_SourceHash_2026-09-26T22-03-44.log"
  [OK] 1: copy /mnt/main/photos -> /mnt/backup/photos
         Totals: 1318 entries | 892 copied (1.2 TiB) | 412 skipped (38 GiB) | 14 directories | 0 ignored
  [OK] 2: verify /mnt/backup/photos
         Full log: "mnt_backup_photos_TargetVerify_2026-09-26T22-03-45.log"

Verify task 2: verify /mnt/backup/photos

========== VERIFY SUMMARY ==========
Total: 7 | OK: 7 | ERR: 0 | WARN: 0
✅ ALL FILES VERIFIED SUCCESSFULLY
```

Run `start` again and it reports `Ran: 0 | Successful: 0 | Errored: 0`: the state
file records that the source is hashed and the target is transferred and
verified, so nothing is scheduled. That is also what makes a crashed run
recoverable — reconcile whatever you changed in the config, then `start` again.

## Configuration reference

The configuration is [KDL](https://kdl.dev). There are two top-level node types:
`disks` and `source`. Everything else is a child of one of them.

> **Child nodes must be newline-separated.** On a single line, KDL reads
> `path "/mnt/main" mounted #true` as one node with two arguments, so the
> `mounted` child node never exists and parsing fails with
> `Missing mandatory child node 'mounted' for 'disk' on line N`. Put every node
> on its own line.

### `disks`

A disk is a mount location that the scheduler can reason about: it decides which
tasks may run in parallel, and it gates them on the disk being available. Every
source and every target path must live under a declared disk, otherwise
reconcile fails with `no declared disk matching path '...'` (the longest
matching path prefix wins, so nested disks are fine).

```kdl
disks {
    disk "main" {
        path "/mnt/main"
        mounted #true
    }
}
```

| Node | Type | Required | Meaning |
|---|---|---|---|
| `disk "<name>"` | positional string | yes | Identity of the disk across reconciles. Rename it and the state file gains a new disk. |
| `path` | positional absolute path | yes | Where the disk is mounted. Prefix match for source and target paths. |
| `mounted` | `#true` / `#false` | yes | `#true`: the disk is expected to be attached, and a task waits until `path` exists as a directory. `#false`: the disk is treated as permanently unavailable, so no task using it is ever scheduled. |

`mounted #false` is a declaration, not a probe. The tool cannot tell a mounted
network share from an unmounted mount point when the disks appear as
subdirectories of one share, so availability is declared instead of detected -
see [declared_mount_status.md](doc/adr/declared_mount_status.md).

### `source`

```kdl
source "/mnt/main/photos" {
    hash_file "/mnt/main/photos/photos.sha512"

    checksums {
        hash_type "sha256"

        files {
            allow {
                "**/*.jpg"
                "**/*.raw"
            }
            block {
                "**/*.tmp"
            }
        }

        checksum_files {
            allow {
                "**/*.cshd"
            }
            block {
                "**/*.md5"
            }
        }
    }

    target "/mnt/backup/photos" {
        transfer_mode copy
        verify #true
    }

    target "/mnt/offsite/photos" {
        transfer_mode copy
    }
}
```

| Node | Type | Required | Meaning |
|---|---|---|---|
| `source "<path>"` | positional absolute path | yes | Directory to protect. Must be a directory, and must be under a declared disk. |
| `hash_file` | positional absolute path | no | An existing checksum file to start from. `start` fills this in with the `.cshd` it generates; set it by hand only to adopt a collection that already exists. It has to live **inside** the source directory, because verification reads it from the target (see [Verification](#verification)). |
| `checksums` | node | no | How the source is hashed. See below. |
| `target "<path>"` | positional absolute path | yes (repeatable) | Where to copy the source. Must be under a declared disk. |

#### `checksums`

| Node | Type | Required | Meaning |
|---|---|---|---|
| `hash_type` | string | no, default `"sha512"` | `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512` - note the **underscore** in the SHA-3 names. |
| `files { allow {} block {} }` | glob lists | no | Which data files are hashed. |
| `checksum_files { allow {} block {} }` | glob lists | no | Which discovered checksum files are merged into the "most current" view that the new hash file is compared against. |

Glob semantics are the `PathMatcher` of `checksum_helper`: patterns are matched
against root-relative paths, an empty allow list means "everything", and a block
pattern always wins over an allow pattern. See
[its README](../checksum_helper/README.md#path-matching) for the details.

`hash_type` and the glob lists are only free to change while the source has no
`hash_file` yet - see [Reconcile semantics](#reconcile-semantics).

Note that the generated `.cshd` lives inside the source directory and is
therefore part of the source tree: it gets copied to the target (which is what
makes verification possible) and it is hashed as a data file on the next run. If
that noise bothers you, block it:

```kdl
checksums {
    files {
        block {
            "*.cshd"
        }
    }
}
```

#### `target`

| Node | Type | Required | Meaning |
|---|---|---|---|
| `target "<path>"` | positional absolute path | yes | Destination directory. |
| `transfer_mode` | `copy` or `sync` | yes | `copy` copies new and changed files. `sync` is parsed and stored but **not implemented**: a `sync` target is currently handled exactly like a `copy` target, and nothing is ever deleted at the target. |
| `verify` | `#true` / `#false` | no, default `#true` | Verify the target against the source checksum file after copying. |

A source may have any number of targets; each one is copied and verified
separately.

## State file reference

`reconcile` and `start` share a single JSON document (default `state.json`).
It is the only thing that carries progress between runs.

```json
{
  "version": 1,
  "disks": [
    { "name": "main", "path": "/mnt/main", "mounted": true },
    { "name": "backup", "path": "/mnt/backup", "mounted": true }
  ],
  "sources": [
    {
      "path": "/mnt/main/photos",
      "hash_file": "/mnt/main/photos/photos_2026-09-26T220344.cshd",
      "hash_log_file": "/home/me/mnt_main_photos_SourceHash_2026-09-26T22-03-44.log",
      "checksums": {
        "hash_type": "sha512",
        "checksum_files": { "allow": [], "block": [] },
        "all_files": { "allow": [], "block": [] }
      },
      "targets": [
        {
          "path": "/mnt/backup/photos",
          "transfer_mode": "Copy",
          "transferred": true,
          "verify": true,
          "verified": {
            "checked": 7,
            "errors": 0,
            "missing": 0,
            "crc_errors": 0,
            "log_file": "/home/me/mnt_backup_photos_TargetVerify_2026-09-26T22-03-45.log"
          },
          "disk": 1
        }
      ],
      "disk": 0
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `version` | State schema version. Only `1` is accepted; anything else is an `InvalidState` error. |
| `disks[].name` | Identity of the disk for reconcile. |
| `disks[].mounted` | The declared mount status from the last reconcile. |
| `sources[].path` | Identity of the source for reconcile. |
| `sources[].hash_file` | The collection the source is hashed against. Non-null means "hashing is done". |
| `sources[].hash_log_file` | Log of the hashing task that produced `hash_file`. |
| `sources[].checksums` | The options the next hashing task will use. |
| `targets[].path` | Identity of the target for reconcile. |
| `targets[].transferred` | True means "copying is done". |
| `targets[].verify` | Whether this target gets a verification task. |
| `targets[].verified` | Verification counts and log, or `null` while unverified. Its presence means "verification is done". |
| `disk` (on source and target) | Index into `disks`. Recomputed on every reconcile, so the order of the `disks` block may change freely. |

The file is rewritten by `reconcile` and after every `start`, including after an
interrupt. It is not meant to be hand-edited, though `start` trusts it: the
schedules above are derived from it.

## Reconcile semantics

`reconcile` is a merge, not a replace. It never throws away progress, because
the point of the state file is to know what is already done.

- Disks are matched by `name`, sources by `path`, targets by `path`.
- `hash_file`, `hash_log_file`, `transferred` and `verified` are carried over.
- New sources and targets are appended; targets that the config no longer lists
  are dropped **unless** they have been transferred; sources that the config no
  longer lists are dropped **unless** they have a `hash_file` or a transferred
  target.
- `checksums`, `transfer_mode` and `verify` are taken from the config.

Some changes are refused, because the recorded progress would stop making sense.
Reconcile then fails with a `ReconcileConflict` error and **writes nothing**:

| Conflict | Message fragment |
|---|---|
| `hash_type` of a source that already has a `hash_file` | `can't change source ... 'hash_type', since it already has a 'hash_file'` |
| Checksum globs of a source that already has a `hash_file` (only when the config actually sets globs) | `can't change source ... checksum options, since it already has a 'hash_file'` |
| `transfer_mode` of a transferred target | `transferred target ... may not have its 'transfer_mode' changed` |
| `verify` of an already verified target | `verified target ... may not have its 'verify' option changed` |
| Dropping a target that has been transferred | `reconciliation would drop transferred target ...` |
| Dropping a source that has a `hash_file` | `reconciliation would drop hashed source ...` |
| Dropping a source that has a transferred target | `reconciliation would drop source ... with transferred targets` |
| A source or target path that is not under a declared disk | `no declared disk matching path '...'` |

To change one of the refused things, drop the progress on purpose: remove the
`hash_file` field (re-hash the source) or the `transferred`/`verified` fields
(re-copy or re-verify the target) in the state file, then reconcile again.

## Tasks and scheduling

`start` turns the state into a task list and runs it:

| Task | Scheduled when | Reads | Writes |
|---|---|---|---|
| `SourceHash` | `hash_file` is null | the source directory and the discovered checksum files | a new `.cshd` in the source directory |
| `SourceToTargetCopy` | `transferred` is false | the source directory | the target directory |
| `TargetVerify` | `verify` is true and `verified` is null | the target directory and the copied `.cshd` | verification counts |

Dependencies: a copy needs the source hash task to be finished, and a verify
needs both the copy and the hash task. So the normal chain is
`SourceHash -> SourceToTargetCopy -> TargetVerify`, and a verify can start as
soon as its dependencies are done, even while other sources are still being
copied.

Scheduling rules:

- One worker thread per declared disk, which is the unit of parallelism: a task
  may only start when **all** disks it touches are idle. A copy touches the
  source and the target disk, so it occupies both for its duration and a copy to
  a disk that is already busy waits its turn.
- A task also waits until every disk it touches reports as mounted
  (`mounted #true` and the path exists as a directory).
- When several tasks are ready at the same time, the highest priority wins: copy
  is 1, hash and verify are 0. Copies keep the disks busy and
  verifications are less likely to run after a copy,
  which decreases the chance of hashing a cached state.
- A failed task fails every task that depends on it, which are then reported as
  failed without having run. Unrelated tasks keep going.
- If tasks are ready but none of them can run because no disk is available, the
  run stops with `ready tasks cannot run because their disks are unavailable`.
  With the default `mounted #true` that means a disk path does not exist.

`--force-overwrite` changes only the copy policy of pending copy tasks
(see [Copy semantics](#copy-semantics)). It cannot re-trigger a hash or a
verification on its own, since those are scheduled from the state file.

## Copy semantics

`copy_tree` walks the source and mirrors it into the target. It never deletes
anything: a file that exists at the target but not at the source stays.

Single-file transfers, metadata restoration, retries and temp cleanup use
[`copy_helper`](../copy_helper/README.md). Tree traversal, skip decisions and
progress reporting remain in `backup_helper`.

- **Directories** are created with `create_dir_all`; existing ones are kept.
  Directory mtimes are not restored.
- **Symlinks** are never followed. A symlink to a file is copied as a regular
  file carrying the target's content and metadata; a symlink to a directory is
  skipped.
- **Everything else** (fifos, sockets, devices) is handed to `fs::copy` like a
  regular file. Only regular files get the skip-if-unchanged test and the
  byte-count check.
- **Skip unchanged**: with the default policy, a destination file whose size and
  modification time both match the source is left alone. This is sound only
  because a destination file is never a partial transfer (see below).
  `--force-overwrite` copies every file a pending copy task walks, regardless.
- **Atomic publish**: the content goes into a sibling temp file named
  `.{name}.bh-tmp-{pid}-{attempt}`, the byte count is checked against the source
  length, the file is flushed, the source mtime (and permissions on Unix) are
  stamped onto it, and only then is it renamed onto the final name. A failure
  removes the temp file, so a destination never contains a plausible-looking
  partial file. A rename is only atomic within a filesystem, which is why the
  temp file lives next to the destination rather than in a staging area.
- **The stamp comes after the flush.** Flushing over CIFS re-opens the file for
  writing and the server bumps `LastWrite` when that handle closes, silently
  discarding the stamp. See [stamp_after_flush.md](doc/adr/stamp_after_flush.md).
- **Durability**: destination directories that received a file are flushed
  afterwards, batched per directory, so a published rename survives a crash.
- **Stale temp sweep**: once per destination directory, before writing into it,
  temp files older than 24 hours are removed. Anything not matching the
  `.{name}.bh-tmp-{pid}-{attempt}` shape is left alone, since a share is
  browsed by hand.
- **Retries**: transient I/O errors (timeouts, connection resets, sharing
  violations, stale network handles, and the platform-specific raw codes for
  those) are retried three times with 100 ms, 200 ms and 400 ms backoff.
- **Rejected up front**: a destination inside the source tree (or the other way
  round), a symlink anywhere in the destination path, and a short write.
- **Progress**: a copy reports counters rather than a line per file, and reports
  its totals when it finishes. See [Progress output](#progress-output).

## Verification

A verify task hashes the target and compares each file against the source
collection. It reads the copy of the source's `.cshd` in the target directory -
the file with the same name as `hash_file`, relative to the target root - so the
collection has to be inside the source directory, which is where `start` puts it.

Results per file, as they are counted in `targets[].verified`:

| Result | Meaning | `errors` | `missing` | `crc_errors` |
|---|---|---|---|---|
| `Ok` | hash matches | | | |
| `FileMissing` | the entry has no file at the target | +1 | +1 | |
| `Mismatch` | hash differs | +1 | | +1 |
| `MismatchSize` | size differs | +1 | | +1 |
| `MismatchCorrupted` | hash differs but the mtime matches the recorded one: silent corruption | +1 | | +1 |
| `MismatchOutdatedHash` | hash differs because the file was legitimately modified after the collection was written | +1 | | +1 |

Two things about this are worth stating plainly:

- **Verification findings do not fail the run.** A missing, corrupted or
  mismatching file is recorded and reported, but the task still succeeds, so
  `start` still exits 0. The counts in the state file and the log are how you
  find out; a scheduler that treats one damaged file as a reason to abandon every
  other copy would be worse than one that finishes and tells you.
- **An outdated hash is a warning, not damage.** The hash differs because the
  source moved on after the last hash pass, which is expected when the source
  changes between runs. It is counted as a crc error in the compact state
  counters, but the `VERIFY SUMMARY` block lists it separately under
  `Outdated hashes` and still reports success when nothing else failed.

The presence of `verified` in the state file means the target will not be
verified again on later runs, so the counts and the log path recorded by that
one run are the record you keep. To verify a target again, clear `verified` for
it in the state file.

## Log files

Each hashing and verification task writes a log file into the current working
directory of `start` (there is no option to change that):

```
<prefix>_SourceHash_<YYYY-MM-DDTHH-MM-SS>.log
<prefix>_TargetVerify_<YYYY-MM-DDTHH-MM-SS>.log
```

`<prefix>` is the absolute path of the hashed root with every run of
non-alphanumeric characters collapsed to a single `_`, trimmed, and cut to its
rightmost 120 characters, so `/mnt/main/photos` becomes
`mnt_main_photos`. Log paths are printed in the task summary and stored in the
state file (`hash_log_file`, `verified.log_file`).

A hash log holds one line per event followed by counts:

```
Root: "/mnt/main/photos"
[SKIP ] "raw/DSC0001.NEF" (unchanged, skipped)
[NEW  ] "raw/DSC0002.NEF"
[DEL  ] "raw/DSC0003.NEF"

Summary:
  unchanged: 0
  skipped: 1
  changed: 0
  corrupted: 0
  local newer than hash: 0
  new: 1
  removed: 1

Done.
```

A verify log holds the collection it used, one line per file, the counts, and
then the same `VERIFY SUMMARY` block that is printed to the terminal:

```
Checksum file: "/mnt/backup/photos/photos_2026-09-26T220344.cshd"
[OK        ] "/mnt/backup/photos/raw/DSC0001.NEF"
[ERR CORR  ] "/mnt/backup/photos/raw/DSC0002.NEF"

Summary:
  checked: 2
  errors: 1
  missing: 0
  checksum errors: 1
  outdated hashes: 0

========== VERIFY SUMMARY ==========
Total: 2 | OK: 1 | ERR: 1 | WARN: 0
❌ VERIFICATION FAILED

--- Corrupted files (1) ---
[ERR CORR  ] "/mnt/backup/photos/raw/DSC0002.NEF"

Done.
```

## Progress output

Progress goes to **stderr**; the task summary goes to **stdout**.

On a terminal, the live tasks are drawn as a block per running task - the whole
block area is cleared and redrawn as events arrive, and the blocks are wrapped to
the terminal width. The block is redrawn at most every 100 ms, since a copy
reports an event per walked entry:

```
0: hash /mnt/main/photos
      [NEW  ] "raw/DSC0002.NEF"
1: copy /mnt/main/photos
   -> /mnt/backup/photos
   892 copied (1.2 TiB) | 412 skipped | 94.2 MiB/s | elapsed 3:41
   raw/DSC0001.NEF
```

A hash and a verification report the file they are working on, one file per
event. A copy reports **counters** instead, because one line per entry would put
one line per file on the screen and rewrite all of them 100 times a second. The
counters come from the byte count `fs::copy` returns and the length the
skip-if-unchanged test has already compared, so they cost no extra work.

There is no percentage and no remaining time on a copy: the source is not walked
a second time to count it first. Such a pass would double the metadata calls the
walk already makes, which costs the most exactly when the copy has the least to
do - a re-copy where one file changed - and against a source on a network
filesystem it costs a round trip per entry. The rate is left out of the counters
row for the first second, where an average over a handful of files says nothing.

When a task finishes, its block is printed once and stays, with `done` or
`failed: <error>` as the last line, followed by the totals of the task: the
`VERIFY SUMMARY` for a verification, and for a copy

```
Totals: 1318 entries | 892 copied (1.2 TiB) | 412 skipped (38 GiB) | 14 directories | 0 ignored
```

A copy writes no log file, so those totals are the whole record of what it did.
They are also printed in the task summary on stdout, under the `[OK]` line of the
copy.

Without a terminal there is no block to redraw, so only those totals are written
to stderr:

```
Totals: 1318 entries | 892 copied (1.2 TiB) | 412 skipped (38 GiB) | 14 directories | 0 ignored

========== VERIFY SUMMARY ==========
Total: 1318 | OK: 1318 | ERR: 0 | WARN: 0
✅ ALL FILES VERIFIED SUCCESSFULLY
```

The per-file detail of a hash and a verification is in their log files, and a
copy has none because its progress is the block above.

## Interrupting a run

Ctrl-C is handled in three stages:

1. **First Ctrl-C** requests cancellation: no new task is started, running tasks
   are allowed to finish, the state is written, and the process exits 1 with
   `Error: Interrupted` (`UserInterrupt` in its `Display` form). Since the state
   is written, the next `start` continues with the tasks that had not run.
2. **Second Ctrl-C** only prints a notice; nothing else happens.
3. **Third Ctrl-C** persists the state under the scheduler lock (so the snapshot
   cannot contain half-applied results) and exits 130.

## Errors and exit codes

`main` returns a `Result`, so a failure prints the error on stderr as
`Error: <Debug of the error>`, for example `Error: ReconcileConflict("...")`, and
exits 1. The error variants are:

| Variant | Raised by |
|---|---|
| `IoError` | a missing config, a missing state file for `start`, an unreadable or unwritable file |
| `InvalidConfig` | a KDL syntax error or an invalid node/argument, with the line number |
| `InvalidState` | the state file is not valid JSON or has an unsupported `version` |
| `ReconcileConflict` | one of the refused changes listed above |
| `SchedulerError` | a task could not be scheduled, e.g. unavailable disks, or a task failed |
| `ChecksumHelper` | hashing or verification failed inside `checksum_helper` |
| `CopyError` | a copy failed: overlapping paths, a symlinked destination component, a short write, a failed publish |
| `TaskError` | a task was invoked with a source that is not a directory |
| `Interrupted` | Ctrl-C (printed as `UserInterrupt`) |

A failed `start` still prints the task summary and still writes the state, so
the failures and the completed work are both visible.

## Development

```bash
cargo test -p backup_helper            # unit and CLI tests
cargo build -p backup_helper           # the binary
just test                              # the whole workspace, with output
```

- Unit tests live next to the code they cover.
- `tests/cli.rs` drives the built binary end to end: it reconciles a config in a
  temp directory, patches `mounted` into the state, runs `start`, and asserts on
  the summary, the log names and the resulting state.
