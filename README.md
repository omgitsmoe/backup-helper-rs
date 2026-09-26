# backup-helper-rs

A Rust workspace for checksumming and reliably backing up directories
in a way that is particularly suited for cold-storage: a backup tool,
the checksum library it is built on, and a standalone CLI for that library.

## Crates

| Crate | Kind | Purpose | README |
|---|---|---|---|
| `backup_helper` | binary | Configuration-driven backup runner: hash, copy and verify each configured source, keeping its progress in a state file. | [backup_helper/README.md](backup_helper/README.md) |
| `checksum_helper` | library | Checksum file discovery, most-current merging, incremental hashing and verification. | [checksum_helper/README.md](checksum_helper/README.md) |
| `checksum_helper_cli` | binary | Command line front end for the library. | [checksum_helper_cli/README.md](checksum_helper_cli/README.md) |

`backup_helper` depends on `checksum_helper`; the CLI is an alternative front end
for the same library.

## How backup_helper works

A run has two steps, and they are always used in this order.

1. **`reconcile`** merges a KDL configuration file into a state file, creating it
   on the first run. It describes the disks, the sources to protect and the
   targets to copy them to, and it copies nothing.
2. **`start`** runs the work the state file still lists as outstanding, prints a
   summary and writes the state back.

```kdl
// backup.kdl
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

For that source, `start` runs three tasks and reports them in its summary:

```
  [OK] 0: hash /mnt/main/photos
  [OK] 1: copy /mnt/main/photos -> /mnt/backup/photos
  [OK] 2: verify /mnt/backup/photos
```

**The state file is the memory.** It records the checksum file of each source and
whether each target has been transferred and verified, so a second `start` runs
nothing, and a run that was interrupted or crashed continues where it stopped.
That is also why `reconcile` refuses to change a few things once progress exists:
you cannot change the hash algorithm of a source that is already hashed, or drop
a target that has already been copied.

**Each source becomes a task chain.** Hash the source, copy it to each target,
then verify the target against the copy of the source's checksum file. Tasks
depend on each other, and a task that fails also fails everything waiting on it,
while unrelated tasks keep running.

**Disks are the unit of parallelism.** A disk is a mount location declared in the
configuration, and the tool will not guess.
There is one worker per disk and a task may only start when
every disk it touches is idle and mounted, so two copies never fight over the
same disk, and a copy holds both the source and the target disk for its
duration. When several tasks are ready, copies win over hashes and verifications.

**Copying is conservative and crash-safe.**

- A destination file whose size and modification time match the source is left
  alone, so re-running a backup copies nothing (can be changes using
  `--force-overwrite`).
- Transient network I/O errors are retried with a short backoff, temp files left
  by a dead run are swept, and nothing is ever deleted at the target.

**Verification is the point.** After copying, the target is hashed again and
compared against the source's collection.
Findings are recorded in the state file and the log rather than failing the run,
so one damaged file does not abandon every other copy.

Details, including the full configuration reference, the state file schema, the
scheduling rules and the copy guarantees:
[backup_helper/README.md](backup_helper/README.md).

## checksum_helper at a glance

The library discovers existing checksum files (`.cshd`, `.md5`, `.sha*`, ...),
merges them into one up-to-date view where the newest file wins, hashes only what
is new or changed, reports what has no checksum at all, and verifies a collection
with per-file diagnostics.

```bash
# Hash what is new or changed below a root, writing a new .cshd
checksum_helper_cli incremental /mnt/backups/photos

# Merge every discovered checksum file into one
checksum_helper_cli build /mnt/backups/photos

# What is not covered by any checksum?
checksum_helper_cli missing /mnt/backups/photos

# Hash only the files that have no checksum yet
checksum_helper_cli fill /mnt/backups/photos

# Verify, and fail if anything is missing, changed or corrupted
checksum_helper_cli verify root /mnt/backups/photos
```

- Commands, options and exit codes:
  [checksum_helper_cli/README.md](checksum_helper_cli/README.md)
- The `.cshd` and single-hash file formats, the library API and the glob
  semantics: [checksum_helper/README.md](checksum_helper/README.md)

```
# version 1
1758938624.512345,1024,sha512,cf83e1357eefb8bd... relative/path/to/file
```

Each line is `<mtime>,<size>,<hash type>,<hex hash> <path relative to the file>`,
written in lexical order so two runs over an unchanged tree produce
byte-identical files.

## Repository layout

```
backup_helper/          the backup binary, with its ADRs in doc/adr
checksum_helper/        the checksum library, with its ADRs in doc/adr
checksum_helper_cli/    the CLI around the library
```

Each crate has its own README; the ADRs next to them record why the tricky parts
work the way they do, and are worth reading before changing the copy, the state
file or the checksum format.

## Development

```bash
just test                  # the whole workspace, with output
cargo test --workspace     # the same, without the wrapper
cargo build                # all three crates
```

Unit tests live next to the code they cover. `backup_helper/tests/cli.rs` and
`checksum_helper_cli/tests/e2e.rs` drive the built binaries end to end against
temp directories. The workspace is not published to crates.io; build or install a
binary with `cargo install --path <crate>`.
