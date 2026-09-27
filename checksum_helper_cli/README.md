# checksum_helper_cli

The command line front end for [`checksum_helper`](../checksum_helper/README.md):
discover existing checksum files, merge them, hash what is new or changed, find
what has no checksum yet, and verify a tree against a collection.

The binary is called `checksum_helper_cli`. It is a thin layer: every command
maps onto one or two methods of `ChecksumHelper`, so anything the CLI can do is
doable from the library, and vice versa.

## Contents

- [Install](#install)
- [Commands](#commands)
- [Output files](#output-files)
- [Exit codes](#exit-codes)
- [Progress output](#progress-output)
- [Development](#development)

## Install

Not published to crates.io; build or install it from the checkout.

```bash
cargo install --path checksum_helper_cli
cargo run -p checksum_helper_cli -- --help
```

```
Usage: checksum_helper_cli [OPTIONS] <COMMAND>

Commands:
  incremental  Creates an incremental checksum file
  build        Creates one checksum file for the given root directory where all
               contained checksums are the most current hashes found in matched
               checksum files
  missing      Check for files that don't have a checksum yet
  fill         Generate checksums for files that don't have one yet
  move         Move a hash file modifying the relative paths inside accordingly
  verify       Subcommands for all verify operations

Options:
  -v, --verbose...  Verbosity level (-v, -vv, -vvv)
  -h, --help        Print help
  -V, --version     Print version
```

## Commands

Every command takes a root directory (except `verify file` and `move`). The
options fall into four groups, and they are the same everywhere they appear:

| Group | Options | Applies to |
|---|---|---|
| Hashing | `--hash-type`, `--no-include-unchanged`, `-s`/`--skip-unchanged`, `--periodic-write-interval-seconds` | `incremental`, `fill` |
| Discovery | `--discover-hash-files-depth`, `--keep-deleted`, `--hash-allow`, `--hash-block` | every command that merges discovered checksum files |
| Data files | `--all-allow`, `--all-block` | `incremental`, `fill` |
| Verification | `--verify-allow`, `--verify-block` | `verify file`, `verify latest`, `verify root` |

`--hash-allow`/`--hash-block` filter the *checksum files* that are discovered;
`--all-allow`/`--all-block` filter the *data files* that are hashed and
verified; `--verify-allow`/`--verify-block` filter the collection entries that
are verified. All of them take one or more glob patterns, and block always wins
over allow. See [Path matching](../checksum_helper/README.md#path-matching).

### `incremental` - hash what is new or changed

Discovers checksum files, compares the tree against the merged result and writes
a new collection holding the new and changed files (unchanged ones too, unless
`--no-include-unchanged`).

```bash
# Basic: discover hash files, hash new/changed files, write output
checksum_helper_cli incremental /mnt/backups/photos

# Use SHA-256 instead of the default SHA-512
checksum_helper_cli incremental /mnt/backups/photos --hash-type sha256

# Trust a matching mtime and skip reading the file entirely
checksum_helper_cli incremental /mnt/backups/photos --skip-unchanged

# Output only the new and changed files
checksum_helper_cli incremental /mnt/backups/photos --no-include-unchanged

# Flush partial results every 300 seconds so an interrupted run keeps its work
checksum_helper_cli incremental /mnt/backups/photos \
    --periodic-write-interval-seconds 300

# Only look at checksum files at most one level deep
checksum_helper_cli incremental /mnt/backups/photos \
    --discover-hash-files-depth 1

# Only hash images, skip everything else
checksum_helper_cli incremental /mnt/backups/photos \
    --all-allow '**/*.jpg' --all-allow '**/*.raw'

# Keep caches and temporary files out of the collection
checksum_helper_cli incremental /mnt/backups/photos \
    --all-block 'cache/**' --all-block 'tmp/**'

# Ignore .md5 files when building the most-current view
checksum_helper_cli incremental /mnt/backups/photos --hash-block '*.md5'
```

With `--periodic-write-interval-seconds`, the file is written while the run is in
progress; without it, only at the end.

### `build` - merge every discovered checksum file into one

```bash
# Merge every .cshd, .md5, .sha* etc. below the root into one file
checksum_helper_cli build /mnt/backups/docs

# Only consider checksum files in the root itself
checksum_helper_cli build /mnt/backups/docs --discover-hash-files-depth 0

# Keep entries for files that no longer exist on disk
checksum_helper_cli build /mnt/backups/docs --keep-deleted
```

### `missing` - what has no checksum at all

Merges the discovered checksum files, compares them with everything under the
root and reports the files and directories that nothing covers. A directory
without any checksum is reported as a directory; its files are not listed
individually.

```bash
# List all files and directories without a checksum
checksum_helper_cli missing /mnt/backups/docs

# Only look at .cshd files when building the merged view
checksum_helper_cli missing /mnt/backups/docs --hash-allow '**/*.cshd'

# Only consider checksum files in the root itself
checksum_helper_cli missing /mnt/backups/docs --discover-hash-files-depth 0
```

`missing` writes nothing and, unlike `fill`, it has no data-file filter: it
reports every file and directory that no discovered checksum file covers. Use
`--hash-allow`/`--hash-block` to control which checksum files it takes into
account, or `fill` when you want the same filtering as `incremental` and a
collection as output.

### `fill` - hash everything that has no checksum

Same discovery and filtering as `incremental`, but the output contains only the
files that had no checksum yet, so it can be applied to a tree that is already
mostly covered without rehashing everything.

```bash
# Hash all unprotected files into a new collection
checksum_helper_cli fill /mnt/backups/docs

# Use MD5 for speed on a large dataset
checksum_helper_cli fill /mnt/backups/docs --hash-type md5

# Only fill checksums for source files
checksum_helper_cli fill /mnt/backups/project \
    --all-allow '**/*.rs' --all-allow '**/*.py' --all-allow '**/*.js'
```

`fill` takes the same options as `incremental`, because it shares the argument
parser, but `--no-include-unchanged` and `--skip-unchanged` have no effect here:
the output of `fill` is by definition only the files that had no checksum.

### `verify file` - check one checksum file

The paths in the file are resolved relative to the directory holding it.

```bash
# Verify all entries in a specific .cshd
checksum_helper_cli verify file /mnt/backups/docs/checksums_2024-09-28.cshd

# Only verify .txt files
checksum_helper_cli verify file /mnt/backups/docs/checksums_2024-09-28.cshd \
    --verify-allow '**/*.txt'
```

### `verify latest` - check the newest checksum file in a directory

Scans the directory and verifies the entries of the checksum file with the most
recent modification time. The scan is **not** recursive and only considers files
with a known checksum file extension, so unlike `verify root` the entries of
several checksum files are never merged. Use `verify root` to merge and verify a
whole tree.

```bash
# Verify the newest .cshd in this directory
checksum_helper_cli verify latest /mnt/backups/docs

# Only verify .docx files
checksum_helper_cli verify latest /mnt/backups/docs \
    --verify-allow '**/*.docx'
```

The command fails if the directory holds no checksum file, or if the path is not
a directory.

### `verify root` - discover, merge, then verify

```bash
# Discover every checksum file below the root, merge, then verify everything
checksum_helper_cli verify root /mnt/backups

# Only verify .docx and .pdf files
checksum_helper_cli verify root /mnt/backups \
    --verify-allow '**/*.docx' --verify-allow '**/*.pdf'
```

All verify commands end with a summary:

```
========== VERIFY SUMMARY ==========
Total: 7 | OK: 5 | ERR: 1 | WARN: 1
❌ VERIFICATION FAILED

--- Missing files (1) ---
[ERR MISS  ] "docs/old.md"

--- Outdated hashes (1) ---
[WARN STALE] "docs/new.md"
```

When nothing failed, the summary is a single line instead of the failure
breakdown:

```
========== VERIFY SUMMARY ==========
Total: 7 | OK: 7 | ERR: 0 | WARN: 0
✅ ALL FILES VERIFIED SUCCESSFULLY
```

The five failure classes are the ones of
[`VerifyResult`](../checksum_helper/README.md#verification-results): a missing
file, a hash mismatch, a size mismatch and a corrupted file are errors, while an
outdated hash - a file modified after the collection was written - is only a
warning.

## Output files

`incremental`, `fill` and `build` write a `.cshd` into the root directory. The
name is `<root directory name>_<timestamp>.cshd`, except `fill`, which uses
`<root directory name>_missing_<timestamp>.cshd`, with the timestamp as
`%Y-%m-%dT%H%M%S` in local time. An existing file is never overwritten, so a
collection is always a new file.

The path of the written file is printed at the end of the command:

```
Wrote collection at: "/mnt/backups/docs/docs_2026-09-26T220344.cshd"
```

The file format is documented in the
[library README](../checksum_helper/README.md#file-formats).

## Exit codes

| Code | When |
|---|---|
| 0 | The command succeeded. For `verify`, this includes a run with only warnings. |
| 1 | The command failed: an invalid glob, an I/O error, or findings. |
| 2 | The command line itself was wrong (clap: unknown flag, missing argument). |

`missing` exits 1 when it found anything without a checksum, and `verify` exits
1 when a file was missing, mismatched, of the wrong size or corrupted. An
outdated hash alone still exits 0.

## Progress output

Everything the tool prints goes to **stdout**; only the final error message goes
to stderr.

Per-event lines are printed as they happen, one line per file:

```
[MERGE] "photos_2026-09-20.cshd"
[READ ] "raw/DSC0001.NEF"
[OK   ] "raw/DSC0002.NEF" unchanged
[SKIP ] "raw/DSC0003.NEF" (unchanged, skipped)
[CHG  ] "raw/DSC0004.NEF" modified
[NEW  ] "raw/DSC0005.NEF"
[DEL  ] "raw/gone.NEF"
Done.
```

`verify` uses `[VERIFY] (  12/ 500) "path"` and a `[PROG ] bytes` line per file,
followed by a result line: `[OK        ]`, `[ERR MISS  ]`, `[ERR HASH  ]`,
`[ERR SIZE  ]`, `[ERR CORR  ]` or `[WARN STALE]`.

On a terminal, one line is additionally redrawn in place at most ten times a
second - either the counters during discovery,

```
hash files: 3 (+1 ign) | missing: 0 | files: 500
```

or the read/hash progress of the current file:

```
[READ ] DSC0001.NEF      12345/ 8388608 bytes
[HASH ] DSC0001.NEF        1024/ 8388608 bytes (  0.0%)
```

Without a terminal those lines are never drawn - a `\r` cannot be redrawn in a
file - and each phase ends with the exact totals instead:

```
Totals: hash files: 3 (+1 ign), filtered missing: 0, files: 500
```

`-v` additionally prints `[MISS ] "path"` for every entry that was dropped from
the most-current view because the file is gone, which is otherwise only a
counter. `-vv` and `-vvv` behave like `-v`.

## Development

```bash
cargo test -p checksum_helper_cli
cargo build -p checksum_helper_cli
just test                              # the whole workspace, with output
```

- Unit tests live next to the code they cover.
- `tests/e2e.rs` runs the built binary against a temp tree and asserts on the
  exit code, the written collection and the reported summary;
  `tests/common.rs` holds the helpers.
