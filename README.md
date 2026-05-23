# checksum-helper

A Rust library and CLI for making checksum operations practical in
real-world backup workflows.

## Features

- **Incremental checksumming** — Scan a directory, compare files against
  the most recent known checksums, and produce a `.cshd` file containing
  only new or changed files. Optionally skip files whose mtime and hash
  match (`--skip-unchanged`) or still include them
  (`--include-unchanged`).
- **Most-current merging** — Automatically discover all checksum files
  (`.cshd`, `.md5`, `.sha*`, etc.) under a root directory and merge them
  into a single up-to-date view. When multiple files cover the same
  path, the entry with the newest file mtime wins.
- **Missing file detection** — Find files and directories that have no
  checksum coverage at all, so you know exactly what's unprotected.
- **Fill missing** — Generate checksums for every file that doesn't
  already have one, writing them into a new timestamped `.cshd` file.
- **Verification** — Verify every entry in a checksum collection against
  the live filesystem, with detailed diagnostics: `Ok`, `Mismatch`,
  `MismatchSize`, `MismatchCorrupted` (hash differs but mtime matches —
  file likely bit-rotted), and `MismatchOutdatedHash` (hash differs
  because file was legitimately modified).
- **Glob-based path filtering** — Allow/block lists to include or
  exclude files by glob pattern, consistently applied across discovery,
  hashing, and verification.
- **Multiple hash algorithms** — MD5, SHA-1, SHA-2 (224/256/384/512),
  SHA-3 (224/256/384/512), BLAKE2.
- **Periodic flush** — During long incremental runs, write partial
  results to disk at configurable intervals to avoid losing progress.

## CLI Usage

```
checksum-helper <COMMAND>

COMMANDS:
  incremental  Walk ROOT, hash new/changed files, write a .cshd
  build        Merge all hash files under ROOT into one .cshd
  missing      List files/dirs without any checksum coverage
  fill         Hash all files lacking checksums, write a .cshd
  verify file  Verify entries in a single .cshd file
  verify root  Discover all hash files, merge, then verify
  move         Relocate a .cshd's internal paths (TODO)
```

### `incremental` — hash only what's new or changed

```bash
# Basic: discover hash files, hash new/changed files, write output
checksum-helper incremental /mnt/backups/photos

# Use SHA-256 instead of the default SHA-512
checksum-helper incremental /mnt/backups/photos --hash-type sha256

# Skip files whose mtime matches (assume unchanged, skip hashing entirely)
checksum-helper incremental /mnt/backups/photos --skip-unchanged

# Include unchanged files in the output too (not just new/changed)
checksum-helper incremental /mnt/backups/photos --include-unchanged

# Flush partial results every 300 seconds to avoid losing progress
checksum-helper incremental /mnt/backups/photos \
    --periodic-write-interval-seconds 300

# Only consider hash files at most 1 level deep
checksum-helper incremental /mnt/backups/photos \
    --discover-hash-files-depth 1

# Only hash files matching *.jpg or *.raw, skip everything else
checksum-helper incremental /mnt/backups/photos \
    --all-allow '*.jpg' --all-allow '*.raw'

# Block certain directories from being hashed
checksum-helper incremental /mnt/backups/photos \
    --all-block 'cache/**' --all-block 'tmp/**'
```

### `build` — merge all existing checksum files into one

```bash
# Merge every .cshd, .md5, .sha* etc. under /mnt/backups/docs into one file
checksum-helper build /mnt/backups/docs

# Only look at hash files in the root (don't recurse into subdirs)
checksum-helper build /mnt/backups/docs --discover-hash-files-depth 0

# Exclude .md5 files from the merge, only use .cshd and .sha512
checksum-helper build /mnt/backups/docs \
    --hash-block '*.md5'
```

### `missing` — see what isn't covered by any checksum

```bash
# List all files and directories without a checksum
checksum-helper missing /mnt/backups/docs

# Only care about missing checksums for images
checksum-helper missing /mnt/backups/docs \
    --all-allow '*.png' --all-allow '*.jpg'

# Ignore certain directories when checking
checksum-helper missing /mnt/backups/docs \
    --all-block 'node_modules/**' --all-block '.git/**'
```

### `fill` — hash everything that's missing a checksum

```bash
# Hash all unprotected files, write them to a new timestamped .cshd
checksum-helper fill /mnt/backups/docs

# Use MD5 for speed on a large dataset
checksum-helper fill /mnt/backups/docs --hash-type md5

# Only fill checksums for source files
checksum-helper fill /mnt/backups/project \
    --all-allow '*.rs' --all-allow '*.py' --all-allow '*.js'
```

### `verify file` — check a single checksum file against disk

```bash
# Verify all entries in a specific .cshd
checksum-helper verify file /mnt/backups/docs/checksums_2024-09-28.cshd

# Only verify .txt files
checksum-helper verify file /mnt/backups/docs/checksums_2024-09-28.cshd \
    --verify-allow '*.txt'
```

### `verify root` — merge all hash files, then verify everything

```bash
# Discover every hash file under /mnt/backups, merge into one view, verify all
checksum-helper verify root /mnt/backups

# Only verify .docx and .pdf files
checksum-helper verify root /mnt/backups \
    --verify-allow '*.docx' --verify-allow '*.pdf'
```

## Common options

| Flag | Description |
|---|---|
| `--hash-type <ALGO>` | Hash algorithm (sha512, sha256, sha1, md5, etc.) |
| `--discover-hash-files-depth <N>` | Limit recursive discovery of hash files |
| `--keep-deleted` | Retain entries for files that no longer exist on disk |
| `--hash-allow/--hash-block <GLOB>` | Filter which hash files are discovered |
| `--all-allow/--all-block <GLOB>` | Filter which data files are hashed/verified |
| `--verify-allow/--verify-block <GLOB>` | Filter which entries to verify (verify only) |

## File Formats

### `.cshd` (custom format)

```
# version 1
1735689600,1024,sha512,abc123def...  relative/path/to/file
```

Each line: `<mtime_epoch>,<size_bytes>,<hash_algo>,<hex_hash>  <relative_path>`

### Single-hash files (`.md5`, `.sha256`, etc.)

Standard `<hash>  <path>` or `<hash> *<path>` format, auto-detected by extension.

## Library Usage

The core is the `checksum_helper` crate. The central type is
`ChecksumHelper`, which ties together path management (`FileTree`), hash
storage (`HashCollection`), directory walking (`Gather`), and glob
filtering (`PathMatcher`).

```rust
use checksum_helper::ChecksumHelper;

let ch = ChecksumHelper::new("/path/to/root")?;

// Incremental: hash only new/changed files
ch.incremental(&mut progress_reporter)?;

// Merge all hash files into one current collection
ch.with_most_current(&mut reporter, |ch, collection| {
    ch.write_collection(collection)?;
    Ok(())
})?;

// Find files without checksums
let missing = ch.check_missing(&mut reporter)?;
```

## Installation

```bash
cargo install --path checksum_helper_cli
```

## Development

```bash
cargo test          # run all tests
cargo build         # build both library and CLI
```
