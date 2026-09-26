# checksum_helper

The hashing library of this workspace: it discovers existing checksum files,
merges them into a single up-to-date view, hashes only what is new or changed,
and verifies files against a collection with diagnostics that distinguish
silent corruption from a legitimately modified file.

It is used by [`backup_helper`](../backup_helper/README.md), which drives the
incremental and verify passes, and by
[`checksum_helper_cli`](../checksum_helper_cli/README.md), which exposes them as
a command line tool.

## Contents

- [Features](#features)
- [File formats](#file-formats)
- [Library usage](#library-usage)
- [Options](#options)
- [Path matching](#path-matching)
- [Verification results](#verification-results)
- [Entry order](#entry-order)
- [Errors](#errors)
- [Architecture decision records](#architecture-decision-records)
- [Development](#development)

## Features

- **Incremental checksumming** - compare a directory against the most recent
  known checksums and produce a collection containing only new or changed files.
  Unchanged files are kept by default. Files whose recorded mtime matches the
  file on disk can be skipped without reading them at all.
- **Most-current merging** - discover all checksum files below a root
  (`.cshd`, `.md5`, `.sha*`, ...) and merge them into one view. When several
  files cover the same path, the entry from the file with the newest mtime wins.
  A file with no recorded mtime counts as older than any with one.
- **Missing file detection** - report files and directories that no discovered
  checksum file covers, so it is clear what is unprotected.
- **Fill missing** - hash everything that has no checksum yet and return it as a
  new collection.
- **Verification** - check every entry of a collection against the live
  filesystem with per-file diagnostics (see
  [Verification results](#verification-results)).
- **Glob filtering** - allow/block lists applied consistently to discovered
  checksum files, to hashed data files and to verification.
- **Several hash algorithms** - MD5, SHA-1, SHA-2 (224/256/384/512) and SHA-3
  (224/256/384/512) can be generated and read.
- **Periodic flush** - during a long incremental run, write partial results to
  disk at a configurable interval so an interrupted run keeps its progress.

## File formats

### `.cshd` collections

The native format. One line per file, paths relative to the collection root,
separators normalised to `/`:

```
# version 1
1758938624.512345,1024,sha512,cf83e1357eefb8bd... relative/path/to/file
```

| Field | Meaning |
|---|---|
| `mtime` | Modification time as fractional Unix seconds, e.g. `1758938624.512345`. Stored as a float, so a round-trip through the file can differ from the original by a few hundred nanoseconds. Comparisons therefore use a 1 µs tolerance, otherwise every file would look modified and nothing could be skipped. |
| `size` | Size in bytes. |
| `hash_type` | One of `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`. |
| `hash` | Hex digest. |
| `path` | Path relative to the directory holding the collection file. |

Lines are written in the order described in [Entry order](#entry-order), so two
runs over an unchanged tree produce byte-identical files and can be compared
with `cmp`.

### Single-hash files

The `<hash>  <path>` / `<hash> *<path>` format written by `md5sum`, `sha512sum`,
PowerShell and friends. The algorithm is taken from the extension
(`.md5`, `.sha1`, `.sha256`, `.sha512`, `.sha3_256`, ...). `#` comments and empty
lines are skipped.

The two formats are interchangeable as *input*: both are discovered and merged
into the most-current view. Only `.cshd` is ever written, because a single-hash
file cannot record the mtime, and the mtime is what makes an incremental run
cheap. `collection::sort_serialized` exists to normalize a foreign file's line
order; our own output is already ordered and must not be re-sorted.

## Library usage

`ChecksumHelper` owns a root directory, the options and the cached most-current
collection. Every path it is given must be absolute. The snippets below use `?`,
which propagates a `ChecksumHelperError`.

```rust
use std::path::Path;
use checksum_helper::ChecksumHelper;

let mut ch = ChecksumHelper::new(Path::new("/data/photos"))?;

// Hash only what is new or changed compared to the discovered checksum files.
let collection = ch.incremental(|progress| {
    println!("{progress:?}");
})?;
ch.write_collection(&collection)?;
println!("wrote {:?}", collection.full_path()?);

// Merge all discovered checksum files into one current view, then act on it.
ch.with_most_current(
    |progress| println!("{progress:?}"),
    |ch, most_current| {
        println!("{} entries", most_current.len());
        // Yields (absolute path, file) in lexical order.
        for (path, file) in ch.iter_collection(most_current)? {
            println!("{path:?} {:?} {:?}", file.size(), file.hash_type());
        }
        Ok(())
    },
)?;

// Report files and directories without any checksum.
let missing = ch.check_missing(|_| {})?;
for directory in &missing.directories {
    println!("no checksums at all: {directory:?}");
}
for file in &missing.files {
    println!("missing: {file:?}");
}

// Hash only the files that have no checksum yet.
let fill = ch.fill_missing(|_| {})?;
ch.write_collection(&fill)?;

// Verify a collection against the live filesystem.
let collection = ch.read_collection(Path::new("/data/photos/photos.cshd"))?;
ch.verify(&collection, |_| true, |progress| println!("{progress:?}"))?;

// Or discover, merge and verify in one pass.
ch.verify_root(|_| true, |progress| println!("{progress:?}"))?;
```

Every method takes a progress callback and reports through a typed event enum
(`IncrementalProgress`, `MostCurrentProgress`, `VerifyProgress`,
`VerifyRootProgress`), so a caller can render a status line, count files or write
a log without the library knowing about any of it.

Further API notes:

- `with_options` replaces `ChecksumHelperOptions`; `new` uses the defaults
  listed below.
- The most-current view is built once and cached; `clear_most_current` drops it
  so the next operation rebuilds it.
- `write_collection` never overwrites: it creates the file. A collection that a
  periodic incremental flush already wrote to disk is written again as a no-op.
- `write_into` serializes a collection into any `Write`, which is how a caller
  can capture the exact bytes instead of a file.
- `rebase_into` relocates a collection to another directory under the same root
  and drops the entries that fall outside it. `move_path` is a `todo!()`.

## Options

`ChecksumHelperOptions::default()`, with the builder methods used to change each
field:

| Option | Default | Meaning |
|---|---|---|
| `hash_type` | `Sha512` | Algorithm for newly generated hashes. |
| `incremental_include_unchanged_files` | `true` | Keep unchanged files in the incremental output. When false, the output contains only new and changed files. |
| `incremental_skip_unchanged` | `false` | Skip hashing a file whose recorded mtime matches the file on disk. Trades the guarantee against silent corruption for speed, so it should only be used where the mtime cannot lie (see `mtime_comparison_epsilon.md` for the tolerance that makes the comparison survive the float round-trip). |
| `incremental_periodic_write_interval` | `None` | `Some(duration)` flushes the output file to disk while the run is in progress. `incremental` then writes the file itself and returns an emptied collection, and a following `write_collection` is a safe no-op. |
| `discover_hash_files_depth` | `None` | How deep to search for checksum files. `Some(0)` looks only in the root, `Some(n)` allows `n` subdirectory levels, `None` is unlimited. |
| `most_current_filter_deleted` | `true` | Drop entries whose file no longer exists when building the most-current view. `false` keeps them, which is what `--keep-deleted` selects. |
| `hash_files_matcher` | empty | Which discovered checksum files feed the most-current view. |
| `all_files_matcher` | empty | Which data files are hashed and considered by `check_missing`/`fill_missing`. |

Verification takes its own predicate (`include`) instead of an option, so a
caller can restrict it per run.

## Path matching

`PathMatcher` is a pair of glob sets, one allow and one block, built with
`PathMatcherBuilder`:

```rust
use checksum_helper::pathmatcher::PathMatcherBuilder;

let matcher = PathMatcherBuilder::new()
    .allow("**/*.jpg")?
    .block("cache/**")?
    .build()?;

assert!(matcher.is_match("photos/DSC0001.jpg"));
assert!(!matcher.is_match("cache/thumb.jpg"));
```

- An empty allow list matches everything.
- A block match always wins over an allow match.
- Patterns are matched against paths relative to the root, never absolute ones.
- Matching is case-insensitive and `literal_separator` is on, so `*` does not
  cross a `/`; use `**` to descend into directories.
- `**` is only legal in three positions, and each has a different reach:
  `**/*.jpg` matches `a.jpg` and `x/a.jpg`; `cache/**` matches `cache/a` and
  `cache/a/b` but not `cache`; `a/**/b` matches `a/b`, `a/x/b` and `a/x/y/b`.
- Trailing slashes are stripped from patterns, since `foo/` would otherwise not
  match the path `foo`.
- An invalid glob is an error, reported per pattern.

## Verification results

`hashed_file::VerifyResult`, one per entry of a collection:

| Variant | Meaning | Severity |
|---|---|---|
| `Ok` | Hash matches. | ok |
| `FileMissing(ErrorKind)` | No file at the recorded path. | error |
| `Mismatch` | Hash differs. | error |
| `MismatchSize` | Size differs. | error |
| `MismatchCorrupted` | Hash differs but the mtime still matches the recorded one: the file changed without its mtime moving. | error |
| `MismatchOutdatedHash` | Hash differs because the file was legitimately modified after the collection was written. | warning |

The distinction between the last two is the point of the enum: a mismatch with a
matching mtime is bit rot, while a mismatch with a newer mtime is a file that
legitimately moved on. Collapsing them into one "mismatch" would make the first
one indistinguishable from ordinary churn.

## Entry order

The entries of a `HashCollection` live in a hash map, so the collection itself
has no order. Anything that produces output, progress or verification results
walks the `FileTree` instead - `HashCollection::iter_sorted` internally,
`ChecksumHelper::iter_collection` from the outside - which looks entries up in
tree order. The `FileTree` stores the children of every directory in a
`BTreeMap`, so the order is lexical and independent of the order in which the
tree was filled. A directory is visited before the files next to it, which means
`baz/foo.txt` comes before `baz.txt`; that is the order, not a bug.

## Errors

`ChecksumHelperError` covers the top level (`RootIsRelative`,
`InvalidMostCurrentHashFile`, `InvalidRebaseDestination`) and wraps the errors of
the three types it composes: `HashCollectionError` (paths, parsing, merging,
writing), `HashedFileError` (reading, hashing) and `GatherError` (walking).
Every one of them implements `std::error::Error` and a `Display` that names the
offending path, the offending line or the failed operation.

## Development

```bash
cargo test -p checksum_helper
cargo build -p checksum_helper
just test                              # the whole workspace, with output
```

Unit tests live next to the code. `test_utils::abs` makes a path absolute,
because `FileTree` and `ChecksumHelper` reject relative roots, and
`test_utils::create_ftree` materializes a tree from a list of paths.
