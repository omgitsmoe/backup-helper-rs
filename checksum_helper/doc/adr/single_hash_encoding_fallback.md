# Single-hash files decode with BOM tolerance and a cp1252 fallback

## Status

Accepted

## Context

Hash files come in two flavors:

1. **`.cshd` collections** — the checksum_helper format. We control the format
   and all producers (the Rust and Python implementations). It is always
   written as UTF-8.
2. **Single-hash files** — `sha512`, `md5sum`, etc. style files with one
   `<hex>  ( |\*)<path>` line per entry. These are produced by external tools
   (TotalCmd, GNU coreutils, Windows PowerShell's default redirects, ...) over
   which we have no control.

Real-world single-hash files have shown up that are not clean UTF-8:

- Files starting with a UTF-8 **BOM** (`EF BB BF`).
- Files encoded in the Windows **ANSI codepage (cp1252)**, e.g. filename bytes
  like `0x96` meaning `–` (EN DASH). Such bytes are invalid UTF-8.

The original Rust parser read every input with `BufRead::lines()`, which
validates UTF-8 and fails with an `io::Error` on any invalid byte, making
entire collections unreadable.

The Python version had already solved this for single-hash files in
`_read_from_single_hash_file`: it opens with `UTF-8-SIG` (strips a BOM) and on
`UnicodeDecodeError` re-opens with `cp1252`.

## Decision

Only the **single-hash parser** (`parse_single_hash`) gets tolerant decoding:

- Read each line as raw bytes (`BufRead::read_until`), retaining line-oriented
  streaming semantics so huge files still only hold one line in memory.
- Decode the line as UTF-8; if that fails, decode it as **Windows-1252** and
  log a warning (once per file).
- Strip a leading UTF-8 BOM from the first line.

The **`.cshd` parser** (`parse`) remains strict UTF-8 via `BufRead::lines()`
with no BOM handling and no fallback. We control the `.cshd` format and its
writers emit UTF-8, so tolerant decoding would only mask producer bugs; an
invalid `.cshd` line should fail loudly instead.

This matches the Python implementation exactly: `_read_from_single_hash_file`
has the fallback, while `_read` (`.cshd`) does not.

## Alternatives considered

- **Fallback in both parsers**: simpler code (shared helpers), but relaxes the
  `.cshd` contract. Rejected in favor of strictness for the controlled format.
- **Whole-file decode** (`read_to_end` + detect encoding): correct
  `encoding_rs` behavior but buffers the entire hash file; breaks the streaming
  parse used to handle huge inputs.
- **Whole-file detection, then streaming decoder** (`Encoding::new_decoder`):
  encoding picked once at the start; more machinery and a chunk-boundary
  UTF-8 continuation problem. Per-line fallback is behaviorally equivalent on
  realistic inputs because a valid UTF-8 line never takes the fallback path.
- **Raw OS-byte path matching** (`OsStr::from_bytes`): only works when the hash
  file and the filesystem bytes were produced with the same encoding. Fails
  for the motivating case (cp1252 file vs UTF-8 on-disk name).
- **Lossy replacement** (`from_utf8_lossy`): maps `0x96` to `U+FFFD`, not `–`,
  so the path never matches the filesystem.

## Consequences

- cp1252- and BOM-written single-hash files parse correctly on first try,
  including on Unix filesystems with UTF-8 names.
- A `.cshd` containing non-UTF-8 still errors (unchanged behavior), keeping
  the format we control strict.
- A malformed line in a single-hash file still fails with
  `InvalidSingleHashLine` (only the decoding of otherwise-valid lines becomes
  more tolerant).
- The ambiguous case of a byte sequence that is both valid UTF-8 and means
  something different in cp1252 (e.g. `C3 A9`) is decoded as UTF-8 — the
  undetectable/undecidable case where either guess can be wrong.
- New dependency: `encoding_rs`.
