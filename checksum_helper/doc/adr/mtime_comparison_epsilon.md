# Problem

Stored mtimes are serialised as f64 (`file_time_to_unix_time_float`) and
round-tripped through `parse_mtime` during incremental runs.  IEEE 754 doubles
cannot exactly represent all sub-second nanosecond values, so the round-tripped
`FileTime` typically differs from the original by up to ~200 ns.  This causes
`==`-based comparison to miss unchanged files, defeating the
`incremental_skip_unchanged` optimisation.

# Proposed Solutions

## Epsilon tolerance (chosen)

Introduce a `mtimes_match(a, b: Option<FileTime>) -> bool` helper that compares
the total nanosecond difference between two `FileTime` values and returns true
when it is ≤ 1 000 ns (1 µs).

**Rationale for 1 µs:**
- The worst-case f64 rounding error for timestamps around ~2³⁰ seconds
  (year 2025) is ~200 ns — well within 1 µs.
- No mainstream filesystem supports sub-microsecond mtime precision
  (ext4: 1 ns but only for `nanosec`; practical tools round to µs).
- The tolerance is small enough that a genuinely changed file will never be
  mis-classified as unchanged (the minimum mtime delta caused by a real
  modification is many orders of magnitude larger).

The helper is used in two places:
1. `incremental.rs` — the "skip unchanged" fast-path.
2. `hashed_file.rs::verify` — the corruption vs. outdated-hash classification.

When either mtime is `None`, the function returns `false` (except
`None, None` → `true`), falling through to hash-from-disk as before.

## Store mtime as separate seconds + nanoseconds

This would avoid the round-trip loss entirely, but requires a format change and
a new version header.  The ADR judges that the complexity of a format migration
is not justified for a ~200 ns loss that can be absorbed with epsilon comparison.

# Decision

Use `mtimes_match` with a 1 µs tolerance.  No format changes.  No new fields.
