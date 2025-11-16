# Problem

Paths in a `HashCollection` are not stored literally, but via
a handle into a space-efficient DB called `FileTree`.
Dealing with this `FileTree` type is quite tricky.
Thus, users should not be exposed to it.

# Proposed Solution

Keep APIs that need a `FileTree` private or as `pub(crate)`/`pub(super)`.
Instead, expose the functionality via the central library type
`ChecksumHelper`, which owns the `FileTree` instance anyway.

E.g, for `HashCollection::verify`, don't expose the method below:

```rust
impl HashCollection {
    pub(crate) fn verify<F, P>(&self, file_tree: &FileTree, include: F, mut progress: P) -> Result<()>
}
```

Provide a `verify` method on `ChecksumHelper` instead, which is
just a thin wrapper that handles the `FileTree`.

```rust
impl ChecksumHelper {
    pub fn verify<F, P>(&self, collection: &HashCollection, include: F, progress: P) -> Result<()>
    where
        F: Fn(&path::Path) -> bool,
        P: FnMut(VerifyProgress),
    {
        collection.verify(&self.file_tree, include, progress)?;

        Ok(())
    }
}
```

# Decision

Accept the proposed solution and keep the `FileTree` private to
the crate. Expose all functionality via `ChecksumHelper`, which
owns the `FileTree` instance instead.
