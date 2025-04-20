# Problem

How should `Collection::relocate` work in combination with the path
storage aka `FileTree`. Trivial when just relocating deeper
into the tree, but what about relocating beyond the
`ChecksumHelper.root`?

All of this needs to account for the following use cases:

0) read/write/relocate
1) incremental/most current
2) verify hf
3) verify filter/all
4) check missing
5) move collection
6) move path cshd aware

# Definitions

- FileTree (FT):
  A FileTree is like a path storage DB, mapping an index to a specific
  path. Currently the indices/handles are used as keys when storing
  the file representation in a Collection.
- ChecksumHelper (CH) root:
  The base path of the application. This would normally be passed
  to the application as command-line argument, alternatively
  the current working directory could be used.
  All operations will be relative to this directory, e.g.
  creating an incremental collection or discovering hash files.
- Collection (CSHD) root:
  Directory where the collection will be stored physically on disk.
  When serializing all paths in the FT need to made relative to
  that directory.

# Proposed Solutions

## FT all paths relative to ChecksumHelper (CH) root
-> ADVANTAGE: less paths to store
-> ADVANTAGE: current

0) - relocate could then just change the root without touching ft/path_handles
   - BUT when serializing -> need to make path relative to CSHD root
   - SAME for reading: need to add CSHD root to CH root to path to
                       get correct handle
1) OK, since we only touch files under CH root.
2) OK, BUT need to make sure that we use the __ch__ root and not
       the CSHD root when passing it to file.verify
       => ERROR-PRONE
3) OK, since filter etc. would be relative to CH root
       could filter directly on the paths returned by ft
4) OK
5) not a PROBLEM, would be OK if we also did not allow moving beyond the CH root,
   but it feels like that would be a common operation e.g. `chsh mv foo.CSHD ../`
   UNLESS we allow parent directory `..` references in the ft

   -> NO, since all paths in FT are relative to CH, we have to transform
      them to the CHSD's root directory anyway, so even this is fine.
      (this is all fine assuming that both the CH root and CSHD root
       are absolute paths)
6) OK, if we don't allow moving beyond the CH root

## FT only absolute paths
-> DISADVANTAGE: more paths to store, but only up to CH root, so negligible
-> ADVANTAGE: easier to think about?

0) - relocate could then just change the root without touching ft/path_handles
   - BUT when serializing -> need to make path relative to CSHD root
   - reading: just add the absolute path
1) OK
2) OK
3) OK, but harder to filter?
4) OK
5) OK
6) OK

# Decision

Keep FT to as having relative paths to the CH root.
It's a littler harder to think about, but since it's the current way,
it's not too much of a transition and all use cases are covered,
we'd rather keep it like this.

If we discover problems in the future, we might change it though.

What we will change though is moving the __absolute__ CH root into
the FileTree such that those cannot be confused.
This makes the error prone situation for 2) impossible.
Then all `file_tree.add` etc. will use an absolute path,
which can be checked and using the correct root also becomes a non-issue.
As a result `file_tree.relative_path` also needs to take in a
(absolute) path that it should be relative to.
-> No, better to just assume the path to be relative to the FT root
   and let higher level parts handle making it relative to something
   else
