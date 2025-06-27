# Problem

Which library to use for matching file paths using globs/regex etc.

# Proposed Solutions

## globset

- Unix-style globbing
- pretty flexible
- lightweight

## ignore

- used by ripgrep
- also uses globset internally
- has lots of defaults like ignoring hidden files,
  respecting .gitignore etc.
- also allows defining custom ignore file name files
  that have the same syntax as .gitignore
    - could e.g. have .cshdignore

# Decision

Using the more basic globset, since just the globbing is enough.
Would've been nice to define a custom ignore file,
but the main goal is to find all files and be explicit.
Accidentally leaving out files due to a forgotten ignore file
is a no-go.

Will be wrapped in a crate type so we don't expose
a globset type as part of our API.

