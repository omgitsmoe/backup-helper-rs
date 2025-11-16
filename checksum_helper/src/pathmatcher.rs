use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

use std::error::Error;
use std::fmt;
use std::path;

type Result<T> = std::result::Result<T, PathMatcherError>;

pub struct PathMatcher {
    allow_list: GlobSet,
    block_list: GlobSet,
}

impl PathMatcher {
    pub fn is_match(&self, path: impl AsRef<path::Path>) -> bool {
        let allowed = self.allow_list.is_empty() || self.allow_list.is_match(&path);

        // check allowed, so we don't try matches even though the file is already not a match
        let blocked = allowed && !self.block_list.is_empty() && self.block_list.is_match(&path);

        // NOTE: allowed files are overridden by block patterns
        allowed && !blocked
    }

    pub fn is_excluded(&self, path: impl AsRef<path::Path>) -> bool {
        !self.block_list.is_empty() && self.block_list.is_match(&path)
    }
}

pub struct PathMatcherBuilder {
    allow_list_builder: GlobSetBuilder,
    block_list_builder: GlobSetBuilder,
}

impl PathMatcherBuilder {
    pub fn new() -> Self {
        Self {
            allow_list_builder: GlobSetBuilder::new(),
            block_list_builder: GlobSetBuilder::new(),
        }
    }

    pub fn build(self) -> Result<PathMatcher> {
        Ok(PathMatcher {
            allow_list: self.allow_list_builder.build()?,
            block_list: self.block_list_builder.build()?,
        })
    }

    pub fn allow(mut self, glob: impl AsRef<str>) -> Result<Self> {
        // NOTE: globset has weird behaviour with trailing slashes,
        //       `foo/` does not match the path `foo`, which can be error-prone
        //       -> strip trailing slashes
        let glob = glob.as_ref().trim_end_matches(['/', '\\']);
        let glob = GlobBuilder::new(glob)
            .case_insensitive(true)
            .literal_separator(true)
            .build()?;
        self.allow_list_builder.add(glob);
        Ok(self)
    }

    pub fn block(mut self, glob: impl AsRef<str>) -> Result<Self> {
        // NOTE: globset has weird behaviour with trailing slashes,
        //       `foo/` does not match the path `foo`, which can be error-prone
        //       -> strip trailing slashes
        let glob = glob.as_ref().trim_end_matches(['/', '\\']);
        let glob = GlobBuilder::new(glob)
            .case_insensitive(true)
            .literal_separator(true)
            .build()?;
        self.block_list_builder.add(glob);
        Ok(self)
    }
}

impl Default for PathMatcherBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum PathMatcherError {
    InvalidGlob(String),
}

impl fmt::Display for PathMatcherError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PathMatcherError::InvalidGlob(s) =>
                write!(f, "invalid glob: {}", &s),
        }
    }
}

impl Error for PathMatcherError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl From<globset::Error> for PathMatcherError {
    fn from(value: globset::Error) -> Self {
        Self::InvalidGlob(value.to_string())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn empty_matches_all() {
        let matcher = PathMatcherBuilder::new().build().unwrap();

        assert!(matcher.is_match(path::Path::new("foo/bar/baz.txt")));
        assert!(matcher.is_match(path::Path::new("/foo")));
        assert!(matcher.is_match(path::Path::new("./foo/bar/baz.txt")));
        assert!(matcher.is_match(path::Path::new("bar/baz.txt")));
        assert!(matcher.is_match(path::Path::new("baz.txt")));
        assert!(matcher.is_match(path::Path::new("xer.mp4")));
        assert!(matcher.is_match(path::Path::new("bar/xer.mp4")));
        assert!(matcher.is_match(path::Path::new("bar/baz/xer.mp4")));

        assert!(!matcher.is_excluded(path::Path::new("foo/bar/baz.txt")));
        assert!(!matcher.is_excluded(path::Path::new("/foo")));
        assert!(!matcher.is_excluded(path::Path::new("./foo/bar/baz.txt")));
        assert!(!matcher.is_excluded(path::Path::new("bar/baz.txt")));
        assert!(!matcher.is_excluded(path::Path::new("baz.txt")));
        assert!(!matcher.is_excluded(path::Path::new("xer.mp4")));
        assert!(!matcher.is_excluded(path::Path::new("bar/xer.mp4")));
        assert!(!matcher.is_excluded(path::Path::new("bar/baz/xer.mp4")));
    }

    #[test]
    fn empty_block_list_excludes_nothing() {
        let matcher = PathMatcherBuilder::new()
            .allow("**/*").unwrap()
            .build().unwrap();

        assert!(matcher.is_match(path::Path::new("foo/bar/baz.txt")));
        assert!(matcher.is_match(path::Path::new("/foo")));
        assert!(matcher.is_match(path::Path::new("./foo/bar/baz.txt")));
        assert!(matcher.is_match(path::Path::new("bar/baz.txt")));
        assert!(matcher.is_match(path::Path::new("baz.txt")));
        assert!(matcher.is_match(path::Path::new("xer.mp4")));
        assert!(matcher.is_match(path::Path::new("bar/xer.mp4")));
        assert!(matcher.is_match(path::Path::new("bar/baz/xer.mp4")));

        assert!(!matcher.is_excluded(path::Path::new("foo/bar/baz.txt")));
        assert!(!matcher.is_excluded(path::Path::new("/foo")));
        assert!(!matcher.is_excluded(path::Path::new("./foo/bar/baz.txt")));
        assert!(!matcher.is_excluded(path::Path::new("bar/baz.txt")));
        assert!(!matcher.is_excluded(path::Path::new("baz.txt")));
        assert!(!matcher.is_excluded(path::Path::new("xer.mp4")));
        assert!(!matcher.is_excluded(path::Path::new("bar/xer.mp4")));
        assert!(!matcher.is_excluded(path::Path::new("bar/baz/xer.mp4")));
    }

    #[test]
    fn allow_only() {
        let matcher = PathMatcherBuilder::new()
            .allow("foo/**/*.txt").unwrap()
            .allow("bar/baz.txt").unwrap()
            .allow("*.mp4").unwrap()
            .build().unwrap();

        assert!(matcher.is_match(path::Path::new("foo/bar/baz.txt")));
        assert!(matcher.is_match(path::Path::new("foo/./bar/baz.txt")));
        assert!(matcher.is_match(path::Path::new("bar/baz.txt")));
        assert!(matcher.is_match(path::Path::new("xer.mp4")));

        // ./foo not matched by foo/
        assert!(!matcher.is_match(path::Path::new("./foo/bar/baz.txt")));
        assert!(!matcher.is_match(path::Path::new("/foo")));
        assert!(!matcher.is_match(path::Path::new("baz.txt")));
        assert!(!matcher.is_match(path::Path::new("bar/xer.mp4")));
        assert!(!matcher.is_match(path::Path::new("bar/baz/xer.mp4")));
    }

    #[test]
    fn exclude_only() {
        let matcher = PathMatcherBuilder::new()
            .block("foo/**/*.txt").unwrap()
            .block("bar/baz.txt").unwrap()
            .block("*.mp4").unwrap()
            .build().unwrap();

        assert!(!matcher.is_match(path::Path::new("foo/bar/baz.txt")));
        assert!(!matcher.is_match(path::Path::new("foo/./bar/baz.txt")));
        assert!(!matcher.is_match(path::Path::new("bar/baz.txt")));
        assert!(!matcher.is_match(path::Path::new("xer.mp4")));
        assert!(matcher.is_excluded(path::Path::new("foo/bar/baz.txt")));
        assert!(matcher.is_excluded(path::Path::new("foo/./bar/baz.txt")));
        assert!(matcher.is_excluded(path::Path::new("bar/baz.txt")));
        assert!(matcher.is_excluded(path::Path::new("xer.mp4")));

        // ./foo not matched by foo/
        assert!(matcher.is_match(path::Path::new("./foo/bar/baz.txt")));
        assert!(matcher.is_match(path::Path::new("/foo")));
        assert!(matcher.is_match(path::Path::new("baz.txt")));
        assert!(matcher.is_match(path::Path::new("bar/xer.mp4")));
        assert!(matcher.is_match(path::Path::new("bar/baz/xer.mp4")));
        assert!(!matcher.is_excluded(path::Path::new("./foo/bar/baz.txt")));
        assert!(!matcher.is_excluded(path::Path::new("/foo")));
        assert!(!matcher.is_excluded(path::Path::new("baz.txt")));
        assert!(!matcher.is_excluded(path::Path::new("bar/xer.mp4")));
        assert!(!matcher.is_excluded(path::Path::new("bar/baz/xer.mp4")));
    }

    #[test]
    fn block_overrides_allow() {
        let matcher = PathMatcherBuilder::new()
            .allow("foo/**/*.txt").unwrap()
            .allow("bar/baz.txt").unwrap()
            .allow("*.mp4").unwrap()
            .block("**/*.txt").unwrap()
            .block("xer.mp4").unwrap()
            .build().unwrap();

        assert!(!matcher.is_match(path::Path::new("foo/bar/baz.txt")));
        assert!(!matcher.is_match(path::Path::new("foo/./bar/baz.txt")));
        assert!(!matcher.is_match(path::Path::new("bar/baz.txt")));
        assert!(!matcher.is_match(path::Path::new("xer.mp4")));

        // ./foo not matched by foo/
        assert!(!matcher.is_match(path::Path::new("./foo/bar/baz.txt")));
        assert!(!matcher.is_match(path::Path::new("/foo")));
        assert!(!matcher.is_match(path::Path::new("baz.txt")));
        assert!(!matcher.is_match(path::Path::new("bar/xer.mp4")));
        assert!(!matcher.is_match(path::Path::new("bar/baz/xer.mp4")));

        assert!(matcher.is_excluded(path::Path::new("foo/bar/baz.txt")));
        assert!(matcher.is_excluded(path::Path::new("foo/./bar/baz.txt")));
        assert!(matcher.is_excluded(path::Path::new("bar/baz.txt")));
        assert!(matcher.is_excluded(path::Path::new("./foo/bar/baz.txt")));
        assert!(matcher.is_excluded(path::Path::new("baz.txt")));
        assert!(matcher.is_excluded(path::Path::new("xer.mp4")));
    }

    #[test]
    fn single_wildcard_not_matching_path_sep() {
        let matcher = PathMatcherBuilder::new()
            .allow("*.txt").unwrap()
            .allow("*.mp4").unwrap()
            .build().unwrap();

        assert!(matcher.is_match(path::Path::new("xer.mp4")));
        assert!(matcher.is_match(path::Path::new("baz.txt")));

        // ./foo not matched by foo/
        assert!(!matcher.is_match(path::Path::new("./foo/bar/baz.txt")));
        assert!(!matcher.is_match(path::Path::new("/foo")));
        assert!(!matcher.is_match(path::Path::new("foo/bar/baz.txt")));
        assert!(!matcher.is_match(path::Path::new("foo/./bar/baz.txt")));
        assert!(!matcher.is_match(path::Path::new("bar/baz.txt")));
        assert!(!matcher.is_match(path::Path::new("bar/xer.mp4")));
        assert!(!matcher.is_match(path::Path::new("bar/baz/xer.mp4")));
    }

    #[test]
    fn block_trims_trailing_separators() {
        let matcher = PathMatcherBuilder::new()
            .block("foo/").unwrap()
            .block("bar/baz\\\\").unwrap()
            .build().unwrap();

        assert!(matcher.is_excluded(path::Path::new("foo")));
        assert!(matcher.is_excluded(path::Path::new("bar/baz")));
    }

    #[test]
    fn allow_trims_trailing_separators() {
        let matcher = PathMatcherBuilder::new()
            .allow("foo/").unwrap()
            .allow("bar/baz\\\\").unwrap()
            .build().unwrap();

        assert!(matcher.is_match(path::Path::new("foo")));
        assert!(matcher.is_match(path::Path::new("bar/baz")));
    }
}
