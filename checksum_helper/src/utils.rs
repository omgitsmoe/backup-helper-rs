use std::path::{Component, Path, PathBuf};

// FnOnce to make sure the cleanup closure is only called once
pub struct Defer<F: FnOnce()> {
    cleanup: Option<F>,
}

impl<F: FnOnce()> Defer<F> {
    pub fn new(cleanup: F) -> Defer<F> {
        Defer {
            cleanup: Some(cleanup),
        }
    }
}

impl<F: FnOnce()> Drop for Defer<F> {
    // drop only takes &mut self, but FnOnce requires ownership
    // -> use an Option, so we can replace it with None
    fn drop(&mut self) {
        if let Some(f) = self.cleanup.take() {
            f();
        }
    }
}

/// Normalize a path by removing all __redundant__ pardir (..)
/// and curdir (.) components.
///
/// Pardir references beyond the given path are kept,
/// e.g., `normalize_path("foo/../../bar")` -> `"../bar"`.
pub(crate) fn normalize_path(p: impl AsRef<Path>) -> PathBuf {
    let p = p.as_ref();
    let mut components = vec![];

    for c in p.components() {
        match c {
            Component::Prefix(_) | Component::RootDir => {
                // Keep prefix/root as-is
                components.push(c);
            }
            Component::CurDir => {
                // skip `.`
            }
            Component::ParentDir => {
                if let Some(last) = components.last() {
                    match last {
                        Component::Normal(_) => {
                            // pop normal components
                            components.pop();
                        }
                        Component::RootDir | Component::Prefix(_) => {
                            // can't pop past root
                            // just ignore the ..
                        }
                        Component::ParentDir => {
                            // keep this parent dir
                            components.push(c);
                        }
                        _ => {}
                    }
                } else {
                    // nothing to pop, keep `..` for relative paths
                    components.push(c);
                }
            }
            Component::Normal(_) => components.push(c),
        }
    }

    PathBuf::from_iter(components)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_defer() {
        // RefCell to allow reading the value even though the defer closure
        // has it mutably borrowed
        let x = std::cell::RefCell::new(0);
        {
            let _defer = Defer::new(|| *x.borrow_mut() += 1);
            assert_eq!(*x.borrow(), 0);
        }

        assert_eq!(*x.borrow(), 1);
    }

    #[test]
    #[cfg(not(windows))]
    fn normalize_path() {
        let input_expected = [
            ("/foo/bar", "/foo/bar"),
            // curdir
            ("/foo/./bar", "/foo/bar"),
            ("./foo/./bar", "foo/bar"),
            ("foo/./bar", "foo/bar"),
            // curdir prefix
            ("./foo/bar", "foo/bar"),
            // pardir
            ("/foo/../bar", "/bar"),
            ("foo/../bar", "bar"),
            ("foo/baz/xer/../../../bar", "bar"),
            // pardir prefix
            ("../../bar", "../../bar"),
            ("../foo/../bar", "../bar"),
            // pardir beyond curdir
            ("foo/../../bar", "../bar"),
            ("foo/../../bar", "../bar"),
            ("foo/../../../bar", "../../bar"),
            ("foo/baz/xer/../../../../bar", "../bar"),
            // pardir beyond root
            ("/foo/../../bar", "/bar"),
            ("/foo/../../bar", "/bar"),
            ("/foo/baz/xer/../../../../bar", "/bar"),
            // combined
            ("/foo/../bar/./", "/bar"),
            ("./foo/../bar/./", "bar"),
        ];

        for (input, expected) in input_expected {
            assert_eq!(super::normalize_path(input), PathBuf::from(expected));
        }
    }

    #[test]
    #[cfg(windows)]
    fn normalize_path() {
        let input_expected = [
            // absolute paths
            (r"C:\foo\bar", r"C:\foo\bar"),
            // curdir
            (r"C:\foo\.\bar", r"C:\foo\bar"),
            (r".\foo\.\bar", r"foo\bar"),
            (r"foo\.\bar", r"foo\bar"),
            // curdir prefix
            (r".\foo\bar", r"foo\bar"),
            // pardir
            (r"C:\foo\..\bar", r"C:\bar"),
            (r"foo\..\bar", r"bar"),
            (r"foo\baz\xer\..\..\..\bar", r"bar"),
            // pardir prefix
            (r"..\..\bar", r"..\..\bar"),
            (r"..\foo\..\bar", r"..\bar"),
            // pardir beyond curdir
            (r"foo\..\..\bar", r"..\bar"),
            (r"foo\..\..\bar", r"..\bar"),
            (r"foo\..\..\..\bar", r"..\..\bar"),
            (r"foo\baz\xer\..\..\..\..\bar", r"..\bar"),
            // pardir beyond root
            (r"C:\foo\..\..\bar", r"C:\bar"),
            (r"C:\foo\..\..\bar", r"C:\bar"),
            (r"C:\foo\baz\xer\..\..\..\..\bar", r"C:\bar"),
            // combined
            (r"C:\foo\..\bar\.", r"C:\bar"),
            (r".\foo\..\bar\.", r"bar"),
        ];

        for (input, expected) in input_expected {
            assert_eq!(super::normalize_path(input), PathBuf::from(expected));
        }
    }
}
