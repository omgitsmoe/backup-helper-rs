use crate::checksum_helper::{ChecksumHelperError, ChecksumHelperOptions, default_filename};
use crate::collection::HashCollection;
use crate::file_tree::FileTree;
use crate::gather::{Gather, VisitType};

use std::path;

type Result<T> = std::result::Result<T, ChecksumHelperError>;

#[derive(Debug, PartialEq)]
pub enum MostCurrentProgress {
    /// Found a hash file that will be included in the most current hash file.
    FoundFile(path::PathBuf),
    /// Ignored a file or directory path. Not used when pre-filtering known hash file
    /// extensions.
    IgnoredPath(path::PathBuf),
    /// Load and merge hash file into most current.
    MergeHashFile(path::PathBuf),
}

pub(crate) fn update_most_current<P>(
    root: impl AsRef<path::Path>,
    file_tree: &mut FileTree,
    options: &ChecksumHelperOptions,
    mut progress: P,
) -> Result<HashCollection>
where
    P: FnMut(MostCurrentProgress),
{
    let root = root.as_ref();
    let discover_result = discover_hash_files(root, options, &mut progress)?;
    let most_current_path = root.join(default_filename(root, "most_current", ""));
    let mut most_current = HashCollection::new(Some(&most_current_path), None)
        .expect("creating an empty hash file collection must succeed");

    for hash_file_path in discover_result.hash_file_paths {
        progress(MostCurrentProgress::MergeHashFile(hash_file_path.clone()));
        let hc = HashCollection::from_disk(&hash_file_path, file_tree)?;
        most_current.merge(hc)?;
    }

    // TODO filter out files that are no longer on disk
    // + callback?

    Ok(most_current)
}

struct DiscoverResult {
    pub hash_file_paths: Vec<path::PathBuf>,
}

const HASH_FILE_EXTENSIONS: &[&str] = &[
    "cshd",
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
    "shake_128",
    "shake_256",
    "blake2b",
    "blake2s",
];

fn discover_hash_files<P>(
    root: impl AsRef<path::Path>,
    options: &ChecksumHelperOptions,
    mut progress: P,
) -> Result<DiscoverResult>
where
    P: FnMut(MostCurrentProgress),
{
    let mut files = vec![];
    let root = root.as_ref();
    let iter = Gather::new(root, |e| {
        if e.is_directory {
            include_hash_file_dir(root, options, e.depth, &e.dir_entry.path(), &mut progress)
        } else {
            include_hash_file(root, options, &e.dir_entry.path(), &mut progress)
        }
    });
    for entry_result in iter {
        let visit_data = entry_result?;
        if let VisitType::File(v) = visit_data {
            files.push(v.entry.path());
        }
    };

    Ok(DiscoverResult {
        hash_file_paths: files,
    })
}

fn include_hash_file<P>(
    root: &path::Path,
    options: &ChecksumHelperOptions,
    hash_file: &path::Path,
    progress: &mut P,
) -> bool
where
    P: FnMut(MostCurrentProgress),
{
    match hash_file.extension() {
        None => false,
        Some(file_ext) => {
            let mut include = false;
            for ext in HASH_FILE_EXTENSIONS {
                if *ext == file_ext {
                    include = true;
                    break;
                }
            }
            if !include {
                return false;
            }

            let relative_path = pathdiff::diff_paths(hash_file, root).expect(
                "discover_hash_files paths must alway be \
                    relative to the ChecksumHelper root!",
            );
            assert!(
                !relative_path.starts_with(".."),
                "discover_hash_files path must always be a sub-path of the ChecksumHelper root!"
            );

            if options.hash_files_matcher.is_match(&relative_path) {
                progress(MostCurrentProgress::FoundFile(relative_path.to_owned()));
                true
            } else {
                progress(MostCurrentProgress::IgnoredPath(relative_path.to_owned()));
                false
            }
        }
    }
}

fn include_hash_file_dir<P>(
    root: &path::Path,
    options: &ChecksumHelperOptions,
    depth: u32,
    dir: &path::Path,
    progress: &mut P,
) -> bool
where
    P: FnMut(MostCurrentProgress),
{
    if let Some(max_depth) = options.discover_hash_files_depth {
        // NOTE: since 0 -> same directory
        // 1 -> one directory down
        // and we decide if we want to enter here, so it needs to be >=
        if depth >= max_depth {
            return false;
        }
    }

    let relative_path = pathdiff::diff_paths(dir, root).expect(
        "discover_hash_files paths must alway be \
            relative to the ChecksumHelper root!",
    );
    assert!(
        !relative_path.starts_with(".."),
        "discover_hash_files path must always be a sub-path of the ChecksumHelper root!"
    );

    if options.hash_files_matcher.is_excluded(&relative_path) {
        progress(MostCurrentProgress::IgnoredPath(relative_path.to_owned()));
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pathmatcher::*;
    use crate::test_utils::*;
    use crate::ChecksumHelperOptions;
    use pretty_assertions::assert_eq;

    fn setup_dir_hash_files() -> std::path::PathBuf {
        let testdir = testdir!();
        create_ftree(
            &testdir,
            "\
foo/bar/baz/file.md5
foo/bar/baz/file.cshd
foo/bar/baz/file.txt
foo/bar/bar.blake2b
foo/bar/bar.mp4
foo/foo.shake_128
foo/foo.bin
bar/baz/baz_2025-06-28.sha256
bar/baz/save.sav
bar/baz_2025-06-28.cshd
bar/other.txt
root.sha3_384
file.rs",
        );
        testdir
    }

    #[test]
    fn discover_hash_files_all_hash_files_found() {
        let testdir = setup_dir_hash_files();
        let options = ChecksumHelperOptions::default();
        let mut found_cb = vec![];
        let mut result = discover_hash_files(&testdir, &options, |p| {
            if let MostCurrentProgress::FoundFile(p) = p {
                found_cb.push(p);
            } else {
                unreachable!();
            }
        })
        .unwrap();
        result.hash_file_paths.sort();
        let expected = vec![
            testdir
                .join("bar")
                .join("baz")
                .join("baz_2025-06-28.sha256"),
            testdir.join("bar").join("baz_2025-06-28.cshd"),
            testdir.join("foo").join("bar").join("bar.blake2b"),
            testdir
                .join("foo")
                .join("bar")
                .join("baz")
                .join("file.cshd"),
            testdir.join("foo").join("bar").join("baz").join("file.md5"),
            testdir.join("foo").join("foo.shake_128"),
            testdir.join("root.sha3_384"),
        ];
        assert_eq!(result.hash_file_paths, expected);

        found_cb.sort();
        assert_eq!(
            found_cb,
            expected
                .iter()
                .map(|p| p.strip_prefix(&testdir).unwrap())
                .collect::<Vec<&path::Path>>(),
        );
    }

    #[test]
    fn discover_hash_files_respects_hash_files_depth() {
        // NOTE: decided this should be part of discover_hash_files
        //       since update_most_current has a different task
        //       harder to reuse discover_hash_files then, but
        //       most likely the options should be respected for everything anyway
        let testdir = setup_dir_hash_files();
        let options = ChecksumHelperOptions {
            discover_hash_files_depth: Some(1),
            ..Default::default()
        };

        let mut result = discover_hash_files(&testdir, &options, |_| {}).unwrap();

        result.hash_file_paths.sort();
        assert_eq!(
            result.hash_file_paths,
            vec! {
                testdir.join("bar").join("baz_2025-06-28.cshd"),
                testdir.join("foo").join("foo.shake_128"),
                testdir.join("root.sha3_384"),
            }
        );
    }

    #[test]
    fn discover_hash_files_respects_hash_files_matcher() {
        // NOTE: decided this should be part of discover_hash_files
        //       since update_most_current has a different task
        //       harder to reuse discover_hash_files then, but
        //       most likely the options should be respected for everything anyway
        let testdir = setup_dir_hash_files();
        let matcher = PathMatcherBuilder::new()
            .allow("**/*.cshd")
            .unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            hash_files_matcher: matcher,
            ..Default::default()
        };

        let mut found_cb = vec![];
        let mut ignored_cb = vec![];
        let mut result = discover_hash_files(&testdir, &options, |p| match p {
            MostCurrentProgress::FoundFile(p) => found_cb.push(p),
            MostCurrentProgress::IgnoredPath(p) => ignored_cb.push(p),
            _ => unreachable!(),
        })
        .unwrap();

        result.hash_file_paths.sort();
        let expected = vec![
            testdir.join("bar").join("baz_2025-06-28.cshd"),
            testdir
                .join("foo")
                .join("bar")
                .join("baz")
                .join("file.cshd"),
        ];
        assert_eq!(result.hash_file_paths, expected,);

        found_cb.sort();
        assert_eq!(
            found_cb,
            expected
                .iter()
                .map(|p| p.strip_prefix(&testdir).unwrap())
                .collect::<Vec<&path::Path>>(),
        );

        ignored_cb.sort();
        assert_eq!(
            ignored_cb,
            vec! {
                path::PathBuf::from("bar").join("baz").join("baz_2025-06-28.sha256"),
                path::PathBuf::from("foo").join("bar").join("bar.blake2b"),
                path::PathBuf::from("foo").join("bar").join("baz").join("file.md5"),
                path::PathBuf::from("foo").join("foo.shake_128"),
                path::PathBuf::from("root.sha3_384"),
            },
        );
    }

    #[test]
    fn discover_hash_files_skips_excluded_directories_early() {
        let testdir = setup_dir_hash_files();
        let matcher = PathMatcherBuilder::new()
            .block("foo/")
            .unwrap()
            .block("bar/*")
            .unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            hash_files_matcher: matcher,
            ..Default::default()
        };

        let mut found_cb = vec![];
        let mut ignored_cb = vec![];
        let mut result = discover_hash_files(&testdir, &options, |p| match p {
            MostCurrentProgress::FoundFile(p) => found_cb.push(p),
            MostCurrentProgress::IgnoredPath(p) => ignored_cb.push(p),
            _ => unreachable!(),
        })
        .unwrap();

        result.hash_file_paths.sort();
        let expected = vec![testdir.join("root.sha3_384")];
        assert_eq!(result.hash_file_paths, expected);

        found_cb.sort();
        assert_eq!(
            found_cb,
            expected
                .iter()
                .map(|p| p.strip_prefix(&testdir).unwrap())
                .collect::<Vec<&path::Path>>(),
        );

        ignored_cb.sort();
        assert_eq!(
            ignored_cb,
            vec! {
                // excluded whole directory early and then no more ignore cbs
                path::PathBuf::from("bar").join("baz"),
                path::PathBuf::from("bar").join("baz_2025-06-28.cshd"),
                path::PathBuf::from("foo"),
            },
        );
    }

    #[test]
    fn discover_hash_files_does_not_exclude_directories_containing_matched_files() {
        // NOTE: discover_hash_files must not exclude directories that would
        //       still have files in it that were not excluded
        let testdir = setup_dir_hash_files();
        let matcher = PathMatcherBuilder::new()
            // must visit all dirs still
            .block("**/*.blake2b")
            .unwrap()
            // must still visit baz itself
            .block("**/baz/*.cshd")
            .unwrap()
            .block("**/baz/*.md5")
            .unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            hash_files_matcher: matcher,
            ..Default::default()
        };

        let mut found_cb = vec![];
        let mut ignored_cb = vec![];
        let mut result = discover_hash_files(&testdir, &options, |p| match p {
            MostCurrentProgress::FoundFile(p) => found_cb.push(p),
            MostCurrentProgress::IgnoredPath(p) => ignored_cb.push(p),
            _ => unreachable!(),
        })
        .unwrap();

        result.hash_file_paths.sort();
        let expected = vec![
            testdir
                .join("bar")
                .join("baz")
                .join("baz_2025-06-28.sha256"),
            testdir.join("bar").join("baz_2025-06-28.cshd"),
            testdir.join("foo").join("foo.shake_128"),
            testdir.join("root.sha3_384"),
        ];
        assert_eq!(result.hash_file_paths, expected,);

        found_cb.sort();
        assert_eq!(
            found_cb,
            expected
                .iter()
                .map(|p| p.strip_prefix(&testdir).unwrap())
                .collect::<Vec<&path::Path>>(),
        );

        ignored_cb.sort();
        // NOTE: no directory excluded early, still traversed all directories
        assert_eq!(
            ignored_cb,
            vec! {
                path::PathBuf::from("foo").join("bar").join("bar.blake2b"),
                path::PathBuf::from("foo").join("bar").join("baz").join("file.cshd"),
                path::PathBuf::from("foo").join("bar").join("baz").join("file.md5"),
            },
        );
    }

    #[test]
    #[should_panic]
    fn include_hash_file_panics_on_path_outside_of_root() {
        let root = path::Path::new("/foo");
        include_hash_file(
            root,
            &ChecksumHelperOptions::default(),
            path::Path::new("/home/bar/f.cshd"),
            &mut |_| {},
        );
    }

    #[test]
    fn include_hash_file_skips_non_hash_files() {
        let root = path::Path::new("/");
        let options = ChecksumHelperOptions::default();
        for ext in HASH_FILE_EXTENSIONS {
            assert!(include_hash_file(
                &root,
                &options,
                path::Path::new(&format!("/opt/foo.{}", ext)),
                &mut |_| {}
            ));
        }

        for ext in vec!["txt", "bin", "iso", "rs"] {
            assert!(!include_hash_file(
                &root,
                &options,
                path::Path::new(&format!("/opt/foo.{}", ext)),
                &mut |_| {}
            ));
        }
    }

    #[test]
    fn include_hash_file_respects_hash_files_matcher() {
        let matcher = PathMatcherBuilder::new()
            .allow("**/*.cshd")
            .unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            hash_files_matcher: matcher,
            ..Default::default()
        };
        let root = path::Path::new("/");

        assert!(include_hash_file(
            &root,
            &options,
            path::Path::new("/foo.cshd"),
            &mut |_| {}
        ));
        assert!(!include_hash_file(
            &root,
            &options,
            path::Path::new("/foo.md5"),
            &mut |_| {}
        ));
    }

    #[test]
    fn include_hash_file_calls_the_progress_callback() {
        let matcher = PathMatcherBuilder::new()
            .allow("**/*.cshd")
            .unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            hash_files_matcher: matcher,
            ..Default::default()
        };
        let root = path::Path::new("/");

        let mut was_called = false;
        assert!(include_hash_file(
            &root,
            &options,
            path::Path::new("/foo.cshd"),
            &mut |p| {
                was_called = true;
                assert!(matches!(
                        p,
                        MostCurrentProgress::FoundFile(ref f) if f == path::Path::new("foo.cshd")
                ));
            }
        ));
        assert!(was_called);

        let mut was_called = false;
        assert!(!include_hash_file(
            &root,
            &options,
            path::Path::new("/foo.md5"),
            &mut |p| {
                was_called = true;
                assert!(matches!(
                        p,
                        MostCurrentProgress::IgnoredPath(ref f) if f == path::Path::new("foo.md5")
                ));
            }
        ));
        assert!(was_called);
    }

    #[test]
    #[should_panic]
    fn include_hash_file_dir_panics_on_path_outside_of_root() {
        let root = path::Path::new("/foo");
        include_hash_file_dir(
            &root,
            &ChecksumHelperOptions::default(),
            1,
            path::Path::new("/home/bar"),
            &mut |_| {},
        );
    }

    #[test]
    fn include_hash_file_dir_respects_disover_hash_files_depth() {
        let options = ChecksumHelperOptions {
            discover_hash_files_depth: Some(3),
            ..Default::default()
        };
        let root = path::Path::new("/");
        assert!(include_hash_file_dir(
            &root,
            &options,
            0,
            path::Path::new("/foo"),
            &mut |_| {}
        ));
        assert!(include_hash_file_dir(
            &root,
            &options,
            1,
            path::Path::new("/foo/bar"),
            &mut |_| {}
        ));
        assert!(include_hash_file_dir(
            &root,
            &options,
            2,
            path::Path::new("/foo/bar/baz"),
            &mut |_| {}
        ));
        assert!(!include_hash_file_dir(
            &root,
            &options,
            3,
            path::Path::new("/foo/bar/baz/qux"),
            &mut |_| {}
        ));
        assert!(!include_hash_file_dir(
            &root,
            &options,
            4,
            path::Path::new("/foo/bar/baz/qux/xer"),
            &mut |_| {}
        ));
    }

    #[test]
    fn include_hash_file_dir_respects_hash_files_matcher() {
        let matcher = PathMatcherBuilder::new()
            .allow("**/*.*")
            .unwrap()
            .block("*/home/")
            .unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            hash_files_matcher: matcher,
            ..Default::default()
        };
        let root = path::Path::new("/");

        // TODO should include_hash_file_dir also check if the path could not match any
        //      of the allowed paths?
        //      would be annoying, since you'd have to split up the pattern into components
        //      and match up to the current depth etc.
        //      -> then
        //      .allow("fo*b/**/*.*")
        //      should only allow /foob/, not /foo/
        assert!(include_hash_file_dir(
            &root,
            &options,
            3,
            path::Path::new("/foo"),
            &mut |_| {}
        ));
        assert!(!include_hash_file_dir(
            &root,
            &options,
            3,
            path::Path::new("/foob/home"),
            &mut |_| {}
        ));
    }

    #[test]
    fn include_hash_file_dir_calls_the_progress_callback() {
        let matcher = PathMatcherBuilder::new()
            .allow("**/*.*")
            .unwrap()
            .block("home/")
            .unwrap()
            .build()
            .unwrap();
        let options = ChecksumHelperOptions {
            hash_files_matcher: matcher,
            ..Default::default()
        };
        let root = path::Path::new("/");

        let mut was_called = false;
        assert!(include_hash_file_dir(
            &root,
            &options,
            3,
            path::Path::new("/foo"),
            &mut |_| {}
        ));
        assert!(!was_called);

        assert!(!include_hash_file_dir(
            &root,
            &options,
            3,
            path::Path::new("/home"),
            &mut |p| {
                was_called = true;
                assert!(matches!(
                        p,
                        MostCurrentProgress::IgnoredPath(ref f) if f == path::Path::new("home")
                ));
            }
        ));
        assert!(was_called);
    }
}
