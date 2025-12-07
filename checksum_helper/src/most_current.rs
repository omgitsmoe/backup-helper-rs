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

    if options.most_current_filter_deleted {
        // TODO + callback?
        most_current.filter_missing(file_tree)?;
    }

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

    fn setup_dir_two_hash_files_with_deleted() -> (std::path::PathBuf, Vec<&'static str>) {
        let testdir = testdir!();
        create_ftree(
            &testdir,
            "\
foo/bar/baz/file.txt
foo/bar/bar.mp4
foo/foo.bin
bar/baz/save.sav
file.rs",
        );

        // missing, should be taken from md5:
        // 1765124822.268275,15,sha512,2cff1435df6bb662a8297cc28f6b00803f91b8dc49d879099e19596b95319a7c2b8a8643ff090ed520f59efc5d5d9a3d9a2c4602dec2fd0996fd60a725947e17 foo/bar/bar.mp4
        // baz/file.txt should also be taken from md5 since mtime is newer
        let root_cshd_contents = "\
# version 1
1765124822.2688851,16,sha512,5b7f0dd92e529aa88471152757a796a548244c2330123a5fe9eb237fac38e2daffd22d765901c0f8af7bc466ed178d635cb31f323fdbc61806291526e7581df1 bar/baz/save.sav
1765124822.2695565,7,sha512,617cf33d1fda9f6f15d686c41cfb03ef959a6296956cf9275c99a2890bce44033d77f2995e2f6c080d156e4af681333dc2314c17eec2667a5fb7639ffd41c986 file.rs
1765124822.2679887,20,sha512,368ade34bd90afe3db2a9a655e883288aef03284cb40481def21b62a9a0b66a7d048a3264c836d6f48fa536daa319e9acb53e21ad6cea3982ad77c90174e8939 foo/bar/baz/file.txt
1765124822.2691188,13,sha512,7d7cabd45d04fcc5b8609c01eecf46f05fa205fc44d99e23568fae9d80ff787fb47d26886b2ea6259d0a5d76ef657feeeb3103d851343da5ef322ce98ca24617 bar/other.txt
1765124822.2685325,11,sha512,847f8f7a2df6539773aa192eb7e449b26cb765aeea13e66010be6ae14a447bfcea4ef99628dffd2dbcd17c624164c521692f43e5e8894955d0fa393b86112b44 foo/foo.bin
1765124822.269339,7,sha512,d0fa60060582bca8845761653d41a4e60f13d00c458c745adc7b16e4c05afbc873fcce18fa37338d6ad65bbd6c4f4bd98f8fbfc8d9065237a7f739314ec1585d vid.mp4\
";
        std::fs::write(testdir.join("root.cshd"), root_cshd_contents).unwrap();

        let foo_bar_file_md5_contents = "\
d4ca4c74d827424ca5e6cb552cc039d3 *bar.mp4
ac06ffd974d80119666da2b17d1595c9 *baz/file.txt\
";
        std::fs::write(
            testdir.join("foo").join("bar").join("file.md5"),
            foo_bar_file_md5_contents,
        )
        .unwrap();

        let deleted = vec![
            "bar/other.txt",
            "vid.mp4",
        ];
        (testdir, deleted)
    }

    #[test]
    fn update_most_current_merges_discovered_hash_files() {
        let (testdir, _deleted_relative) = setup_dir_two_hash_files_with_deleted();
        let options = ChecksumHelperOptions {
            most_current_filter_deleted: false,
            ..Default::default()
        };
        let mut ft = FileTree::new(&testdir).unwrap();

        let most_current = update_most_current(&testdir, &mut ft, &options, |_| {}).unwrap();

        let expected = "\
# version 1
1765124822.2688851,16,sha512,5b7f0dd92e529aa88471152757a796a548244c2330123a5fe9eb237fac38e2daffd22d765901c0f8af7bc466ed178d635cb31f323fdbc61806291526e7581df1 bar/baz/save.sav
1765124822.2695565,7,sha512,617cf33d1fda9f6f15d686c41cfb03ef959a6296956cf9275c99a2890bce44033d77f2995e2f6c080d156e4af681333dc2314c17eec2667a5fb7639ffd41c986 file.rs
,,md5,ac06ffd974d80119666da2b17d1595c9 foo/bar/baz/file.txt
1765124822.2691188,13,sha512,7d7cabd45d04fcc5b8609c01eecf46f05fa205fc44d99e23568fae9d80ff787fb47d26886b2ea6259d0a5d76ef657feeeb3103d851343da5ef322ce98ca24617 bar/other.txt
1765124822.2685325,11,sha512,847f8f7a2df6539773aa192eb7e449b26cb765aeea13e66010be6ae14a447bfcea4ef99628dffd2dbcd17c624164c521692f43e5e8894955d0fa393b86112b44 foo/foo.bin
1765124822.269339,7,sha512,d0fa60060582bca8845761653d41a4e60f13d00c458c745adc7b16e4c05afbc873fcce18fa37338d6ad65bbd6c4f4bd98f8fbfc8d9065237a7f739314ec1585d vid.mp4
,,md5,d4ca4c74d827424ca5e6cb552cc039d3 foo/bar/bar.mp4
";

        assert_eq!(
            most_current.to_str(&ft).unwrap(),
            expected,
        );
    }

    #[test]
    fn update_most_current_filters_deleted_files_by_default() {
        let (testdir, deleted_relative) = setup_dir_two_hash_files_with_deleted();
        let options = ChecksumHelperOptions {
            ..Default::default()
        };
        let mut ft = FileTree::new(&testdir).unwrap();

        let most_current = update_most_current(&testdir, &mut ft, &options, |_| {}).unwrap();


        for deleted_path in deleted_relative {
            assert!(!most_current.contains_path(deleted_path, &ft));
        }

        let expected = "\
# version 1
1765124822.2688851,16,sha512,5b7f0dd92e529aa88471152757a796a548244c2330123a5fe9eb237fac38e2daffd22d765901c0f8af7bc466ed178d635cb31f323fdbc61806291526e7581df1 bar/baz/save.sav
1765124822.2695565,7,sha512,617cf33d1fda9f6f15d686c41cfb03ef959a6296956cf9275c99a2890bce44033d77f2995e2f6c080d156e4af681333dc2314c17eec2667a5fb7639ffd41c986 file.rs
,,md5,ac06ffd974d80119666da2b17d1595c9 foo/bar/baz/file.txt
1765124822.2685325,11,sha512,847f8f7a2df6539773aa192eb7e449b26cb765aeea13e66010be6ae14a447bfcea4ef99628dffd2dbcd17c624164c521692f43e5e8894955d0fa393b86112b44 foo/foo.bin
,,md5,d4ca4c74d827424ca5e6cb552cc039d3 foo/bar/bar.mp4
";

        assert_eq!(
            most_current.to_str(&ft).unwrap(),
            expected,
        );
    }

    #[test]
    fn update_most_current_respects_keep_deleted_option() {
        let (testdir, deleted_relative) = setup_dir_two_hash_files_with_deleted();
        let options = ChecksumHelperOptions {
            most_current_filter_deleted: false,
            ..Default::default()
        };
        let mut ft = FileTree::new(&testdir).unwrap();

        let most_current = update_most_current(&testdir, &mut ft, &options, |_| {}).unwrap();

        for deleted_path in deleted_relative {
            assert!(most_current.contains_path(deleted_path, &ft));
        }
    }
}
