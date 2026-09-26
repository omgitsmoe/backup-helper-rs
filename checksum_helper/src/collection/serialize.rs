use super::{HashCollection, HashCollectionError, Result};

use crate::file_tree::{EntryHandle, FileTree};
use crate::hashed_file::FileRaw;

use hex;

use std::io::Write;
use std::path;

// TODO serialze as single hash file, otherwise we can't move them without
//      converting to .cshd

const VERSION_HEADER: &str = "# version 1\n";
pub fn serialize<W: Write>(
    collection: &HashCollection,
    writer: &mut W,
    file_tree: &FileTree,
    with_header: bool,
) -> Result<()> {
    let prefix = collection.root_prefix(file_tree)?;
    assert!(
        !&prefix.components().any(|c| c == path::Component::ParentDir),
        "prefix contains parent dir components: collection root is not a subpath of the file tree root!");

    if with_header {
        writer.write_all(VERSION_HEADER.as_bytes())?;
    }

    // NOTE: iterate the file tree instead of `collection.map`, which is a hash
    //       map and has no order. The entries end up in the lexical order in
    //       which `gather` yields them.
    let mut entries = collection.iter_sorted(file_tree)?;
    for (path_handle, hashed_file) in entries.by_ref() {
        serialize_entry(writer, &prefix, &path_handle, hashed_file, file_tree)?;
    }
    entries.check_all_yielded()?;

    Ok(())
}

fn serialize_entry<W: Write>(
    writer: &mut W,
    path_prefix: &path::Path,
    path_handle: &EntryHandle,
    hashed_file: &FileRaw,
    file_tree: &FileTree,
) -> Result<()> {
    let path_ft_relative = file_tree.relative_path(path_handle);
    let path = path_ft_relative
        .strip_prefix(path_prefix)
        .expect("serialize checks if the collection root is a subpath of the file tree, so this should not happen!");
    let Some(path) = path.to_str() else {
        return Err(HashCollectionError::NonUnicodePath(path.to_owned()));
    };
    let path = path.replace("\\", "/");
    let mtime = hashed_file.mtime_str().unwrap_or("".to_string());
    let size = match hashed_file.size() {
        Some(size) => size.to_string(),
        None => String::from(""),
    };
    let hash_type = hashed_file.hash_type().to_string();
    let hash_hex = hex::encode(hashed_file.hash_bytes());

    writeln!(writer, "{mtime},{size},{hash_type},{hash_hex} {path}")?;

    Ok(())
}

/// Warning: Does not preserve comments that do not directly follow the
///          header!
pub fn sort_serialized(serialized: &str) -> Option<String> {
    let mut header = Vec::new();
    let iter = serialized.lines();
    let mut lines = Vec::new();

    // Collect header lines manually, ensuring the first non-header line is not consumed
    let mut in_header = true;
    for line in iter {
        let is_comment = line.starts_with('#');
        if in_header {
            if !is_comment {
                in_header = false;
            } else {
                header.push(line);
            }
        }

        if !is_comment {
            lines.push(line.split_once(' ').map(|parts| (line, parts))?);
        }
    }
    lines.sort_by(|a, b| a.1 .1.cmp(b.1 .1));
    let mut result = header
        .iter()
        .chain(lines.iter().map(|(line, _)| line))
        // NOTE: @Perf avoid extra intermediate vec and add directly to a string
        .fold(String::new(), |mut acc, &line| {
            if !acc.is_empty() {
                acc.push('\n'); // Manually add newline instead of join()
            }
            acc.push_str(line);
            acc
        });
    // enforce trailing newline
    result.push('\n');
    Some(result)
}

#[cfg(test)]
mod test {
    use super::super::test::setup_minimal_hc;
    use super::*;
    use crate::hash_type::HashType;
    use crate::test_utils::abs;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_serialize_entry() {
        let mut ft = FileTree::new(abs("foo")).unwrap();
        let mut buf = vec![];
        let prefix = path::Path::new("foo"); // prefix will be stripped from v
        let path_handle = ft.add_file("./foo/bar/baz.txt").unwrap();
        let file = FileRaw::new(
            path_handle.clone(),
            Some(filetime::FileTime::from_unix_time(1337, 1_337_000)),
            Some(1337),
            HashType::Sha512,
            vec![0xde, 0xad, 0xbe, 0xef],
        );

        serialize_entry(&mut buf, prefix, &path_handle, &file, &ft).unwrap();

        let result = std::str::from_utf8(&buf).unwrap();

        assert_eq!(result, "1337.001337,1337,sha512,deadbeef bar/baz.txt\n",);
    }

    #[test]
    fn test_serialize_entry_missing_mtime_and_size() {
        let mut ft = FileTree::new(abs("foo")).unwrap();
        let mut buf = vec![];
        let prefix = path::Path::new("foo");
        let path_handle = ft.add_file("./foo/bar/baz.txt").unwrap();
        let file = FileRaw::new(
            path_handle.clone(),
            None,
            None,
            HashType::Sha3_224,
            vec![0xab, 0xcd, 0xef, 0x09],
        );

        serialize_entry(&mut buf, prefix, &path_handle, &file, &ft).unwrap();

        let result = std::str::from_utf8(&buf).unwrap();

        assert_eq!(result, ",,sha3_224,abcdef09 bar/baz.txt\n",);
    }

    #[test]
    fn test_serialize() {
        let mut buf = vec![];
        let (mut hc, ft, expected_serialization) = setup_minimal_hc(&abs("foo"));
        hc.relocate(abs("foo"));

        serialize(&hc, &mut buf, &ft, true).unwrap();

        let result = std::str::from_utf8(&buf).unwrap();
        assert_eq!(result, expected_serialization,);
    }

    #[test]
    fn test_serialize_strips_collection_root_prefix() {
        // NOTE: The prefix from the FileTree root to the root dir of the collection should
        //       be stripped from paths when serializing.
        let mut ft = FileTree::new(abs("foo")).unwrap();
        let mut hc = HashCollection::new(Some(&abs("foo/foo/bar/foo.cshd")), None).unwrap();
        let path_handle = ft.add_file("./foo/bar/baz.txt").unwrap();
        hc.update(
            path_handle.clone(),
            FileRaw::new(
                path_handle.clone(),
                Some(filetime::FileTime::from_unix_time(1337, 1_330_000)),
                Some(1337),
                HashType::Sha512,
                vec![0xde, 0xad, 0xbe, 0xef],
            ),
        );

        let path_handle = ft.add_file("foo/bar/baz/foo.txt").unwrap();
        hc.update(
            path_handle.clone(),
            FileRaw::new(
                path_handle.clone(),
                Some(filetime::FileTime::from_unix_time(1212, 0)),
                None,
                HashType::Md5,
                vec![0xaa, 0xbb, 0xcc, 0xdd],
            ),
        );

        let path_handle = ft.add_file("./foo/bar/xer.mp4").unwrap();
        hc.update(
            path_handle.clone(),
            FileRaw::new(
                path_handle.clone(),
                None,
                Some(4206969),
                HashType::Sha3_512,
                vec![0xee, 0xff, 0x00, 0x11],
            ),
        );

        // NOTE: a directory is visited before the files next to it, so this is
        //       not the same as sorting the paths
        let expected_serialization = "\
# version 1
1212,,md5,aabbccdd baz/foo.txt
1337.00133,1337,sha512,deadbeef baz.txt
,4206969,sha3_512,eeff0011 xer.mp4\n";

        let mut buf = vec![];
        serialize(&hc, &mut buf, &ft, true).unwrap();

        let result = std::str::from_utf8(&buf).unwrap();
        assert_eq!(result, expected_serialization,);
    }

    #[test]
    fn serialize_with_and_without_header() {
        let mut ft = FileTree::new(abs("foo")).unwrap();
        let mut hc = HashCollection::new(Some(&abs("foo/foo/bar/foo.cshd")), None).unwrap();
        let path_handle = ft.add_file("./foo/bar/baz.txt").unwrap();
        hc.update(
            path_handle.clone(),
            FileRaw::new(
                path_handle.clone(),
                Some(filetime::FileTime::from_unix_time(1337, 1_330_000)),
                Some(1337),
                HashType::Sha512,
                vec![0xde, 0xad, 0xbe, 0xef],
            ),
        );

        let mut buf = vec![];
        serialize(&hc, &mut buf, &ft, true).unwrap();
        let result = std::str::from_utf8(&buf).unwrap();

        assert_eq!(
            result,
            "\
# version 1
1337.00133,1337,sha512,deadbeef baz.txt\n"
        );

        let mut buf = vec![];
        serialize(&hc, &mut buf, &ft, false).unwrap();
        let result = std::str::from_utf8(&buf).unwrap();
        assert_eq!(
            result,
            "\
1337.00133,1337,sha512,deadbeef baz.txt\n"
        );
    }

    #[test]
    fn test_serialize_sorts_independently_of_insertion_order() {
        // NOTE: the collection's map is a hash map and the file tree is filled
        //       in whatever order the entries are discovered (e.g. parsing
        //       several hash files, merged by mtime), so the serialized order
        //       has to come from the tree
        let mut ft = FileTree::new(abs("foo")).unwrap();
        let mut hc = HashCollection::new(Some(&abs("foo/foo.cshd")), None).unwrap();

        for path in [
            "vid.mp4",
            "subdir/other/file.txt",
            "file.txt",
            "subdir/foo.txt",
        ] {
            let path_handle = ft.add_file(path).unwrap();
            hc.update(
                path_handle.clone(),
                FileRaw::new(
                    path_handle,
                    None,
                    None,
                    HashType::Md5,
                    vec![0xde, 0xad, 0xbe, 0xef],
                ),
            );
        }

        let mut buf = vec![];
        serialize(&hc, &mut buf, &ft, true).unwrap();

        assert_eq!(
            std::str::from_utf8(&buf).unwrap(),
            "\
# version 1
,,md5,deadbeef file.txt
,,md5,deadbeef subdir/foo.txt
,,md5,deadbeef subdir/other/file.txt
,,md5,deadbeef vid.mp4\n"
        );
    }

    #[test]
    fn test_sort_serialized() {
        let unsorted = "\
# version 1
# comment
,4206969,sha3_512,eeff0011 xer.mp4
# comment intra
1212,,md5,aabbccdd bar/foo.txt
# comment intra2
1337.001337,1337,sha512,deadbeef foo/bar/baz.txt";

        assert_eq!(
            sort_serialized(unsorted).unwrap(),
            "\
# version 1
# comment
1212,,md5,aabbccdd bar/foo.txt
1337.001337,1337,sha512,deadbeef foo/bar/baz.txt
,4206969,sha3_512,eeff0011 xer.mp4\n",
        );
    }
}
