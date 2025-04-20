use super::{HashCollection, HashCollectionError, Result};

use crate::file_tree::{EntryHandle, FileTree};
use crate::hashed_file::{FileRaw, HashType};

use pathdiff::diff_paths;
use hex;

use std::io::Write;
use std::path;

// TODO serialze as single hash file, otherwise we can't move them without
//      converting to .cshd

const VERSION_HEADER: &str = "# version 1\n";
pub fn serialize<W: Write>(collection: &HashCollection, writer: &mut W, file_tree: &FileTree) -> Result<()> {
    let prefix = match &collection.root_dir {
        None => return Err(HashCollectionError::MissingPath(
                (collection.root_dir.clone(), collection.name.clone()))),
        Some(hc_root) => {
            let ft_root = file_tree.absolute_path(&file_tree.root());
            diff_paths(hc_root, ft_root)
                .ok_or_else(||
                    HashCollectionError::InvalidCollectionRoot(Some(hc_root.clone())))?
        },
    };
    assert!(
        !&prefix.components().any(|c| c == path::Component::ParentDir),
        "prefix contains parent dir components: collection root is not a subpath of the file tree root!");

    writer.write_all(VERSION_HEADER.as_bytes())?;
    for (path_handle, hashed_file) in &collection.map {
        serialize_entry(writer, &prefix, path_handle, hashed_file, file_tree)?;
    }
    Ok(())
}

// TODO test that an entry gets its correct path when the FT has a different root than the collection
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

    write!(writer, "{mtime},{size},{hash_type},{hash_hex} {path}\n")?;

    Ok(())
}

/// Warning: Does not preserve comments that do not directly follow the
///          header!
pub fn sort_serialized(serialized: &str) -> Option<String> {
    let mut header = Vec::new();
    let mut iter = serialized.lines();
    let mut lines = Vec::new();

    // Collect header lines manually, ensuring the first non-header line is not consumed
    let mut in_header = true;
    while let Some(line) = iter.next() {
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
    use super::*;
    use super::super::test::setup_minimal_hc;
    use pretty_assertions::assert_eq;
    use std::path::Path;

    #[test]
    fn test_serialize_entry() {
        let mut ft = FileTree::new(Path::new("/foo")).unwrap();
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
        let mut ft = FileTree::new(Path::new("/foo")).unwrap();
        let mut buf = vec![];
        let prefix = path::Path::new("foo");
        let path_handle = ft.add_file("./foo/bar/baz.txt").unwrap();
        let file = FileRaw::new(
            path_handle.clone(),
            None,
            None,
            HashType::Blake2s,
            vec![0xab, 0xcd, 0xef, 0x09],
        );

        serialize_entry(&mut buf, prefix, &path_handle, &file, &ft).unwrap();

        let result = std::str::from_utf8(&buf).unwrap();

        assert_eq!(result, ",,blake2s,abcdef09 bar/baz.txt\n",);
    }

    #[test]
    fn test_serialize() {
        let mut buf = vec![];
        let (mut hc, ft, expected_serialization) = setup_minimal_hc(Path::new("/foo"));
        hc.relocate(Path::new("/foo"));

        serialize(&hc, &mut buf, &ft).unwrap();

        let result = sort_serialized(std::str::from_utf8(&buf).unwrap()).unwrap();
        assert_eq!(
            result,
            expected_serialization,
        );
    }

    #[test]
    fn test_serialize_strips_collection_root_prefix() {
        // NOTE: The prefix from the FileTree root to the root dir of the collection should
        //       be stripped from paths when serializing.
        let mut ft = FileTree::new(Path::new("/foo")).unwrap();
        let mut hc = HashCollection::new(
            Some(&"/foo/foo/bar/foo.cshd"), None).unwrap();
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

        let expected_serialization_sorted = "\
# version 1
1337.00133,1337,sha512,deadbeef baz.txt
1212,,md5,aabbccdd baz/foo.txt
,4206969,sha3_512,eeff0011 xer.mp4\n";

        let mut buf = vec![];
        serialize(&hc, &mut buf, &ft).unwrap();

        let result = sort_serialized(std::str::from_utf8(&buf).unwrap()).unwrap();
        assert_eq!(
            result,
            expected_serialization_sorted,
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
