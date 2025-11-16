use super::{is_path_above_hash_file, HashCollection, HashCollectionError, Result};

use crate::file_tree::{is_absolute, FileTree};
use crate::hash_type::HashType;
use crate::hashed_file::FileRaw;

use hex;
use pathdiff::diff_paths;
use log::{error, warn};

use std::io::BufRead;
use std::path::{Path, PathBuf};

// TODO separate parser that just has a feed/feed_line method -> more flexible?
pub fn parse<R: BufRead>(reader: R, collection_path: impl AsRef<Path>, file_tree: &mut FileTree) -> Result<HashCollection> {
    let mut lines = reader.lines();
    let mut result =
        HashCollection::new(Some(&collection_path), None).expect("should always succeed without root");
    let mut warned_above_hash_file = false;

    let prefix = ft_to_collection_root_prefix(&result, file_tree)?;
    let version = match &lines.next() {
        Some(Ok(line)) => {
            let (found, version) = parse_version_header(&line)?;
            if !found {
                // no header line found, parse the line
                parse_line(
                    line,
                    &prefix,
                    file_tree,
                    version,
                    &mut warned_above_hash_file,
                    &mut result,
                )?;
            }
            version
        }
        Some(Err(e)) => return Err(HashCollectionError::IOError(e.kind())),
        // no error, but there was no line -> empty string
        None => return Ok(result),
    };

    for line in lines {
        match line {
            Ok(line) => parse_line(
                &line,
                &prefix,
                file_tree,
                version,
                &mut warned_above_hash_file,
                &mut result,
            )?,
            Err(e) => return Err(HashCollectionError::IOError(e.kind())),
        };
    }

    Ok(result)
}

fn ft_to_collection_root_prefix(collection: &HashCollection, file_tree: &FileTree) -> Result<PathBuf> {
    let root = &collection.root_dir
        .as_ref()
        .expect("expected to be set by parse on the hash collection");
    let prefix = diff_paths(
        root, file_tree.absolute_path(&file_tree.root()))
        .ok_or_else(|| HashCollectionError::InvalidCollectionRoot(Some((*root).clone())))?;
    Ok(prefix)
}

pub fn parse_single_hash<R: BufRead>(
    reader: R,
    hash_type: HashType,
    collection_path: impl AsRef<Path>,
    file_tree: &mut FileTree,
) -> Result<HashCollection> {
    let mut result =
        HashCollection::new(Some(&collection_path), None).expect("should always succeed without root");
    let prefix = ft_to_collection_root_prefix(&result, file_tree)?;
    for line in reader.lines() { match line {
            Ok(line) => {
                let (hash_hex, mut file_path) = line.split_once(' ').ok_or_else(|| {
                    HashCollectionError::InvalidSingleHashLine((line.to_string(), "".to_string()))
                })?;
                // strip ' ' (text mode) and '*' (binary mode) from GNU md5sum-style files
                if file_path.starts_with(' ') || file_path.starts_with('*') {
                    file_path = &file_path[1..];
                }
                let file_path = prefix.join(file_path);
                let path_handle = file_tree
                    .add(&file_path, false)
                    .map_err(HashCollectionError::FileTreeError)?;
                result.update(
                    path_handle.clone(),
                    FileRaw::new(
                        path_handle.clone(),
                        None,
                        None,
                        hash_type,
                        hex::decode(hash_hex).map_err(|_| {
                            HashCollectionError::InvalidSingleHashLine((
                                hash_hex.to_string(),
                                format!("{:?}", file_path),
                            ))
                        })?,
                    ),
                )
            }
            Err(e) => return Err(HashCollectionError::IOError(e.kind())),
        };
    }

    Ok(result)
}

fn parse_line(
    line: &str,
    prefix: &Path,
    file_tree: &mut FileTree,
    version: u32,
    warned_above_hash_file: &mut bool,
    result: &mut HashCollection,
) -> Result<()> {
    if line.starts_with('#') {
        return Ok(());
    }

    if line.trim().is_empty() {
        return Ok(());
    }

    let (mtime, rest) = parse_mtime(line)?;
    let (size, rest) = if version > 0 {
        parse_size(rest)?
    } else {
        (None, rest)
    };

    let (hash_type, hash_bytes, file_path) = parse_hash(rest)?;

    if !*warned_above_hash_file && is_path_above_hash_file(file_path) {
        warn!(
            "Found a file path going beyond the hash file's directory. \
                This is strongly discouraged, as it makes the hash file \
                not portable! Path: {}",
            file_path
        );
        *warned_above_hash_file = true;
    }

    let file_path = prefix.join(file_path);
    let path_handle = match file_tree.add(&file_path, false) {
        Ok(path_handle) => path_handle,
        Err(e) => return Err(HashCollectionError::FileTreeError(e)),
    };

    if let Some(old) = result.map.insert(
        path_handle.clone(),
        FileRaw::new(path_handle, mtime, size, hash_type, hash_bytes),
    ) {
        error!(
            "Duplicate file path: {}",
            old.relative_path_to(file_tree, result.root_dir.as_ref()
                .expect("root_dir is expected to be known in parse_line!")).display()
        );
    };

    Ok(())
}

fn parse_version_header(line: &str) -> Result<(bool, u32)> {
    if line.starts_with("# version ") {
        let version_start = line
            .strip_prefix("# version ")
            .expect("must not fail, was checked above");
        let version_str = version_start.trim();

        Ok((
            true,
            version_str.parse::<u32>().map_err(|_| {
                error!(
                    "Malformed version number, expected an usigned integer, got {}",
                    version_str
                );
                HashCollectionError::InvalidVersionHeader(version_str.to_owned())
            })?,
        ))
    } else {
        Ok((false, 0))
    }
}

fn parse_mtime(str: &str) -> Result<(Option<filetime::FileTime>, &str)> {
    let Some((mtime, rest)) = str.split_once(',') else {
        error!(
            "Expected ',' delimeter after modification time field, got '{}'",
            str
        );
        return Err(HashCollectionError::InvalidHashLine((
            str.to_owned(),
            String::new(),
        )));
    };
    let mtime = mtime.trim();
    if mtime.is_empty() {
        return Ok((None, rest));
    }
    let Ok(mtime) = mtime.parse::<f64>() else {
        error!("Failed to parse modification time string: {}", mtime);
        return Err(HashCollectionError::InvalidHashLine((
            mtime.to_owned(),
            str.to_owned(),
        )));
    };

    const NS_PER_SEC: f64 = 1_000_000_000.0;
    let seconds = mtime.trunc() as i64;
    let nanoseconds = (mtime.fract() * NS_PER_SEC) as u32;
    let mtime = filetime::FileTime::from_unix_time(seconds, nanoseconds);

    Ok((Some(mtime), rest))
}

fn parse_size(str: &str) -> Result<(Option<u64>, &str)> {
    let (size_str, after_size) =
        str.split_once(',')
            .ok_or(HashCollectionError::InvalidHashLine((
                str.to_owned(),
                String::new(),
            )))?;
    let size_str = size_str.trim();
    if size_str.is_empty() {
        return Ok((None, after_size));
    }

    Ok((
        Some(size_str.parse::<u64>().map_err(|_| {
            HashCollectionError::InvalidHashLine((size_str.to_owned(), str.to_owned()))
        })?),
        after_size,
    ))
}

fn parse_hash(str: &str) -> Result<(HashType, Vec<u8>, &str)> {
    let Some((hash_type, rest)) = str.split_once(',') else {
        error!("Expected ',' delimiter after hash type, got '{}'", str);
        return Err(HashCollectionError::InvalidHashLine((
            str.to_owned(),
            String::new(),
        )));
    };
    let Ok(hash_type): std::result::Result<HashType, _> = hash_type.try_into() else {
        error!("Malformed or unsupported hash type '{}'", hash_type);
        return Err(HashCollectionError::UnsupportedHashType(
            hash_type.to_owned(),
        ));
    };

    let Some((hash_hex, file_path)) = rest.split_once(' ') else {
        error!("Expected ' ' delimiter after hash type, got '{}'", str);
        return Err(HashCollectionError::InvalidHashLine((
            rest.to_owned(),
            String::new(),
        )));
    };

    let Ok(hash_bytes) = hex::decode(hash_hex) else {
        error!(
            "Malformed hex representation of hash '{}': '{}'",
            hash_type.to_str(),
            hash_hex
        );
        return Err(HashCollectionError::InvalidHashLine((
            hash_hex.to_owned(),
            String::new(),
        )));
    };

    if is_absolute(file_path) {
        error!(
            "Only relative paths are allowed in hash files, but found: {}",
            file_path
        );
        return Err(HashCollectionError::AbsolutePath(file_path.to_owned()));
    }

    Ok((hash_type, hash_bytes, file_path))
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;
    use crate::test_utils::*;
    use filetime::FileTime;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_parse_version_header_no_version() {
        assert_eq!(parse_version_header("").unwrap(), (false, 0));
        assert_eq!(parse_version_header("# ver foo").unwrap(), (false, 0));
        assert_eq!(parse_version_header("# foo").unwrap(), (false, 0));
    }

    #[test]
    fn test_parse_version_header_with_version() {
        assert_eq!(parse_version_header("# version 1\n").unwrap(), (true, 1));
        assert_eq!(
            parse_version_header("# version 1337\n").unwrap(),
            (true, 1337)
        );
        assert_eq!(
            parse_version_header("# version    1337    \n").unwrap(),
            (true, 1337)
        );
    }

    #[test]
    fn test_parse_version_header_error_cases() {
        // malformed version number
        assert_eq!(
            parse_version_header("# version foo"),
            Err(HashCollectionError::InvalidVersionHeader("foo".to_string()))
        );
        assert_eq!(
            parse_version_header("# version 13.37"),
            Err(HashCollectionError::InvalidVersionHeader(
                "13.37".to_string()
            ))
        );
    }

    #[test]
    fn test_parse_mtime_empty() {
        assert_eq!(parse_mtime(",foo,bar"), Ok((None, "foo,bar")));
        assert_eq!(parse_mtime("   ,foo,bar"), Ok((None, "foo,bar")));
    }

    // TODO: error cases
    #[test]
    fn test_parse_mtime() {
        assert_eq!(
            parse_mtime("1337,foo,bar"),
            Ok((Some(FileTime::from_unix_time(1337, 0)), "foo,bar"))
        );
        assert_eq!(
            parse_mtime("   1337.00133     ,foo,bar"),
            Ok((Some(FileTime::from_unix_time(1337, 1_330_000)), "foo,bar"))
        );
    }

    #[test]
    fn test_parse_size_empty() {
        assert_eq!(parse_size(",foo,bar"), Ok((None, "foo,bar")));
        assert_eq!(parse_size("   ,foo,bar"), Ok((None, "foo,bar")));
    }

    // TODO: error cases
    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("42069,foo,bar"), Ok((Some(42069), "foo,bar")));
        assert_eq!(
            parse_size("   1337   ,foo,bar"),
            Ok((Some(1337), "foo,bar"))
        );
    }

    #[test]
    fn test_parse_handles_empty_string() {
        let mut ft = FileTree::new(Path::new("/foo")).unwrap();
        assert!(parse(Cursor::new(""), Path::new("/foo/hc.cshd"), &mut ft,)
            .inspect_err(|e| println!("{}", e))
            .is_ok());

        assert!(parse(Cursor::new("\n"), Path::new("/foo/hc.cshd"), &mut ft,)
            .inspect_err(|e| println!("{}", e))
            .is_ok());
    }

    #[test]
    fn parse_line_respects_prefix() {
        let mut ft = FileTree::new(Path::new("/foo")).unwrap();
        let mut hc = HashCollection::new(
            Some(&Path::new("/foo/hc.cshd")), None)
            .unwrap();
        let line = "123,1337,md5,aabbccdd foo/bar/baz.txt";

        parse_line(line, Path::new("bar"), &mut ft, 1, &mut false, &mut hc)
            .unwrap();

        let (path_handle, _file) = hc.map.iter().next().unwrap();
        let path = ft.relative_path(path_handle);
        assert_eq!(path, Path::new("bar/foo/bar/baz.txt"));
    }

    #[test]
    fn test_parse_version_1() {
        let mut ft = FileTree::new(Path::new("/foo")).unwrap();
        let mtime = "1673815645.7979772";
        let size = 1337;
        let hash_type = HashType::Sha512;
        let hash_hex = "90b834a83748223190dd1cce445bb1e7582e55948234e962aba9a3004cc558ce061c865a4fae255e048768e7d7011f958dad463243bb3560ee49335ec4c9e8a0";
        let file_path = ".gitignore";
        let hc = parse(
            Cursor::new(format!(
                "\
# version 1
{},{},{},{} {}
0,1337,md5,abcdef foo/bar/baz
,,sha3_256,abcdefff foo/xer.mp4
\
        ",
                mtime,
                size,
                hash_type.to_str(),
                hash_hex,
                file_path
            )),
            Path::new("/foo/bar/hc.cshd"),
            &mut ft,
        )
        .inspect_err(|e| println!("{}", e))
        .unwrap();

        let key = ft.find("bar/.gitignore").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new("bar/.gitignore"));
        assert_eq!(hf.relative_path_to(&ft, hc.root_dir.as_ref().unwrap()), Path::new(".gitignore"));
        assert_eq!(hf.mtime_str(), Some(mtime.to_owned()));
        assert_eq!(hf.size(), Some(size));
        assert_eq!(hf.hash_type(), hash_type);
        assert_eq!(hf.hash_bytes(), hex::decode(hash_hex).unwrap());

        let key = ft.find("bar/foo/xer.mp4").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new("bar/foo/xer.mp4"));
        assert_eq!(hf.relative_path_to(&ft, hc.root_dir.as_ref().unwrap()), Path::new("foo/xer.mp4"));
        assert_eq!(hf.mtime_str(), None);
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), HashType::Sha3_256);
        assert_eq!(hf.hash_bytes(), vec![0xab, 0xcd, 0xef, 0xff]);

        assert_eq!(
            to_file_list(&ft),
            "FileTree{
  bar/.gitignore
  bar/foo/bar/baz
  bar/foo/xer.mp4
}"
        );
    }

    #[test]
    fn test_parse_version_0() {
        let mut ft = FileTree::new(Path::new("/foo")).unwrap();
        let mtime = "1673815645.7979772";
        let hash_type = HashType::Sha512;
        let hash_hex = "90b834a83748223190dd1cce445bb1e7582e55948234e962aba9a3004cc558ce061c865a4fae255e048768e7d7011f958dad463243bb3560ee49335ec4c9e8a0";
        let file_path = ".gitignore";
        let hc = parse(
            Cursor::new(&format!(
                "\
{},{},{} {}
0,md5,abcdefff foo/bar/baz
,sha3_256,abcdefff foo/xer.mp4
\
        ",
                mtime,
                hash_type.to_str(),
                hash_hex,
                file_path
            )),
            Path::new("/foo/bar/hc.cshd"),
            &mut ft,
        )
        .inspect_err(|e| println!("{}", e))
        .unwrap();

        let key = ft.find("bar/.gitignore").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new("bar/.gitignore"));
        assert_eq!(hf.relative_path_to(&ft, hc.root_dir.as_ref().unwrap()), Path::new(".gitignore"));
        assert_eq!(hf.mtime_str(), Some(mtime.to_owned()));
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), hash_type);
        assert_eq!(hf.hash_bytes(), hex::decode(hash_hex).unwrap());

        let key = ft.find("bar/foo/bar/baz").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new("bar/foo/bar/baz"));
        assert_eq!(hf.relative_path_to(&ft, hc.root_dir.as_ref().unwrap()), Path::new("foo/bar/baz"));
        assert_eq!(hf.mtime_str(), Some("0".to_string()));
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), HashType::Md5);
        assert_eq!(hf.hash_bytes(), vec![0xab, 0xcd, 0xef, 0xff]);

        let key = ft.find("bar/foo/xer.mp4").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new("bar/foo/xer.mp4"));
        assert_eq!(hf.relative_path_to(&ft, hc.root_dir.as_ref().unwrap()), Path::new("foo/xer.mp4"));
        assert_eq!(hf.mtime_str(), None);
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), HashType::Sha3_256);
        assert_eq!(hf.hash_bytes(), vec![0xab, 0xcd, 0xef, 0xff]);

        assert_eq!(
            to_file_list(&ft),
            "FileTree{
  bar/.gitignore
  bar/foo/bar/baz
  bar/foo/xer.mp4
}"
        );
    }

    #[test]
    fn test_parse_single_hash() {
        let mut ft = FileTree::new(Path::new("/foo")).unwrap();
        let hash_type = HashType::Sha512;
        let hash_hex = "90b834a83748223190dd1cce445bb1e7582e55948234e962aba9a3004cc558ce061c865a4fae255e048768e7d7011f958dad463243bb3560ee49335ec4c9e8a0";
        let file_path = ".gitignore";
        let hc = parse_single_hash(
            Cursor::new(&format!(
                "\
{} {}
abcdefff  foo/bar/baz
abcdefff *foo/xer.mp4
\
        ",
                hash_hex,
                file_path
            )),
            hash_type,
            Path::new("/foo/hc.cshd"),
            &mut ft,
        )
        .inspect_err(|e| println!("{}", e))
        .unwrap();

        let key = ft.find(".gitignore").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new(file_path));
        assert_eq!(hf.relative_path_to(&ft, hc.root_dir.as_ref().unwrap()), Path::new(".gitignore"));
        assert_eq!(hf.mtime_str(), None);
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), hash_type);
        assert_eq!(hf.hash_bytes(), hex::decode(hash_hex).unwrap());

        let key = ft.find("foo/bar/baz").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new("foo/bar/baz"));
        assert_eq!(hf.relative_path_to(&ft, hc.root_dir.as_ref().unwrap()), Path::new("foo/bar/baz"));
        assert_eq!(hf.mtime_str(), None);
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), hash_type);
        assert_eq!(hf.hash_bytes(), vec![0xab, 0xcd, 0xef, 0xff]);

        let key = ft.find("foo/xer.mp4").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new("foo/xer.mp4"));
        assert_eq!(hf.relative_path_to(&ft, hc.root_dir.as_ref().unwrap()), Path::new("foo/xer.mp4"));
        assert_eq!(hf.mtime_str(), None);
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), hash_type);
        assert_eq!(hf.hash_bytes(), vec![0xab, 0xcd, 0xef, 0xff]);

        assert_eq!(
            to_file_list(&ft),
            "FileTree{
  .gitignore
  foo/bar/baz
  foo/xer.mp4
}"
        );
    }

    #[test]
    fn test_parse_single_hash_respects_ft_root() {
        let mut ft = FileTree::new(Path::new("/foo")).unwrap();
        let hash_type = HashType::Sha512;
        let hash_hex = "90b834a83748223190dd1cce445bb1e7582e55948234e962aba9a3004cc558ce061c865a4fae255e048768e7d7011f958dad463243bb3560ee49335ec4c9e8a0";
        let file_path = ".gitignore";
        let hc = parse_single_hash(
            Cursor::new(&format!(
                "\
{} {}
abcdefff foo/bar/baz
abcdefff foo/xer.mp4
\
        ",
                hash_hex,
                file_path
            )),
            hash_type,
            Path::new("/foo/bar/hc.cshd"),
            &mut ft,
        )
        .inspect_err(|e| println!("{}", e))
        .unwrap();

        let key = ft.find("bar/.gitignore").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new("bar/.gitignore"));
        assert_eq!(hf.relative_path_to(&ft, hc.root_dir.as_ref().unwrap()), Path::new(".gitignore"));
        assert_eq!(hf.mtime_str(), None);
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), hash_type);
        assert_eq!(hf.hash_bytes(), hex::decode(hash_hex).unwrap());

        let key = ft.find("bar/foo/bar/baz").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new("bar/foo/bar/baz"));
        assert_eq!(hf.relative_path_to(&ft, hc.root_dir.as_ref().unwrap()), Path::new("foo/bar/baz"));
        assert_eq!(hf.mtime_str(), None);
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), hash_type);
        assert_eq!(hf.hash_bytes(), vec![0xab, 0xcd, 0xef, 0xff]);

        let key = ft.find("bar/foo/xer.mp4").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new("bar/foo/xer.mp4"));
        assert_eq!(hf.relative_path_to(&ft, hc.root_dir.as_ref().unwrap()), Path::new("foo/xer.mp4"));
        assert_eq!(hf.mtime_str(), None);
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), hash_type);
        assert_eq!(hf.hash_bytes(), vec![0xab, 0xcd, 0xef, 0xff]);

        assert_eq!(
            to_file_list(&ft),
            "FileTree{
  bar/.gitignore
  bar/foo/bar/baz
  bar/foo/xer.mp4
}"
        );
    }

    #[test]
    fn parse_respects_ft_root() {
        let mut ft = FileTree::new(Path::new("/foo")).unwrap();
        let mtime = "1673815645.7979772";
        let hash_type = HashType::Sha512;
        let hash_hex = "90b834a83748223190dd1cce445bb1e7582e55948234e962aba9a3004cc558ce061c865a4fae255e048768e7d7011f958dad463243bb3560ee49335ec4c9e8a0";
        let file_path = ".gitignore";
        let hc = parse(
            Cursor::new(&format!(
                "\
{},{},{} {}
0,md5,abcdefff foo/bar/baz
,sha3_256,abcdefff foo/xer.mp4
\
        ",
                mtime,
                hash_type.to_str(),
                hash_hex,
                file_path
            )),
            Path::new("/foo/bar/hc.cshd"),
            &mut ft,
        )
        .inspect_err(|e| println!("{}", e))
        .unwrap();

        let key = ft.find("bar/.gitignore").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new("bar/.gitignore"));
        assert_eq!(hf.relative_path_to(&ft, hc.root_dir.as_ref().unwrap()), Path::new(".gitignore"));
        assert_eq!(hf.mtime_str(), Some(mtime.to_owned()));
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), hash_type);
        assert_eq!(hf.hash_bytes(), hex::decode(hash_hex).unwrap());

        let key = ft.find("bar/foo/bar/baz").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new("bar/foo/bar/baz"));
        assert_eq!(hf.relative_path_to(&ft, hc.root_dir.as_ref().unwrap()), Path::new("foo/bar/baz"));
        assert_eq!(hf.mtime_str(), Some("0".to_string()));
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), HashType::Md5);
        assert_eq!(hf.hash_bytes(), vec![0xab, 0xcd, 0xef, 0xff]);

        let key = ft.find("bar/foo/xer.mp4").unwrap();
        let hf = &hc.map[&key];
        assert_eq!(hf.relative_path(&ft), Path::new("bar/foo/xer.mp4"));
        assert_eq!(hf.relative_path_to(&ft, hc.root_dir.as_ref().unwrap()), Path::new("foo/xer.mp4"));
        assert_eq!(hf.mtime_str(), None);
        assert_eq!(hf.size(), None);
        assert_eq!(hf.hash_type(), HashType::Sha3_256);
        assert_eq!(hf.hash_bytes(), vec![0xab, 0xcd, 0xef, 0xff]);

        assert_eq!(
            to_file_list(&ft),
            "FileTree{
  bar/.gitignore
  bar/foo/bar/baz
  bar/foo/xer.mp4
}"
        );
    }
}
