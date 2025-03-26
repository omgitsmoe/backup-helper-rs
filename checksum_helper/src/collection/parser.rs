use super::{HashCollection, HashCollectionError, Result, is_path_above_hash_file};

use crate::file_tree::{is_absolute, FileTree};
use crate::hashed_file::{FileRaw, HashType};

use hex;
use log::{error, warn};

use std::io::{BufRead, Cursor};
use std::path::Path;

// TODO from single hash file with hash_type as parameter
// TODO separate parser that just has a feed/feed_line method -> more flexible?
pub fn parse<R: BufRead>(reader: R, file_tree: &mut FileTree) -> Result<HashCollection> {
    let mut lines = reader.lines();
    let mut result =
        HashCollection::new(None::<&&str>).expect("should always succeed without root");
    let mut warned_above_hash_file = false;

    let version = match &lines.next() {
        Some(Ok(line)) => {
            let (found, version) = parse_version_header(&line)?;
            if !found {
                // no header line found, parse the line
                parse_line(
                    &line,
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

fn parse_line(
    line: &str,
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

    let path_handle = match file_tree.add(Path::new(file_path), false) {
        Ok(path_handle) => path_handle,
        Err(e) => return Err(HashCollectionError::FileTreeError(e)),
    };

    if let Some(old) = result.map.insert(
        path_handle.clone(),
        FileRaw::new(path_handle, mtime, size, hash_type, hash_bytes),
    ) {
        error!(
            "Duplicate file path: {}",
            old.relative_path(file_tree).display()
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
    use filetime::FileTime;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_parse_version_header_no_version() {
        assert_eq!(
            parse_version_header("").unwrap(),
            (false, 0)
        );
        assert_eq!(
            parse_version_header("# ver foo").unwrap(),
            (false, 0)
        );
        assert_eq!(
            parse_version_header("# foo").unwrap(),
            (false, 0)
        );
    }

    #[test]
    fn test_parse_version_header_with_version() {
        assert_eq!(
            parse_version_header("# version 1\n").unwrap(),
            (true, 1)
        );
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
        assert_eq!(
            parse_mtime(",foo,bar"),
            Ok((None, "foo,bar"))
        );
        assert_eq!(
            parse_mtime("   ,foo,bar"),
            Ok((None, "foo,bar"))
        );
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
        assert_eq!(
            parse_size(",foo,bar"),
            Ok((None, "foo,bar"))
        );
        assert_eq!(
            parse_size("   ,foo,bar"),
            Ok((None, "foo,bar"))
        );
    }

    // TODO: error cases
    #[test]
    fn test_parse_size() {
        assert_eq!(
            parse_size("42069,foo,bar"),
            Ok((Some(42069), "foo,bar"))
        );
        assert_eq!(
            parse_size("   1337   ,foo,bar"),
            Ok((Some(1337), "foo,bar"))
        );
    }

}
