use super::{serialize, HashCollection, HashCollectionError, Result};

use crate::file_tree::FileTree;

use std::fs;

// NOTE: Not storing a &HashCollection, since it would need to be mut
//       which would greatly hinder using HashCollection while the
//       writer exists
//       Passing the &mut HashCollection to the methods instead.
//       Could also move the collection by storing a { collection: HashCollection }
pub struct HashCollectionWriter {
    wrote_header: bool,
}

impl HashCollectionWriter {
    pub fn new() -> HashCollectionWriter {
        HashCollectionWriter {
            wrote_header: false,
        }
    }

    /// Flushes the current entries of the `collection` to disk.
    /// Entries of the `collection` will be cleared.
    ///
    /// Will append to an existing file.
    pub fn flush(&mut self, collection: &mut HashCollection, file_tree: &FileTree) -> Result<()> {
        let full_path = collection.full_path()?;
        if self.wrote_header {
            let file = fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(full_path)?;
            let mut buf_writer = std::io::BufWriter::new(file);
            serialize::serialize(collection, &mut buf_writer, file_tree, false)?;
        } else {
            self.write(collection, file_tree)?;
        }

        collection.map.clear();
        collection.map.shrink_to_fit();

        Ok(())
    }

    /// Flushes the whole file to the disk.
    /// Does not modify the `collection`.
    ///
    /// Errors if the file exists.
    pub fn write(&mut self, collection: &mut HashCollection, file_tree: &FileTree) -> Result<()> {
        let full_path = collection.full_path()?;
        let file = fs::File::create_new(full_path)?;

        let mut buf_writer = std::io::BufWriter::new(file);
        collection.serialize(&mut buf_writer, file_tree).map(|_| {
            self.wrote_header = true;
        })
    }
}

#[cfg(test)]
mod test {
    use super::super::serialize;
    use super::super::test::setup_minimal_hc;
    use super::*;
    use crate::test_utils::*;

    use std::ffi::OsString;

    #[test]
    fn test_write_never_overwrites() {
        let testdir = testdir!();
        let path = testdir.join("foo.cshd");
        let ft = FileTree::new(&testdir).unwrap();
        let mut hc = HashCollection::new(Some(&path), None).unwrap();
        fs::write(path, "foo").unwrap();

        let mut writer = HashCollectionWriter::new();
        let result = writer.write(&mut hc, &ft);

        assert_eq!(
            result,
            Err(HashCollectionError::IOError(
                std::io::ErrorKind::AlreadyExists
            ))
        );
    }

    #[test]
    fn test_write() {
        let testdir = testdir!();
        let path = testdir.join("foo.cshd");
        let (mut hc, mut ft, expected_serialization) = setup_minimal_hc(&testdir);
        hc.relocate(&testdir);
        hc.rename(&OsString::from("foo.cshd"));

        let mut writer = HashCollectionWriter::new();
        writer.write(&mut hc, &ft).unwrap();

        let read_back = fs::read_to_string(path).unwrap();
        assert_eq!(
            serialize::sort_serialized(&read_back).unwrap(),
            expected_serialization,
        );
    }

    #[test]
    fn test_flush() {
        let testdir = testdir!();
        let path = testdir.join("foo.cshd");
        let (mut hc, mut ft, expected_serialization) = setup_minimal_hc(&testdir);
        hc.relocate(&testdir);
        hc.rename(&OsString::from("foo.cshd"));

        println!("{:?}", hc.full_path());

        let mut writer = HashCollectionWriter::new();
        writer.flush(&mut hc, &ft).unwrap();

        let read_back = fs::read_to_string(path).unwrap();
        assert_eq!(
            serialize::sort_serialized(&read_back).unwrap(),
            expected_serialization,
        );
    }

    #[test]
    fn test_flush_only_writes_header_once() {
        let testdir = testdir!();
        let path = testdir.join("foo.cshd");
        let (mut hc, mut ft, expected_serialization) = setup_minimal_hc(&testdir);
        hc.relocate(&testdir);
        hc.rename(&OsString::from("foo.cshd"));

        let mut writer = HashCollectionWriter::new();
        writer.flush(&mut hc, &ft).unwrap();
        writer.flush(&mut hc, &ft).unwrap();

        let read_back = fs::read_to_string(path).unwrap();
        assert_eq!(
            serialize::sort_serialized(&read_back).unwrap(),
            expected_serialization,
        );
    }

    #[test]
    fn test_flush_clears_entries() {
        let testdir = testdir!();
        let path = testdir.join("foo.cshd");
        let (mut hc, mut ft, expected_serialization) = setup_minimal_hc(&testdir);
        hc.relocate(&testdir);
        hc.rename(&OsString::from("foo.cshd"));

        let mut writer = HashCollectionWriter::new();
        writer.flush(&mut hc, &ft).unwrap();

        assert!(hc.map.is_empty());
    }
}

