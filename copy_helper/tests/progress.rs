use std::{fs, io};

use copy_helper::{copy_file_with_progress, preserved_metadata};
use filetime::FileTime;
use testdir::testdir;

#[test]
fn progress_tracks_chunks_and_preserves_metadata_including_empty_files() {
    let root = testdir!();
    for size in [0, 1, 200_000] {
        let source = root.join("source");
        let target = root.join("target");
        let data = vec![42; size];
        fs::write(&source, &data).unwrap();
        fs::write(&target, b"old").unwrap();
        let mtime = FileTime::from_unix_time(1234, 500_000_000);
        filetime::set_file_mtime(&source, mtime).unwrap();
        let metadata = preserved_metadata(&fs::metadata(&source).unwrap()).unwrap();
        let mut events = Vec::new();
        let copied = copy_file_with_progress(
            &source,
            &target,
            &metadata,
            Some(size as u64),
            "test",
            |bytes| {
                events.push(bytes);
                assert_eq!(fs::read(&target)?, b"old");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(copied, size as u64);
        assert_eq!(events[0], 0);
        assert_eq!(*events.last().unwrap(), size as u64);
        assert!(
            events
                .windows(2)
                .all(|pair| pair[0] < pair[1] && pair[1] - pair[0] <= 64 * 1024)
        );
        assert_eq!(fs::read(&target).unwrap(), data);
        assert_eq!(
            FileTime::from_last_modification_time(&fs::metadata(&target).unwrap()),
            mtime
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&target).unwrap().permissions().mode(),
                metadata.permissions.mode()
            );
        }
    }
}

#[test]
fn errors_keep_the_old_destination_and_clean_up_temporary_files() {
    let root = testdir!();
    let source = root.join("source");
    let target = root.join("target");
    fs::write(&source, b"data").unwrap();
    fs::write(&target, b"old").unwrap();
    let metadata = preserved_metadata(&fs::metadata(&source).unwrap()).unwrap();
    for callback_failure in [false, true] {
        let result =
            copy_file_with_progress(&source, &target, &metadata, Some(999), "test", |bytes| {
                if callback_failure && bytes > 0 {
                    Err(io::Error::other("reporting failed"))
                } else {
                    Ok(())
                }
            });
        assert!(result.is_err());
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
    }
}

#[test]
fn a_retried_transfer_resets_progress_and_restarts_the_temp_file() {
    let root = testdir!();
    let source = root.join("source");
    let target = root.join("target");
    let data = vec![42; 200_000];
    fs::write(&source, &data).unwrap();
    let metadata = preserved_metadata(&fs::metadata(&source).unwrap()).unwrap();
    let mut events = Vec::new();
    let mut interrupted = false;
    let copied = copy_file_with_progress(
        &source,
        &target,
        &metadata,
        Some(data.len() as u64),
        "test",
        |bytes| {
            events.push(bytes);
            if bytes > 0 && !interrupted {
                interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(&events[..3], &[0, 64 * 1024, 0]);
    assert_eq!(copied, data.len() as u64);
    assert_eq!(fs::read(target).unwrap(), data);
    assert_eq!(fs::read_dir(root).unwrap().count(), 2);
}
