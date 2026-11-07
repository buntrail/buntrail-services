#![cfg(unix)]
use buntrail_core::contracts::*;
use buntrail_services::{
    files::{LocalFileService, document_io},
    leases::LeasePool,
};
use std::{fs, os::unix::ffi::OsStrExt};

#[test]
fn snapshot_reader_rejects_target_size_and_digest_mismatches_before_journaling() {
    let dir = tempfile::tempdir().unwrap();
    let target = buntrail_services::connections::local::identity().unwrap();
    let service = LocalFileService::new(target.clone(), dir.path().join("local")).unwrap();
    let path = dir.path().join("source");
    fs::write(&path, b"\xff\xfea\0\r\0\n\0").unwrap();
    let snapshot = service
        .read_sync(FileRef {
            target,
            path: TargetPath::posix(path.as_os_str().as_bytes().to_vec()).unwrap(),
            resolved_identity: None,
        })
        .unwrap();
    let pool = LeasePool::open(dir.path().join("reader")).unwrap();
    for (changed, expected) in [
        (0, ErrorCode::TargetChanged),
        (1, ErrorCode::InvalidArgument),
        (2, ErrorCode::InvalidArgument),
    ] {
        let mut invalid = snapshot.clone();
        match changed {
            0 => invalid.version.target.security_binding.push(0),
            1 => invalid.size += 1,
            _ => invalid.version.content_digest[0] ^= 1,
        }
        let result = document_io::load_snapshot(
            invalid,
            DocumentID([1; 16]),
            Some(&service.recovery),
            &pool,
        );
        assert_eq!(
            result
                .err()
                .expect("inconsistent target snapshot accepted")
                .code,
            expected
        );
        assert!(service.recovery.inventory().unwrap().is_empty());
    }
    let (loaded, _budget) = document_io::load_snapshot(
        snapshot,
        DocumentID([2; 16]),
        Some(&service.recovery),
        &pool,
    )
    .unwrap();
    assert_eq!(loaded.text.as_str(), "a\r\n");
    assert_eq!(loaded.encoding, Encoding::Other("UTF-16LE".into()));
    assert_eq!(loaded.line_endings, LineEndings::CrLf);
    assert!(loaded.journal_lease.is_some());
}
