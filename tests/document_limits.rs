#![cfg(unix)]
use buntrail_core::contracts::*;
use buntrail_services::files::*;
use std::{fs, os::unix::ffi::OsStrExt};
#[test]
fn byte_budget_holds_until_owner_consumes_and_large_unicode_load_is_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let target = TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    let service = LocalFileService::new(target.clone(), dir.path().join("private")).unwrap();
    let path = dir.path().join("file");
    let file = FileRef {
        target,
        path: TargetPath::posix(path.as_os_str().as_bytes().to_vec()).unwrap(),
        resolved_identity: None,
    };
    fs::write(&path, b"original").unwrap();
    let initial = service.read_sync(file.clone()).unwrap();
    let held = LoadBudget::acquire(MAX_LOAD_BYTES).unwrap();
    let receipt = service.save_sync(SaveRequest {
        operation: OperationID([9; 16]),
        file: initial.file,
        expected_version: Some(initial.version),
        submitted_revision: BufferRevision(1),
        source: ByteSource::Memory(std::sync::Arc::from(b"new".as_slice())),
    });
    assert!(matches!(
        receipt.state,
        OperationState::Failed(OperationFailure {
            error: CoreError {
                code: ErrorCode::Busy,
                ..
            },
            effect: FailureEffect::ProvenNoEffect,
            ..
        })
    ));
    assert_eq!(fs::read(&path).unwrap(), b"original");
    assert!(LoadBudget::acquire(1).is_err());
    drop(held);
    let released = LoadBudget::acquire(MAX_LOAD_BYTES).unwrap();
    drop(released);
    fs::write(&path, vec![b'x'; 1024 * 1024]).unwrap();
    let (loaded, budget) = service
        .load_budgeted(file.clone(), DocumentID([1; 16]))
        .unwrap();
    assert_eq!(loaded.text.len(), 1024 * 1024);
    assert!(LoadBudget::acquire(MAX_LOAD_BYTES).is_err());
    drop(budget);
    fs::write(&path, vec![b'x'; MAX_DOCUMENT_BYTES]).unwrap();
    let (loaded, budget) = service
        .load_budgeted(file.clone(), DocumentID([2; 16]))
        .unwrap();
    assert_eq!(loaded.text.len(), MAX_DOCUMENT_BYTES);
    drop((loaded, budget));
    fs::write(&path, vec![b'x'; MAX_DOCUMENT_BYTES + 1]).unwrap();
    assert!(matches!(
        service.load_sync(file.clone(), DocumentID([3; 16])),
        Err(CoreError {
            code: ErrorCode::Unavailable,
            ..
        })
    ));
    let mut bytes = vec![0xff, 0xfe];
    bytes.extend(std::iter::repeat_n([0x00, 0x08], MAX_DOCUMENT_BYTES / 3 + 1).flatten());
    fs::write(&path, bytes).unwrap();
    assert!(service.load_sync(file, DocumentID([4; 16])).is_err());
}

#[test]
fn released_spools_reuse_capacity_and_retained_source_survives_service_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let target = TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    let path = dir.path().join("large");
    fs::write(&path, vec![b'x'; MEMORY_FILE_BYTES + 1]).unwrap();
    let file = FileRef {
        target: target.clone(),
        path: TargetPath::posix(path.as_os_str().as_bytes().to_vec()).unwrap(),
        resolved_identity: None,
    };
    let service = LocalFileService::new(target.clone(), dir.path().join("private")).unwrap();
    let retained = service.read_sync(file.clone()).unwrap().source;
    for _ in 0..80 {
        let read = service
            .read_sync(file.clone())
            .expect("released reads must reuse capacity");
        assert_eq!(service.source_bytes(&read.source, 1, false).unwrap(), b"x");
    }
    drop(service);
    let reopened = LocalFileService::new(target, dir.path().join("private")).unwrap();
    assert_eq!(
        reopened
            .source_bytes(&retained, MEMORY_FILE_BYTES + 1, true)
            .unwrap()
            .len(),
        MEMORY_FILE_BYTES + 1
    );
}

#[test]
fn spool_crash_child() {
    let Some(root) = std::env::var_os("BUNTRAIL_SPOOL_CRASH_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let target = TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    let service = LocalFileService::new(target.clone(), root.join("private")).unwrap();
    let file = FileRef {
        target,
        path: TargetPath::posix(root.join("large").as_os_str().as_bytes().to_vec()).unwrap(),
        resolved_identity: None,
    };
    let mut retained = vec![];
    for _ in 0..64 {
        retained.push(service.read_sync(file.clone()).unwrap());
    }
    std::process::exit(86);
}

#[test]
fn process_exit_reclaims_orphans_and_live_capacity_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("large"), vec![b'x'; MEMORY_FILE_BYTES + 1]).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "spool_crash_child", "--nocapture"])
        .env("BUNTRAIL_SPOOL_CRASH_ROOT", dir.path())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(86));
    let target = TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    let service = LocalFileService::new(target.clone(), dir.path().join("private")).unwrap();
    let file = FileRef {
        target,
        path: TargetPath::posix(dir.path().join("large").as_os_str().as_bytes().to_vec()).unwrap(),
        resolved_identity: None,
    };
    let mut retained = vec![];
    for _ in 0..64 {
        retained.push(service.read_sync(file.clone()).unwrap());
    }
    assert_eq!(
        service.read_sync(file.clone()).unwrap_err().code,
        ErrorCode::Busy
    );
    retained.pop();
    let replacement = service.read_sync(file).unwrap();
    assert_eq!(
        service.source_bytes(&replacement.source, 1, false).unwrap(),
        b"x"
    );
}

#[test]
fn spool_observer_child() {
    let Some(root) = std::env::var_os("BUNTRAIL_SPOOL_LIVE_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let target = TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    let service = LocalFileService::new(target.clone(), root.join("private")).unwrap();
    let file = FileRef {
        target,
        path: TargetPath::posix(root.join("large").as_os_str().as_bytes().to_vec()).unwrap(),
        resolved_identity: None,
    };
    assert_eq!(service.read_sync(file).unwrap_err().code, ErrorCode::Busy);
}

#[test]
fn another_process_cannot_reclaim_retained_spools() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("large"), vec![b'x'; MEMORY_FILE_BYTES + 1]).unwrap();
    let target = TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    let service = LocalFileService::new(target.clone(), dir.path().join("private")).unwrap();
    let file = FileRef {
        target,
        path: TargetPath::posix(dir.path().join("large").as_os_str().as_bytes().to_vec()).unwrap(),
        resolved_identity: None,
    };
    let retained: Vec<_> = (0..64)
        .map(|_| service.read_sync(file.clone()).unwrap())
        .collect();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "spool_observer_child", "--nocapture"])
        .env("BUNTRAIL_SPOOL_LIVE_ROOT", dir.path())
        .status()
        .unwrap();
    assert!(status.success());
    for read in retained {
        assert_eq!(service.source_bytes(&read.source, 1, false).unwrap(), b"x");
    }
}
