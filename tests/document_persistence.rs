#![cfg(unix)]
use buntrail_core::{contracts::*, documents::*};
use buntrail_services::files::{FailPoint, LocalFileService};
use std::{fs, os::unix::fs::symlink, sync::Arc};
fn setup() -> (tempfile::TempDir, LocalFileService, FileRef) {
    let dir = tempfile::tempdir().unwrap();
    let target = TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    let service = LocalFileService::new(target.clone(), dir.path().join("private")).unwrap();
    let path = dir.path().join("file");
    fs::write(&path, b"original\r\n").unwrap();
    use std::os::unix::ffi::OsStrExt;
    let file = FileRef {
        target,
        path: TargetPath::posix(path.as_os_str().as_bytes().to_vec()).unwrap(),
        resolved_identity: None,
    };
    (dir, service, file)
}
fn request(service: &LocalFileService, file: FileRef, id: u8) -> SaveRequest {
    let snapshot = service.read_sync(file).unwrap();
    SaveRequest {
        operation: OperationID([id; 16]),
        file: snapshot.file,
        expected_version: Some(snapshot.version),
        submitted_revision: BufferRevision(3),
        source: ByteSource::Memory(Arc::from(b"new\r\nno-final-newline".as_slice())),
    }
}
#[test]
#[allow(non_snake_case)]
fn testSaveAcknowledgementLoss() {
    let (dir, service, file) = setup();
    let r = request(&service, file.clone(), 1);
    service.set_failpoint(FailPoint::Acknowledgement);
    assert!(matches!(
        service.save_sync(r.clone()).state,
        OperationState::Unknown(_)
    ));
    assert_eq!(
        fs::read(dir.path().join("file")).unwrap(),
        b"new\r\nno-final-newline"
    );
    fs::write(dir.path().join("file"), b"external").unwrap();
    service.set_failpoint(FailPoint::None);
    let _ = service.save_sync(r);
    assert_eq!(
        fs::read(dir.path().join("file")).unwrap(),
        b"external",
        "retryCount must be zero"
    );
}
#[test]
#[allow(non_snake_case)]
fn testSymlinkTargetChanged() {
    let (dir, service, mut file) = setup();
    let link = dir.path().join("link");
    symlink("file", &link).unwrap();
    use std::os::unix::ffi::OsStrExt;
    file.path = TargetPath::posix(link.as_os_str().as_bytes().to_vec()).unwrap();
    let r = request(&service, file, 2);
    fs::write(dir.path().join("other"), b"other").unwrap();
    fs::remove_file(&link).unwrap();
    symlink("other", &link).unwrap();
    assert!(matches!(
        service.save_sync(r).state,
        OperationState::Failed(_)
    ));
    assert_eq!(fs::read(dir.path().join("other")).unwrap(), b"other");
    assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
}

#[test]
fn version_distinguishes_replaced_indirect_symlink_to_same_destination() {
    let (dir, service, mut file) = setup();
    symlink("file", dir.path().join("middle")).unwrap();
    symlink("middle", dir.path().join("alias")).unwrap();
    use std::os::unix::ffi::OsStrExt;
    file.path =
        TargetPath::posix(dir.path().join("alias").as_os_str().as_bytes().to_vec()).unwrap();
    let before = service.read_sync(file.clone()).unwrap().version;
    symlink("file", dir.path().join("replacement-link")).unwrap();
    fs::rename(
        dir.path().join("replacement-link"),
        dir.path().join("middle"),
    )
    .unwrap();
    let after = service.read_sync(file).unwrap().version;
    assert_eq!(before.content_digest, after.content_digest);
    assert_ne!(
        before.opaque_token, after.opaque_token,
        "the version must bind each followed link, including indirect targets"
    );
}
#[test]
#[allow(non_snake_case)]
fn testEditDuringSaveStaysDirty() {
    let (_dir, service, file) = setup();
    let initial = service.load_sync(file, DocumentID([3; 16])).unwrap();
    let mut d = DocumentSession::from_loaded(initial);
    let prepared = d.prepare_save(OperationID([3; 16])).unwrap();
    d.apply_transaction(EditTransaction {
        expected_revision: BufferRevision(0),
        source_view: ViewID(1),
        replacements: vec![Replacement {
            range: BufferRange {
                revision: BufferRevision(0),
                start: 0,
                end: 0,
            },
            text: "later".into(),
        }],
        intent: EditIntent::Replace,
    })
    .unwrap();
    let receipt = service.save_prepared(prepared);
    assert!(
        matches!(
            receipt.state,
            OperationState::Confirmed(MutationResult::Saved(SaveResult {
                saved_revision: BufferRevision(0),
                ..
            }))
        ),
        "{receipt:?}"
    );
    d.complete_save(receipt).unwrap();
    assert!(d.is_dirty());
}
#[test]
fn failures_before_replacement_preserve_original() {
    for fail in [
        FailPoint::Acceptance,
        FailPoint::Write,
        FailPoint::FullDisk,
        FailPoint::Permission,
    ] {
        let (dir, service, file) = setup();
        let r = request(&service, file, 4);
        service.set_failpoint(fail);
        assert!(matches!(
            service.save_sync(r).state,
            OperationState::Failed(_)
        ));
        assert_eq!(fs::read(dir.path().join("file")).unwrap(), b"original\r\n");
    }
}
#[test]
fn external_write_delete_and_rename_are_conflicts() {
    for action in 0..3 {
        let (dir, service, file) = setup();
        let r = request(&service, file, 5);
        match action {
            0 => fs::write(dir.path().join("file"), b"external").unwrap(),
            1 => fs::remove_file(dir.path().join("file")).unwrap(),
            _ => fs::rename(dir.path().join("file"), dir.path().join("moved")).unwrap(),
        }
        assert!(matches!(
            service.save_sync(r).state,
            OperationState::Failed(_)
        ));
    }
}
#[test]
fn recovery_restores_exact_encoding_provisional_text_and_operation() {
    let (dir, service, file) = setup();
    let mut loaded = service.load_sync(file, DocumentID([7; 16])).unwrap();
    loaded.encoding = Encoding::Other("UTF-16LE".into());
    let mut d = DocumentSession::from_loaded(loaded);
    d.apply_transaction(EditTransaction {
        expected_revision: BufferRevision(0),
        source_view: ViewID(1),
        replacements: vec![],
        intent: EditIntent::BeginComposition,
    })
    .unwrap();
    d.apply_transaction(EditTransaction {
        expected_revision: BufferRevision(0),
        source_view: ViewID(1),
        replacements: vec![Replacement {
            range: BufferRange {
                revision: BufferRevision(0),
                start: 0,
                end: 8,
            },
            text: "😀".into(),
        }],
        intent: EditIntent::UpdateComposition,
    })
    .unwrap();
    service.recovery.write_sync(d.recovery_snapshot()).unwrap();
    drop(service);
    let target = loaded_target();
    let service = LocalFileService::new(target, dir.path().join("private")).unwrap();
    let draft = service.recovery.restore(DocumentID([7; 16])).unwrap();
    assert!(draft.provisional_composition);
    assert_eq!(
        buntrail_services::files::encode(&draft.snapshot).unwrap(),
        [0xff, 0xfe, 0x3d, 0xd8, 0x00, 0xde, 0x0d, 0x00, 0x0a, 0x00]
    );
}
fn loaded_target() -> TargetIdentity {
    TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    }
}
#[test]
fn matching_current_contents_after_acceptance_do_not_prove_the_original_save_ran() {
    let (dir, service, file) = setup();
    let request = request(&service, file.clone(), 18);
    service.set_failpoint(FailPoint::AfterAcceptance);
    assert!(matches!(
        service.save_sync(request.clone()).state,
        OperationState::Unknown(_)
    ));
    if let ByteSource::Memory(bytes) = &request.source {
        fs::write(dir.path().join("file"), bytes).unwrap();
    }
    let inspected = service
        .inspect_sync(request.operation, file.target.clone())
        .unwrap();
    assert!(
        matches!(inspected.state, OperationState::Unknown(_)),
        "matching current bytes cannot establish historical execution: {inspected:?}"
    );
}
#[test]
fn restart_after_completion_loss_inspects_contents_without_reexecution() {
    let (dir, service, file) = setup();
    let r = request(&service, file.clone(), 8);
    service.set_failpoint(FailPoint::Completion);
    assert!(matches!(
        service.save_sync(r.clone()).state,
        OperationState::Unknown(_)
    ));
    drop(service);
    let service = LocalFileService::new(loaded_target(), dir.path().join("private")).unwrap();
    assert!(matches!(
        service
            .inspect_sync(r.operation, file.target)
            .unwrap()
            .state,
        OperationState::Unknown(_)
    ));
    fs::write(dir.path().join("file"), b"external").unwrap();
    let _ = service.save_sync(r);
    assert_eq!(fs::read(dir.path().join("file")).unwrap(), b"external");
}
#[test]
fn conflicting_operation_digest_is_rejected_and_mode_and_symlink_preserved() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, service, mut file) = setup();
    let original = dir.path().join("file");
    fs::set_permissions(&original, fs::Permissions::from_mode(0o640)).unwrap();
    let link = dir.path().join("link");
    symlink("file", &link).unwrap();
    use std::os::unix::ffi::OsStrExt;
    file.path = TargetPath::posix(link.as_os_str().as_bytes().to_vec()).unwrap();
    let mut r = request(&service, file, 9);
    assert!(matches!(
        service.save_sync(r.clone()).state,
        OperationState::Confirmed(_)
    ));
    assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
    assert_eq!(
        fs::metadata(original).unwrap().permissions().mode() & 0o777,
        0o640
    );
    r.source = ByteSource::Memory(Arc::from(b"different".as_slice()));
    assert!(matches!(
        service.save_sync(r).state,
        OperationState::Failed(OperationFailure {
            error: CoreError {
                code: ErrorCode::InvalidArgument,
                ..
            },
            ..
        })
    ));
}
#[test]
fn utf_boms_mixed_newlines_and_binary_are_explicit() {
    for b in [
        b"\xef\xbb\xbfhello\r\nworld\rno-final\n".to_vec(),
        vec![0xff, 0xfe, 0x3d, 0xd8, 0x00, 0xde],
        vec![0xfe, 0xff, 0x00, 0x61, 0x00, 0x0d, 0x00, 0x0a],
    ] {
        let (dir, service, file) = setup();
        fs::write(dir.path().join("file"), &b).unwrap();
        let loaded = service.load_sync(file, DocumentID([4; 16])).unwrap();
        let d = DocumentSession::from_loaded(loaded);
        assert_eq!(buntrail_services::files::encode(&d.snapshot()).unwrap(), b);
    }
    assert!(buntrail_services::files::decode(b"a\0b").is_err());
    assert!(buntrail_services::files::decode(&[0xff, 0x00]).is_err());
}
#[test]
fn hardlink_is_refused_without_changing_either_name() {
    let (dir, service, file) = setup();
    fs::hard_link(dir.path().join("file"), dir.path().join("hard")).unwrap();
    let r = request(&service, file, 10);
    assert!(matches!(
        service.save_sync(r).state,
        OperationState::Failed(OperationFailure {
            error: CoreError {
                code: ErrorCode::Unavailable,
                ..
            },
            ..
        })
    ));
    assert_eq!(fs::read(dir.path().join("hard")).unwrap(), b"original\r\n");
}
#[test]
fn save_crash_child() {
    let Some(root) = std::env::var_os("BUNTRAIL_SAVE_CRASH_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let target = loaded_target();
    let service = LocalFileService::new(target.clone(), root.join("private")).unwrap();
    use std::os::unix::ffi::OsStrExt;
    let file = FileRef {
        target,
        path: TargetPath::posix(root.join("file").as_os_str().as_bytes().to_vec()).unwrap(),
        resolved_identity: None,
    };
    let r = request(&service, file, 12);
    service.set_failpoint(FailPoint::Completion);
    let result = service.save_sync(r);
    assert!(matches!(result.state, OperationState::Unknown(_)));
    std::process::exit(86);
}
#[test]
fn process_exit_after_replacement_recovers_without_replay() {
    let (dir, service, file) = setup();
    let r = request(&service, file.clone(), 12);
    drop(service);
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "save_crash_child", "--nocapture"])
        .env("BUNTRAIL_SAVE_CRASH_ROOT", dir.path())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(86));
    let restarted = LocalFileService::new(loaded_target(), dir.path().join("private")).unwrap();
    assert!(matches!(
        restarted
            .inspect_sync(r.operation, file.target)
            .unwrap()
            .state,
        OperationState::Unknown(_)
    ));
    fs::write(dir.path().join("file"), b"later external").unwrap();
    let _ = restarted.save_sync(r);
    assert_eq!(
        fs::read(dir.path().join("file")).unwrap(),
        b"later external"
    );
}
#[test]
fn late_draft_write_cannot_restore_a_confirmed_pending_operation() {
    let (_dir, service, file) = setup();
    let mut d =
        DocumentSession::from_loaded(service.load_sync(file, DocumentID([13; 16])).unwrap());
    d.apply_transaction(EditTransaction {
        expected_revision: BufferRevision(0),
        source_view: ViewID(1),
        intent: EditIntent::Replace,
        replacements: vec![Replacement {
            range: BufferRange {
                revision: BufferRevision(0),
                start: 0,
                end: 8,
            },
            text: "draft".into(),
        }],
    })
    .unwrap();
    let prepared = d.prepare_save(OperationID([13; 16])).unwrap();
    let late = prepared.recovery.clone();
    let receipt = service.save_prepared(prepared);
    d.complete_save(receipt).unwrap();
    service.recovery.write_sync(d.recovery_snapshot()).unwrap();
    service.recovery.write_sync(late).unwrap();
    assert_eq!(
        service
            .recovery
            .restore(DocumentID([13; 16]))
            .unwrap_err()
            .code,
        ErrorCode::Unavailable
    );
}

#[test]
fn reopened_session_recovers_after_clean_marker_and_rejects_delayed_old_writer() {
    let (dir, service, file) = setup();
    let id = DocumentID([20; 16]);
    let mut old = DocumentSession::from_loaded(service.load_sync(file.clone(), id).unwrap());
    let edit = |d: &mut DocumentSession, text: &str| {
        let revision = d.snapshot().revision;
        d.apply_transaction(EditTransaction {
            expected_revision: revision,
            source_view: ViewID(1),
            intent: EditIntent::Replace,
            replacements: vec![Replacement {
                range: BufferRange {
                    revision,
                    start: 0,
                    end: 0,
                },
                text: text.into(),
            }],
        })
        .unwrap();
    };
    edit(&mut old, "saved");
    let prepared = old.prepare_save(OperationID([20; 16])).unwrap();
    let delayed = prepared.recovery.clone();
    old.complete_save(service.save_prepared(prepared)).unwrap();
    service
        .recovery
        .write_sync(old.recovery_snapshot())
        .unwrap();
    drop(old);
    let mut reopened = DocumentSession::from_loaded(service.load_sync(file, id).unwrap());
    edit(&mut reopened, "new dirty");
    service
        .recovery
        .write_sync(reopened.recovery_snapshot())
        .unwrap();
    service.recovery.write_sync(delayed).unwrap();
    let expected = reopened.snapshot().text;
    drop((reopened, service));
    let restarted = LocalFileService::new(loaded_target(), dir.path().join("private")).unwrap();
    assert_eq!(
        restarted.recovery.restore(id).unwrap().snapshot.text,
        expected
    );
}

#[test]
fn matching_bytes_at_retargeted_symlink_do_not_confirm_or_clean_pending_save() {
    let (dir, service, mut file) = setup();
    let link = dir.path().join("link");
    symlink("file", &link).unwrap();
    use std::os::unix::ffi::OsStrExt;
    file.path = TargetPath::posix(link.as_os_str().as_bytes().to_vec()).unwrap();
    let mut session = DocumentSession::from_loaded(
        service
            .load_sync(file.clone(), DocumentID([21; 16]))
            .unwrap(),
    );
    session
        .apply_transaction(EditTransaction {
            expected_revision: BufferRevision(0),
            source_view: ViewID(1),
            intent: EditIntent::Replace,
            replacements: vec![Replacement {
                range: BufferRange {
                    revision: BufferRevision(0),
                    start: 0,
                    end: 8,
                },
                text: "wanted".into(),
            }],
        })
        .unwrap();
    let prepared = session.prepare_save(OperationID([21; 16])).unwrap();
    service.set_failpoint(FailPoint::AfterAcceptance);
    session
        .complete_save(service.save_prepared(prepared.clone()))
        .unwrap();
    let identity = session.file().resolved_identity.clone();
    fs::write(dir.path().join("other"), b"wanted\r\n").unwrap();
    fs::remove_file(&link).unwrap();
    symlink("other", &link).unwrap();
    let receipt = service
        .inspect_sync(prepared.operation, file.target)
        .unwrap();
    assert!(
        matches!(receipt.state, OperationState::Unknown(_)),
        "{receipt:?}"
    );
    session.complete_save(receipt).unwrap();
    assert!(session.is_dirty());
    assert_eq!(session.file().resolved_identity, identity);
    service.set_failpoint(FailPoint::None);
    let _ = service.save_prepared(prepared);
    assert_eq!(fs::read(dir.path().join("file")).unwrap(), b"original\r\n");
    assert_eq!(fs::read(dir.path().join("other")).unwrap(), b"wanted\r\n");
}

#[test]
fn clean_marker_is_not_pruned_while_delayed_snapshot_can_still_write() {
    let (_dir, service, file) = setup();
    let id = DocumentID([22; 16]);
    let mut old = DocumentSession::from_loaded(service.load_sync(file.clone(), id).unwrap());
    let prepared = old.prepare_save(OperationID([22; 16])).unwrap();
    let delayed = prepared.recovery.clone();
    old.complete_save(service.save_prepared(prepared)).unwrap();
    service
        .recovery
        .write_sync(old.recovery_snapshot())
        .unwrap();
    drop(old);
    let new = DocumentSession::from_loaded(service.load_sync(file.clone(), id).unwrap());
    service
        .recovery
        .write_sync(new.recovery_snapshot())
        .unwrap();
    drop(new);
    // This new ID triggers clean-marker pruning, with the old writer still retained.
    let other =
        DocumentSession::from_loaded(service.load_sync(file, DocumentID([23; 16])).unwrap());
    service
        .recovery
        .write_sync(other.recovery_snapshot())
        .unwrap();
    service.recovery.write_sync(delayed).unwrap();
    assert_eq!(
        service.recovery.restore(id).unwrap_err().code,
        ErrorCode::Unavailable
    );
}

#[test]
fn failed_discard_tombstone_preserves_draft_and_late_marker_cannot_clear_reopened_edits() {
    let (dir, service, file) = setup();
    let id = DocumentID([92; 16]);
    let mut session = DocumentSession::from_loaded(service.load_sync(file.clone(), id).unwrap());
    let edit = |session: &mut DocumentSession, text: &str| {
        let revision = session.snapshot().revision;
        session
            .apply_transaction(EditTransaction {
                expected_revision: revision,
                source_view: ViewID(1),
                intent: EditIntent::Replace,
                replacements: vec![Replacement {
                    range: BufferRange {
                        revision,
                        start: 0,
                        end: 0,
                    },
                    text: text.into(),
                }],
            })
            .unwrap();
    };
    edit(&mut session, "discarded ");
    service
        .recovery
        .write_sync(session.recovery_snapshot())
        .unwrap();
    let marker = session.discard().unwrap();
    let recovery = dir.path().join("private/recovery");
    fs::remove_file(recovery.join("lock")).unwrap();
    symlink(dir.path().join("file"), recovery.join("lock")).unwrap();
    assert_eq!(
        service
            .recovery
            .write_sync(marker.clone())
            .unwrap_err()
            .code,
        ErrorCode::Io
    );
    assert_eq!(
        service
            .recovery
            .preview_budgeted(id)
            .unwrap()
            .0
            .snapshot
            .text
            .as_str(),
        "discarded original\r\n"
    );
    assert_eq!(fs::read(dir.path().join("file")).unwrap(), b"original\r\n");
    fs::remove_file(recovery.join("lock")).unwrap();
    service.recovery.write_sync(marker.clone()).unwrap();
    assert!(service.recovery.inventory().unwrap().is_empty());
    drop(session);
    let mut reopened = DocumentSession::from_loaded(service.load_sync(file, id).unwrap());
    assert_eq!(reopened.snapshot().text.as_str(), "original\r\n");
    edit(&mut reopened, "new ");
    service
        .recovery
        .write_sync(reopened.recovery_snapshot())
        .unwrap();
    service.recovery.write_sync(marker).unwrap();
    assert_eq!(
        service
            .recovery
            .preview_budgeted(id)
            .unwrap()
            .0
            .snapshot
            .text
            .as_str(),
        "new original\r\n"
    );
}

#[cfg(target_os = "linux")]
mod linux_metadata {
    use super::*;
    use std::{
        collections::BTreeMap,
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, PermissionsExt},
        },
    };

    fn set_attribute(file: &fs::File, name: &[u8], value: &[u8]) {
        let name = std::ffi::CString::new(name).unwrap();
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    file.as_raw_fd(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
    }
    fn attributes(file: &fs::File) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let mut names = vec![0u8; 65536];
        let count =
            unsafe { libc::flistxattr(file.as_raw_fd(), names.as_mut_ptr().cast(), names.len()) };
        assert!(count >= 0);
        names.truncate(count as usize);
        names
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
            .map(|name| {
                let c_name = std::ffi::CString::new(name).unwrap();
                let mut value = vec![0; 65536];
                let count = unsafe {
                    libc::fgetxattr(
                        file.as_raw_fd(),
                        c_name.as_ptr(),
                        value.as_mut_ptr().cast(),
                        value.len(),
                    )
                };
                assert!(count >= 0);
                value.truncate(count as usize);
                (name.to_vec(), value)
            })
            .collect()
    }
    fn acl(named_user: bool) -> Vec<u8> {
        let mut value = 2u32.to_le_bytes().to_vec();
        let mut entries = vec![(1u16, 6u16, u32::MAX)];
        if named_user {
            entries.push((2, 4, 65534));
        }
        entries.push((4, 4, u32::MAX));
        if named_user {
            entries.push((16, 4, u32::MAX));
        }
        entries.push((32, 0, u32::MAX));
        for (tag, perm, id) in entries {
            value.extend(tag.to_le_bytes());
            value.extend(perm.to_le_bytes());
            value.extend(id.to_le_bytes());
        }
        value
    }
    #[test]
    fn linux_atomic_save_preserves_complete_extended_metadata() {
        let (dir, service, file) = setup();
        let path = dir.path().join("file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let source = fs::File::open(&path).unwrap();
        set_attribute(
            &source,
            b"user.security.m.metadata",
            &(0..107).map(|n| n as u8).collect::<Vec<_>>(),
        );
        set_attribute(&source, b"user.buntrail.empty", &[]);
        set_attribute(&source, b"user.buntrail.binary", &[0, 255, 0, 128, 10]);
        let before = attributes(&source);
        let original_inode = source.metadata().unwrap().ino();
        let r = request(&service, file.clone(), 31);
        let receipt = service.save_sync(r.clone());
        assert!(
            matches!(
                receipt.state,
                OperationState::Confirmed(MutationResult::Saved(_))
            ),
            "{receipt:?}"
        );
        let destination = fs::File::open(&path).unwrap();
        assert_ne!(destination.metadata().unwrap().ino(), original_inode);
        assert_eq!(destination.metadata().unwrap().mode() & 0o7777, 0o640);
        assert_eq!(fs::read(&path).unwrap(), b"new\r\nno-final-newline");
        assert_eq!(attributes(&destination), before);
        assert_eq!(
            attributes(&source),
            before,
            "replacement must not modify the open original inode"
        );
        assert_eq!(
            service.inspect_sync(r.operation, file.target).unwrap(),
            receipt
        );
        assert_eq!(
            service.save_sync(r),
            receipt,
            "an already confirmed operation is inspected, never executed again"
        );
        assert_eq!(
            fs::metadata(path).unwrap().ino(),
            destination.metadata().unwrap().ino()
        );
    }
    #[test]
    fn linux_atomic_save_preserves_access_acl_and_removes_only_inherited_temporary_acl() {
        for source_acl in [false, true] {
            let (dir, service, file) = setup();
            let path = dir.path().join("file");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            let source = fs::File::open(&path).unwrap();
            if source_acl {
                set_attribute(&source, b"system.posix_acl_access", &acl(true));
            }
            let before = attributes(&source);
            // A temporary created later inherits metadata that was never on the source.
            let parent = fs::File::open(dir.path()).unwrap();
            set_attribute(&parent, b"system.posix_acl_default", &acl(true));
            let inherited = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
            assert!(
                attributes(inherited.as_file()).contains_key(b"system.posix_acl_access".as_slice())
            );
            let r = request(&service, file, 32);
            let receipt = service.save_sync(r);
            assert!(
                matches!(
                    receipt.state,
                    OperationState::Confirmed(MutationResult::Saved(_))
                ),
                "{receipt:?}"
            );
            let destination = fs::File::open(path).unwrap();
            assert_eq!(attributes(&destination), before);
            assert_eq!(destination.metadata().unwrap().mode() & 0o7777, 0o640);
            assert_eq!(attributes(&source), before);
            assert_eq!(
                attributes(&parent).get(b"system.posix_acl_default".as_slice()),
                Some(&acl(true))
            );
        }
    }
    #[test]
    fn linux_metadata_change_after_preparing_save_is_a_conflict_without_replacement() {
        let (dir, service, file) = setup();
        let path = dir.path().join("file");
        let source = fs::File::open(&path).unwrap();
        let r = request(&service, file.clone(), 33);
        set_attribute(&source, b"user.buntrail.concurrent", b"external");
        let before = attributes(&source);
        let receipt = service.save_sync(r.clone());
        assert!(
            matches!(
                receipt.state,
                OperationState::Failed(OperationFailure {
                    error: CoreError {
                        code: ErrorCode::StaleRevision,
                        ..
                    },
                    effect: FailureEffect::ProvenNoEffect,
                    ..
                })
            ),
            "{receipt:?}"
        );
        assert_eq!(fs::read(&path).unwrap(), b"original\r\n");
        assert_eq!(
            fs::metadata(path).unwrap().ino(),
            source.metadata().unwrap().ino()
        );
        assert_eq!(attributes(&source), before);
        assert!(
            matches!(
                service
                    .inspect_sync(r.operation, file.target)
                    .unwrap()
                    .state,
                OperationState::Unknown(_)
            ),
            "pre-admission refusal must not invent an accepted ledger record"
        );
    }
    #[test]
    fn linux_no_attribute_large_save_keeps_existing_admission_limit() {
        let (dir, service, file) = setup();
        assert!(attributes(&fs::File::open(dir.path().join("file")).unwrap()).is_empty());
        let mut r = request(&service, file, 34);
        let bytes: Arc<[u8]> = vec![b'x'; 31 * 1024 * 1024].into();
        r.source = ByteSource::Memory(bytes.clone());
        let receipt = service.save_sync(r);
        assert!(
            matches!(
                receipt.state,
                OperationState::Confirmed(MutationResult::Saved(_))
            ),
            "{receipt:?}"
        );
        assert_eq!(
            fs::metadata(dir.path().join("file")).unwrap().len(),
            bytes.len() as u64
        );
        assert_eq!(
            fs::read(dir.path().join("file")).unwrap().as_slice(),
            bytes.as_ref()
        );
    }

    #[test]
    fn linux_metadata_admission_refusal_is_durable_without_replacement() {
        let (dir, service, file) = setup();
        let path = dir.path().join("file");
        let source = fs::File::open(&path).unwrap();
        set_attribute(&source, b"user.buntrail.test", b"must survive");
        let before = attributes(&source);
        let metadata = source.metadata().unwrap();
        let r = request(&service, file.clone(), 35);
        // The existing save staging fits; additional metadata snapshots must share
        // the same unchanged global admission instead of allocating around its cap.
        let held = buntrail_services::files::LoadBudget::acquire(62 * 1024 * 1024).unwrap();
        let receipt = service.save_sync(r.clone());
        assert!(
            matches!(
                receipt.state,
                OperationState::Failed(OperationFailure {
                    error: CoreError {
                        code: ErrorCode::Busy,
                        ..
                    },
                    effect: FailureEffect::ProvenNoEffect,
                    ..
                })
            ),
            "{receipt:?}"
        );
        drop(held);
        assert_eq!(fs::read(&path).unwrap(), b"original\r\n");
        assert_eq!(fs::metadata(path).unwrap().ino(), metadata.ino());
        assert_eq!(attributes(&source), before);
        assert_eq!(
            service.inspect_sync(r.operation, file.target).unwrap(),
            receipt
        );
        assert_eq!(
            service.save_sync(r),
            receipt,
            "failed original ID remains failed; no replay"
        );
    }
}

#[test]
fn inactive_pending_inspection_preserves_text_and_rejects_live_or_wrong_receipts() {
    let (dir, service, file) = setup();
    let id = DocumentID([87; 16]);
    let mut doc = DocumentSession::from_loaded(service.load_sync(file, id).unwrap());
    doc.apply_transaction(EditTransaction {
        expected_revision: BufferRevision(0),
        source_view: ViewID(1),
        intent: EditIntent::Replace,
        replacements: vec![Replacement {
            range: BufferRange {
                revision: BufferRevision(0),
                start: 0,
                end: 8,
            },
            text: "recovered text".into(),
        }],
    })
    .unwrap();
    let prepared = doc.prepare_save(OperationID([88; 16])).unwrap();
    let receipt = service.save_prepared(prepared);
    assert!(matches!(receipt.state, OperationState::Confirmed(_)));
    assert!(
        service
            .recovery
            .inspect_pending(id, |_, _| panic!("must not inspect a live journal"))
            .is_err()
    );
    drop(doc);
    fs::write(dir.path().join("file"), b"external replacement").unwrap();
    let mut wrong = receipt.clone();
    if let OperationState::Confirmed(MutationResult::Saved(saved)) = &mut wrong.state {
        saved.saved_revision = BufferRevision(999);
    }
    assert!(
        service
            .recovery
            .inspect_pending(id, |_, _| Ok(wrong))
            .is_err()
    );
    assert!(
        service
            .recovery
            .preview_budgeted(id)
            .unwrap()
            .0
            .pending_operation
            .is_some()
    );
    service
        .recovery
        .inspect_pending(id, |operation, target| {
            service.inspect_sync(operation, target)
        })
        .unwrap();
    let (draft, _budget) = service.recovery.preview_budgeted(id).unwrap();
    assert!(draft.pending_operation.is_none());
    assert!(draft.snapshot.text.as_str().contains("recovered text"));
    assert!(!draft.clean);
    assert_eq!(
        fs::read(dir.path().join("file")).unwrap(),
        b"external replacement"
    );
    service.recovery.discard(id).unwrap();
}
