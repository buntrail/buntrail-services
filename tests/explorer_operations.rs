#![cfg(unix)]
use buntrail_core::{contracts::*, workspaces::*};
use buntrail_services::workspaces::store::WorkspaceStore;
fn target_path(path: &std::path::Path) -> TargetPath {
    use std::os::unix::ffi::OsStrExt;
    TargetPath::posix(path.as_os_str().as_bytes().to_vec()).unwrap()
}
fn fixture() -> (
    tempfile::TempDir,
    WorkspaceStore,
    WorkspaceRecord,
    FileRecoveryReference,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = WorkspaceStore::new(dir.path().join("state")).unwrap();
    let target = TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    let WorkspaceState::Ready(record) =
        store.open(target_path(dir.path()), target.clone()).unwrap()
    else {
        panic!()
    };
    let reference = FileRecoveryReference {
        operation: OperationID([7; 16]),
        file: FileRef {
            target,
            path: target_path(&dir.path().join("file")),
            resolved_identity: None,
        },
        destination: None,
        kind: FileRecoveryKind::Trash,
        request_digest: [8; 32],
        owner: WorkspaceLease {
            client: store.load().unwrap().client,
            workspace: record.id,
            lease: record.lease,
            runtime: RuntimeGeneration {
                supervisor_boot: [9; 16],
                container_start: None,
            },
        },
    };
    (dir, store, record, reference)
}
#[test]
fn explorer_operations_survive_restart() {
    let (dir, store, record, reference) = fixture();
    let stale = store.load().unwrap();
    assert!(
        store
            .retain_file_recovery(record.id, reference.clone())
            .unwrap()
            .1
    );
    store.save(&stale).unwrap();
    drop(store);
    let reopened = WorkspaceStore::new(dir.path().join("state")).unwrap();
    assert_eq!(
        reopened.load().unwrap().records[0].file_recoveries,
        vec![reference]
    );
    assert!(reopened.remove(record.id).is_err());
}
#[test]
fn explorer_operations_reject_foreign_target() {
    let (_dir, store, record, mut reference) = fixture();
    reference.file.target.effective_user = vec![99];
    assert!(store.retain_file_recovery(record.id, reference).is_err());
    assert!(store.load().unwrap().records[0].file_recoveries.is_empty());
}
#[test]
fn explorer_operations_never_replay_unknown_outcome() {
    let (_dir, store, record, reference) = fixture();
    assert!(
        store
            .retain_file_recovery(record.id, reference.clone())
            .unwrap()
            .1
    );
    assert!(
        !store
            .retain_file_recovery(record.id, reference.clone())
            .unwrap()
            .1
    );
    let mut different = reference.clone();
    different.request_digest = [44; 32];
    assert!(store.retain_file_recovery(record.id, different).is_err());
    let mut next = reference.clone();
    next.operation = OperationID([66; 16]);
    assert!(store.retain_file_recovery(record.id, next).is_err());
    store.resolve_file_recovery(record.id, &reference).unwrap();
    assert!(store.load().unwrap().records[0].file_recoveries.is_empty());
}
