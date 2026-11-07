#![cfg(unix)]
use buntrail_core::contracts::*;
use buntrail_services::{contracts::FileService, files::LocalFileService};
use std::{
    fs,
    future::Future,
    os::unix::ffi::OsStrExt,
    pin::pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};
fn run<T>(f: impl Future<Output = T>) -> T {
    let w = Waker::noop();
    let mut c = Context::from_waker(w);
    let mut f = pin!(f);
    match f.as_mut().poll(&mut c) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("local synchronous seam unexpectedly pending"),
    }
}
fn fixture() -> (tempfile::TempDir, LocalFileService, FileRef) {
    let d = tempfile::tempdir().unwrap();
    let target = TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    fs::create_dir(d.path().join("project")).unwrap();
    let root = FileRef {
        target: target.clone(),
        path: TargetPath::posix(d.path().join("project").as_os_str().as_bytes().to_vec()).unwrap(),
        resolved_identity: None,
    };
    let service = LocalFileService::new(target, d.path().join("private")).unwrap();
    (d, service, root)
}
#[test]
fn test_folder_without_git() {
    let (d, s, root) = fixture();
    fs::write(
        d.path().join("project/complete-filename.component.vue"),
        b"hello",
    )
    .unwrap();
    fs::create_dir(d.path().join("project/.agents")).unwrap();
    let entries = run(s.list(root)).expect("a non-Git folder is a workspace");
    assert!(entries.iter().any(|e| e.display_name == ".agents"));
    let f = entries
        .iter()
        .find(|e| e.display_name == "complete-filename.component.vue")
        .unwrap();
    assert_eq!(
        s.load_sync(f.file.clone(), DocumentID([1; 16]))
            .unwrap()
            .text
            .as_str(),
        "hello"
    );
}
#[test]
fn mutations_revalidate_and_never_overwrite_an_existing_destination() {
    let (d, s, root) = fixture();
    let file = FileRef {
        path: TargetPath::posix(
            d.path()
                .join("project/file")
                .as_os_str()
                .as_bytes()
                .to_vec(),
        )
        .unwrap(),
        ..root
    };
    let create = FileMutationRequest {
        operation: OperationID([1; 16]),
        file: file.clone(),
        expected: ExpectedPathState::Absent,
        command: FileMutation::Create {
            source: ByteSource::Memory(Arc::from(b"original".as_slice())),
        },
    };
    assert!(matches!(
        run(s.mutate(create.clone())).state,
        OperationState::Confirmed(_)
    ));
    fs::write(d.path().join("project/file"), b"external").unwrap();
    assert!(
        matches!(run(s.mutate(create)).state, OperationState::Confirmed(_)),
        "duplicate returns receipt"
    );
    assert_eq!(
        fs::read(d.path().join("project/file")).unwrap(),
        b"external"
    );
    let snap = s.read_sync(file).unwrap();
    let destination = d.path().join("project/occupied");
    fs::write(&destination, b"occupied").unwrap();
    let rename = FileMutationRequest {
        operation: OperationID([2; 16]),
        file: snap.file,
        expected: ExpectedPathState::Present(snap.version),
        command: FileMutation::Rename {
            destination: TargetPath::posix(destination.as_os_str().as_bytes().to_vec()).unwrap(),
        },
    };
    assert!(matches!(
        run(s.mutate(rename)).state,
        OperationState::Failed(_)
    ));
    assert_eq!(fs::read(destination).unwrap(), b"occupied");
}
#[test]
fn preview_preserves_active_epoch_and_dirty_document_state() {
    use buntrail_core::documents::DocumentSession;
    let (d, s, root) = fixture();
    let file = FileRef {
        path: TargetPath::posix(
            d.path()
                .join("project/preview")
                .as_os_str()
                .as_bytes()
                .to_vec(),
        )
        .unwrap(),
        ..root
    };
    fs::write(d.path().join("project/preview"), b"disk").unwrap();
    let id = DocumentID([30; 16]);
    let mut session = DocumentSession::from_loaded(s.load_sync(file, id).unwrap());
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
    edit(&mut session, "draft ");
    s.recovery.write_sync(session.recovery_snapshot()).unwrap();
    let before = session.recovery_snapshot();
    let epoch = fs::read(d.path().join("private/recovery/epoch")).unwrap();
    let (preview, _budget) = s.recovery.preview_budgeted(id).unwrap();
    assert_eq!(preview.snapshot.text.as_str(), "draft disk");
    assert!(preview.lease.is_none());
    assert_eq!(
        fs::read(d.path().join("private/recovery/epoch")).unwrap(),
        epoch
    );
    assert_eq!(session.recovery_snapshot().epoch, before.epoch);
    assert_eq!(session.snapshot().revision, before.snapshot.revision);
    assert!(session.is_dirty());
    edit(&mut session, "new ");
    s.recovery.write_sync(session.recovery_snapshot()).unwrap();
    assert_eq!(
        s.recovery
            .preview_budgeted(id)
            .unwrap()
            .0
            .snapshot
            .text
            .as_str(),
        "new draft disk"
    );
}
#[test]
fn workspace_store_retains_latest_preferences_and_missing_entry_identity() {
    use buntrail_core::workspaces::*;
    use buntrail_services::workspaces::store::WorkspaceStore;
    let (d, s, root) = fixture();
    let store = WorkspaceStore::new(d.path().join("workspaces")).unwrap();
    let WorkspaceState::Ready(mut record) =
        store.open(root.path.clone(), s.target().clone()).unwrap()
    else {
        panic!()
    };
    let old = record.clone();
    fs::write(d.path().join("project/navigation.txt"), b"same content").unwrap();
    record.documents.push(WorkspaceDocument {
        id: DocumentID([31; 16]),
        file: FileRef {
            path: TargetPath::posix(
                d.path()
                    .join("project/navigation.txt")
                    .as_os_str()
                    .as_bytes()
                    .to_vec(),
            )
            .unwrap(),
            ..root.clone()
        },
        version: None,
        viewport: None,
    });
    record.generation = 2;
    record.show_hidden = false;
    record.show_icons = false;
    record.terminal_height = Some(176.0);
    store.update(record.clone()).unwrap();
    store.update(old).unwrap();
    assert_eq!(store.load().unwrap().records[0], record);
    fs::rename(d.path().join("project"), d.path().join("relocated")).unwrap();
    assert!(matches!(
        store
            .open(record.locator.root.clone(), s.target().clone())
            .unwrap(),
        WorkspaceState::Missing(_)
    ));
    let moved = store
        .relocate(
            record.id,
            TargetPath::posix(d.path().join("relocated").as_os_str().as_bytes().to_vec()).unwrap(),
            s.target(),
        )
        .unwrap();
    assert_eq!(moved.id, record.id);
    assert_eq!(moved.lease, record.lease);
    let expected = fs::canonicalize(d.path().join("relocated"))
        .unwrap()
        .join("navigation.txt");
    assert_eq!(
        moved.documents[0].file.path,
        TargetPath::posix(expected.as_os_str().as_bytes().to_vec()).unwrap(),
        "relocation rebinds clean saved paths through filesystem aliases"
    );
    store.remove(moved.id).unwrap();
    assert!(store.load().unwrap().records.is_empty());
}
#[test]
fn local_connection_reports_identity_capabilities_and_owner_state_changes() {
    use buntrail_services::{
        connections::local::LocalConnection,
        contracts::{EnvironmentService, ServiceAvailability},
    };
    let d = tempfile::tempdir().unwrap();
    let connection = LocalConnection::open(d.path().join("local")).unwrap();
    let locator = EnvironmentLocator {
        route: RouteKind::Local,
        ssh_profile: None,
        engine: None,
        engine_context: None,
        container_selector: None,
        effective_user: None,
    };
    let environment =
        run(connection.connect(locator.clone(), Some(connection.identity.clone()))).unwrap();
    assert!(environment.capabilities.0.contains(&Capability::Watch));
    assert!(environment.capabilities.0.contains(&Capability::Search));
    assert!(matches!(
        environment.search,
        ServiceAvailability::Available(_)
    ));
    let mut states = environment.owner.states();
    let w = Waker::noop();
    let mut cx = Context::from_waker(w);
    assert!(matches!(
        states.as_mut().poll_next(&mut cx),
        Poll::Ready(Some(Ok(ConnectionState::Ready)))
    ));
    run(environment
        .owner
        .close(ConnectionCloseReason::WindowDetachment))
    .unwrap();
    assert!(matches!(states.as_mut().poll_next(&mut cx), Poll::Pending));
    run(environment
        .owner
        .close(ConnectionCloseReason::ApplicationShutdown))
    .unwrap();
    assert!(matches!(
        states.as_mut().poll_next(&mut cx),
        Poll::Ready(Some(Ok(ConnectionState::Disconnected)))
    ));
    let mut changed = connection.identity.clone();
    changed.security_binding.push(0);
    assert!(run(connection.connect(locator, Some(changed))).is_err());
}
#[test]
fn explorer_keeps_broken_symlinks_discoverable() {
    let (d, s, root) = fixture();
    std::os::unix::fs::symlink("missing", d.path().join("project/broken-link")).unwrap();
    let entries = s.list_sync(root).unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e.display_name == "broken-link" && e.kind == FileKind::Symlink)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn moves_preserve_raw_posix_names_despite_equal_lossy_display() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let (d, service, root) = fixture();
    let original = d.path().join("project");
    let chosen = original.join("chosen");
    fs::create_dir(&chosen).unwrap();
    // This real UTF-8 name must not conflict with either raw basename.
    fs::write(chosen.join("name-�"), b"display collision").unwrap();
    for (index, byte) in [0xff, 0xfe].into_iter().enumerate() {
        let name = OsString::from_vec([b"name-".as_slice(), &[byte]].concat());
        fs::write(original.join(&name), [byte]).unwrap();
        let entry = service
            .list_sync(root.clone())
            .unwrap()
            .into_iter()
            .find(|e| {
                e.file.path
                    == TargetPath::posix(original.join(&name).as_os_str().as_bytes().to_vec())
                        .unwrap()
            })
            .unwrap();
        assert_eq!(entry.display_name, "name-�");
        let version = service.path_version(entry.file.clone()).unwrap();
        let receipt = service.mutate_sync(FileMutationRequest {
            operation: OperationID([100 + index as u8; 16]),
            file: entry.file,
            expected: ExpectedPathState::Present(version),
            command: FileMutation::Move {
                destination: TargetPath::posix(chosen.join(&name).as_os_str().as_bytes().to_vec())
                    .unwrap(),
            },
        });
        assert!(
            matches!(receipt.state, OperationState::Confirmed(_)),
            "{receipt:?}"
        );
        assert!(!original.join(&name).exists());
        assert_eq!(fs::read(chosen.join(&name)).unwrap(), [byte]);
    }
    assert_eq!(
        fs::read(chosen.join("name-�")).unwrap(),
        b"display collision"
    );
}

#[test]
fn terminal_topology_and_runtime_survive_workspace_store_reopen() {
    use buntrail_core::{terminal::layout::SplitOrientation, workspaces::WorkspaceState};
    use buntrail_services::workspaces::store::WorkspaceStore;
    let (dir, service, root) = fixture();
    let store = WorkspaceStore::new(dir.path().join("workspaces")).unwrap();
    let WorkspaceState::Ready(mut record) =
        store.open(root.path, service.target().clone()).unwrap()
    else {
        panic!()
    };
    let runtime = RuntimeGeneration {
        supervisor_boot: [8; 16],
        container_start: None,
    };
    record
        .terminal_layout
        .new_tab(
            TerminalTabID([1; 16]),
            TerminalSessionID([2; 16]),
            OperationID([4; 16]),
            runtime.clone(),
        )
        .unwrap();
    record
        .terminal_layout
        .split(
            TerminalSessionID([2; 16]),
            TerminalSessionID([3; 16]),
            SplitOrientation::Right,
            OperationID([5; 16]),
            runtime.clone(),
        )
        .unwrap();
    record.terminal_starts = vec![
        buntrail_core::workspaces::TerminalStart {
            session: TerminalSessionID([2; 16]),
            directory: record.locator.root.clone(),
            shell: TargetPath::posix(b"/bin/bash".to_vec()).unwrap(),
        },
        buntrail_core::workspaces::TerminalStart {
            session: TerminalSessionID([3; 16]),
            directory: record.locator.root.clone(),
            shell: TargetPath::posix(b"/bin/bash".to_vec()).unwrap(),
        },
    ];
    record.generation += 1;
    store.update(record.clone()).unwrap();
    drop(store);
    let reopened = WorkspaceStore::new(dir.path().join("workspaces"))
        .unwrap()
        .load()
        .unwrap();
    assert_eq!(reopened.records[0].terminal_layout, record.terminal_layout);
    assert_eq!(
        reopened.records[0].terminal_layout.runtimes,
        vec![
            (
                TerminalSessionID([2; 16]),
                OperationID([4; 16]),
                runtime.clone()
            ),
            (TerminalSessionID([3; 16]), OperationID([5; 16]), runtime)
        ]
    );
}
