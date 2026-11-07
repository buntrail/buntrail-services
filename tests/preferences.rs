#![cfg(unix)]
use buntrail_core::{
    contracts::WorkspaceID,
    preferences::{Appearance, PreferencesOverride},
};
use buntrail_services::preferences::store::PreferencesStore;

#[test]
fn workspace_overrides_survive_reload_without_changing_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let workspace_store = std::sync::Arc::new(
        buntrail_services::workspaces::store::WorkspaceStore::new(dir.path().join("workspace"))
            .unwrap(),
    );
    let store = PreferencesStore::new(dir.path().join("state"), workspace_store.clone()).unwrap();
    let workspace = WorkspaceID([1; 16]);
    let other = WorkspaceID([2; 16]);
    let defaults = store.effective(other).unwrap();
    assert_eq!(defaults.appearance, Appearance::System);
    store
        .set_override(
            workspace,
            PreferencesOverride {
                terminal: Some({
                    let mut style = defaults.terminal.clone();
                    style.font_size = 16.0;
                    style
                }),
                ..Default::default()
            },
        )
        .unwrap();
    let workspace_store = std::sync::Arc::new(
        buntrail_services::workspaces::store::WorkspaceStore::new(dir.path().join("workspace"))
            .unwrap(),
    );
    let store = PreferencesStore::new(dir.path().join("state"), workspace_store.clone()).unwrap();
    assert_eq!(store.effective(workspace).unwrap().terminal.font_size, 16.0);
    assert_eq!(store.effective(other).unwrap(), defaults);
}

#[test]
fn invalid_style_is_rejected_without_overwriting_saved_preferences() {
    let dir = tempfile::tempdir().unwrap();
    let workspace_store = std::sync::Arc::new(
        buntrail_services::workspaces::store::WorkspaceStore::new(dir.path().join("workspace"))
            .unwrap(),
    );
    let store = PreferencesStore::new(dir.path().join("state"), workspace_store.clone()).unwrap();
    let workspace = WorkspaceID([3; 16]);
    let mut defaults = store.effective(workspace).unwrap();
    defaults.terminal.font_size = 16.0;
    store.set_defaults(defaults.clone()).unwrap();
    let mut invalid = defaults.clone();
    invalid.terminal.font_size = f64::NAN;
    assert!(store.set_defaults(invalid).is_err());
    assert_eq!(store.effective(workspace).unwrap(), defaults);
}

#[test]
fn effective_icons_follow_the_existing_workspace_record() {
    use buntrail_core::{
        contracts::{TargetIdentity, TargetPath},
        workspaces::WorkspaceState,
    };
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let workspaces = std::sync::Arc::new(
        buntrail_services::workspaces::store::WorkspaceStore::new(dir.path().join("workspace"))
            .unwrap(),
    );
    let target = TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    let WorkspaceState::Ready(mut record) = workspaces
        .open(
            TargetPath::posix(project.as_os_str().as_bytes().to_vec()).unwrap(),
            target,
        )
        .unwrap()
    else {
        panic!()
    };
    record.show_icons = false;
    record.generation += 1;
    workspaces.update(record.clone()).unwrap();
    let store = PreferencesStore::new(dir.path().join("preferences"), workspaces).unwrap();
    assert!(!store.effective(record.id).unwrap().show_icons);
}

#[test]
fn newer_scheduled_defaults_cannot_be_overwritten_by_a_late_older_write() {
    let dir = tempfile::tempdir().unwrap();
    let workspaces = std::sync::Arc::new(
        buntrail_services::workspaces::store::WorkspaceStore::new(dir.path().join("workspace"))
            .unwrap(),
    );
    let store = PreferencesStore::new(dir.path().join("preferences"), workspaces).unwrap();
    let first = store.reserve_defaults().unwrap();
    let second = store.reserve_defaults().unwrap();
    let mut old = store.effective(WorkspaceID([1; 16])).unwrap();
    let mut new = old.clone();
    old.terminal.font_size = 13.0;
    new.terminal.font_size = 16.0;
    store.set_defaults_ordered(second, new.clone()).unwrap();
    store.set_defaults_ordered(first, old).unwrap();
    assert_eq!(store.effective(WorkspaceID([1; 16])).unwrap(), new);
}

#[test]
fn independent_store_instances_do_not_silently_drop_an_update() {
    let dir = tempfile::tempdir().unwrap();
    let workspaces = std::sync::Arc::new(
        buntrail_services::workspaces::store::WorkspaceStore::new(dir.path().join("workspace"))
            .unwrap(),
    );
    let first = PreferencesStore::new(dir.path().join("preferences"), workspaces.clone()).unwrap();
    let second = PreferencesStore::new(dir.path().join("preferences"), workspaces).unwrap();
    let a = first.reserve_defaults().unwrap();
    let b = second.reserve_defaults().unwrap();
    let mut p = first.effective(WorkspaceID([1; 16])).unwrap();
    p.terminal.font_size = 14.0;
    first.set_defaults_ordered(a, p.clone()).unwrap();
    p.terminal.font_size = 16.0;
    second.set_defaults_ordered(b, p.clone()).unwrap();
    assert_eq!(second.effective(WorkspaceID([1; 16])).unwrap(), p);
}
