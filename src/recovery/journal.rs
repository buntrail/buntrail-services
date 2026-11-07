//! Per-buffer journal ownership; the buffer itself stays in the engine registry.
use super::store::RecoveryStore;
use buntrail_core::{contracts::*, documents::RecoverySnapshot};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
pub struct Journal {
    active: AtomicBool,
    used: AtomicBool,
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    highest: Option<u64>,
    persisted: Option<u64>,
    session: Option<Session>,
}
struct Session {
    document: DocumentID,
    epoch: u64,
    lease: Arc<()>,
    store: Arc<RecoveryStore>,
}
impl Default for Journal {
    fn default() -> Self {
        Self {
            active: AtomicBool::new(true),
            used: AtomicBool::new(false),
            state: Mutex::new(State::default()),
        }
    }
}
impl Journal {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn retire(&self) -> bool {
        self.active.store(false, Ordering::SeqCst);
        self.used.load(Ordering::SeqCst)
    }
    pub fn activate(&self) {
        self.active.store(true, Ordering::SeqCst);
    }
    pub fn write(
        &self,
        store: Arc<RecoveryStore>,
        mut snapshot: RecoverySnapshot,
    ) -> Result<(), CoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::Poisoned, "Recovery ownership is poisoned"))?;
        if (!self.active.load(Ordering::SeqCst) && !snapshot.clean)
            || state.highest.is_some_and(|g| snapshot.generation < g)
            || state.persisted == Some(snapshot.generation)
        {
            return Ok(());
        }
        state.highest = Some(snapshot.generation);
        if state.session.is_none() {
            if snapshot.clean {
                state.persisted = Some(snapshot.generation);
                return Ok(());
            }
            let document = DocumentID(crate::connections::local::new_id()?);
            let (epoch, lease) = store.begin_session(document)?;
            state.session = Some(Session {
                document,
                epoch,
                lease,
                store,
            });
            self.used.store(true, Ordering::SeqCst);
        }
        if !self.active.load(Ordering::SeqCst) && !snapshot.clean {
            return Ok(());
        }
        let session = state.session.as_ref().unwrap();
        snapshot.snapshot.document = session.document;
        snapshot.epoch = session.epoch;
        snapshot.lease = Some(session.lease.clone());
        let generation = snapshot.generation;
        session.store.write_sync(snapshot)?;
        state.persisted = Some(generation);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buntrail_core::Text;
    fn fixture() -> (tempfile::TempDir, Arc<RecoveryStore>, RecoverySnapshot) {
        let root = tempfile::tempdir().unwrap();
        let service = crate::files::LocalFileService::new(
            TargetIdentity {
                security_binding: vec![1],
                effective_user: vec![2],
                filesystem_namespace: vec![3],
                container: None,
            },
            root.path().join("private"),
        )
        .unwrap();
        let path = root.path().join("file");
        std::fs::write(&path, "original").unwrap();
        let file = FileRef {
            target: service.target().clone(),
            path: crate::files::target_path(&path),
            resolved_identity: None,
        };
        let read = service.read_sync(file).unwrap();
        let snapshot = RecoverySnapshot {
            snapshot: DocumentSnapshot {
                document: DocumentID([0; 16]),
                revision: BufferRevision(1),
                text: Arc::new(Text::from("draft")),
                encoding: Encoding::Utf8 { bom: false },
                line_endings: LineEndings::Lf,
                language: None,
            },
            file: read.file,
            version: read.version,
            pending_operation: None,
            pending_revision: None,
            provisional_composition: false,
            generation: 1,
            epoch: 0,
            lease: None,
            clean: false,
        };
        (root, service.recovery.clone(), snapshot)
    }
    #[test]
    fn late_snapshot_cannot_resurrect_a_retired_draft() {
        let (_root, store, snapshot) = fixture();
        let journal = Journal::default();
        journal.write(store.clone(), snapshot.clone()).unwrap();
        assert!(journal.retire());
        let mut clean = snapshot.clone();
        clean.clean = true;
        clean.generation = 3;
        journal.write(store.clone(), clean).unwrap();
        let mut stale = snapshot;
        stale.generation = 2;
        journal.write(store.clone(), stale).unwrap();
        assert!(store.inventory().unwrap().is_empty());
    }
    #[test]
    fn older_clean_marker_cannot_erase_newer_edits() {
        let (_root, store, mut snapshot) = fixture();
        let journal = Journal::new();
        snapshot.generation = 3;
        snapshot.snapshot.text = Arc::new(Text::from("latest"));
        journal.write(store.clone(), snapshot.clone()).unwrap();
        let mut clean = snapshot;
        clean.clean = true;
        clean.generation = 2;
        journal.write(store.clone(), clean).unwrap();
        let entry = &store.inventory().unwrap()[0];
        assert_eq!(
            store
                .restore(entry.document)
                .unwrap()
                .snapshot
                .text
                .as_str(),
            "latest"
        );
    }
    #[test]
    fn failed_discard_keeps_draft_and_can_retry() {
        let (root, store, snapshot) = fixture();
        let journal = Journal::new();
        journal.write(store.clone(), snapshot.clone()).unwrap();
        let directory = root.path().join("private/recovery");
        let moved = root.path().join("held-recovery");
        std::fs::rename(&directory, &moved).unwrap();
        std::fs::write(&directory, b"not a directory").unwrap();
        assert!(journal.retire());
        let mut clean = snapshot.clone();
        clean.clean = true;
        clean.generation = 2;
        let result = journal.write(store.clone(), clean);
        std::fs::remove_file(&directory).unwrap();
        std::fs::rename(&moved, &directory).unwrap();
        assert!(result.is_err());
        let id = store.inventory().unwrap()[0].document;
        assert_eq!(store.restore(id).unwrap().snapshot.text.as_str(), "draft");
        journal.activate();
        let mut retry = snapshot;
        retry.generation = 3;
        retry.snapshot.text = Arc::new(Text::from("latest"));
        journal.write(store.clone(), retry).unwrap();
        assert_eq!(store.restore(id).unwrap().snapshot.text.as_str(), "latest");
    }
}
