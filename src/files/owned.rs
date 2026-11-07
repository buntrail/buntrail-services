//! Immutable save identity captured from a real local registration before dispatch.
use super::{LoadBudget, LocalFileService, MAX_DOCUMENT_BYTES, digest, io_error};
use crate::git::observation::ObservationOwner;
use buntrail_core::{contracts::*, documents::PreparedSave};
use std::sync::Arc;

pub fn save_request_digest(
    file: &FileRef,
    expected: &Option<FileVersion>,
    revision: BufferRevision,
    content: [u8; 32],
) -> Result<[u8; 32], CoreError> {
    Ok(digest(
        &serde_json::to_vec(&(file, expected, revision, content)).map_err(io_error)?,
    ))
}

#[derive(Clone)]
pub struct OwnedLocalFiles {
    files: Arc<LocalFileService>,
    owner: ObservationOwner,
}
pub struct OwnedSave {
    files: Arc<LocalFileService>,
    owner: ObservationOwner,
    request: SaveRequest,
    approval: GitSaveApproval,
    _budget: LoadBudget,
}
impl OwnedLocalFiles {
    pub(crate) fn new(files: Arc<LocalFileService>, owner: ObservationOwner) -> Self {
        Self { files, owner }
    }
    pub fn registration(&self) -> &WorkspaceLease {
        self.owner.registration()
    }
    pub fn prepare(&self, request: SaveRequest) -> Result<OwnedSave, CoreError> {
        self.owner.check()?;
        let length = match &request.source {
            ByteSource::Memory(b) => b.len() as u64,
            ByteSource::PrivateSpool { length, .. } => *length,
        };
        if length > (MAX_DOCUMENT_BYTES * 2 + 4) as u64 {
            return Err(CoreError::new(
                ErrorCode::Unavailable,
                "save source exceeds staging bound",
            ));
        }
        let budget = LoadBudget::acquire(length as usize * 2 + 1024 * 1024)?;
        self.freeze(request, budget)
    }
    pub fn prepare_document(&self, prepared: PreparedSave) -> Result<OwnedSave, CoreError> {
        self.owner.check()?;
        self.files.validate(&prepared.recovery.file)?;
        let (request, budget) = super::document_io::prepare_save(&self.files.recovery, prepared)?;
        self.freeze(request, budget)
    }
    fn freeze(&self, mut request: SaveRequest, budget: LoadBudget) -> Result<OwnedSave, CoreError> {
        self.owner.check()?;
        if request.file.target != self.owner.target {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "owned save target changed",
            ));
        }
        let bytes = match &request.source {
            ByteSource::Memory(bytes) => bytes.clone(),
            source => Arc::from(self.files.source_bytes(
                source,
                MAX_DOCUMENT_BYTES * 2 + 4,
                true,
            )?),
        };
        let approval = GitSaveApproval {
            operation: request.operation,
            actor: self.owner.registration().clone(),
            request_digest: save_request_digest(
                &request.file,
                &request.expected_version,
                request.submitted_revision,
                digest(&bytes),
            )?,
        };
        request.source = ByteSource::Memory(bytes);
        Ok(OwnedSave {
            files: self.files.clone(),
            owner: self.owner.clone(),
            request,
            approval,
            _budget: budget,
        })
    }
}

impl OwnedSave {
    pub fn approval(&self) -> &GitSaveApproval {
        &self.approval
    }
    pub fn execute(self) -> OperationReceipt {
        self.files
            .save_inner(self.request, Some((self.owner.lease, &self.owner.active)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{connections::local::LocalConnection, files::target_path};
    #[test]
    fn owned_prepared_document_keeps_original_identity_and_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let local = LocalConnection::open(dir.path().join("state")).unwrap();
        let lease = WorkspaceLeaseID([11; 16]);
        local.register(WorkspaceID([12; 16]), lease).unwrap();
        let path = dir.path().join("file");
        std::fs::write(&path, "original").unwrap();
        let file = FileRef {
            target: local.identity.clone(),
            path: target_path(&path),
            resolved_identity: None,
        };
        let mut document = buntrail_core::documents::DocumentSession::from_loaded(
            local.files.load_sync(file, DocumentID([13; 16])).unwrap(),
        );
        let pending = local
            .owned_files(lease)
            .unwrap()
            .prepare_document(document.prepare_save(OperationID([14; 16])).unwrap())
            .unwrap();
        let identity = pending.approval().clone();
        document
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
                    text: "later edit".into(),
                }],
            })
            .unwrap();
        let receipt = pending.execute();
        assert!(matches!(receipt.state, OperationState::Confirmed(_)));
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        let ledger = local.files.ledger.lock().unwrap();
        let record = ledger.read(identity.operation).unwrap().unwrap();
        assert_eq!(record.envelope.request_digest, identity.request_digest);
        assert_eq!(record.save_proof.unwrap().actor, identity.actor);
    }
    #[test]
    fn renewed_local_registration_cannot_revive_an_old_prepared_save() {
        let dir = tempfile::tempdir().unwrap();
        let local = LocalConnection::open(dir.path().join("state")).unwrap();
        let lease = WorkspaceLeaseID([15; 16]);
        let workspace = WorkspaceID([16; 16]);
        local.register(workspace, lease).unwrap();
        let path = dir.path().join("new");
        let file = FileRef {
            target: local.identity.clone(),
            path: target_path(&path),
            resolved_identity: None,
        };
        let request = SaveRequest {
            operation: OperationID([17; 16]),
            file,
            expected_version: None,
            submitted_revision: BufferRevision(1),
            source: ByteSource::Memory(Arc::from(b"owned".as_slice())),
        };
        let old = local.owned_files(lease).unwrap();
        let prepared = old.prepare(request.clone()).unwrap();
        local.release(lease);
        local.register(workspace, lease).unwrap();
        assert!(old.prepare(request.clone()).is_err());
        assert!(matches!(
            prepared.execute().state,
            OperationState::Failed(_)
        ));
        assert!(!path.exists());
        assert!(
            local
                .files
                .ledger
                .lock()
                .unwrap()
                .read(request.operation)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            local
                .owned_files(lease)
                .unwrap()
                .prepare(request)
                .unwrap()
                .execute()
                .state,
            OperationState::Confirmed(_)
        ));
    }
}
