use crate::files::{atomic_private, io_error, private_directory};
use buntrail_core::contracts::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
const MAX_RECORDS: usize = 10_000;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SaveObservation {
    pub(crate) requested: FileVersion,
    pub(crate) canonical: FileVersion,
    pub(crate) resolved: TargetPath,
    pub(crate) resolution_token: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SaveProof {
    pub(crate) actor: WorkspaceLease,
    pub(crate) before: Option<SaveObservation>,
    pub(crate) after: Option<SaveObservation>,
}
#[derive(Serialize, Deserialize)]
pub struct Record {
    pub envelope: OperationEnvelope,
    #[serde(default)]
    pub(crate) destination: Option<crate::files::ResolutionEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) save_proof: Option<SaveProof>,
    #[serde(default)]
    pub terminal_request: Option<TerminalOpenRequest>,
    #[serde(default)]
    pub git_intent: Option<GitNetworkIntent>,
    #[serde(default)]
    pub file_destination: Option<TargetPath>,
    pub requested_digest: [u8; 32],
    pub revision: BufferRevision,
    pub receipt: OperationReceipt,
    pub created: u64,
}
pub struct Ledger {
    pub directory: PathBuf,
    lock: File,
    clock: fn() -> u64,
}
pub struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
impl Ledger {
    pub fn open(directory: PathBuf) -> Result<Self, CoreError> {
        private_directory(&directory)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.join("lock"))
            .map_err(io_error)?;
        Ok(Self {
            directory,
            lock,
            clock: now,
        })
    }
    pub fn lock(&self) -> Result<Lock, CoreError> {
        let lock = self.lock.try_clone().map_err(io_error)?;
        lock.lock().map_err(io_error)?;
        Ok(Lock(lock))
    }
    /// Reserved inspection callers must not wait behind durable admission.
    pub fn try_lock(&self) -> Result<Lock, CoreError> {
        let lock = self.lock.try_clone().map_err(io_error)?;
        lock.try_lock().map_err(|_| {
            CoreError::new(
                ErrorCode::Unavailable,
                "operation ledger lookup is busy or unavailable",
            )
        })?;
        Ok(Lock(lock))
    }
    fn path(&self, id: OperationID) -> PathBuf {
        self.directory.join(format!(
            "{}.json",
            id.0.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ))
    }
    pub fn read(&self, id: OperationID) -> Result<Option<Record>, CoreError> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.path(id))
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_error(e)),
        };
        let mut bytes = vec![];
        file.take(128 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() > 128 * 1024 {
            return Err(io_error("operation record too large"));
        }
        let r: Record = serde_json::from_slice(&bytes).map_err(io_error)?;
        if r.envelope.id != id || r.receipt.id != id {
            return Err(io_error("operation record identity mismatch"));
        }
        Ok(Some(r))
    }
    pub fn write(&self, record: &Record) -> Result<(), CoreError> {
        let bytes = serde_json::to_vec(record).map_err(io_error)?;
        if bytes.len() > 128 * 1024 {
            return Err(io_error("operation record exceeds inspectable size bound"));
        }
        atomic_private(&self.path(record.envelope.id), &bytes)
    }
    /// The caller retains the shared admission lock through this check and durable write.
    /// Some(receipt) means the ID already belongs to that request: do not execute it again.
    pub fn accept(
        &self,
        record: &Record,
        _lock: &Lock,
    ) -> Result<Option<OperationReceipt>, CoreError> {
        if let Some(old) = self.read(record.envelope.id)? {
            if old.envelope != record.envelope {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "operation ID belongs to a different request, target or service",
                ));
            }
            return self
                .inspect(record.envelope.id, record.envelope.target.clone())
                .map(Some);
        }
        let mut count = 0;
        let mut running = 0;
        for entry in fs::read_dir(&self.directory).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            if entry.path().extension().is_none_or(|e| e != "json") {
                continue;
            }
            count += 1;
            let f = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(entry.path())
                .map_err(io_error)?;
            let mut bytes = vec![];
            f.take(128 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(io_error)?;
            if bytes.len() > 128 * 1024 {
                return Err(io_error("operation record too large"));
            }
            let mut r: Record = serde_json::from_slice(&bytes).map_err(io_error)?;
            if let (Some(existing), Some(requested)) =
                (&r.terminal_request, &record.terminal_request)
                && existing.session == requested.session
                && r.envelope.id != record.envelope.id
            {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "terminal session ID was already used",
                ));
            }
            if self.expired(&r)
                && matches!(
                    r.receipt.state,
                    OperationState::Confirmed(_) | OperationState::Failed(_)
                )
            {
                r.receipt = unknown(
                    r.envelope.id,
                    r.envelope.target.clone(),
                    "expired receipt; never replay",
                );
                self.write(&r)?;
            }
            if matches!(
                r.receipt.state,
                OperationState::Accepted | OperationState::Running
            ) {
                running += 1;
            }
        }
        // Retain bounded ID tombstones: at capacity refuse new work instead of replaying an expired ID.
        if count >= MAX_RECORDS || running >= 64 {
            return Err(CoreError::new(
                ErrorCode::Busy,
                "durable operation capacity reached",
            ));
        }
        self.write(record)?;
        Ok(None)
    }
    /// Only the exclusive supervisor owner calls recovery, before accepting connections.
    pub fn recover_and_compact(&self, lock: &Lock) -> Result<(), CoreError> {
        self.maintenance(true, lock)
    }
    pub fn compact(&self, lock: &Lock) -> Result<(), CoreError> {
        self.maintenance(false, lock)
    }
    fn maintenance(&self, recover: bool, _lock: &Lock) -> Result<(), CoreError> {
        for entry in fs::read_dir(&self.directory).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| io_error("invalid receipt filename"))?;
            if name.len() != 32 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(io_error("invalid receipt filename"));
            }
            let mut bytes = [0; 16];
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = u8::from_str_radix(&name[i * 2..i * 2 + 2], 16).map_err(io_error)?;
            }
            let Some(mut record) = self.read(OperationID(bytes))? else {
                continue;
            };
            if recover
                && matches!(
                    record.receipt.state,
                    OperationState::Accepted | OperationState::Running
                )
            {
                record.receipt = unknown(
                    record.envelope.id,
                    record.envelope.target.clone(),
                    "supervisor interrupted; reconcile, never replay",
                );
                self.write(&record)?;
            } else if self.expired(&record)
                && matches!(
                    record.receipt.state,
                    OperationState::Confirmed(_) | OperationState::Failed(_)
                )
            {
                record.receipt = unknown(
                    record.envelope.id,
                    record.envelope.target.clone(),
                    "expired receipt; never replay",
                );
                record.destination = None;
                // Preserve envelope and terminal session ownership: compaction must not enable ID reuse.
                self.write(&record)?;
            }
        }
        Ok(())
    }
    pub fn expired(&self, record: &Record) -> bool {
        (self.clock)().saturating_sub(record.created) > 86400
    }
    pub fn inspect(
        &self,
        id: OperationID,
        target: TargetIdentity,
    ) -> Result<OperationReceipt, CoreError> {
        let Some(record) = self.read(id)? else {
            return Ok(unknown(
                id,
                target,
                "operation record missing; never replay",
            ));
        };
        if record.envelope.target != target {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "operation target mismatch",
            ));
        }
        if self.expired(&record)
            || matches!(
                record.receipt.state,
                OperationState::Accepted | OperationState::Running
            )
        {
            return Ok(unknown(
                id,
                target,
                &format!(
                    "expired or interrupted operation; inspect current contents, never replay; destination: {:?}",
                    record.file_destination
                ),
            ));
        }
        if record.file_destination.is_some()
            && matches!(record.receipt.state, OperationState::Unknown(_))
        {
            return Ok(unknown(
                id,
                target,
                &format!(
                    "File outcome is unresolved; inspect original paths and destination: {:?}; never replay",
                    record.file_destination
                ),
            ));
        }
        Ok(record.receipt)
    }
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn unknown(id: OperationID, target: TargetIdentity, message: &str) -> OperationReceipt {
    OperationReceipt {
        id,
        state: OperationState::Unknown(ReconciliationEvidence {
            target,
            observed: ObservedState::Unobserved,
            explanation: message.into(),
        }),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn record(n: u16, running: bool) -> Record {
        let target = TargetIdentity {
            security_binding: vec![1],
            effective_user: vec![2],
            filesystem_namespace: vec![3],
            container: None,
        };
        let mut id = [0; 16];
        id[..2].copy_from_slice(&n.to_be_bytes());
        let id = OperationID(id);
        Record {
            envelope: OperationEnvelope {
                id,
                target: target.clone(),
                request_digest: [1; 32],
                kind: MutationKind::Save,
                expected: ExpectedState::File {
                    file: FileRef {
                        target: target.clone(),
                        path: TargetPath::posix(b"/file".to_vec()).unwrap(),
                        resolved_identity: None,
                    },
                    version: None,
                },
            },
            destination: None,
            save_proof: None,
            terminal_request: None,
            git_intent: None,
            file_destination: None,
            requested_digest: [2; 32],
            revision: BufferRevision(1),
            receipt: if running {
                OperationReceipt {
                    id,
                    state: OperationState::Accepted,
                }
            } else {
                crate::files::failure(
                    id,
                    target,
                    CoreError::new(ErrorCode::Io, "failed before mutation"),
                )
            },
            created: 100,
        }
    }
    #[test]
    fn oversized_admission_is_refused_before_writing_an_uninspectable_record() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(dir.path().join("ledger")).unwrap();
        let lock = ledger.lock().unwrap();
        let mut r = record(4, true);
        r.git_intent = Some(GitNetworkIntent {
            action: GitNetworkAction::Push,
            remote: vec![255; 128 * 1024],
            reference: b"refs/heads/main".to_vec(),
            endpoint_fingerprint: None,
            push_mapping_unconfigured: true,
        });
        assert!(ledger.accept(&r, &lock).is_err());
        assert!(!ledger.path(r.envelope.id).exists());
    }
    #[test]
    fn duplicate_admission_never_overwrites_original_record() {
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = Ledger::open(dir.path().join("ledger")).unwrap();
        ledger.clock = || 100;
        let _lock = ledger.lock().unwrap();
        let original = record(1, false);
        ledger.accept(&original, &_lock).unwrap();
        for change in 0..3 {
            let mut conflicting = record(1, true);
            match change {
                0 => conflicting.envelope.request_digest = [9; 32],
                1 => conflicting.envelope.target.effective_user = vec![9],
                _ => conflicting.envelope.kind = MutationKind::Git,
            }
            assert!(
                ledger.accept(&conflicting, &_lock).is_err(),
                "changed request/target/service must be refused"
            );
            assert_eq!(
                ledger.read(original.envelope.id).unwrap().unwrap().receipt,
                original.receipt
            );
        }
        // The same request must not replace its completed receipt with Accepted.
        let retry = record(1, true);
        assert_eq!(
            ledger.accept(&retry, &_lock).unwrap(),
            Some(original.receipt.clone())
        );
        assert_eq!(
            ledger.read(original.envelope.id).unwrap().unwrap().receipt,
            original.receipt
        );
    }
    #[test]
    fn expired_receipt_is_unknown_and_tombstone_rejects_reacceptance() {
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = Ledger::open(dir.path().join("ledger")).unwrap();
        ledger.clock = || 86501;
        let r = record(1, false);
        ledger.write(&r).unwrap();
        assert!(matches!(
            ledger
                .inspect(r.envelope.id, r.envelope.target.clone())
                .unwrap()
                .state,
            OperationState::Unknown(_)
        ));
        assert!(ledger.read(r.envelope.id).unwrap().is_some());
    }
    #[test]
    fn acceptance_rejects_sixty_fifth_running_record_before_writing() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(dir.path().join("ledger")).unwrap();
        for n in 0..64 {
            let r = record(n, true);
            fs::write(ledger.path(r.envelope.id), serde_json::to_vec(&r).unwrap()).unwrap();
        }
        let rejected = record(64, true);
        let lock = ledger.lock().unwrap();
        assert_eq!(
            ledger.accept(&rejected, &lock).unwrap_err().code,
            ErrorCode::Busy
        );
        assert!(ledger.read(rejected.envelope.id).unwrap().is_none());
    }
    #[test]
    fn tombstone_capacity_rejects_before_acceptance() {
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = Ledger::open(dir.path().join("ledger")).unwrap();
        ledger.clock = || 100;
        for n in 0..10_000 {
            let r = record(n, false);
            fs::write(ledger.path(r.envelope.id), serde_json::to_vec(&r).unwrap()).unwrap();
        }
        let rejected = record(10_000, false);
        let lock = ledger.lock().unwrap();
        assert_eq!(
            ledger.accept(&rejected, &lock).unwrap_err().code,
            ErrorCode::Busy
        );
        assert!(ledger.read(rejected.envelope.id).unwrap().is_none());
    }
    #[test]
    fn compaction_preserves_running_and_rejects_expired_id_reuse() {
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = Ledger::open(dir.path().join("ledger")).unwrap();
        ledger.clock = || 86501;
        let original = record(1, false);
        let running = record(2, true);
        ledger.write(&original).unwrap();
        ledger.write(&running).unwrap();
        let lock = ledger.lock().unwrap();
        ledger.compact(&lock).unwrap();
        assert!(matches!(
            ledger
                .read(running.envelope.id)
                .unwrap()
                .unwrap()
                .receipt
                .state,
            OperationState::Accepted
        ));
        ledger.recover_and_compact(&lock).unwrap();
        for id in [original.envelope.id, running.envelope.id] {
            assert!(matches!(
                ledger.read(id).unwrap().unwrap().receipt.state,
                OperationState::Unknown(_)
            ));
        }
        assert!(matches!(
            ledger.accept(&original, &lock).unwrap().unwrap().state,
            OperationState::Unknown(_)
        ));
        let mut different = original;
        different.envelope.request_digest = [99; 32];
        assert_eq!(
            ledger.accept(&different, &lock).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }
}
