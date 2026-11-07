use crate::files::{LoadBudget, MAX_DOCUMENT_BYTES, io_error, private_directory};
use buntrail_core::{Text, contracts::*, documents::RecoverySnapshot};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
};
#[derive(Serialize, Deserialize)]
struct Header {
    schema: u32,
    generation: u64,
    #[serde(default)]
    epoch: u64,
    clean: bool,
    document: DocumentID,
    revision: BufferRevision,
    encoding: Encoding,
    line_endings: LineEndings,
    language: Option<String>,
    file: FileRef,
    version: FileVersion,
    pending_operation: Option<OperationID>,
    pending_revision: Option<BufferRevision>,
    provisional_composition: bool,
    text_sha256: [u8; 32],
}
pub struct RecoveryStore {
    directory: PathBuf,
    write_lock: Mutex<()>,
    sessions: Arc<crate::leases::LeasePool>,
}
impl RecoveryStore {
    pub fn new(directory: PathBuf) -> Result<Self, CoreError> {
        private_directory(&directory)?;
        Ok(Self {
            sessions: crate::leases::LeasePool::open(directory.join("sessions"))?,
            directory,
            write_lock: Mutex::new(()),
        })
    }
    fn name(id: DocumentID) -> String {
        id.0.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn disk_lock(&self) -> Result<RecoveryLock, CoreError> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.directory.join("lock"))
            .map_err(io_error)?;
        f.lock().map_err(io_error)?;
        Ok(RecoveryLock(f))
    }
    /// Called only during worker loading/restoration. The durable epoch survives clean-marker pruning.
    pub fn begin_session(&self, id: DocumentID) -> Result<(u64, Arc<()>), CoreError> {
        let _lock = self.write_lock.lock().map_err(io_error)?;
        let _disk = self.disk_lock()?;
        let token = self.sessions.session(&Self::name(id))?;
        let epoch = self.next_epoch()?;
        Ok((epoch, token))
    }
    // The caller holds both store admission locks.
    fn next_epoch(&self) -> Result<u64, CoreError> {
        let path = self.directory.join("epoch");
        let old = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => {
                let mut bytes = vec![];
                file.take(9).read_to_end(&mut bytes).map_err(io_error)?;
                u64::from_be_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| io_error("invalid journal epoch"))?,
                )
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(io_error(e)),
        };
        let epoch = old
            .checked_add(1)
            .ok_or_else(|| io_error("journal epoch exhausted"))?;
        crate::files::atomic_private(&path, &epoch.to_be_bytes())?;
        Ok(epoch)
    }
    pub fn active(&self, id: DocumentID) -> Result<bool, CoreError> {
        self.sessions.sweep()?;
        self.sessions.session_is_live(&Self::name(id))
    }
    pub fn discard(&self, id: DocumentID) -> Result<(), CoreError> {
        let _lock = self.write_lock.lock().map_err(io_error)?;
        let _disk = self.disk_lock()?;
        let (header, _) = match self.header(id) {
            Ok(value) => value,
            Err(_error) if !self.path(id).exists() => return Ok(()),
            Err(error) => return Err(error),
        };
        if header.clean {
            return Ok(());
        }
        if header.pending_operation.is_some() {
            return Err(CoreError::new(
                ErrorCode::Unknown,
                "Inspect the uncertain save before deleting its recovery draft",
            ));
        }
        let _owner = self.sessions.exclusive_session(&Self::name(id))?;
        let generation = header
            .generation
            .checked_add(1)
            .ok_or_else(|| io_error("Recovery generation exhausted"))?;
        let epoch = self.next_epoch()?;
        self.write_locked(RecoverySnapshot {
            snapshot: DocumentSnapshot {
                document: id,
                revision: header.revision,
                text: Arc::new(Text::from("")),
                encoding: header.encoding,
                line_endings: header.line_endings,
                language: header.language,
            },
            file: header.file,
            version: header.version,
            pending_operation: None,
            pending_revision: None,
            provisional_composition: false,
            generation,
            epoch,
            lease: None,
            clean: true,
        })
    }
    /// Observation only; a confirmed receipt never discards recovered text.
    pub fn inspect_pending(
        &self,
        id: DocumentID,
        inspect: impl FnOnce(OperationID, TargetIdentity) -> Result<OperationReceipt, CoreError>,
    ) -> Result<OperationReceipt, CoreError> {
        let _owner = self.sessions.exclusive_session(&Self::name(id))?;
        let (mut snapshot, _budget) = self.preview_budgeted(id)?;
        let operation = snapshot.pending_operation.ok_or_else(|| {
            CoreError::new(ErrorCode::InvalidArgument, "Recovery has no pending save")
        })?;
        let receipt = inspect(operation, snapshot.file.target.clone())?;
        let target = &snapshot.file.target;
        let resolved = match &receipt.state {
            OperationState::Confirmed(MutationResult::Saved(saved))
                if Some(saved.saved_revision) == snapshot.pending_revision
                    && &saved.version.target == target =>
            {
                true
            }
            OperationState::Confirmed(_) => {
                return Err(io_error("Recovery receipt revision or kind differs"));
            }
            OperationState::Failed(f) if &f.target == target => {
                f.effect == FailureEffect::ProvenNoEffect
            }
            OperationState::Unknown(e) if &e.target == target => false,
            OperationState::Accepted | OperationState::Running => false,
            _ => return Err(io_error("Recovery receipt target differs")),
        };
        if receipt.id != operation {
            return Err(io_error("Recovery receipt operation differs"));
        }
        if resolved {
            let _lock = self.write_lock.lock().map_err(io_error)?;
            let _disk = self.disk_lock()?;
            let (current, _) = self.header(id)?;
            if current.epoch != snapshot.epoch
                || current.generation != snapshot.generation
                || current.pending_operation != Some(operation)
                || current.file != snapshot.file
                || current.version != snapshot.version
            {
                return Err(CoreError::new(
                    ErrorCode::StaleRevision,
                    "Recovery changed during inspection",
                ));
            }
            snapshot.pending_operation = None;
            snapshot.pending_revision = None;
            snapshot.generation = snapshot
                .generation
                .checked_add(1)
                .ok_or_else(|| io_error("Recovery generation exhausted"))?;
            snapshot.epoch = self.next_epoch()?;
            self.write_locked(snapshot)?;
        }
        Ok(receipt)
    }
    fn path(&self, id: DocumentID) -> PathBuf {
        self.directory.join(format!(
            "{}.draft",
            id.0.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ))
    }
    fn header(&self, id: DocumentID) -> Result<(Header, File), CoreError> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.path(id))
            .map_err(io_error)?;
        let mut length = [0; 4];
        file.read_exact(&mut length).map_err(io_error)?;
        let length = u32::from_be_bytes(length) as usize;
        if length > 65536 {
            return Err(io_error("recovery header exceeds limit"));
        }
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes).map_err(io_error)?;
        let header: Header = serde_json::from_slice(&bytes).map_err(io_error)?;
        if header.schema != 1
            || header.document != id
            || header.file.target != header.version.target
            || header.pending_operation.is_some() != header.pending_revision.is_some()
        {
            return Err(io_error("recovery identity/schema mismatch"));
        }
        Ok((header, file))
    }
    /// Metadata only; corrupt/unsupported files remain visible and are never removed here.
    pub fn inventory(&self) -> Result<Vec<buntrail_core::workspaces::RecoveryEntry>, CoreError> {
        let mut found = vec![];
        for entry in fs::read_dir(&self.directory).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name();
            let Some(name) = name.to_str().and_then(|s| s.strip_suffix(".draft")) else {
                continue;
            };
            if name.len() != 32 || !name.is_ascii() {
                continue;
            }
            let mut bytes = [0; 16];
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = u8::from_str_radix(&name[i * 2..i * 2 + 2], 16).map_err(io_error)?;
            }
            let document = DocumentID(bytes);
            match self.header(document) {
                Ok((h, _)) if !h.clean => found.push(buntrail_core::workspaces::RecoveryEntry {
                    document,
                    file: Some(h.file),
                    provisional: h.provisional_composition,
                    unknown_save: h.pending_operation.is_some(),
                    error: None,
                }),
                Ok(_) => {}
                Err(error) => found.push(buntrail_core::workspaces::RecoveryEntry {
                    document,
                    file: None,
                    provisional: false,
                    unknown_save: false,
                    error: Some(error),
                }),
            }
            if found.len() > 64 {
                return Err(io_error("draft discovery exceeds 64 document limit"));
            }
        }
        Ok(found)
    }
    pub fn discover(&self) -> Result<Vec<(DocumentID, FileRef)>, CoreError> {
        Ok(self
            .inventory()?
            .into_iter()
            .filter_map(|e| e.file.map(|f| (e.document, f)))
            .collect())
    }
    pub fn write_sync(&self, snapshot: RecoverySnapshot) -> Result<(), CoreError> {
        let _lock = self.write_lock.lock().map_err(io_error)?;
        let _disk = self.disk_lock()?;
        self.write_locked(snapshot)
    }
    fn write_locked(&self, snapshot: RecoverySnapshot) -> Result<(), CoreError> {
        if snapshot.snapshot.text.len() > MAX_DOCUMENT_BYTES {
            return Err(CoreError::new(
                ErrorCode::Unavailable,
                "draft exceeds editable limit",
            ));
        }
        if let Ok((old, _)) = self.header(snapshot.snapshot.document) {
            if (old.epoch, old.generation) > (snapshot.epoch, snapshot.generation) {
                return Ok(());
            }
            if old.file.target != snapshot.file.target
                || (old.file.path != snapshot.file.path
                    && !(old.epoch == snapshot.epoch
                        && old.version.file_identity == snapshot.version.file_identity
                        && snapshot.generation > old.generation))
            {
                return Err(CoreError::new(
                    ErrorCode::TargetChanged,
                    "document draft belongs to another file",
                ));
            }
            if (old.epoch, old.generation) > (snapshot.epoch, snapshot.generation) {
                return Ok(());
            }
        }
        if !self.path(snapshot.snapshot.document).exists() {
            for entry in fs::read_dir(&self.directory).map_err(io_error)? {
                let entry = entry.map_err(io_error)?;
                let name = entry.file_name();
                let Some(name) = name.to_str().and_then(|s| s.strip_suffix(".draft")) else {
                    continue;
                };
                if name.len() != 32 || !name.is_ascii() {
                    continue;
                }
                let parsed = (0..16)
                    .map(|i| u8::from_str_radix(&name[i * 2..i * 2 + 2], 16))
                    .collect::<Result<Vec<_>, _>>();
                if let Ok(bytes) = parsed {
                    let id = DocumentID(bytes.try_into().unwrap());
                    if self.header(id).is_ok_and(|(h, _)| h.clean)
                        && !self.sessions.session_is_live(&Self::name(id))?
                    {
                        fs::remove_file(entry.path()).map_err(io_error)?;
                    }
                }
            }
        }
        if !self.path(snapshot.snapshot.document).exists()
            && fs::read_dir(&self.directory)
                .map_err(io_error)?
                .filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|v| v == "draft"))
                .take(64)
                .count()
                >= 64
        {
            return Err(CoreError::new(
                ErrorCode::Busy,
                "recovery document capacity reached",
            ));
        }
        let mut digest = Sha256::new();
        for chunk in snapshot.snapshot.text.chunks() {
            digest.update(chunk.as_bytes());
        }
        let header = Header {
            schema: 1,
            generation: snapshot.generation,
            epoch: snapshot.epoch,
            clean: snapshot.clean,
            document: snapshot.snapshot.document,
            revision: snapshot.snapshot.revision,
            encoding: snapshot.snapshot.encoding,
            line_endings: snapshot.snapshot.line_endings,
            language: snapshot.snapshot.language,
            file: snapshot.file,
            version: snapshot.version,
            pending_operation: snapshot.pending_operation,
            pending_revision: snapshot.pending_revision,
            provisional_composition: snapshot.provisional_composition,
            text_sha256: digest.finalize().into(),
        };
        let bytes = serde_json::to_vec(&header).map_err(io_error)?;
        if bytes.len() > 65536 {
            return Err(io_error("recovery header exceeds limit"));
        }
        let mut temporary = tempfile::NamedTempFile::new_in(&self.directory).map_err(io_error)?;
        temporary
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .map_err(io_error)?;
        temporary.write_all(&bytes).map_err(io_error)?;
        if !snapshot.clean {
            for chunk in snapshot.snapshot.text.chunks() {
                temporary.write_all(chunk.as_bytes()).map_err(io_error)?;
            }
        }
        temporary.as_file().sync_all().map_err(io_error)?;
        temporary
            .persist(self.path(header.document))
            .map_err(io_error)?;
        File::open(&self.directory)
            .and_then(|f| f.sync_all())
            .map_err(io_error)
    }
    pub fn restore(&self, document: DocumentID) -> Result<RecoverySnapshot, CoreError> {
        self.restore_budgeted(document).map(|(s, _)| s)
    }
    pub fn restore_budgeted(
        &self,
        document: DocumentID,
    ) -> Result<(RecoverySnapshot, LoadBudget), CoreError> {
        let (epoch, lease) = self.begin_session(document)?;
        let (mut snapshot, budget) = self.preview_budgeted(document)?;
        snapshot.epoch = epoch;
        snapshot.lease = Some(lease);
        Ok((snapshot, budget))
    }
    /// A preview reads an immutable draft file without acquiring or advancing session ownership.
    pub fn preview_budgeted(
        &self,
        document: DocumentID,
    ) -> Result<(RecoverySnapshot, LoadBudget), CoreError> {
        let (h, file) = self.header(document)?;
        if h.clean {
            return Err(CoreError::new(
                ErrorCode::Unavailable,
                "document has no unconfirmed recovery draft",
            ));
        }
        let size = file.metadata().map_err(io_error)?.len();
        if size > MAX_DOCUMENT_BYTES as u64 + 65540 {
            return Err(io_error("recovery file exceeds limit"));
        }
        let budget = LoadBudget::acquire(
            (size as usize)
                .saturating_mul(3)
                .saturating_add(1024 * 1024),
        )?;
        let mut bytes = vec![];
        file.take(MAX_DOCUMENT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() > MAX_DOCUMENT_BYTES
            || <[u8; 32]>::from(Sha256::digest(&bytes)) != h.text_sha256
        {
            return Err(io_error("recovery checksum/length mismatch"));
        }
        let text = String::from_utf8(bytes).map_err(io_error)?;
        Ok((
            RecoverySnapshot {
                snapshot: DocumentSnapshot {
                    document: h.document,
                    revision: h.revision,
                    text: Arc::new(Text::from(text)),
                    encoding: h.encoding,
                    line_endings: h.line_endings,
                    language: h.language,
                },
                file: h.file,
                version: h.version,
                pending_operation: h.pending_operation,
                pending_revision: h.pending_revision,
                provisional_composition: h.provisional_composition,
                generation: h.generation,
                epoch: h.epoch,
                lease: None,
                clean: false,
            },
            budget,
        ))
    }
    pub fn write(
        &self,
        snapshot: RecoverySnapshot,
    ) -> buntrail_core::contracts::async_types::ServiceFuture<'_, Result<(), CoreError>> {
        Box::pin(async move { self.write_sync(snapshot) })
    }
}

struct RecoveryLock(File);
impl Drop for RecoveryLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
