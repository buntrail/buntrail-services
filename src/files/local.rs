use crate::{contracts::*, operations::ledger::Ledger, recovery::store::RecoveryStore};
use buntrail_core::{contracts::*, documents::*};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Seek, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
};
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_ENCODED_BYTES: usize = MAX_DOCUMENT_BYTES * 2 + 4;
pub const MEMORY_FILE_BYTES: usize = 256 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FailPoint {
    None,
    Acceptance,
    Write,
    FullDisk,
    Permission,
    Acknowledgement,
    Completion,
    AfterAcceptance,
}
pub struct LocalFileService {
    target: TargetIdentity,
    spools: Arc<crate::leases::LeasePool>,
    pub(crate) ledger: Mutex<Ledger>,
    failpoint: AtomicU8,
    pub recovery: Arc<RecoveryStore>,
    #[cfg(test)]
    before_read_validation: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    after_save_acceptance: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    after_save_authorization: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    after_save_replacement: Option<Arc<dyn Fn() + Send + Sync>>,
}
pub(crate) fn io_error(e: impl std::fmt::Display) -> CoreError {
    CoreError::new(ErrorCode::Io, &e.to_string())
}
pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub(crate) fn absent_structure(
    destination: &Option<ResolutionEvidence>,
) -> Result<[u8; 32], CoreError> {
    let mut hash = Sha256::new();
    hash.update(b"buntrail.node-structure.v1\0");
    hash.update(b"absent");
    hash_field(
        &mut hash,
        &serde_json::to_vec(destination).map_err(io_error)?,
    );
    Ok(hash.finalize().into())
}
pub(crate) fn path(p: &TargetPath) -> Result<PathBuf, CoreError> {
    match p {
        TargetPath::PosixBytes(b) if b.first() == Some(&b'/') && !b.contains(&0) => {
            Ok(PathBuf::from(std::ffi::OsStr::from_bytes(b)))
        }
        _ => Err(CoreError::new(
            ErrorCode::InvalidArgument,
            "invalid local POSIX path",
        )),
    }
}
pub(crate) fn target_path(p: &Path) -> TargetPath {
    TargetPath::PosixBytes(p.as_os_str().as_bytes().to_vec())
}
pub(crate) fn private_directory(p: &Path) -> Result<(), CoreError> {
    match std::os::unix::fs::DirBuilderExt::mode(&mut fs::DirBuilder::new(), 0o700).create(p) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io_error(e)),
    }
    let m = fs::symlink_metadata(p).map_err(io_error)?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err(CoreError::new(
            ErrorCode::InvalidArgument,
            "storage directory must be private and owned by current user",
        ));
    }
    File::open(p).and_then(|f| f.sync_all()).map_err(io_error)?;
    if let Some(parent) = p.parent() {
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(io_error)?;
    }
    Ok(())
}
pub(crate) fn atomic_private(path: &Path, bytes: &[u8]) -> Result<(), CoreError> {
    let parent = path.parent().ok_or_else(|| io_error("missing parent"))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(io_error)?;
    temp.write_all(bytes).map_err(io_error)?;
    temp.as_file().sync_all().map_err(io_error)?;
    temp.persist(path).map_err(io_error)?;
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(io_error)
}
fn identity(m: &Metadata) -> Vec<u8> {
    [m.dev().to_be_bytes(), m.ino().to_be_bytes()].concat()
}
fn metadata_token(m: &Metadata) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(identity(m));
    hash.update(m.mode().to_be_bytes());
    hash.update(m.uid().to_be_bytes());
    hash.update(m.gid().to_be_bytes());
    hash.update(m.len().to_be_bytes());
    hash.update(m.mtime().to_be_bytes());
    hash.update(m.mtime_nsec().to_be_bytes());
    hash.update(m.ctime().to_be_bytes());
    hash.update(m.ctime_nsec().to_be_bytes());
    hash.finalize().into()
}
fn hash_field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}
pub(super) fn open_regular(p: &Path) -> Result<File, CoreError> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)
        .map_err(io_error)?;
    if !f.metadata().map_err(io_error)?.is_file() {
        return Err(CoreError::new(
            ErrorCode::Unavailable,
            "special files cannot be edited",
        ));
    }
    Ok(f)
}
fn version(
    file: &FileRef,
    resolved: &Path,
    meta: &Metadata,
    content: [u8; 32],
    link: &Metadata,
    destination: &ResolutionEvidence,
) -> FileVersion {
    let mut h = Sha256::new();
    h.update(b"buntrail.file-version.v2\0");
    hash_field(&mut h, resolved.as_os_str().as_bytes());
    // Canonical resolution and every symlink node participate in the opened version.
    for (path, identity, destination) in &destination.links {
        if let TargetPath::PosixBytes(bytes) = path {
            hash_field(&mut h, bytes);
        }
        hash_field(&mut h, identity);
        if let TargetPath::PosixBytes(bytes) = destination {
            hash_field(&mut h, bytes);
        }
    }
    h.update(&destination.parent_identity);
    h.update(metadata_token(meta));
    h.update(metadata_token(link));
    h.update(content);
    FileVersion {
        target: file.target.clone(),
        opaque_token: h.finalize().to_vec(),
        content_digest: content,
        file_identity: identity(meta),
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FileObservation {
    pub(crate) version: FileVersion,
    pub(crate) canonical_version: FileVersion,
    pub(crate) destination: ResolutionEvidence,
    pub(crate) size: u64,
}
impl FileObservation {
    fn save_observation(&self) -> Result<crate::operations::ledger::SaveObservation, CoreError> {
        Ok(crate::operations::ledger::SaveObservation {
            requested: self.version.clone(),
            canonical: self.canonical_version.clone(),
            resolved: self.destination.resolved.clone(),
            resolution_token: digest(&serde_json::to_vec(&self.destination).map_err(io_error)?),
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NodeObservation {
    pub(crate) structural_token: [u8; 32],
    pub(crate) regular: Option<FileObservation>,
    pub(crate) destination: Option<ResolutionEvidence>,
}
// Destination evidence excludes the final regular-file inode: atomic replacement changes it.
// Symlink nodes and the resolved parent must retain their identity across reconciliation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ResolutionEvidence {
    pub(crate) resolved: TargetPath,
    pub(crate) parent_identity: Vec<u8>,
    pub(crate) links: Vec<(TargetPath, Vec<u8>, TargetPath)>,
}
fn resolution(original: &Path) -> Result<ResolutionEvidence, CoreError> {
    resolve_observed(original, false)
}
fn resolve_observed(
    original: &Path,
    allow_missing_parents: bool,
) -> Result<ResolutionEvidence, CoreError> {
    let expected = match fs::canonicalize(original) {
        Ok(p) => Some(p),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(io_error(e)),
    };
    let mut missing_parent = None;
    let mut prefix = PathBuf::from("/");
    let mut pending: std::collections::VecDeque<_> = original
        .components()
        .skip(1)
        .map(|c| c.as_os_str().to_os_string())
        .collect();
    let mut links = vec![];
    while let Some(component) = pending.pop_front() {
        if component == "." {
            continue;
        }
        if component == ".." {
            prefix.pop();
            continue;
        }
        prefix.push(&component);
        match fs::symlink_metadata(&prefix) {
            Ok(m) if m.file_type().is_symlink() => {
                // Linux resolves at most 40 links; macOS canonicalize above enforces its smaller limit.
                if links.len() == 40 {
                    return Err(io_error(std::io::Error::from_raw_os_error(libc::ELOOP)));
                }
                let destination = fs::read_link(&prefix).map_err(io_error)?;
                if metadata_token(&fs::symlink_metadata(&prefix).map_err(io_error)?)
                    != metadata_token(&m)
                {
                    return Err(CoreError::new(
                        ErrorCode::Busy,
                        "symlink changed during resolution",
                    ));
                }
                links.push((
                    target_path(&prefix),
                    metadata_token(&m).to_vec(),
                    target_path(&destination),
                ));
                prefix.pop();
                if destination.is_absolute() {
                    prefix = PathBuf::from("/");
                }
                for part in destination.components().rev() {
                    if !matches!(part, std::path::Component::RootDir) {
                        pending.push_front(part.as_os_str().to_os_string());
                    }
                }
            }
            Ok(_) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && (pending.is_empty() || allow_missing_parents) =>
            {
                missing_parent = Some(identity(
                    &fs::metadata(prefix.parent().ok_or_else(|| io_error("missing parent"))?)
                        .map_err(io_error)?,
                ));
                for tail in pending.drain(..) {
                    if tail == ".." {
                        return Err(io_error("missing path component before parent traversal"));
                    }
                    prefix.push(tail);
                }
            }
            Err(e) => return Err(io_error(e)),
        }
    }
    if expected
        .as_ref()
        .is_some_and(|resolved| &prefix != resolved)
    {
        return Err(CoreError::new(
            ErrorCode::Busy,
            "destination changed during resolution",
        ));
    }
    let resolved = prefix;
    let parent = resolved
        .parent()
        .ok_or_else(|| io_error("missing parent"))?;
    Ok(ResolutionEvidence {
        resolved: target_path(&resolved),
        parent_identity: match missing_parent {
            Some(identity) => identity,
            None => identity(&fs::metadata(parent).map_err(io_error)?),
        },
        links,
    })
}
impl LocalFileService {
    pub fn new(target: TargetIdentity, directory: PathBuf) -> Result<Self, CoreError> {
        private_directory(&directory)?;
        let ledger = Ledger::open(directory.join("operations"))?;
        let recovery = Arc::new(RecoveryStore::new(directory.join("recovery"))?);
        let spools = crate::leases::LeasePool::open(directory.join("spools"))?;
        Ok(Self {
            target,
            spools,
            ledger: Mutex::new(ledger),
            failpoint: AtomicU8::new(0),
            recovery,
            #[cfg(test)]
            before_read_validation: None,
            #[cfg(test)]
            after_save_acceptance: None,
            #[cfg(test)]
            after_save_authorization: None,
            #[cfg(test)]
            after_save_replacement: None,
        })
    }
    pub fn target(&self) -> &TargetIdentity {
        &self.target
    }
    pub fn set_failpoint(&self, point: FailPoint) {
        self.failpoint.store(point as u8, Ordering::SeqCst);
    }
    fn failing(&self, point: FailPoint) -> bool {
        self.failpoint.load(Ordering::SeqCst) == point as u8
    }
    pub(super) fn validate(&self, file: &FileRef) -> Result<PathBuf, CoreError> {
        if file.target != self.target {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "file target does not match installed service",
            ));
        }
        path(&file.path)
    }
    pub(super) fn current_version(&self, file: FileRef) -> Result<FileVersion, CoreError> {
        Ok(self
            .capture_regular(
                file,
                Some(MAX_ENCODED_BYTES as u64),
                None,
                |_| Ok(()),
                || Ok(()),
            )?
            .version)
    }
    /// Memory-only retention for native submission before the source result is released.
    pub fn retain_source(&self, source: &mut ByteSource) -> Result<(), CoreError> {
        if let ByteSource::PrivateSpool {
            local_path, lease, ..
        } = source
        {
            *lease = Some(self.spools.retain(&path(local_path)?).ok_or_else(|| {
                CoreError::new(ErrorCode::Unavailable, "private spool source was released")
            })?);
        }
        Ok(())
    }
    pub(crate) fn observe_regular_sync(
        &self,
        file: FileRef,
        cancel: &std::sync::atomic::AtomicBool,
        started: std::time::Instant,
    ) -> Result<FileObservation, CoreError> {
        self.capture_regular(
            file,
            None,
            None,
            |_| Ok(()),
            || {
                if cancel.load(Ordering::SeqCst)
                    || started.elapsed() >= crate::git::process::DEADLINE
                {
                    Err(CoreError::new(
                        ErrorCode::Cancelled,
                        "file observation cancelled or timed out",
                    ))
                } else {
                    Ok(())
                }
            },
        )
    }
    pub(crate) fn observe_node_sync(
        &self,
        file: FileRef,
        cancel: &std::sync::atomic::AtomicBool,
        started: std::time::Instant,
    ) -> Result<NodeObservation, CoreError> {
        let original = self.validate(&file)?;
        let metadata = match fs::symlink_metadata(&original) {
            Ok(value) => Some(value),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(io_error(e)),
        };
        let destination = match resolve_observed(&original, true) {
            Ok(value) => Some(value),
            Err(_) if metadata.as_ref().is_some_and(|m| m.is_symlink()) => None,
            Err(error) => return Err(error),
        };
        let follows_regular = match fs::metadata(&original) {
            Ok(m) => m.is_file(),
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(libc::ELOOP) =>
            {
                false
            }
            Err(e) => return Err(io_error(e)),
        };
        let regular = if follows_regular {
            Some(self.observe_regular_sync(file, cancel, started)?)
        } else {
            None
        };
        let mut hash = Sha256::new();
        hash.update(b"buntrail.node-structure.v1\0");
        match &metadata {
            None => hash.update(b"absent"),
            Some(m) if m.is_file() => {
                hash.update(b"regular");
                hash.update(m.mode().to_be_bytes());
                hash.update(m.uid().to_be_bytes());
                hash.update(m.gid().to_be_bytes());
            }
            Some(m) => {
                hash.update(metadata_token(m));
                if m.is_symlink() {
                    hash_field(
                        &mut hash,
                        fs::read_link(&original)
                            .map_err(io_error)?
                            .as_os_str()
                            .as_bytes(),
                    );
                }
            }
        }
        hash_field(
            &mut hash,
            &serde_json::to_vec(&destination).map_err(io_error)?,
        );
        let after = match fs::symlink_metadata(&original) {
            Ok(value) => Some(value),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(io_error(e)),
        };
        if metadata.as_ref().map(metadata_token) != after.as_ref().map(metadata_token)
            || destination != resolve_observed(&original, true).ok()
            || regular
                .as_ref()
                .is_some_and(|r| Some(&r.destination) != destination.as_ref())
        {
            return Err(CoreError::new(
                ErrorCode::Busy,
                "node changed while observing",
            ));
        }
        Ok(NodeObservation {
            structural_token: if metadata.is_none() {
                absent_structure(&destination)?
            } else {
                hash.finalize().into()
            },
            regular,
            destination,
        })
    }
    fn capture_regular(
        &self,
        file: FileRef,
        maximum: Option<u64>,
        descriptor: Option<File>,
        mut consume: impl FnMut(&[u8]) -> Result<(), CoreError>,
        mut check: impl FnMut() -> Result<(), CoreError>,
    ) -> Result<FileObservation, CoreError> {
        check()?;
        let original = self.validate(&file)?;
        let destination = resolution(&original)?;
        let before = fs::symlink_metadata(&original).map_err(io_error)?;
        let resolved = path(&destination.resolved)?;
        let mut f = match descriptor {
            Some(mut file) => {
                file.rewind().map_err(io_error)?;
                file
            }
            None => open_regular(&resolved)?,
        };
        let meta = f.metadata().map_err(io_error)?;
        if maximum.is_some_and(|limit| meta.len() > limit) {
            return Err(CoreError::new(
                ErrorCode::Unavailable,
                "file exceeds bounded spool capacity",
            ));
        }
        let mut h = Sha256::new();
        let mut size = 0u64;
        let mut chunk = [0; 65536];
        loop {
            check()?;
            let n = f.read(&mut chunk).map_err(io_error)?;
            if n == 0 {
                break;
            }
            size = size
                .checked_add(n as u64)
                .ok_or_else(|| io_error("file size overflow"))?;
            if maximum.is_some_and(|limit| size > limit) {
                return Err(CoreError::new(
                    ErrorCode::Unavailable,
                    "file grew beyond bounded spool capacity",
                ));
            }
            h.update(&chunk[..n]);
            consume(&chunk[..n])?;
        }
        let after = f.metadata().map_err(io_error)?;
        #[cfg(test)]
        if let Some(hook) = &self.before_read_validation {
            hook();
        }
        if resolution(&original)? != destination
            || meta.len() != size
            || metadata_token(&meta) != metadata_token(&after)
            || metadata_token(&fs::symlink_metadata(&original).map_err(io_error)?)
                != metadata_token(&before)
            || metadata_token(&fs::metadata(&resolved).map_err(io_error)?) != metadata_token(&after)
        {
            return Err(CoreError::new(
                ErrorCode::Busy,
                "file changed while reading",
            ));
        }
        check()?;
        let hash: [u8; 32] = h.finalize().into();
        let version = version(&file, &resolved, &after, hash, &before, &destination);
        let canonical_destination = ResolutionEvidence {
            links: vec![],
            ..destination.clone()
        };
        let canonical_version = self::version(
            &file,
            &resolved,
            &after,
            hash,
            &after,
            &canonical_destination,
        );
        Ok(FileObservation {
            version,
            canonical_version,
            destination,
            size,
        })
    }
    pub fn read_sync(&self, mut file: FileRef) -> Result<FileSnapshot, CoreError> {
        let mut memory = Vec::new();
        let mut spool = None;
        let observation = self.capture_regular(
            file.clone(),
            Some(MAX_ENCODED_BYTES as u64),
            None,
            |chunk| {
                if spool.is_none() && memory.len() + chunk.len() > MEMORY_FILE_BYTES {
                    let (mut writer, path, token) = self.spools.create_spool()?;
                    writer.write_all(&memory).map_err(io_error)?;
                    memory.clear();
                    spool = Some((writer, path, token));
                }
                if let Some((s, _, _)) = &mut spool {
                    s.write_all(chunk).map_err(io_error)?;
                } else {
                    memory.extend_from_slice(chunk);
                }
                Ok(())
            },
            || Ok(()),
        )?;
        file.resolved_identity = Some(observation.version.file_identity.clone());
        let source = if let Some((s, p, token)) = spool {
            s.sync_all().map_err(io_error)?;
            ByteSource::PrivateSpool {
                local_path: target_path(&p),
                length: observation.size,
                digest: observation.version.content_digest,
                lease: Some(token),
            }
        } else {
            ByteSource::Memory(memory.into())
        };
        let prefix = self.source_bytes(&source, 4, false)?;
        Ok(FileSnapshot {
            file,
            version: observation.version,
            size: observation.size,
            encoding: detect_encoding(&prefix),
            source,
        })
    }
    pub fn source_bytes(
        &self,
        source: &ByteSource,
        maximum: usize,
        verify: bool,
    ) -> Result<Vec<u8>, CoreError> {
        super::document_io::source_bytes(&self.spools, source, maximum, verify)
    }
    pub fn load_sync(
        &self,
        file: FileRef,
        document: DocumentID,
    ) -> Result<LoadedDocument, CoreError> {
        self.load_budgeted(file, document).map(|(loaded, _)| loaded)
    }
    pub fn load_budgeted(
        &self,
        file: FileRef,
        document: DocumentID,
    ) -> Result<(LoadedDocument, LoadBudget), CoreError> {
        self.load_contents(file, document, true)
    }
    pub fn revalidate_budgeted(
        &self,
        file: FileRef,
        document: DocumentID,
    ) -> Result<(LoadedDocument, LoadBudget), CoreError> {
        self.load_contents(file, document, false)
    }
    fn load_contents(
        &self,
        file: FileRef,
        document: DocumentID,
        acquire_session: bool,
    ) -> Result<(LoadedDocument, LoadBudget), CoreError> {
        super::document_io::load_snapshot(
            self.read_sync(file)?,
            document,
            if acquire_session {
                Some(&self.recovery)
            } else {
                None
            },
            &self.spools,
        )
    }
    /// Decode an immutable source using its owning pool and the caller's client-local recovery store.
    pub fn load_snapshot(
        &self,
        snapshot: FileSnapshot,
        document: DocumentID,
        recovery: Option<&RecoveryStore>,
    ) -> Result<(LoadedDocument, LoadBudget), CoreError> {
        if snapshot.file.target != self.target {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "snapshot target differs from service",
            ));
        }
        super::document_io::load_snapshot(snapshot, document, recovery, &self.spools)
    }
    pub fn save_prepared(&self, prepared: PreparedSave) -> OperationReceipt {
        let operation = prepared.operation;
        let target = prepared.recovery.file.target.clone();
        if let Err(error) = self.validate(&prepared.recovery.file) {
            return failure(operation, target, error);
        }
        match super::document_io::prepare_save(&self.recovery, prepared) {
            Ok((request, _budget)) => self.save_inner(request, None),
            Err(error) => failure(operation, target, error),
        }
    }
    /// Caller supplies the target-authenticated actor and its monotonic registration marker.
    pub fn save_owned_sync(
        &self,
        request: SaveRequest,
        actor: WorkspaceLease,
        active: &std::sync::atomic::AtomicBool,
    ) -> OperationReceipt {
        self.save_request(request, Some((actor, active)))
    }
    pub fn save_sync(&self, request: SaveRequest) -> OperationReceipt {
        self.save_request(request, None)
    }
    fn save_request(
        &self,
        request: SaveRequest,
        actor: Option<(WorkspaceLease, &std::sync::atomic::AtomicBool)>,
    ) -> OperationReceipt {
        let length = match &request.source {
            ByteSource::Memory(b) => b.len() as u64,
            ByteSource::PrivateSpool { length, .. } => *length,
        };
        if length > (MAX_DOCUMENT_BYTES * 2 + 4) as u64 {
            return failure(
                request.operation,
                request.file.target,
                CoreError::new(ErrorCode::Unavailable, "save source exceeds staging bound"),
            );
        }
        let _budget = match LoadBudget::acquire(length as usize * 2 + 1024 * 1024) {
            Ok(b) => b,
            Err(error) => return failure(request.operation, request.file.target, error),
        };
        self.save_inner(request, actor)
    }
    pub(super) fn save_inner(
        &self,
        request: SaveRequest,
        actor: Option<(WorkspaceLease, &std::sync::atomic::AtomicBool)>,
    ) -> OperationReceipt {
        use crate::operations::ledger::{Record, SaveProof, now, unknown};
        let fail = |e| failure(request.operation, request.file.target.clone(), e);
        let result = (|| -> Result<OperationReceipt, CoreError> {
            self.validate(&request.file)?;
            if request
                .expected_version
                .as_ref()
                .is_some_and(|v| v.target != request.file.target)
            {
                return Err(CoreError::new(
                    ErrorCode::TargetChanged,
                    "expected version target mismatch",
                ));
            }
            let bytes = self.source_bytes(&request.source, MAX_DOCUMENT_BYTES * 2 + 4, true)?;
            let contents = digest(&bytes);
            let fingerprint = super::save_request_digest(
                &request.file,
                &request.expected_version,
                request.submitted_revision,
                contents,
            )?;
            let ledger = self.ledger.lock().map_err(io_error)?;
            let _lock = ledger.lock()?;
            if let Some(existing) = ledger.read(request.operation)? {
                if existing.envelope.request_digest != fingerprint
                    || existing.envelope.target != request.file.target
                {
                    return Err(CoreError::new(
                        ErrorCode::InvalidArgument,
                        "operation ID reused with different request",
                    ));
                }
                return ledger.inspect(request.operation, request.file.target.clone());
            }
            if self.failing(FailPoint::Acceptance) {
                return Err(io_error("injected durable acceptance failure"));
            }
            if actor
                .as_ref()
                .is_some_and(|(_, active)| !active.load(Ordering::SeqCst))
            {
                return Err(CoreError::new(
                    ErrorCode::Closed,
                    "save registration revoked before acceptance",
                ));
            }
            let original = self.validate(&request.file)?;
            let destination = resolution(&original)?;
            let before = if actor.is_some() && request.expected_version.is_some() {
                Some(self.capture_regular(
                    request.file.clone(),
                    Some(MAX_ENCODED_BYTES as u64),
                    None,
                    |_| Ok(()),
                    || Ok(()),
                )?)
            } else {
                None
            };
            if before.as_ref().is_some_and(|b| {
                Some(&b.version) != request.expected_version.as_ref()
                    || b.destination != destination
            }) {
                return Err(CoreError::new(
                    ErrorCode::StaleRevision,
                    "save observation differs from expected destination/version",
                ));
            }
            match &request.expected_version {
                Some(expected) if self.current_version(request.file.clone())? != *expected => {
                    return Err(CoreError::new(
                        ErrorCode::StaleRevision,
                        "file version conflict before acceptance",
                    ));
                }
                None if original.symlink_metadata().is_ok() => {
                    return Err(CoreError::new(
                        ErrorCode::StaleRevision,
                        "expected absent file",
                    ));
                }
                _ => {}
            }
            if resolution(&original)? != destination {
                return Err(CoreError::new(
                    ErrorCode::TargetChanged,
                    "destination changed before acceptance",
                ));
            }
            let before_endpoint = before
                .as_ref()
                .map(FileObservation::save_observation)
                .transpose()?;
            let mut record = Record {
                envelope: OperationEnvelope {
                    id: request.operation,
                    target: request.file.target.clone(),
                    request_digest: fingerprint,
                    kind: MutationKind::Save,
                    expected: ExpectedState::File {
                        file: request.file.clone(),
                        version: request.expected_version.clone(),
                    },
                },
                destination: Some(destination),
                save_proof: actor.as_ref().map(|(actor, _)| SaveProof {
                    actor: actor.clone(),
                    before: before_endpoint.clone(),
                    after: None,
                }),
                terminal_request: None,
                git_intent: None,
                requested_digest: contents,
                revision: request.submitted_revision,
                receipt: OperationReceipt {
                    id: request.operation,
                    state: OperationState::Accepted,
                },
                created: now(),
            };
            if let Some(existing) = ledger.accept(&record, &_lock)? {
                return Ok(existing);
            }
            #[cfg(test)]
            if let Some(hook) = &self.after_save_acceptance {
                hook();
            }
            // A true monotonic marker after fsync proves this registration survived durable admission.
            if actor
                .as_ref()
                .is_some_and(|(_, active)| !active.load(Ordering::SeqCst))
            {
                record.receipt = fail(CoreError::new(
                    ErrorCode::Closed,
                    "save registration revoked during acceptance",
                ));
                if ledger.write(&record).is_err() {
                    return Ok(unknown(
                        request.operation,
                        request.file.target.clone(),
                        "revoked acceptance outcome was not durably recorded; inspect, never replay",
                    ));
                }
                return Ok(record.receipt);
            }
            #[cfg(test)]
            if let Some(hook) = &self.after_save_authorization {
                hook();
            }
            if self.failing(FailPoint::AfterAcceptance) {
                return Ok(unknown(
                    request.operation,
                    request.file.target.clone(),
                    "interrupted after acceptance; never replay",
                ));
            }
            let mut replaced = false;
            let write = (|| -> Result<SaveResult, CoreError> {
                let original = self.validate(&request.file)?;
                let resolved = match &request.expected_version {
                    Some(expected) => {
                        let current = self.current_version(request.file.clone())?;
                        if current != *expected {
                            return Err(CoreError::new(
                                ErrorCode::StaleRevision,
                                "file version conflict",
                            ));
                        }
                        fs::canonicalize(&original).map_err(io_error)?
                    }
                    None => {
                        if original.symlink_metadata().is_ok() {
                            return Err(CoreError::new(
                                ErrorCode::StaleRevision,
                                "expected absent file",
                            ));
                        }
                        original.clone()
                    }
                };
                let parent = resolved
                    .parent()
                    .ok_or_else(|| io_error("missing parent"))?;
                let metadata = if request.expected_version.is_some() {
                    let m = fs::metadata(&resolved).map_err(io_error)?;
                    validate_metadata(&resolved, &m)?;
                    Some(m)
                } else {
                    None
                };
                let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(io_error)?;
                if self.failing(FailPoint::Permission) {
                    return Err(io_error(std::io::Error::from_raw_os_error(libc::EACCES)));
                }
                if self.failing(FailPoint::Write) || self.failing(FailPoint::FullDisk) {
                    return Err(io_error(std::io::Error::from_raw_os_error(libc::ENOSPC)));
                }
                temporary.write_all(&bytes).map_err(io_error)?;
                if let Some(m) = metadata {
                    preserve_metadata(&resolved, temporary.as_file(), &m)?;
                }
                temporary.as_file().sync_all().map_err(io_error)?;
                let persisted = if let Some(expected) = &request.expected_version {
                    let current = self.current_version(request.file.clone())?;
                    if current != *expected
                        || fs::canonicalize(&original).map_err(io_error)? != resolved
                    {
                        return Err(CoreError::new(
                            ErrorCode::StaleRevision,
                            "file changed before replacement",
                        ));
                    }
                    temporary.persist(&resolved).map_err(io_error)?
                } else {
                    temporary.persist_noclobber(&resolved).map_err(io_error)?
                };
                replaced = true;
                #[cfg(test)]
                if let Some(hook) = &self.after_save_replacement {
                    hook();
                }
                File::open(parent)
                    .and_then(|f| f.sync_all())
                    .map_err(io_error)?;
                let observed = self.capture_regular(
                    request.file.clone(),
                    Some(MAX_ENCODED_BYTES as u64),
                    Some(persisted),
                    |_| Ok(()),
                    || Ok(()),
                )?;
                if observed.destination != *record.destination.as_ref().unwrap() {
                    return Err(io_error("save destination changed after replacement"));
                }
                let current = observed.version.clone();
                if current.content_digest != contents {
                    return Err(io_error("contents changed after replacement"));
                }
                if let Some(proof) = &mut record.save_proof {
                    proof.after = Some(observed.save_observation()?);
                }
                Ok(SaveResult {
                    saved_revision: request.submitted_revision,
                    version: current,
                })
            })();
            record.receipt = match write {
                Ok(saved) => OperationReceipt {
                    id: request.operation,
                    state: OperationState::Confirmed(MutationResult::Saved(saved)),
                },
                Err(e) if replaced => unknown(
                    request.operation,
                    request.file.target.clone(),
                    &format!("replacement may have taken effect: {}", e.message),
                ),
                Err(e) => fail(e),
            };
            if self.failing(FailPoint::Completion) || ledger.write(&record).is_err() {
                return Ok(unknown(
                    request.operation,
                    request.file.target.clone(),
                    "completion record not durable; inspect, never replay",
                ));
            }
            if self.failing(FailPoint::Acknowledgement) {
                return Ok(unknown(
                    request.operation,
                    request.file.target.clone(),
                    "acknowledgement lost; inspect, never replay",
                ));
            }
            Ok(record.receipt)
        })();
        result.unwrap_or_else(fail)
    }
    pub fn inspect_sync(
        &self,
        id: OperationID,
        target: TargetIdentity,
    ) -> Result<OperationReceipt, CoreError> {
        if target != self.target {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "operation target mismatch",
            ));
        }
        let ledger = self.ledger.lock().map_err(io_error)?;
        let _lock = ledger.lock()?;
        let receipt = ledger.inspect(id, target.clone())?;
        if matches!(receipt.state, OperationState::Unknown(_))
            && let Some(mut record) = ledger.read(id)?
        {
            if ledger.expired(&record) {
                return Ok(receipt);
            }
            if let ExpectedState::File { file, .. } = &record.envelope.expected
                && let Some(expected) = &record.destination
                && let Ok(original) = self.validate(file)
                && resolution(&original).as_ref() == Ok(expected)
                && let Ok(current) = self.current_version(file.clone())
                && resolution(&original).as_ref() == Ok(expected)
            {
                // Current contents cannot prove who wrote them or that the original operation completed.
                record.receipt = OperationReceipt {
                    id,
                    state: OperationState::Unknown(ReconciliationEvidence {
                        target,
                        observed: ObservedState::File { file: FileRef {resolved_identity:Some(current.file_identity.clone()), ..file.clone()}, digest: Some(current.content_digest), version: Some(current) },
                        explanation: "Current file evidence does not establish original save execution; inspect before resolving, never replay automatically".into(),
                    }),
                };
                ledger.write(&record)?;
                return Ok(record.receipt);
            }
        }
        Ok(receipt)
    }
}
pub fn failure(id: OperationID, target: TargetIdentity, error: CoreError) -> OperationReceipt {
    OperationReceipt {
        id,
        state: OperationState::Failed(OperationFailure {
            error,
            target,
            observed: ObservedState::Unobserved,
            effect: FailureEffect::ProvenNoEffect,
        }),
    }
}
fn detect_encoding(b: &[u8]) -> Encoding {
    if b.starts_with(&[0xff, 0xfe]) {
        Encoding::Other("UTF-16LE".into())
    } else if b.starts_with(&[0xfe, 0xff]) {
        Encoding::Other("UTF-16BE".into())
    } else {
        Encoding::Utf8 {
            bom: b.starts_with(&[0xef, 0xbb, 0xbf]),
        }
    }
}
pub fn decode(b: &[u8]) -> Result<(String, Encoding), CoreError> {
    let enc = detect_encoding(b);
    let text = match &enc {
        Encoding::Utf8 { bom } => String::from_utf8(b[if *bom { 3 } else { 0 }..].to_vec())
            .map_err(|_| {
                CoreError::new(
                    ErrorCode::Unavailable,
                    "unsupported encoding: select encoding explicitly or open read-only bytes",
                )
            })?,
        Encoding::Other(name) => {
            if !b.len().is_multiple_of(2) {
                return Err(io_error("incomplete UTF-16 code unit"));
            }
            let u: Vec<u16> = b[2..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| {
                    if name == "UTF-16LE" {
                        u16::from_le_bytes([c[0], c[1]])
                    } else {
                        u16::from_be_bytes([c[0], c[1]])
                    }
                })
                .collect();
            String::from_utf16(&u).map_err(|_| {
                CoreError::new(
                    ErrorCode::Unavailable,
                    "invalid UTF-16: open read-only bytes",
                )
            })?
        }
    };
    if text.contains('\0') {
        return Err(CoreError::new(
            ErrorCode::Unavailable,
            "binary data: open read-only bytes",
        ));
    }
    Ok((text, enc))
}
pub fn encode(s: &DocumentSnapshot) -> Result<Vec<u8>, CoreError> {
    let mut out = vec![];
    match &s.encoding {
        Encoding::Utf8 { bom } => {
            if *bom {
                out.extend_from_slice(&[0xef, 0xbb, 0xbf]);
            }
            for c in s.text.chunks() {
                out.extend_from_slice(c.as_bytes());
            }
        }
        Encoding::Other(name) if name == "UTF-16LE" || name == "UTF-16BE" => {
            let le = name == "UTF-16LE";
            out.extend_from_slice(if le { &[0xff, 0xfe] } else { &[0xfe, 0xff] });
            for c in s.text.chunks() {
                for u in c.encode_utf16() {
                    out.extend_from_slice(&if le { u.to_le_bytes() } else { u.to_be_bytes() });
                }
            }
        }
        _ => {
            return Err(CoreError::new(
                ErrorCode::Unavailable,
                "unsupported output encoding",
            ));
        }
    }
    Ok(out)
}
impl FileService for LocalFileService {
    fn resolve(
        &self,
        root: FileRef,
        purpose: FileResolvePurpose,
    ) -> async_types::ServiceFuture<'_, Result<FileResolution, CoreError>> {
        Box::pin(async move { self.resolve_sync(root, purpose) })
    }
    fn read(
        &self,
        file: FileRef,
    ) -> buntrail_core::contracts::async_types::ServiceFuture<'_, Result<FileSnapshot, CoreError>>
    {
        Box::pin(async move { self.read_sync(file) })
    }
    fn save(
        &self,
        request: SaveRequest,
    ) -> buntrail_core::contracts::async_types::ServiceFuture<'_, OperationReceipt> {
        Box::pin(async move { self.save_sync(request) })
    }
    fn list(
        &self,
        directory: FileRef,
    ) -> buntrail_core::contracts::async_types::ServiceFuture<'_, Result<Vec<FileEntry>, CoreError>>
    {
        Box::pin(async move { self.list_sync(directory) })
    }
    fn watch(
        &self,
        root: FileRef,
    ) -> buntrail_core::contracts::async_types::ServiceFuture<
        '_,
        Result<buntrail_core::contracts::async_types::EventStream<FileEvent>, CoreError>,
    > {
        Box::pin(async move { super::watcher::watch(self.target.clone(), root) })
    }
    fn mutate(
        &self,
        request: FileMutationRequest,
    ) -> buntrail_core::contracts::async_types::ServiceFuture<'_, OperationReceipt> {
        Box::pin(async move { self.mutate_sync(request) })
    }
}
impl OperationService for LocalFileService {
    fn inspect(
        &self,
        id: OperationID,
        target: TargetIdentity,
    ) -> buntrail_core::contracts::async_types::ServiceFuture<'_, Result<OperationReceipt, CoreError>>
    {
        Box::pin(async move { self.inspect_sync(id, target) })
    }
}

fn validate_metadata(path: &Path, m: &Metadata) -> Result<(), CoreError> {
    if m.nlink() != 1 {
        return Err(CoreError::new(
            ErrorCode::Unavailable,
            "atomic replacement of hard-linked files is unsupported",
        ));
    }
    if m.uid() != unsafe { libc::geteuid() } || m.gid() != unsafe { libc::getegid() } {
        return Err(CoreError::new(
            ErrorCode::Unavailable,
            "cannot preserve file ownership",
        ));
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let p = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(io_error)?;
        let attributes = unsafe { libc::listxattr(p.as_ptr(), std::ptr::null_mut(), 0) };
        if attributes < 0 {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        if attributes > 0 {
            return Err(CoreError::new(
                ErrorCode::Unavailable,
                "atomic replacement cannot preserve extended metadata on this platform",
            ));
        }
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let _ = path;
    Ok(())
}
fn preserve_metadata(
    path: &Path,
    destination: &File,
    metadata: &Metadata,
) -> Result<(), CoreError> {
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let source = open_regular(path)?;
        if unsafe {
            libc::fcopyfile(
                source.as_raw_fd(),
                destination.as_raw_fd(),
                std::ptr::null_mut(),
                libc::COPYFILE_METADATA,
            )
        } != 0
        {
            return Err(io_error(std::io::Error::last_os_error()));
        }
    }
    #[cfg(target_os = "linux")]
    return LinuxMetadata::capture(open_regular(path)?, metadata)?.preserve(destination);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = path;
    #[cfg(not(target_os = "linux"))]
    destination
        .set_permissions(fs::Permissions::from_mode(metadata.mode()))
        .map_err(io_error)
}

#[cfg(target_os = "linux")]
const MAX_XATTR_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_XATTR_LIST_BYTES: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const MAX_XATTR_COUNT: usize = 1024;

#[cfg(target_os = "linux")]
struct ExtendedMetadata {
    values: Vec<(std::ffi::CString, Vec<u8>)>,
    _budget: Option<LoadBudget>,
}
#[cfg(target_os = "linux")]
impl ExtendedMetadata {
    fn read(file: &File) -> Result<Self, CoreError> {
        use std::os::fd::AsRawFd;
        let fd = file.as_raw_fd();
        let count = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
        if count < 0 {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        if count == 0 {
            return Ok(Self {
                values: Vec::new(),
                _budget: None,
            });
        }
        let limit = || {
            CoreError::new(
                ErrorCode::Unavailable,
                "extended metadata exceeds atomic save preservation budget",
            )
        };
        let count = count as usize;
        if count > MAX_XATTR_LIST_BYTES {
            return Err(limit());
        }
        // Account for values, names, the temporary name list and bounded structural overhead.
        // Empty metadata needs no extra admission, preserving the existing large-file path.
        let budget = LoadBudget::acquire(
            MAX_XATTR_BYTES
                + MAX_XATTR_LIST_BYTES
                + MAX_XATTR_COUNT * std::mem::size_of::<(std::ffi::CString, Vec<u8>)>(),
        )?;
        let mut names = vec![0u8; count];
        let actual = unsafe { libc::flistxattr(fd, names.as_mut_ptr().cast(), names.len()) };
        if actual < 0 {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        if actual as usize != count || names.last() != Some(&0) {
            return Err(metadata_changed());
        }
        let mut values = Vec::new();
        let mut total = count;
        for name in names[..count - 1].split(|byte| *byte == 0) {
            if name.is_empty() || values.len() == MAX_XATTR_COUNT {
                return Err(limit());
            }
            let name = std::ffi::CString::new(name).map_err(io_error)?;
            let length = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0) };
            if length < 0 {
                return Err(io_error(std::io::Error::last_os_error()));
            }
            let length = length as usize;
            if length > 64 * 1024 || length > MAX_XATTR_BYTES.saturating_sub(total) {
                return Err(limit());
            }
            total += length;
            let mut value = vec![0; length];
            let actual = unsafe {
                libc::fgetxattr(fd, name.as_ptr(), value.as_mut_ptr().cast(), value.len())
            };
            if actual < 0 {
                return Err(io_error(std::io::Error::last_os_error()));
            }
            if actual as usize != length {
                return Err(metadata_changed());
            }
            values.push((name, value));
        }
        values.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        if values.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(metadata_changed());
        }
        Ok(Self {
            values,
            _budget: Some(budget),
        })
    }
}
#[cfg(target_os = "linux")]
fn metadata_changed() -> CoreError {
    CoreError::new(
        ErrorCode::StaleRevision,
        "file metadata changed during atomic save",
    )
}
#[cfg(target_os = "linux")]
struct LinuxMetadata {
    source: File,
    metadata: Metadata,
    attributes: ExtendedMetadata,
}
#[cfg(target_os = "linux")]
impl LinuxMetadata {
    fn capture(source: File, metadata: &Metadata) -> Result<Self, CoreError> {
        let current = source.metadata().map_err(io_error)?;
        validate_metadata(Path::new(""), &current)?;
        if metadata_token(&current) != metadata_token(metadata) || metadata.nlink() != 1 {
            return Err(metadata_changed());
        }
        let attributes = ExtendedMetadata::read(&source)?;
        let snapshot = Self {
            source,
            metadata: current,
            attributes,
        };
        snapshot.check_source()?;
        Ok(snapshot)
    }
    fn check_source(&self) -> Result<(), CoreError> {
        let before = self.source.metadata().map_err(io_error)?;
        validate_metadata(Path::new(""), &before)?;
        let attributes = ExtendedMetadata::read(&self.source)?;
        let after = self.source.metadata().map_err(io_error)?;
        validate_metadata(Path::new(""), &after)?;
        if metadata_token(&before) != metadata_token(&self.metadata)
            || metadata_token(&after) != metadata_token(&self.metadata)
            || attributes.values != self.attributes.values
        {
            return Err(metadata_changed());
        }
        Ok(())
    }
    fn preserve(self, destination: &File) -> Result<(), CoreError> {
        use std::os::fd::AsRawFd;
        // Copy ACL/capability attributes after chmod; then verify their resulting mode.
        destination
            .set_permissions(fs::Permissions::from_mode(self.metadata.mode()))
            .map_err(io_error)?;
        let fd = destination.as_raw_fd();
        let inherited = ExtendedMetadata::read(destination)?;
        for (name, _) in &inherited.values {
            if !self
                .attributes
                .values
                .iter()
                .any(|(source_name, _)| source_name == name)
                && unsafe { libc::fremovexattr(fd, name.as_ptr()) } != 0
            {
                return Err(io_error(std::io::Error::last_os_error()));
            }
        }
        drop(inherited);
        for (name, value) in &self.attributes.values {
            if unsafe { libc::fsetxattr(fd, name.as_ptr(), value.as_ptr().cast(), value.len(), 0) }
                != 0
            {
                return Err(io_error(std::io::Error::last_os_error()));
            }
        }
        let actual = destination.metadata().map_err(io_error)?;
        if actual.mode() != self.metadata.mode()
            || actual.uid() != self.metadata.uid()
            || actual.gid() != self.metadata.gid()
            || ExtendedMetadata::read(destination)?.values != self.attributes.values
        {
            return Err(CoreError::new(
                ErrorCode::Unavailable,
                "atomic save could not preserve file metadata",
            ));
        }
        self.check_source()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_metadata_tests {
    use super::*;
    use std::os::fd::AsRawFd;
    fn fixture() -> (tempfile::TempDir, PathBuf, File) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source");
        fs::write(&path, b"unchanged source").unwrap();
        let source = open_regular(&path).unwrap();
        set(&source, b"before");
        (dir, path, source)
    }
    fn set(file: &File, value: &[u8]) {
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    file.as_raw_fd(),
                    c"user.buntrail.test".as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            },
            0
        );
    }
    #[test]
    fn pinned_source_metadata_race_is_refused_without_replacing_source() {
        let (dir, path, source) = fixture();
        let metadata = source.metadata().unwrap();
        let snapshot = LinuxMetadata::capture(source.try_clone().unwrap(), &metadata).unwrap();
        set(&source, b"external change");
        let temporary = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        let error = snapshot.preserve(temporary.as_file()).unwrap_err();
        assert_eq!(error.code, ErrorCode::StaleRevision);
        assert_eq!(fs::metadata(&path).unwrap().ino(), metadata.ino());
        assert_eq!(fs::read(&path).unwrap(), b"unchanged source");
        assert_eq!(
            ExtendedMetadata::read(&source).unwrap().values[0].1,
            b"external change"
        );
    }
    #[test]
    fn replaced_or_symlinked_source_cannot_supply_metadata() {
        let (dir, path, source) = fixture();
        let metadata = source.metadata().unwrap();
        let replacement = dir.path().join("replacement");
        fs::write(&replacement, b"external replacement").unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert!(LinuxMetadata::capture(open_regular(&path).unwrap(), &metadata).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"external replacement");
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("replacement", &path).unwrap();
        assert!(
            open_regular(&path).is_err(),
            "metadata source must not follow a last-component symlink"
        );
    }
    #[test]
    fn synthetic_denied_snapshot_uses_real_copy_syscall_without_replacing_source() {
        let (dir, path, source) = fixture();
        let metadata = source.metadata().unwrap();
        let before = ExtendedMetadata::read(&source).unwrap();
        let mut snapshot = LinuxMetadata::capture(source.try_clone().unwrap(), &metadata).unwrap();
        // Synthetic component fixture only: this entry was NOT read from a real source.
        // The unchanged production copier must still fail at the real kernel syscall.
        snapshot.attributes.values.push((
            std::ffi::CString::new("security.buntrail.denied").unwrap(),
            b"denied".to_vec(),
        ));
        let temporary = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        let temp_path = temporary.path().to_owned();
        let error = snapshot.preserve(temporary.as_file()).unwrap_err();
        assert_eq!(error.code, ErrorCode::Io);
        assert_eq!(
            error.message,
            std::io::Error::from_raw_os_error(libc::EPERM).to_string()
        );
        assert_eq!(fs::metadata(&path).unwrap().ino(), metadata.ino());
        assert_eq!(fs::read(&path).unwrap(), b"unchanged source");
        assert_eq!(
            ExtendedMetadata::read(&source).unwrap().values,
            before.values
        );
        drop(temporary);
        assert!(!temp_path.exists());
    }
    #[test]
    fn unreadable_metadata_descriptor_fails_closed_and_releases_admission() {
        let (_dir, path, source) = fixture();
        let before = LOAD_BYTES.load(Ordering::SeqCst);
        use std::os::fd::FromRawFd;
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // musl O_ACCMODE makes OpenOptions mask O_PATH out of custom flags.
        let fd = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0, "{}", std::io::Error::last_os_error());
        let descriptor = unsafe { File::from_raw_fd(fd) };
        let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0, "{}", std::io::Error::last_os_error());
        assert_eq!(flags & libc::O_PATH, libc::O_PATH);
        assert!(ExtendedMetadata::read(&descriptor).is_err());
        assert_eq!(LOAD_BYTES.load(Ordering::SeqCst), before);
        assert_eq!(fs::read(path).unwrap(), b"unchanged source");
        assert_eq!(
            ExtendedMetadata::read(&source).unwrap().values[0].1,
            b"before"
        );
    }
}

static LOAD_BYTES: AtomicUsize = AtomicUsize::new(0);
pub const MAX_LOAD_BYTES: usize = 512 * 1024 * 1024;
pub struct LoadBudget(usize);
impl LoadBudget {
    pub fn acquire(bytes: usize) -> Result<Self, CoreError> {
        LOAD_BYTES
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                n.checked_add(bytes).filter(|v| *v <= MAX_LOAD_BYTES)
            })
            .map(|_| Self(bytes))
            .map_err(|_| CoreError::new(ErrorCode::Busy, "document load memory budget reached"))
    }
}
impl Drop for LoadBudget {
    fn drop(&mut self) {
        LOAD_BYTES.fetch_sub(self.0, Ordering::SeqCst);
    }
}

/// Shared load/save scratch admission includes encoder growth, immutable source conversion and write staging.
pub fn reserve_encoding(snapshot: &DocumentSnapshot) -> Result<LoadBudget, CoreError> {
    let encoded = match snapshot.encoding {
        Encoding::Utf8 { .. } => snapshot.text.len().saturating_add(3),
        _ => snapshot.text.len().saturating_mul(2).saturating_add(2),
    };
    LoadBudget::acquire(encoded.saturating_mul(3).saturating_add(1024 * 1024))
}

#[cfg(test)]
mod observation_tests {
    use super::*;

    #[test]
    fn historical_after_cannot_adopt_external_same_content_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let target = TargetIdentity {
            security_binding: vec![1],
            effective_user: vec![2],
            filesystem_namespace: vec![3],
            container: None,
        };
        let mut service = LocalFileService::new(target.clone(), root.join("state")).unwrap();
        let destination = root.join("file");
        let external = root.join("external-replacement");
        fs::write(&destination, b"before").unwrap();
        fs::write(&external, b"after").unwrap();
        let snapshot = service
            .read_sync(FileRef {
                target: target.clone(),
                path: target_path(&destination),
                resolved_identity: None,
            })
            .unwrap();
        service.after_save_replacement = Some(Arc::new(move || {
            fs::rename(&external, &destination).unwrap();
        }));
        let receipt = service.save_owned_sync(
            SaveRequest {
                operation: OperationID([14; 16]),
                file: snapshot.file,
                expected_version: Some(snapshot.version),
                submitted_revision: BufferRevision(1),
                source: ByteSource::Memory(Arc::from(b"after".as_slice())),
            },
            WorkspaceLease {
                client: ClientID([1; 16]),
                workspace: WorkspaceID([2; 16]),
                lease: WorkspaceLeaseID([3; 16]),
                runtime: RuntimeGeneration {
                    supervisor_boot: [4; 16],
                    container_start: None,
                },
            },
            &std::sync::atomic::AtomicBool::new(true),
        );
        assert!(
            matches!(receipt.state, OperationState::Unknown(_)),
            "external same-content inode was attributed to our save: {receipt:?}"
        );
        let read_proof = || {
            service
                .ledger
                .lock()
                .unwrap()
                .read(receipt.id)
                .unwrap()
                .unwrap()
                .save_proof
                .unwrap()
        };
        assert!(read_proof().after.is_none());
        assert!(matches!(
            service.inspect_sync(receipt.id, target).unwrap().state,
            OperationState::Unknown(_)
        ));
        assert!(
            read_proof().after.is_none(),
            "inspection manufactured replacement provenance"
        );
        assert_eq!(fs::read(root.join("file")).unwrap(), b"after");
    }

    #[test]
    fn registered_local_save_retains_the_original_actor_and_digest() {
        let dir = tempfile::tempdir().unwrap();
        let local =
            crate::connections::local::LocalConnection::open(dir.path().join("state")).unwrap();
        let lease = WorkspaceLeaseID([81; 16]);
        local.register(WorkspaceID([82; 16]), lease).unwrap();
        let actor = local
            .observation_owner(lease)
            .unwrap()
            .registration()
            .clone();
        let file = FileRef {
            target: local.identity.clone(),
            path: target_path(&dir.path().join("new-file")),
            resolved_identity: None,
        };
        let request = SaveRequest {
            operation: OperationID([83; 16]),
            file,
            expected_version: None,
            submitted_revision: BufferRevision(1),
            source: ByteSource::Memory(Arc::from(b"created".as_slice())),
        };
        let expected_digest = digest(
            &serde_json::to_vec(&(
                &request.file,
                &request.expected_version,
                request.submitted_revision,
                digest(b"created"),
            ))
            .unwrap(),
        );
        let pending = local.owned_files(lease).unwrap().prepare(request).unwrap();
        assert_eq!(pending.approval().actor, actor);
        assert_eq!(pending.approval().request_digest, expected_digest);
        let receipt = pending.execute();
        assert!(matches!(receipt.state, OperationState::Confirmed(_)));
        let ledger = local.files.ledger.lock().unwrap();
        let record = ledger.read(receipt.id).unwrap().unwrap();
        assert_eq!(record.envelope.request_digest, expected_digest);
        let proof = record
            .save_proof
            .expect("registered local save must retain its actual original actor");
        assert_eq!(proof.actor, actor);
        assert!(proof.before.is_none());
        assert!(proof.after.is_some());
    }

    #[test]
    fn save_revocation_before_during_and_after_durable_admission() {
        for phase in ["before", "during", "after"] {
            let dir = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(dir.path()).unwrap();
            let target = TargetIdentity {
                security_binding: vec![1],
                effective_user: vec![2],
                filesystem_namespace: vec![3],
                container: None,
            };
            let mut service = LocalFileService::new(target.clone(), root.join("state")).unwrap();
            fs::write(root.join("file"), b"before").unwrap();
            let snapshot = service
                .read_sync(FileRef {
                    target: target.clone(),
                    path: target_path(&root.join("file")),
                    resolved_identity: None,
                })
                .unwrap();
            let actor = WorkspaceLease {
                client: ClientID([1; 16]),
                workspace: WorkspaceID([2; 16]),
                lease: WorkspaceLeaseID([3; 16]),
                runtime: RuntimeGeneration {
                    supervisor_boot: [4; 16],
                    container_start: None,
                },
            };
            let active = Arc::new(std::sync::atomic::AtomicBool::new(phase != "before"));
            let marker = active.clone();
            let revoke: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                marker.store(false, Ordering::SeqCst);
            });
            if phase == "during" {
                service.after_save_acceptance = Some(revoke);
            } else if phase == "after" {
                service.after_save_authorization = Some(revoke);
            }
            let receipt = service.save_owned_sync(
                SaveRequest {
                    operation: OperationID([7; 16]),
                    file: snapshot.file,
                    expected_version: Some(snapshot.version),
                    submitted_revision: BufferRevision(1),
                    source: ByteSource::Memory(Arc::from(b"after".as_slice())),
                },
                actor,
                &active,
            );
            let record = service.ledger.lock().unwrap().read(receipt.id).unwrap();
            if phase == "after" {
                assert!(
                    matches!(receipt.state, OperationState::Confirmed(_)),
                    "accepted save lost authority retroactively"
                );
                assert!(record.unwrap().save_proof.unwrap().after.is_some());
                assert_eq!(fs::read(root.join("file")).unwrap(), b"after");
            } else {
                assert!(
                    matches!(receipt.state, OperationState::Failed(_)),
                    "revoked {phase} acceptance mutated the file"
                );
                assert_eq!(fs::read(root.join("file")).unwrap(), b"before");
                if phase == "before" {
                    assert!(record.is_none());
                } else {
                    let record = record.unwrap();
                    assert!(matches!(record.receipt.state, OperationState::Failed(_)));
                    assert!(record.save_proof.unwrap().after.is_none());
                }
            }
        }
    }

    #[test]
    fn owned_save_records_actual_alias_and_canonical_history_without_retrofit() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let target = TargetIdentity {
            security_binding: vec![1],
            effective_user: vec![2],
            filesystem_namespace: vec![3],
            container: None,
        };
        let service = LocalFileService::new(target.clone(), root.join("state")).unwrap();
        fs::write(root.join("file"), b"before").unwrap();
        std::os::unix::fs::symlink("file", root.join("alias")).unwrap();
        let snapshot = service
            .read_sync(FileRef {
                target: target.clone(),
                path: target_path(&root.join("alias")),
                resolved_identity: None,
            })
            .unwrap();
        let actor = WorkspaceLease {
            client: ClientID([1; 16]),
            workspace: WorkspaceID([2; 16]),
            lease: WorkspaceLeaseID([3; 16]),
            runtime: RuntimeGeneration {
                supervisor_boot: [4; 16],
                container_start: None,
            },
        };
        let request = SaveRequest {
            operation: OperationID([5; 16]),
            file: snapshot.file,
            expected_version: Some(snapshot.version.clone()),
            submitted_revision: BufferRevision(1),
            source: ByteSource::Memory(Arc::from(b"after".as_slice())),
        };
        let receipt = service.save_owned_sync(
            request.clone(),
            actor.clone(),
            &std::sync::atomic::AtomicBool::new(true),
        );
        assert!(matches!(
            receipt.state,
            OperationState::Confirmed(MutationResult::Saved(_))
        ));
        let read_record = || {
            service
                .ledger
                .lock()
                .unwrap()
                .read(request.operation)
                .unwrap()
                .unwrap()
        };
        let record = read_record();
        let proof = record
            .save_proof
            .as_ref()
            .expect("actual owned save must retain authenticated historical endpoints");
        assert_eq!(proof.actor, actor);
        assert_eq!(proof.before.as_ref().unwrap().requested, snapshot.version);
        let after = proof.after.as_ref().unwrap();
        let canonical = service
            .read_sync(FileRef {
                target,
                path: target_path(&root.join("file")),
                resolved_identity: None,
            })
            .unwrap();
        assert_eq!(after.canonical, canonical.version);
        assert_ne!(after.requested, after.canonical);
        let different_actor = WorkspaceLease {
            workspace: WorkspaceID([8; 16]),
            lease: WorkspaceLeaseID([9; 16]),
            ..actor
        };
        assert_eq!(
            service.save_owned_sync(
                request.clone(),
                different_actor,
                &std::sync::atomic::AtomicBool::new(false)
            ),
            receipt
        );
        assert_eq!(
            read_record().save_proof,
            record.save_proof,
            "duplicate retrofitted provenance"
        );
        assert_eq!(read_record().envelope, record.envelope);
        std::os::unix::fs::symlink("file", root.join("second-alias")).unwrap();
        let next = service
            .read_sync(FileRef {
                target: service.target().clone(),
                path: target_path(&root.join("second-alias")),
                resolved_identity: None,
            })
            .unwrap();
        let next_actor = WorkspaceLease {
            workspace: WorkspaceID([11; 16]),
            lease: WorkspaceLeaseID([12; 16]),
            ..proof.actor.clone()
        };
        let second = service.save_owned_sync(
            SaveRequest {
                operation: OperationID([13; 16]),
                file: next.file,
                expected_version: Some(next.version),
                submitted_revision: BufferRevision(2),
                source: ByteSource::Memory(Arc::from(b"second".as_slice())),
            },
            next_actor.clone(),
            &std::sync::atomic::AtomicBool::new(true),
        );
        assert!(matches!(second.state, OperationState::Confirmed(_)));
        let next_record = service
            .ledger
            .lock()
            .unwrap()
            .read(second.id)
            .unwrap()
            .unwrap();
        let next_proof = next_record.save_proof.unwrap();
        assert_eq!(next_proof.actor, next_actor);
        assert_eq!(
            next_proof.before.as_ref().unwrap().canonical,
            after.canonical
        );
        assert_ne!(
            next_proof.before.as_ref().unwrap().requested,
            after.requested
        );
        println!(
            "actual_save_record_bytes={} actual_save_proof_bytes={}",
            serde_json::to_vec(&record).unwrap().len(),
            serde_json::to_vec(proof).unwrap().len()
        );
    }

    #[test]
    fn inspection_and_legacy_saves_cannot_manufacture_historical_after_evidence() {
        for failpoint in [
            FailPoint::None,
            FailPoint::Completion,
            FailPoint::Acknowledgement,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(dir.path()).unwrap();
            let target = TargetIdentity {
                security_binding: vec![1],
                effective_user: vec![2],
                filesystem_namespace: vec![3],
                container: None,
            };
            let service = LocalFileService::new(target.clone(), root.join("state")).unwrap();
            fs::write(root.join("file"), b"before").unwrap();
            let snapshot = service
                .read_sync(FileRef {
                    target: target.clone(),
                    path: target_path(&root.join("file")),
                    resolved_identity: None,
                })
                .unwrap();
            let request = SaveRequest {
                operation: OperationID([10; 16]),
                file: snapshot.file,
                expected_version: Some(snapshot.version),
                submitted_revision: BufferRevision(1),
                source: ByteSource::Memory(Arc::from(b"after".as_slice())),
            };
            let owned = failpoint != FailPoint::None;
            service.set_failpoint(failpoint);
            let receipt = if owned {
                service.save_owned_sync(
                    request,
                    WorkspaceLease {
                        client: ClientID([1; 16]),
                        workspace: WorkspaceID([2; 16]),
                        lease: WorkspaceLeaseID([3; 16]),
                        runtime: RuntimeGeneration {
                            supervisor_boot: [4; 16],
                            container_start: None,
                        },
                    },
                    &std::sync::atomic::AtomicBool::new(true),
                )
            } else {
                service.save_sync(request)
            };
            assert!(if owned {
                matches!(receipt.state, OperationState::Unknown(_))
            } else {
                matches!(receipt.state, OperationState::Confirmed(_))
            });
            service.set_failpoint(FailPoint::None);
            if failpoint == FailPoint::Acknowledgement {
                fs::write(root.join("file"), b"external after saved").unwrap();
            }
            let inspected = service.inspect_sync(receipt.id, target).unwrap();
            assert!(if failpoint == FailPoint::Completion {
                matches!(inspected.state, OperationState::Unknown(_))
            } else {
                matches!(inspected.state, OperationState::Confirmed(_))
            });
            let record = service
                .ledger
                .lock()
                .unwrap()
                .read(receipt.id)
                .unwrap()
                .unwrap();
            if owned {
                let proof = record.save_proof.unwrap();
                assert!(proof.before.is_some());
                assert_eq!(
                    proof.after.is_some(),
                    failpoint == FailPoint::Acknowledgement,
                    "inspection changed historical replacement proof eligibility"
                );
                if let Some(after) = proof.after {
                    let OperationState::Confirmed(MutationResult::Saved(saved)) =
                        record.receipt.state
                    else {
                        panic!("missing saved receipt")
                    };
                    assert_eq!(after.requested, saved.version);
                }
            } else {
                assert!(
                    record.save_proof.is_none(),
                    "legacy save acquired an unauthenticated actor"
                );
            }
        }
    }

    #[test]
    fn observation_normalizes_alias_versions_from_one_file_identity() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let target = TargetIdentity {
            security_binding: vec![1],
            effective_user: vec![2],
            filesystem_namespace: vec![3],
            container: None,
        };
        let service = LocalFileService::new(target.clone(), root.join("state")).unwrap();
        fs::write(root.join("file"), b"content").unwrap();
        std::os::unix::fs::symlink("file", root.join("middle")).unwrap();
        std::os::unix::fs::symlink("middle", root.join("alias")).unwrap();
        let observe = |name| {
            service
                .observe_regular_sync(
                    FileRef {
                        target: target.clone(),
                        path: target_path(&root.join(name)),
                        resolved_identity: None,
                    },
                    &std::sync::atomic::AtomicBool::new(false),
                    std::time::Instant::now(),
                )
                .unwrap()
        };
        let canonical = observe("file");
        let alias = observe("alias");
        assert_ne!(canonical.version, alias.version);
        assert_eq!(
            canonical.version, alias.canonical_version,
            "aliases need the same canonical strong endpoint for contiguous save chains"
        );
        std::os::unix::fs::symlink("file", root.join("replacement")).unwrap();
        fs::rename(root.join("replacement"), root.join("middle")).unwrap();
        let replaced = observe("alias");
        assert_ne!(alias.version, replaced.version);
        assert_eq!(alias.canonical_version, replaced.canonical_version);
    }

    #[test]
    fn read_refuses_symlink_destination_replaced_after_streaming() {
        let dir = tempfile::tempdir().unwrap();
        let target = TargetIdentity {
            security_binding: vec![1],
            effective_user: vec![2],
            filesystem_namespace: vec![3],
            container: None,
        };
        let mut service = LocalFileService::new(target.clone(), dir.path().join("state")).unwrap();
        let destination = dir.path().join("destination");
        fs::write(&destination, b"original").unwrap();
        std::os::unix::fs::symlink("destination", dir.path().join("alias")).unwrap();
        // The descriptor metadata has been sampled; now replace its still-unchanged resolved pathname.
        let retired = dir.path().join("retired");
        let replacement = dir.path().join("replacement");
        fs::write(&replacement, b"replacement").unwrap();
        service.before_read_validation = Some(Arc::new(move || {
            fs::rename(&destination, &retired).unwrap();
            fs::rename(&replacement, &destination).unwrap();
        }));
        let result = service.read_sync(FileRef {
            target,
            path: target_path(&dir.path().join("alias")),
            resolved_identity: None,
        });
        assert!(
            result.is_err(),
            "read returned old descriptor contents for the newly replaced symlink destination"
        );
    }
}
