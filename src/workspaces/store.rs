use crate::{
    connections::local::new_id,
    files::{atomic_private, io_error, private_directory},
};
use buntrail_core::{contracts::*, workspaces::*};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::{Path, PathBuf},
};
// Disk catalogs retain documents and authority, never terminal restoration state.
fn clear_terminal_state(catalog: &mut serde_json::Value) -> bool {
    let mut changed = false;
    if let Some(records) = catalog.get_mut("records").and_then(|v| v.as_array_mut()) {
        for record in records {
            if let Some(record) = record.as_object_mut() {
                for key in ["terminal_layout", "terminal_starts", "terminal_height"] {
                    changed |= record.remove(key).is_some();
                }
                changed |= record.get("terminal_visible") != Some(&serde_json::Value::Bool(false));
                record.insert("terminal_visible".into(), serde_json::Value::Bool(false));
            }
        }
    }
    changed
}
pub struct WorkspaceStore {
    directory: PathBuf,
    lock: std::sync::Mutex<File>,
}
impl WorkspaceStore {
    pub fn new(directory: PathBuf) -> Result<Self, CoreError> {
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
            lock: std::sync::Mutex::new(lock),
        })
    }
    fn guard(&self) -> Result<StoreLock<'_>, CoreError> {
        let guard = self.lock.lock().map_err(io_error)?;
        guard.lock().map_err(io_error)?;
        Ok(StoreLock(guard))
    }
    pub fn load(&self) -> Result<WorkspaceCatalog, CoreError> {
        let _lock = self.guard()?;
        self.read()
    }
    fn read(&self) -> Result<WorkspaceCatalog, CoreError> {
        let path = self.directory.join("workspaces.json");
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let c = WorkspaceCatalog {
                    schema: 1,
                    client: ClientID(new_id()?),
                    records: vec![],
                };
                self.write(&c)?;
                return Ok(c);
            }
            Err(e) => return Err(io_error(e)),
        };
        let mut bytes = vec![];
        Read::by_ref(&mut file)
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(io_error("workspace state exceeds limit"));
        }
        let mut disk: serde_json::Value = serde_json::from_slice(&bytes).map_err(io_error)?;
        let migrated = clear_terminal_state(&mut disk);
        let c: WorkspaceCatalog = serde_json::from_value(disk).map_err(io_error)?;
        if c.schema != 1
            || !valid_git_recoveries(&c)
            || !valid_file_recoveries(&c)
            || c.records.len() > 100
            || c.records.iter().any(|r| {
                r.documents.len() > 64
                    || r.terminal_layout.validate().is_err()
                    || !valid_terminal_starts(r)
                    || r.terminal_height
                        .is_some_and(|h| !h.is_finite() || !(40.0..=10000.0).contains(&h))
            })
        {
            return Err(io_error("workspace schema or bounds invalid"));
        }
        if migrated {
            self.write(&c)?;
        }
        Ok(c)
    }
    pub fn save(&self, catalog: &WorkspaceCatalog) -> Result<(), CoreError> {
        let _lock = self.guard()?;
        let current = self.read()?;
        let mut catalog = catalog.clone();
        for old in &current.records {
            let Some(record) = catalog
                .records
                .iter_mut()
                .find(|record| record.id == old.id)
            else {
                if !old.git_recoveries.is_empty() || !old.file_recoveries.is_empty() {
                    return Err(CoreError::new(
                        ErrorCode::Busy,
                        "cannot drop retained Git outcomes in a catalog write",
                    ));
                }
                continue;
            };
            if record.target != old.target || record.lease != old.lease {
                return Err(CoreError::new(
                    ErrorCode::TargetChanged,
                    "retained Git recovery identity changed",
                ));
            }
            record.git_recoveries = old.git_recoveries.clone();
            record.file_recoveries = old.file_recoveries.clone();
            record.git_recovery_generation = old.git_recovery_generation;
        }
        self.write(&catalog)
    }
    fn write(&self, catalog: &WorkspaceCatalog) -> Result<(), CoreError> {
        let mut disk = serde_json::to_value(catalog).map_err(io_error)?;
        clear_terminal_state(&mut disk);
        let bytes = serde_json::to_vec(&disk).map_err(io_error)?;
        if catalog.schema != 1
            || !valid_git_recoveries(catalog)
            || !valid_file_recoveries(catalog)
            || catalog.records.len() > 100
            || catalog.records.iter().any(|r| {
                r.terminal_layout.validate().is_err()
                    || !valid_terminal_starts(r)
                    || r.terminal_height
                        .is_some_and(|h| !h.is_finite() || !(40.0..=10000.0).contains(&h))
            })
            || bytes.len() > 4 * 1024 * 1024
        {
            return Err(io_error("workspace state exceeds limit"));
        }
        atomic_private(&self.directory.join("workspaces.json"), &bytes)
    }
    pub fn open(
        &self,
        root: TargetPath,
        target: TargetIdentity,
    ) -> Result<WorkspaceState, CoreError> {
        let _lock = self.guard()?;
        let raw = crate::files::path(&root)?;
        let verified = std::fs::canonicalize(&raw);
        let mut c = self.read()?;
        let existing = c
            .records
            .iter()
            .position(|r| r.locator.root == root && r.target == target);
        let canonical = match verified {
            Ok(p) if p.is_dir() => Some(p),
            _ => None,
        };
        if canonical.is_none() {
            return existing
                .map(|i| WorkspaceState::Missing(c.records[i].clone()))
                .ok_or_else(|| {
                    CoreError::new(ErrorCode::Io, "workspace folder is missing or inaccessible")
                });
        }
        let root = crate::files::target_path(canonical.as_ref().unwrap());
        let existing = existing.or_else(|| {
            c.records
                .iter()
                .position(|r| r.locator.root == root && r.target == target)
        });
        let record = if let Some(i) = existing {
            let mut r = c.records.remove(i);
            r.locator.root = root;
            r
        } else {
            WorkspaceRecord {
                id: WorkspaceID(new_id()?),
                generation: 0,
                lease: WorkspaceLeaseID(new_id()?),
                display_name: raw
                    .file_name()
                    .unwrap_or(raw.as_os_str())
                    .to_string_lossy()
                    .into_owned(),
                locator: WorkspaceLocator {
                    environment: EnvironmentLocator {
                        route: RouteKind::Local,
                        ssh_profile: None,
                        engine: None,
                        engine_context: None,
                        container_selector: None,
                        effective_user: None,
                    },
                    root,
                },
                target,
                documents: vec![],
                selected: None,
                show_hidden: true,
                show_icons: true,
                sidebar_visible: true,
                terminal_visible: false,
                terminal_height: None,
                terminal_layout: Default::default(),
                terminal_starts: vec![],
                graph_filters: vec![],
                git_recoveries: vec![],
                git_recovery_generation: 0,
                file_recoveries: vec![],
            }
        };
        c.records.insert(0, record.clone());
        self.write(&c)?;
        Ok(WorkspaceState::Ready(record))
    }
    /// Catalog-only insertion. Root resolution and lease registration belong to the selected backend.
    pub fn register_resolved(&self, record: WorkspaceRecord) -> Result<WorkspaceRecord, CoreError> {
        let _lock = self.guard()?;
        let mut catalog = self.read()?;
        if let Some(existing) = catalog.records.iter().find(|r| {
            r.id == record.id || (r.target == record.target && r.locator == record.locator)
        }) {
            if existing.id != record.id
                || existing.lease != record.lease
                || existing.target != record.target
                || existing.locator != record.locator
            {
                return Err(CoreError::new(
                    ErrorCode::TargetChanged,
                    "saved workspace identity differs; register its existing owner explicitly",
                ));
            }
            return Ok(existing.clone());
        }
        catalog.records.insert(0, record.clone());
        self.write(&catalog)?;
        Ok(record)
    }
    pub fn update(&self, mut record: WorkspaceRecord) -> Result<(), CoreError> {
        let _lock = self.guard()?;
        let mut c = self.read()?;
        let old = c
            .records
            .iter_mut()
            .find(|r| r.id == record.id)
            .ok_or_else(|| io_error("workspace no longer saved"))?;
        if old.target != record.target || old.locator != record.locator {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "workspace identity changed",
            ));
        }
        if old.generation < record.generation {
            // Navigation/selection writes cannot replace worker-persisted operation references.
            record.git_recoveries = old.git_recoveries.clone();
            record.file_recoveries = old.file_recoveries.clone();
            record.git_recovery_generation = old.git_recovery_generation;
            *old = record;
        }
        self.write(&c)
    }
    pub fn remove(&self, id: WorkspaceID) -> Result<(), CoreError> {
        let _lock = self.guard()?;
        let mut c = self.read()?;
        if c.records
            .iter()
            .any(|r| r.id == id && (!r.git_recoveries.is_empty() || !r.file_recoveries.is_empty()))
        {
            return Err(CoreError::new(
                ErrorCode::Busy,
                "inspect retained Git outcomes before removing the saved workspace",
            ));
        }
        c.records.retain(|r| r.id != id);
        self.write(&c)
    }
    /// Only this locked path adds references; insertion durably precedes target admission.
    pub fn retain_git_recovery(
        &self,
        workspace: WorkspaceID,
        reference: GitRecoveryReference,
    ) -> Result<(WorkspaceRecord, bool), CoreError> {
        let _lock = self.guard()?;
        let mut catalog = self.read()?;
        if let Some(record) = catalog.records.iter().find(|r| {
            r.git_recoveries
                .iter()
                .any(|old| old.operation == reference.operation)
        }) {
            let old = record
                .git_recoveries
                .iter()
                .find(|r| r.operation == reference.operation)
                .unwrap();
            if old.worktree != reference.worktree
                || old.kind != reference.kind
                || old.request_digest != reference.request_digest
            {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "original Git recovery identity/digest differs",
                ));
            }
            return Ok((record.clone(), false));
        }
        if let Some(old) = catalog
            .records
            .iter()
            .flat_map(|r| &r.git_recoveries)
            .find(|old| {
                old.worktree.target == reference.worktree.target
                    && old.worktree.common_git_directory_identity
                        == reference.worktree.common_git_directory_identity
            })
        {
            return Err(CoreError {code:ErrorCode::Busy,message:"Inspect the retained original Git outcome before another mutation in this repository".into(),context:ErrorContext::Operation(old.operation)});
        }
        let client = catalog.client;
        let record = catalog
            .records
            .iter_mut()
            .find(|r| r.id == workspace)
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::Closed,
                    "Git recovery workspace is no longer saved",
                )
            })?;
        if record.target != reference.worktree.target
            || reference.owner.workspace != workspace
            || reference.owner.lease != record.lease
            || reference.owner.client != client
        {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "Git recovery owner/target differs",
            ));
        }
        record.git_recovery_generation = record
            .git_recovery_generation
            .checked_add(1)
            .ok_or_else(|| io_error("Git recovery generation exhausted"))?;
        record.git_recoveries.push(reference);
        let record = record.clone();
        self.write(&catalog)?;
        Ok((record, true))
    }
    /// Called only after an authoritative terminal receipt or proven current unsent cancellation.
    pub fn resolve_git_recovery(
        &self,
        workspace: WorkspaceID,
        reference: &GitRecoveryReference,
    ) -> Result<WorkspaceRecord, CoreError> {
        let _lock = self.guard()?;
        let mut catalog = self.read()?;
        let record = catalog
            .records
            .iter_mut()
            .find(|r| r.id == workspace)
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::Closed,
                    "original Git recovery workspace is no longer saved",
                )
            })?;
        if let Some(old) = record
            .git_recoveries
            .iter()
            .find(|old| old.operation == reference.operation)
        {
            if old != reference {
                return Err(CoreError::new(
                    ErrorCode::TargetChanged,
                    "Git recovery reference changed before resolution",
                ));
            }
            record
                .git_recoveries
                .retain(|old| old.operation != reference.operation);
            record.git_recovery_generation = record
                .git_recovery_generation
                .checked_add(1)
                .ok_or_else(|| io_error("Git recovery generation exhausted"))?;
        }
        let record = record.clone();
        self.write(&catalog)?;
        Ok(record)
    }
    /// Only this locked path adds references; insertion durably precedes target admission.
    pub fn retain_file_recovery(
        &self,
        workspace: WorkspaceID,
        reference: FileRecoveryReference,
    ) -> Result<(WorkspaceRecord, bool), CoreError> {
        let _lock = self.guard()?;
        let mut catalog = self.read()?;
        if let Some(record) = catalog.records.iter().find(|r| {
            r.file_recoveries
                .iter()
                .any(|old| old.operation == reference.operation)
        }) {
            let old = record
                .file_recoveries
                .iter()
                .find(|r| r.operation == reference.operation)
                .unwrap();
            if old.file != reference.file
                || old.owner != reference.owner
                || old.destination != reference.destination
                || old.kind != reference.kind
                || old.request_digest != reference.request_digest
            {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "original File recovery identity/digest differs",
                ));
            }
            return Ok((record.clone(), false));
        }
        if let Some(old) = catalog
            .records
            .iter()
            .flat_map(|r| &r.file_recoveries)
            .find(|old| old.file.target == reference.file.target)
        {
            return Err(CoreError {code:ErrorCode::Busy,message:"Inspect the retained original file outcome before another mutation in this repository".into(),context:ErrorContext::Operation(old.operation)});
        }
        let client = catalog.client;
        let record = catalog
            .records
            .iter_mut()
            .find(|r| r.id == workspace)
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::Closed,
                    "File recovery workspace is no longer saved",
                )
            })?;
        if record.target != reference.file.target
            || reference.owner.workspace != workspace
            || reference.owner.lease != record.lease
            || reference.owner.client != client
        {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "File recovery owner/target differs",
            ));
        }
        record.file_recoveries.push(reference);
        let record = record.clone();
        self.write(&catalog)?;
        Ok((record, true))
    }
    /// Called only after an authoritative terminal receipt or proven current unsent cancellation.
    pub fn resolve_file_recovery(
        &self,
        workspace: WorkspaceID,
        reference: &FileRecoveryReference,
    ) -> Result<WorkspaceRecord, CoreError> {
        let _lock = self.guard()?;
        let mut catalog = self.read()?;
        let record = catalog
            .records
            .iter_mut()
            .find(|r| r.id == workspace)
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::Closed,
                    "original File recovery workspace is no longer saved",
                )
            })?;
        if let Some(old) = record
            .file_recoveries
            .iter()
            .find(|old| old.operation == reference.operation)
        {
            if old != reference {
                return Err(CoreError::new(
                    ErrorCode::TargetChanged,
                    "File recovery reference changed before resolution",
                ));
            }
            record
                .file_recoveries
                .retain(|old| old.operation != reference.operation);
        }
        let record = record.clone();
        self.write(&catalog)?;
        Ok(record)
    }
    pub fn relocate(
        &self,
        id: WorkspaceID,
        root: TargetPath,
        target: &TargetIdentity,
    ) -> Result<WorkspaceRecord, CoreError> {
        let _lock = self.guard()?;
        let canonical = std::fs::canonicalize(crate::files::path(&root)?).map_err(io_error)?;
        if !canonical.is_dir() {
            return Err(io_error("choose a folder"));
        }
        let mut c = self.read()?;
        let r = c
            .records
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| io_error("workspace no longer saved"))?;
        if &r.target != target {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "workspace target changed",
            ));
        }
        let previous = crate::files::path(&r.locator.root)?;
        for document in &mut r.documents {
            if let Ok(file) = saved_path(&document.file.path)
                && let Ok(relative) = file.strip_prefix(&previous)
            {
                document.file.path = crate::files::target_path(&canonical.join(relative));
                document.file.resolved_identity = None;
            }
        }
        // Recovery lookup uses the document ID and retains a draft's original target/path.
        r.locator.root = crate::files::target_path(&canonical);
        r.generation = r
            .generation
            .checked_add(1)
            .ok_or_else(|| io_error("workspace generation exhausted"))?;
        let record = r.clone();
        self.write(&c)?;
        Ok(record)
    }
}
// Resolve existing ancestors without assigning identity to a missing saved suffix.
fn saved_path(value: &TargetPath) -> Result<PathBuf, CoreError> {
    let mut candidate = crate::files::path(value)?;
    let mut suffix = vec![];
    loop {
        match std::fs::canonicalize(&candidate) {
            Ok(mut verified) => {
                for part in suffix.into_iter().rev() {
                    verified.push(part);
                }
                return Ok(verified);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let name = candidate
                    .file_name()
                    .ok_or_else(|| io_error("saved path has no existing ancestor"))?
                    .to_os_string();
                suffix.push(name);
                if !candidate.pop() {
                    return Err(io_error("saved path has no parent"));
                }
            }
            Err(e) => return Err(io_error(e)),
        }
    }
}
pub fn is_within(root: &TargetPath, file: &TargetPath) -> bool {
    match (root, file) {
        (TargetPath::PosixBytes(r), TargetPath::PosixBytes(f)) => {
            Path::new(std::ffi::OsStr::from_bytes(f))
                .starts_with(Path::new(std::ffi::OsStr::from_bytes(r)))
        }
        _ => false,
    }
}

pub fn resolved_parent(path: &TargetPath) -> Result<PathBuf, CoreError> {
    let p = crate::files::path(path)?;
    let parent = p.parent().ok_or_else(|| io_error("missing parent"))?;
    Ok(std::fs::canonicalize(parent)
        .map_err(io_error)?
        .join(p.file_name().ok_or_else(|| io_error("missing filename"))?))
}
pub fn validate_child(root: &TargetPath, file: &TargetPath) -> Result<(), CoreError> {
    let root = std::fs::canonicalize(crate::files::path(root)?).map_err(io_error)?;
    if !resolved_parent(file)?.starts_with(root) {
        return Err(CoreError::new(
            ErrorCode::InvalidArgument,
            "file is outside workspace root",
        ));
    }
    Ok(())
}
pub fn same_path(a: &TargetPath, b: &TargetPath) -> bool {
    a == b
        || resolved_parent(a)
            .ok()
            .zip(resolved_parent(b).ok())
            .is_some_and(|(a, b)| a == b)
}

struct StoreLock<'a>(std::sync::MutexGuard<'a, File>);
impl Drop for StoreLock<'_> {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

pub fn relative_child(root: &TargetPath, file: &TargetPath) -> Option<PathBuf> {
    let r = resolved_parent(root).ok()?;
    let f = resolved_parent(file).ok()?;
    f.strip_prefix(r).ok().map(Path::to_path_buf)
}
pub fn rebased(destination: &TargetPath, relative: &Path) -> Result<TargetPath, CoreError> {
    if relative.as_os_str().is_empty() {
        Ok(destination.clone())
    } else {
        Ok(crate::files::target_path(
            &crate::files::path(destination)?.join(relative),
        ))
    }
}

fn valid_terminal_starts(record: &WorkspaceRecord) -> bool {
    let sessions = record.terminal_layout.sessions();
    let mut seen = std::collections::HashSet::new();
    record.terminal_starts.len() == sessions.len()
        && record.terminal_starts.len() <= 64
        && record.terminal_starts.iter().all(|start| {
            seen.insert(start.session)
                && sessions.contains(&start.session)
                && [&start.directory, &start.shell]
                    .iter()
                    .all(|path| match path {
                        TargetPath::PosixBytes(bytes) => {
                            bytes.len() <= 65536
                                && bytes.first() == Some(&b'/')
                                && !bytes.contains(&0)
                        }
                        _ => false,
                    })
        })
}
fn valid_git_recoveries(catalog: &WorkspaceCatalog) -> bool {
    let mut seen = std::collections::HashSet::new();
    catalog.records.iter().all(|record|record.git_recoveries.iter().all(|reference| {
        reference.worktree.target==record.target && reference.owner.workspace==record.id
            && reference.owner.lease==record.lease && reference.owner.client==catalog.client
            && !reference.worktree.common_git_directory_identity.is_empty()
            && reference.worktree.common_git_directory_identity.len()<=65536
            && matches!(&reference.worktree.canonical_path,TargetPath::PosixBytes(bytes) if bytes.len()<=65536 && bytes.first()==Some(&b'/') && !bytes.contains(&0))
            && seen.insert(reference.operation)
    }))
}

fn valid_file_recoveries(catalog: &WorkspaceCatalog) -> bool {
    let mut seen = std::collections::HashSet::new();
    let path_valid = |path: &TargetPath| {
        matches!(path, TargetPath::PosixBytes(bytes)
        if bytes.len() <= 65536 && bytes.first() == Some(&b'/') && !bytes.contains(&0))
    };
    catalog.records.iter().all(|record| {
        record.file_recoveries.len() <= 64
            && record.file_recoveries.iter().all(|reference| {
                reference.file.target == record.target
                    && reference.owner.workspace == record.id
                    && reference.owner.lease == record.lease
                    && reference.owner.client == catalog.client
                    && path_valid(&reference.file.path)
                    && reference.destination.as_ref().is_none_or(path_valid)
                    && seen.insert(reference.operation)
            })
    })
}
