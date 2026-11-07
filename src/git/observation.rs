//! Target-owned retained observations. These are data, not permission to execute Git.
pub(super) use super::observation_store::Store;
pub use super::observation_store::{
    ObservationInput, ObservationInputReader, ObservationInputWriter, ObservationPin,
    ObservationReader, ObservationStorageStats,
};
use crate::files::{io_error, path, target_path};
use buntrail_core::contracts::*;
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

#[derive(Clone)]
pub struct ObservationOwner {
    pub(crate) target: TargetIdentity,
    pub(crate) lease: WorkspaceLease,
    pub(crate) active: Arc<AtomicBool>,
}
impl ObservationOwner {
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }
    pub fn registration(&self) -> &WorkspaceLease {
        &self.lease
    }
    pub(crate) fn check(&self) -> Result<(), CoreError> {
        if self.active.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(CoreError::new(
                ErrorCode::Closed,
                "observation registration revoked",
            ))
        }
    }
    pub(crate) fn same(&self, other: &Self) -> bool {
        self.target == other.target
            && self.lease == other.lease
            && Arc::ptr_eq(&self.active, &other.active)
    }
    /// Trusted registration adapters only: authenticate the exact registration before calling.
    pub fn authenticated(
        target: TargetIdentity,
        lease: WorkspaceLease,
        active: Arc<AtomicBool>,
    ) -> Self {
        Self {
            target,
            lease,
            active,
        }
    }
}
pub struct RetainedStatus {
    pub id: [u8; 16],
    pub snapshot: GitSnapshot,
    pub bytes: u64,
}
/// Target-decoded original alias identity; the hint is identity, never filesystem authority.
pub struct CapturedAlias {
    pub(super) file: FileRef,
    pub(super) digest: [u8; 32],
}
impl CapturedAlias {
    fn from_file(mut file: FileRef) -> Result<Self, CoreError> {
        let digest = serialized_digest(&file)?;
        file.resolved_identity = None;
        Ok(Self { file, digest })
    }
    pub fn path(&self) -> &TargetPath {
        &self.file.path
    }
    pub fn reference_digest(&self) -> [u8; 32] {
        self.digest
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationMembership {
    pub requested_repository: Option<[u8; 32]>,
    pub resolved_repository: Option<[u8; 32]>,
    pub affected: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegularObservation {
    pub requested: [u8; 32],
    pub canonical: [u8; 32],
    pub content_digest: [u8; 32],
    pub resolution: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationRecord {
    pub path: TargetPath,
    pub structural_token: [u8; 32],
    pub resolved: Option<TargetPath>,
    pub regular: Option<RegularObservation>,
    /// None is a Git-enumerated node; Some is an original supplemental alias.
    pub membership: Option<ObservationMembership>,
    pub file_reference: Option<[u8; 32]>,
}
pub(super) fn serialized_digest(value: &impl serde::Serialize) -> Result<[u8; 32], CoreError> {
    struct HashWriter(Sha256);
    impl std::io::Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = HashWriter(Sha256::new());
    serde_json::to_writer(&mut writer, value).map_err(io_error)?;
    Ok(writer.0.finalize().into())
}
fn invalid() -> CoreError {
    CoreError::new(
        ErrorCode::InvalidArgument,
        "invalid retained observation record",
    )
}
impl ObservationRecord {
    pub(super) fn from_node(
        path: TargetPath,
        node: &crate::files::NodeObservation,
        membership: Option<ObservationMembership>,
    ) -> Result<Self, CoreError> {
        Ok(Self {
            path,
            structural_token: node.structural_token,
            resolved: node.destination.as_ref().map(|d| d.resolved.clone()),
            regular: node
                .regular
                .as_ref()
                .map(|r| {
                    Ok(RegularObservation {
                        requested: r
                            .version
                            .opaque_token
                            .as_slice()
                            .try_into()
                            .map_err(|_| invalid())?,
                        canonical: r
                            .canonical_version
                            .opaque_token
                            .as_slice()
                            .try_into()
                            .map_err(|_| invalid())?,
                        content_digest: r.version.content_digest,
                        resolution: Sha256::digest(
                            serde_json::to_vec(&r.destination).map_err(io_error)?,
                        )
                        .into(),
                    })
                })
                .transpose()?,
            membership,
            file_reference: None,
        })
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, CoreError> {
        fn path_bytes(out: &mut Vec<u8>, path: Option<&TargetPath>) -> Result<(), CoreError> {
            let bytes = match path {
                Some(TargetPath::PosixBytes(bytes)) => bytes.as_slice(),
                None => &[],
                _ => return Err(invalid()),
            };
            let length: u32 = bytes.len().try_into().map_err(|_| invalid())?;
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(bytes);
            Ok(())
        }
        let mut out = vec![u8::from(self.membership.is_some())];
        path_bytes(&mut out, Some(&self.path))?;
        out.extend_from_slice(&self.structural_token);
        path_bytes(&mut out, self.resolved.as_ref())?;
        out.push(u8::from(self.regular.is_some()));
        if let Some(r) = &self.regular {
            for digest in [&r.requested, &r.canonical, &r.content_digest, &r.resolution] {
                out.extend_from_slice(digest);
            }
        }
        if let Some(m) = &self.membership {
            out.push(u8::from(m.affected));
            for repo in [&m.requested_repository, &m.resolved_repository] {
                out.push(u8::from(repo.is_some()));
                if let Some(repo) = repo {
                    out.extend_from_slice(repo);
                }
            }
            out.extend_from_slice(&self.file_reference.ok_or_else(invalid)?);
        }
        Ok(out)
    }
    pub(super) fn read(reader: &mut impl Read) -> Result<Option<Self>, CoreError> {
        Self::read_with_path_limit(reader, libc::PATH_MAX as usize)
    }
    pub(super) fn read_with_path_limit(
        reader: &mut impl Read,
        path_limit: usize,
    ) -> Result<Option<Self>, CoreError> {
        fn byte(reader: &mut impl Read) -> Result<u8, CoreError> {
            let mut b = [0];
            reader.read_exact(&mut b).map_err(io_error)?;
            Ok(b[0])
        }
        fn digest(reader: &mut impl Read) -> Result<[u8; 32], CoreError> {
            let mut b = [0; 32];
            reader.read_exact(&mut b).map_err(io_error)?;
            Ok(b)
        }
        let mut tag = [0];
        if reader.read(&mut tag).map_err(io_error)? == 0 {
            return Ok(None);
        }
        if tag[0] > 1 {
            return Err(invalid());
        }
        let path = read_path(reader, path_limit)?.ok_or_else(invalid)?;
        let structural_token = digest(reader)?;
        let resolved = self::read_path(reader, path_limit)?;
        let regular = match byte(reader)? {
            0 => None,
            1 => Some(RegularObservation {
                requested: digest(reader)?,
                canonical: digest(reader)?,
                content_digest: digest(reader)?,
                resolution: digest(reader)?,
            }),
            _ => return Err(invalid()),
        };
        let membership = if tag[0] == 1 {
            let affected = match byte(reader)? {
                0 => false,
                1 => true,
                _ => return Err(invalid()),
            };
            let mut repo = || match byte(reader)? {
                0 => Ok(None),
                1 => digest(reader).map(Some),
                _ => Err(invalid()),
            };
            Some(ObservationMembership {
                affected,
                requested_repository: repo()?,
                resolved_repository: repo()?,
            })
        } else {
            None
        };
        let file_reference = if membership.is_some() {
            Some(digest(reader)?)
        } else {
            None
        };
        Ok(Some(Self {
            path,
            structural_token,
            resolved,
            regular,
            membership,
            file_reference,
        }))
    }
    pub fn matches_alias(&self, file: &FileRef) -> Result<bool, CoreError> {
        Ok(self.path == file.path && self.file_reference == Some(serialized_digest(file)?))
    }
}
fn read_path(reader: &mut impl Read, path_limit: usize) -> Result<Option<TargetPath>, CoreError> {
    let mut size = [0; 4];
    reader.read_exact(&mut size).map_err(io_error)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 {
        return Ok(None);
    }
    if size > path_limit {
        return Err(invalid());
    }
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes).map_err(io_error)?;
    TargetPath::posix(bytes).map(Some)
}
impl super::LocalGitService {
    pub(super) fn observation_store(&self) -> Result<&Arc<Store>, CoreError> {
        self.observations.as_ref().map_err(Clone::clone)
    }
    fn checked_owner(&self, owner: &ObservationOwner) -> Result<(), CoreError> {
        owner.check()?;
        if owner.target != *self.files.target() {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "observation target changed",
            ));
        }
        Ok(())
    }
    pub fn observation_input(
        &self,
        owner: &ObservationOwner,
    ) -> Result<ObservationInputWriter, CoreError> {
        self.checked_owner(owner)?;
        self.observation_store()?.input(owner)
    }
    /// Exactly two charged parts share one admission; failure of either poisons both.
    pub fn observation_input_pair(
        &self,
        owner: &ObservationOwner,
    ) -> Result<(ObservationInputWriter, ObservationInputWriter), CoreError> {
        self.checked_owner(owner)?;
        self.observation_store()?.input_pair(owner)
    }
    pub fn observation_reader(
        &self,
        owner: &ObservationOwner,
        id: [u8; 16],
    ) -> Result<ObservationReader, CoreError> {
        self.checked_owner(owner)?;
        self.observation_store()?.reader(owner, id)
    }
    pub fn pin_observation(
        &self,
        owner: &ObservationOwner,
        id: [u8; 16],
    ) -> Result<ObservationPin, CoreError> {
        self.checked_owner(owner)?;
        self.observation_store()?.pin(owner, id)
    }
    pub fn release_observation(&self, owner: &ObservationOwner, id: [u8; 16]) {
        if let Ok(store) = &self.observations {
            store.release(owner, id)
        }
    }
    pub fn observation_storage_stats(&self) -> Result<ObservationStorageStats, CoreError> {
        Ok(self.observation_store()?.stats())
    }
    pub fn reap_observations(&self) {
        if let Ok(store) = &self.observations {
            store.prune()
        }
    }
    fn repository_for_path(
        &self,
        target: &TargetIdentity,
        file: &TargetPath,
        cancel: &AtomicBool,
    ) -> Result<Option<WorktreeIdentity>, CoreError> {
        let path = path(file)?;
        let mut parent = path.parent().ok_or_else(invalid)?;
        while !parent.is_dir() {
            parent = parent.parent().ok_or_else(invalid)?;
        }
        self.discover_sync(
            FileRef {
                target: target.clone(),
                path: target_path(parent),
                resolved_identity: None,
            },
            cancel,
        )
    }
    pub(super) fn alias_record(
        &self,
        worktree: &WorktreeIdentity,
        file: FileRef,
        cancel: &AtomicBool,
        started: Instant,
    ) -> Result<ObservationRecord, CoreError> {
        self.alias_node_record(worktree, file, cancel, started)
            .map(|(record, _)| record)
    }
    pub(super) fn alias_node_record(
        &self,
        worktree: &WorktreeIdentity,
        file: FileRef,
        cancel: &AtomicBool,
        started: Instant,
    ) -> Result<(ObservationRecord, Option<crate::files::ResolutionEvidence>), CoreError> {
        if file.target != worktree.target {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "supplemental alias target changed",
            ));
        }
        let node = self
            .files
            .observe_node_sync(file.clone(), cancel, started)?;
        let requested = self.repository_for_path(&file.target, &file.path, cancel)?;
        let resolved = node
            .destination
            .as_ref()
            .map(|d| self.repository_for_path(&file.target, &d.resolved, cancel))
            .transpose()?
            .flatten();
        let hash = |repo: &WorktreeIdentity| -> Result<[u8; 32], CoreError> {
            Ok(Sha256::digest(serde_json::to_vec(repo).map_err(io_error)?).into())
        };
        let membership = ObservationMembership {
            affected: requested.as_ref() == Some(worktree) || resolved.as_ref() == Some(worktree),
            requested_repository: requested.as_ref().map(hash).transpose()?,
            resolved_repository: resolved.as_ref().map(hash).transpose()?,
        };
        let digest = serialized_digest(&file)?;
        let mut record = ObservationRecord::from_node(file.path, &node, Some(membership))?;
        record.file_reference = Some(digest);
        Ok((record, node.destination))
    }
    pub fn observe_owned_sync(
        &self,
        owner: &ObservationOwner,
        worktree: WorktreeIdentity,
        aliases: impl IntoIterator<Item = Result<FileRef, CoreError>>,
        cancel: &AtomicBool,
    ) -> Result<RetainedStatus, CoreError> {
        self.observe_captured_sync(
            owner,
            worktree,
            aliases
                .into_iter()
                .map(|file| CapturedAlias::from_file(file?)),
            cancel,
        )
    }
    /// Only target-decoded aliases or the equivalent FileRef convenience path can create this input.
    pub fn observe_captured_sync(
        &self,
        owner: &ObservationOwner,
        worktree: WorktreeIdentity,
        aliases: impl IntoIterator<Item = Result<CapturedAlias, CoreError>>,
        cancel: &AtomicBool,
    ) -> Result<RetainedStatus, CoreError> {
        self.checked_owner(owner)?;
        let store = self.observation_store()?;
        let mut capture = store.begin(owner)?;
        let mutex = super::mutations::repository_mutex(&worktree);
        let _repository = mutex.lock().map_err(io_error)?;
        let root = self.validate(&worktree, cancel)?;
        let started = Instant::now();
        let (state, raw) = self.state_records(&root, cancel, |name, node| {
            use std::os::unix::ffi::OsStrExt;
            capture.append(&ObservationRecord::from_node(
                target_path(&root.join(std::ffi::OsStr::from_bytes(name))),
                node,
                None,
            )?)
        })?;
        for alias in aliases {
            if cancel.load(Ordering::SeqCst) {
                return Err(CoreError::new(
                    ErrorCode::Cancelled,
                    "observation capture cancelled",
                ));
            }
            let alias = alias?;
            let mut record = self.alias_record(&worktree, alias.file, cancel, started)?;
            record.file_reference = Some(alias.digest);
            capture.append(&record)?;
        }
        if self.state(&root, cancel)? != state {
            return Err(CoreError::new(
                ErrorCode::StaleRevision,
                "repository changed during retained observation",
            ));
        }
        let mut reader = capture.cursor()?;
        while let Some(original) = ObservationRecord::read(&mut reader)? {
            if original.membership.is_some() {
                let mut current = self.alias_record(
                    &worktree,
                    FileRef {
                        target: worktree.target.clone(),
                        path: original.path.clone(),
                        resolved_identity: None,
                    },
                    cancel,
                    started,
                )?;
                // The registered FileRef is immutable input; its hint is not filesystem authority.
                current.file_reference = original.file_reference;
                if current != original {
                    return Err(CoreError::new(
                        ErrorCode::StaleRevision,
                        "supplemental alias changed during original observation",
                    ));
                }
            }
        }
        let mut snapshot = GitSnapshot {
            worktree,
            state,
            staged: vec![],
            unstaged: vec![],
            untracked: vec![],
            conflicts: vec![],
        };
        super::output_parser::status(&root, &raw, &mut snapshot)?;
        if cancel.load(Ordering::SeqCst) {
            return Err(CoreError::new(
                ErrorCode::Cancelled,
                "observation capture cancelled",
            ));
        }
        let id = capture.id;
        let bytes = capture.publish(&snapshot)?;
        Ok(RetainedStatus {
            id,
            snapshot,
            bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::local::LocalConnection;
    use crate::contracts::ServiceAvailability;
    use std::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    fn run<T>(future: impl Future<Output = T>) -> T {
        match pin!(future)
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("local lease unexpectedly pending"),
        }
    }
    fn git(root: &std::path::Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn owned_status_retains_the_original_streamed_observation() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        git(&root, &["init", "-b", "main"]);
        std::fs::write(root.join("file"), "original").unwrap();
        let local = LocalConnection::open(dir.path().join("state")).unwrap();
        let lease = WorkspaceLeaseID([1; 16]);
        local.register(WorkspaceID([1; 16]), lease).unwrap();
        let owner = local.observation_owner(lease).unwrap();
        let cancel = AtomicBool::new(false);
        let worktree = local
            .git
            .discover_sync(
                FileRef {
                    target: local.identity.clone(),
                    path: crate::files::target_path(&root),
                    resolved_identity: None,
                },
                &cancel,
            )
            .unwrap()
            .unwrap();
        let retained = local
            .git
            .observe_owned_sync(&owner, worktree.clone(), std::iter::empty(), &cancel)
            .expect("owned status must retain an original observation");
        assert!(retained.bytes > 0);
        assert_eq!(
            retained.snapshot,
            local.git.status_sync(worktree, &cancel).unwrap()
        );
    }
    #[test]
    fn detached_local_proof_authority_does_not_revive_or_revoke_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let local = LocalConnection::open(dir.path().join("state")).unwrap();
        let a = WorkspaceLeaseID([1; 16]);
        let b = WorkspaceLeaseID([2; 16]);
        local.register(WorkspaceID([3; 16]), a).unwrap();
        local.register(WorkspaceID([3; 16]), b).unwrap();
        let first = local.observation_owner(a).unwrap();
        let sibling = local.observation_owner(b).unwrap();
        let ServiceAvailability::Available(leases) = local.environment().leases else {
            panic!("leases missing")
        };
        run(leases.release(a, LeaseReleaseIntent::ViewDetachment)).unwrap();
        assert!(
            !first.active.load(std::sync::atomic::Ordering::SeqCst),
            "detachment retained original proof authority"
        );
        assert!(sibling.active.load(std::sync::atomic::Ordering::SeqCst));
        local.register(WorkspaceID([3; 16]), a).unwrap();
        assert!(!first.active.load(std::sync::atomic::Ordering::SeqCst));
        assert!(
            local
                .observation_owner(a)
                .unwrap()
                .active
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        local.release(b);
        assert!(!sibling.active.load(std::sync::atomic::Ordering::SeqCst));
    }
    #[test]
    fn closed_local_connection_cannot_mint_new_observation_authority() {
        let dir = tempfile::tempdir().unwrap();
        let local = LocalConnection::open(dir.path().join("state")).unwrap();
        let lease = WorkspaceLeaseID([1; 16]);
        local.register(WorkspaceID([1; 16]), lease).unwrap();
        let owner = local.observation_owner(lease).unwrap();
        local.close_connection(ConnectionCloseReason::ApplicationShutdown);
        assert!(!owner.is_active());
        assert!(
            local.register(WorkspaceID([1; 16]), lease).is_err(),
            "closed registration recreated proof authority"
        );
        assert!(local.observation_owner(lease).is_err());
    }
    #[test]
    fn dropped_local_registration_authority_cannot_outlive_its_runtime_owner() {
        let dir = tempfile::tempdir().unwrap();
        let local = LocalConnection::open(dir.path().join("state")).unwrap();
        let lease = WorkspaceLeaseID([1; 16]);
        local.register(WorkspaceID([1; 16]), lease).unwrap();
        let owner = local.observation_owner(lease).unwrap();
        drop(local);
        assert!(
            !owner.is_active(),
            "local runtime destruction left proof authority active"
        );
    }
    fn repository_fixture() -> (
        tempfile::TempDir,
        LocalConnection,
        ObservationOwner,
        WorktreeIdentity,
        std::path::PathBuf,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        git(&root, &["init", "-b", "main"]);
        git(&root, &["config", "user.name", "Fixture"]);
        git(&root, &["config", "user.email", "fixture@example.invalid"]);
        git(&root, &["config", "commit.gpgsign", "false"]);
        std::fs::write(root.join("tracked"), "original").unwrap();
        git(&root, &["add", "tracked"]);
        git(&root, &["commit", "-m", "initial"]);
        let local = LocalConnection::open(dir.path().join("state")).unwrap();
        let lease = WorkspaceLeaseID([1; 16]);
        local.register(WorkspaceID([1; 16]), lease).unwrap();
        let owner = local.observation_owner(lease).unwrap();
        let worktree = local
            .git
            .discover_sync(
                FileRef {
                    target: local.identity.clone(),
                    path: target_path(&root),
                    resolved_identity: None,
                },
                &AtomicBool::new(false),
            )
            .unwrap()
            .unwrap();
        let root = path(&worktree.canonical_path).unwrap();
        (dir, local, owner, worktree, root)
    }
    fn second_owner(local: &LocalConnection, n: u8) -> ObservationOwner {
        let id = WorkspaceLeaseID([n; 16]);
        local.register(WorkspaceID([n; 16]), id).unwrap();
        local.observation_owner(id).unwrap()
    }
    fn records(
        local: &LocalConnection,
        owner: &ObservationOwner,
        id: [u8; 16],
    ) -> Vec<ObservationRecord> {
        let mut reader = local.git.observation_reader(owner, id).unwrap();
        let mut records = vec![];
        while let Some(record) = reader.next_record().unwrap() {
            records.push(record)
        }
        records
    }
    #[test]
    fn decoded_alias_capture_preserves_the_actual_original_observation() {
        let (_dir, local, owner, worktree, root) = repository_fixture();
        let alias = FileRef {
            target: local.identity.clone(),
            path: target_path(&root.join("tracked")),
            resolved_identity: Some(vec![255; 65537]),
        };
        let cancel = AtomicBool::new(false);
        let old = local
            .git
            .observe_owned_sync(&owner, worktree.clone(), [Ok(alias.clone())], &cancel)
            .unwrap();
        let old_records = records(&local, &owner, old.id);
        let mut wire = Vec::new();
        super::super::proof_codec::write_aliases(&mut wire, &local.identity, [&alias]).unwrap();
        let aliases = super::super::proof_codec::AliasReader::new(
            wire.as_slice(),
            wire.len() as u64,
            &local.identity,
            super::super::proof_codec::TargetPathLimit::declared(libc::PATH_MAX as u32).unwrap(),
        )
        .unwrap();
        let new = local
            .git
            .observe_captured_sync(&owner, worktree, aliases, &cancel)
            .expect("decoded target aliases must capture");
        assert_eq!(old.snapshot, new.snapshot);
        assert_eq!(old.bytes, new.bytes);
        let retained = records(&local, &owner, new.id);
        assert_eq!(retained, old_records);
        assert!(retained.last().unwrap().matches_alias(&alias).unwrap());
        std::fs::write(root.join("tracked"), "external").unwrap();
        assert_eq!(
            records(&local, &owner, new.id),
            retained,
            "capture was replaced by later filesystem state"
        );
    }
    #[test]
    fn dedup_cannot_merge_different_original_registered_file_refs() {
        let (_dir, local, a, worktree, root) = repository_fixture();
        let b = second_owner(&local, 2);
        let alias = FileRef {
            target: local.identity.clone(),
            path: target_path(&root.join("tracked")),
            resolved_identity: Some(vec![1]),
        };
        let first = local
            .git
            .observe_owned_sync(
                &a,
                worktree.clone(),
                [Ok(alias.clone())],
                &AtomicBool::new(false),
            )
            .unwrap();
        let second = local
            .git
            .observe_owned_sync(
                &b,
                worktree,
                [Ok(FileRef {
                    resolved_identity: Some(vec![2]),
                    ..alias
                })],
                &AtomicBool::new(false),
            )
            .unwrap();
        assert_eq!(first.snapshot.state, second.snapshot.state);
        assert_eq!(
            local.git.observation_storage_stats().unwrap().bytes,
            first.bytes + second.bytes,
            "different original FileRefs shared retained data"
        );
    }
    #[test]
    fn original_aliases_include_ignored_missing_outside_nested_and_submodule_membership() {
        let (dir, local, owner, worktree, root) = repository_fixture();
        std::fs::write(root.join(".gitignore"), "ignored\nmissing\n").unwrap();
        std::fs::write(root.join("ignored"), "ignored body").unwrap();
        let nested = root.join("nested");
        std::fs::create_dir(&nested).unwrap();
        git(&nested, &["init", "-b", "inner"]);
        std::fs::write(nested.join("file"), "nested").unwrap();
        let source = dir.path().join("source");
        std::fs::create_dir(&source).unwrap();
        git(&source, &["init", "-b", "main"]);
        git(&source, &["config", "user.name", "Fixture"]);
        git(
            &source,
            &["config", "user.email", "fixture@example.invalid"],
        );
        git(&source, &["config", "commit.gpgsign", "false"]);
        std::fs::write(source.join("file"), "submodule").unwrap();
        git(&source, &["add", "file"]);
        git(&source, &["commit", "-m", "initial"]);
        git(
            &root,
            &[
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                source.to_str().unwrap(),
                "module",
            ],
        );
        let middle = dir.path().join("middle");
        let outside = dir.path().join("outside");
        std::os::unix::fs::symlink(root.join("tracked"), &middle).unwrap();
        std::os::unix::fs::symlink(&middle, &outside).unwrap();
        let aliases = [
            root.join("ignored"),
            root.join("missing/parent/file"),
            outside.clone(),
            nested.join("file"),
            root.join("module/file"),
        ];
        let observed = local
            .git
            .observe_owned_sync(
                &owner,
                worktree,
                aliases.iter().map(|p| {
                    Ok(FileRef {
                        target: local.identity.clone(),
                        path: target_path(p),
                        resolved_identity: None,
                    })
                }),
                &AtomicBool::new(false),
            )
            .unwrap();
        let original = records(&local, &owner, observed.id);
        let supplemental: Vec<_> = original.iter().filter(|r| r.membership.is_some()).collect();
        assert_eq!(
            supplemental
                .iter()
                .map(|r| r.membership.as_ref().unwrap().affected)
                .collect::<Vec<_>>(),
            vec![true, true, true, false, false]
        );
        assert!(supplemental[0].regular.is_some());
        assert!(supplemental[1].regular.is_none());
        assert_eq!(
            supplemental[2].resolved,
            Some(target_path(&root.join("tracked")))
        );
        std::fs::remove_file(&middle).unwrap();
        std::os::unix::fs::symlink(root.join("tracked"), &middle).unwrap();
        assert_eq!(
            records(&local, &owner, observed.id),
            original,
            "read retroactively replaced original alias structure"
        );
        let current = local
            .git
            .alias_record(
                &observed.snapshot.worktree,
                FileRef {
                    target: local.identity.clone(),
                    path: target_path(&outside),
                    resolved_identity: None,
                },
                &AtomicBool::new(false),
                Instant::now(),
            )
            .unwrap();
        assert_ne!(current.structural_token, supplemental[2].structural_token);
    }
    #[test]
    fn revoked_or_cancelled_capture_never_publishes_and_failed_refresh_has_no_baseline() {
        let (_dir, local, owner, worktree, root) = repository_fixture();
        let cancel = AtomicBool::new(false);
        let initial = local
            .git
            .observe_owned_sync(&owner, worktree.clone(), std::iter::empty(), &cancel)
            .unwrap();
        let file = FileRef {
            target: local.identity.clone(),
            path: target_path(&root.join("tracked")),
            resolved_identity: None,
        };
        let aliases = std::iter::once_with(|| {
            local.release(owner.lease.lease);
            Ok(file)
        });
        assert!(
            local
                .git
                .observe_owned_sync(&owner, worktree.clone(), aliases, &cancel)
                .is_err()
        );
        assert!(local.git.observation_reader(&owner, initial.id).is_err());
        let resumed = second_owner(&local, 1);
        let mut count = 0;
        let aliases = std::iter::from_fn(|| {
            count += 1;
            if count == 1 {
                cancel.store(true, Ordering::SeqCst);
            }
            None
        });
        assert_eq!(
            local
                .git
                .observe_owned_sync(&resumed, worktree, aliases, &cancel)
                .err()
                .unwrap()
                .code,
            ErrorCode::Cancelled
        );
        local.git.reap_observations();
        assert_eq!(local.git.observation_storage_stats().unwrap().bytes, 0);
    }

    #[test]
    fn identical_data_shares_bytes_but_alias_sets_and_owners_remain_distinct() {
        let (_dir, local, a, worktree, root) = repository_fixture();
        let b = second_owner(&local, 2);
        let c = second_owner(&local, 3);
        std::fs::write(root.join(".gitignore"), "ignored*\n").unwrap();
        std::fs::write(root.join("ignored-one"), "one").unwrap();
        std::fs::write(root.join("ignored-two"), "two").unwrap();
        let alias = |name: &str| {
            Ok(FileRef {
                target: local.identity.clone(),
                path: target_path(&root.join(name)),
                resolved_identity: None,
            })
        };
        let first = local
            .git
            .observe_owned_sync(
                &a,
                worktree.clone(),
                [alias("ignored-one")],
                &AtomicBool::new(false),
            )
            .unwrap();
        let second = local
            .git
            .observe_owned_sync(
                &b,
                worktree.clone(),
                [alias("ignored-one")],
                &AtomicBool::new(false),
            )
            .unwrap();
        assert_ne!(first.id, second.id);
        assert_eq!(
            local.git.observation_storage_stats().unwrap().bytes,
            first.bytes
        );
        assert!(local.git.observation_reader(&b, first.id).is_err());
        let third = local
            .git
            .observe_owned_sync(
                &c,
                worktree,
                [alias("ignored-two")],
                &AtomicBool::new(false),
            )
            .unwrap();
        assert_eq!(first.snapshot.state, third.snapshot.state);
        assert_eq!(
            local.git.observation_storage_stats().unwrap().bytes,
            first.bytes + third.bytes
        );
        local.release(a.lease.lease);
        local.git.reap_observations();
        assert!(local.git.observation_reader(&a, first.id).is_err());
        assert!(local.git.observation_reader(&b, second.id).is_ok());
    }
    #[test]
    fn equal_git_state_does_not_dedup_changed_ignored_link_structure() {
        let (_dir, local, a, worktree, root) = repository_fixture();
        let b = second_owner(&local, 2);
        std::fs::write(root.join(".gitignore"), "ignored\n").unwrap();
        let link = root.join("ignored");
        std::os::unix::fs::symlink("tracked", &link).unwrap();
        let alias = FileRef {
            target: local.identity.clone(),
            path: target_path(&link),
            resolved_identity: None,
        };
        let first = local
            .git
            .observe_owned_sync(
                &a,
                worktree.clone(),
                [Ok(alias.clone())],
                &AtomicBool::new(false),
            )
            .unwrap();
        let original = records(&local, &a, first.id);
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink("./tracked", &link).unwrap();
        let second = local
            .git
            .observe_owned_sync(&b, worktree, [Ok(alias)], &AtomicBool::new(false))
            .unwrap();
        assert_eq!(first.snapshot.state, second.snapshot.state);
        assert_ne!(original, records(&local, &b, second.id));
        assert_eq!(original, records(&local, &a, first.id));
        assert_eq!(
            local.git.observation_storage_stats().unwrap().bytes,
            first.bytes + second.bytes
        );
    }
    #[test]
    fn linked_worktree_pins_do_not_lock_sibling_capture_or_save() {
        let (dir, local, a, worktree, root) = repository_fixture();
        let b = second_owner(&local, 2);
        let same = second_owner(&local, 3);
        let linked = dir.path().join("linked");
        git(
            &root,
            &["worktree", "add", "-b", "linked", linked.to_str().unwrap()],
        );
        let linked = local
            .git
            .discover_sync(
                FileRef {
                    target: local.identity.clone(),
                    path: target_path(&linked),
                    resolved_identity: None,
                },
                &AtomicBool::new(false),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            worktree.common_git_directory_identity,
            linked.common_git_directory_identity
        );
        let first = local
            .git
            .observe_owned_sync(
                &a,
                worktree.clone(),
                std::iter::empty(),
                &AtomicBool::new(false),
            )
            .unwrap();
        let pin = local.git.pin_observation(&a, first.id).unwrap();
        let duplicate = local
            .git
            .observe_owned_sync(&same, worktree, std::iter::empty(), &AtomicBool::new(false))
            .unwrap();
        assert!(local.git.pin_observation(&same, duplicate.id).is_err());
        let second = local
            .git
            .observe_owned_sync(
                &b,
                linked.clone(),
                std::iter::empty(),
                &AtomicBool::new(false),
            )
            .unwrap();
        let other = local.git.pin_observation(&b, second.id).unwrap();
        let file = FileRef {
            target: local.identity.clone(),
            path: target_path(&path(&linked.canonical_path).unwrap().join("tracked")),
            resolved_identity: None,
        };
        let snapshot = local.files.read_sync(file.clone()).unwrap();
        let receipt = local.files.save_owned_sync(
            SaveRequest {
                operation: OperationID([9; 16]),
                file,
                expected_version: Some(snapshot.version),
                submitted_revision: BufferRevision(1),
                source: ByteSource::Memory(Arc::from(b"saved sibling".as_slice())),
            },
            b.lease.clone(),
            &b.active,
        );
        assert!(matches!(receipt.state, OperationState::Confirmed(_)));
        assert!(pin.validate().is_ok());
        assert!(other.validate().is_ok());
    }
    #[test]
    fn two_real_capture_workers_allow_sibling_progress_and_refuse_a_third() {
        let (dir, local, a, first, root) = repository_fixture();
        let b = second_owner(&local, 2);
        let c = second_owner(&local, 3);
        let second = dir.path().join("second");
        std::fs::create_dir(&second).unwrap();
        git(&second, &["init", "-b", "main"]);
        std::fs::write(second.join("file"), "second").unwrap();
        let second = local
            .git
            .discover_sync(
                FileRef {
                    target: local.identity.clone(),
                    path: target_path(&second),
                    resolved_identity: None,
                },
                &AtomicBool::new(false),
            )
            .unwrap()
            .unwrap();
        let barrier = std::sync::Barrier::new(3);
        let (sent, received) = std::sync::mpsc::channel();
        let run = |owner: &ObservationOwner, worktree: WorktreeIdentity| {
            let aliases = std::iter::once_with(|| {
                sent.send(()).unwrap();
                barrier.wait();
                Ok(FileRef {
                    target: local.identity.clone(),
                    path: target_path(&root.join("tracked")),
                    resolved_identity: None,
                })
            });
            local
                .git
                .observe_owned_sync(owner, worktree, aliases, &AtomicBool::new(false))
        };
        std::thread::scope(|scope| {
            let left = scope.spawn(|| run(&a, first.clone()));
            let right = scope.spawn(|| run(&b, second));
            received
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            received
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            assert_eq!(local.git.observation_storage_stats().unwrap().captures, 2);
            let refused = local.git.observe_owned_sync(
                &c,
                first.clone(),
                std::iter::empty(),
                &AtomicBool::new(false),
            );
            barrier.wait();
            assert_eq!(refused.err().unwrap().code, ErrorCode::Busy);
            assert!(left.join().unwrap().is_ok());
            assert!(right.join().unwrap().is_ok());
        });
        assert_eq!(local.git.observation_storage_stats().unwrap().captures, 0);
    }
    #[test]
    #[ignore = "representative capture measurement"]
    fn retained_manifest_measurements() {
        let (_dir, local, owner, worktree, root) = repository_fixture();
        let mode =
            std::env::var("BUNTRAIL_OBSERVATION_MEASUREMENT").unwrap_or_else(|_| "10000".into());
        let mut aliases = vec![];
        match mode.as_str() {
            "large" => {
                let file = std::fs::File::create(root.join("large")).unwrap();
                file.set_len(67_108_865).unwrap();
            }
            "aliases" => {
                let parent = root.parent().unwrap();
                let mut destination = root.join("tracked");
                for n in 0..20 {
                    let link = parent.join(format!("indirect-{n}"));
                    std::os::unix::fs::symlink(&destination, &link).unwrap();
                    destination = link;
                }
                for n in 0..1000 {
                    let link = parent.join(format!("outside-alias-{n:04}"));
                    std::os::unix::fs::symlink(&destination, &link).unwrap();
                    aliases.push(FileRef {
                        target: local.identity.clone(),
                        path: target_path(&link),
                        resolved_identity: None,
                    });
                }
            }
            _ => {
                for n in 0..10000 {
                    std::fs::write(root.join(format!("path-{n:026}")), b"content\n").unwrap();
                }
            }
        }
        fn rss() -> i64 {
            let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
            assert_eq!(
                unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
                0
            );
            unsafe { usage.assume_init() }.ru_maxrss
        }
        let before = rss();
        let started = Instant::now();
        let retained = local
            .git
            .observe_owned_sync(
                &owner,
                worktree,
                aliases.into_iter().map(Ok),
                &AtomicBool::new(false),
            )
            .unwrap();
        let elapsed = started.elapsed();
        let after = rss();
        let mut reader = local.git.observation_reader(&owner, retained.id).unwrap();
        let mut count = 0;
        while reader.next_record().unwrap().is_some() {
            count += 1;
        }
        println!(
            "measurement mode={mode} records={count} actual_spool_bytes={} capture_ms={} max_rss_before_bytes={before} max_rss_after_bytes={after} rss_growth_bytes={} hash_scratch_bytes_per_capture=65536",
            retained.bytes,
            elapsed.as_millis(),
            after - before
        );
        assert_eq!(
            local.git.observation_storage_stats().unwrap().bytes,
            retained.bytes
        );
        if mode == "large" {
            assert!(retained.bytes < 4096);
            assert!(after - before < 32 * 1024 * 1024);
        }
    }

    #[test]
    fn proof_retirement_preserves_the_actual_durable_git_record_and_receipt() {
        let (_dir, local, owner, worktree, root) = repository_fixture();
        std::fs::write(root.join("tracked"), b"changed").unwrap();
        let cancel = AtomicBool::new(false);
        let request = GitMutationRequest {
            operation: OperationID([37; 16]),
            worktree: worktree.clone(),
            expected: local
                .git
                .status_sync(worktree.clone(), &cancel)
                .unwrap()
                .state,
            command: GitMutation::Stage(vec![target_path(&root.join("tracked"))]),
        };
        let receipt = local.git.mutate_sync(request.clone(), &cancel);
        assert!(matches!(receipt.state, OperationState::Confirmed(_)));
        let record_path = local
            .files
            .ledger
            .lock()
            .unwrap()
            .directory
            .join(format!("{}.json", "25".repeat(16)));
        let original_record = std::fs::read(&record_path).unwrap();
        let captured = local
            .git
            .observe_owned_sync(&owner, worktree, std::iter::empty(), &cancel)
            .unwrap();
        let pin = local.git.pin_observation(&owner, captured.id).unwrap();
        local.git.release_observation(&owner, captured.id);
        local.release(owner.registration().lease);
        local.git.reap_observations();
        assert!(pin.validate().is_err());
        drop(pin);
        assert_eq!(local.git.observation_storage_stats().unwrap().bytes, 0);
        assert_eq!(std::fs::read(record_path).unwrap(), original_record);
        assert_eq!(
            local.git.existing_receipt_sync(&request).unwrap(),
            Some(receipt)
        );
    }

    #[test]
    #[ignore = "one hundred actual linked worktrees capacity fixture"]
    fn hundred_actual_workspaces_retain_independent_pins_and_cleanup() {
        let (dir, local, owner, first, root) = repository_fixture();
        let cancel = AtomicBool::new(false);
        let started = Instant::now();
        let mut pins = Vec::new();
        let mut total = 0;
        for n in 1..=100 {
            let (actor, worktree) = if n == 1 {
                (owner.clone(), first.clone())
            } else {
                let directory = dir.path().join(format!("workspace-{n:03}"));
                git(
                    &root,
                    &["worktree", "add", "--detach", directory.to_str().unwrap()],
                );
                let worktree = local
                    .git
                    .discover_sync(
                        FileRef {
                            target: local.identity.clone(),
                            path: target_path(&directory),
                            resolved_identity: None,
                        },
                        &cancel,
                    )
                    .unwrap()
                    .unwrap();
                (second_owner(&local, n), worktree)
            };
            let captured = local
                .git
                .observe_owned_sync(&actor, worktree, std::iter::empty(), &cancel)
                .unwrap();
            total += captured.bytes;
            pins.push(local.git.pin_observation(&actor, captured.id).unwrap());
        }
        let stats = local.git.observation_storage_stats().unwrap();
        assert_eq!(stats.owners, 100);
        assert_eq!(stats.pins, 100);
        assert_eq!(stats.captures, 0);
        assert_eq!(stats.bytes, total);
        for pin in &pins {
            pin.validate().unwrap();
        }
        local.release(owner.registration().lease);
        local.git.reap_observations();
        assert!(pins[0].validate().is_err());
        assert!(pins[99].validate().is_ok());
        println!(
            "actual_workspaces=100 actual_live_pins=100 actual_spool_bytes={total} fixture_and_capture_ms={}",
            started.elapsed().as_millis()
        );
        local.close_connection(ConnectionCloseReason::ApplicationShutdown);
        local.git.reap_observations();
        assert_eq!(local.git.observation_storage_stats().unwrap().bytes, total);
        drop(pins);
        assert_eq!(local.git.observation_storage_stats().unwrap().bytes, 0);
        assert_eq!(local.git.observation_storage_stats().unwrap().owners, 0);
    }
}
