//! Prepared worktree changes retain the original request and authenticated save history.
use super::{
    LocalGitService,
    observation::{ObservationInput, ObservationOwner, ObservationRecord},
    observation_store::{Cursor, Plan, Spool},
};
use crate::{
    files::{absent_structure, io_error, save_request_digest, target_path},
    operations::ledger::SaveObservation,
};
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

fn refused(message: &str) -> CoreError {
    CoreError::new(ErrorCode::StaleRevision, message)
}
fn check_proof(cancel: &AtomicBool, started: Instant) -> Result<(), CoreError> {
    if cancel.load(Ordering::SeqCst) || started.elapsed() >= super::process::DEADLINE {
        Err(CoreError::new(
            ErrorCode::Cancelled,
            "proof verification cancelled or timed out",
        ))
    } else {
        Ok(())
    }
}
fn request_digest(original: &GitMutationRequest) -> Result<[u8; 32], CoreError> {
    super::observation::serialized_digest(original)
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Evidence {
    operation: OperationID,
    file: FileRef,
    before: Option<SaveObservation>,
    after: SaveObservation,
    captured_absence: bool,
}
fn read_evidence(reader: &mut impl Read) -> Result<Option<Evidence>, CoreError> {
    let mut size = [0; 4];
    if reader.read(&mut size[..1]).map_err(io_error)? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut size[1..]).map_err(io_error)?;
    let size = u32::from_be_bytes(size) as usize;
    if size > 128 * 1024 {
        return Err(refused(
            "save evidence exceeds existing ledger record bound",
        ));
    }
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes).map_err(io_error)?;
    serde_json::from_slice(&bytes).map(Some).map_err(io_error)
}
fn read_approval(
    reader: &mut impl Read,
    owner: &ObservationOwner,
) -> Result<Option<GitSaveApproval>, CoreError> {
    let mut bytes = [0; 96];
    if reader.read(&mut bytes[..1]).map_err(io_error)? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut bytes[1..]).map_err(io_error)?;
    Ok(Some(GitSaveApproval {
        operation: OperationID(bytes[..16].try_into().unwrap()),
        request_digest: bytes[16..48].try_into().unwrap(),
        actor: WorkspaceLease {
            client: ClientID(bytes[48..64].try_into().unwrap()),
            workspace: WorkspaceID(bytes[64..80].try_into().unwrap()),
            lease: WorkspaceLeaseID(bytes[80..96].try_into().unwrap()),
            runtime: owner.registration().runtime.clone(),
        },
    }))
}
fn cursor(spool: &Arc<Spool>) -> Cursor {
    Cursor {
        spool: spool.clone(),
        offset: 0,
    }
}
fn approval_stream(plan: &Plan, additional: Option<&Arc<Spool>>) -> impl Read {
    let tail: Box<dyn Read> = match additional {
        Some(spool) => Box::new(cursor(spool)),
        None => Box::new(std::io::empty()),
    };
    plan.approvals().chain(tail)
}
fn endpoint(record: &ObservationRecord, version: &FileVersion) -> bool {
    record.regular.as_ref().is_some_and(|regular| {
        regular.canonical.as_slice() == version.opaque_token.as_slice()
            && regular.content_digest == version.content_digest
    })
}
fn valid_endpoint(endpoint: &SaveObservation, target: &TargetIdentity) -> bool {
    endpoint.requested.target == *target
        && endpoint.canonical.target == *target
        && endpoint.requested.opaque_token.len() == 32
        && endpoint.canonical.opaque_token.len() == 32
        && endpoint.requested.file_identity.len() == 16
        && endpoint.requested.file_identity == endpoint.canonical.file_identity
        && endpoint.requested.content_digest == endpoint.canonical.content_digest
}

#[derive(Debug)]
pub enum WorktreePreparation {
    Existing(Box<OperationReceipt>),
    Prepared([u8; 16]),
}

impl LocalGitService {
    pub fn save_approval_input(
        &self,
        owner: &ObservationOwner,
        approvals: impl IntoIterator<Item = GitSaveApproval>,
    ) -> Result<ObservationInput, CoreError> {
        let mut writer = self.observation_input(owner)?;
        for approval in approvals {
            if approval.actor.client != owner.registration().client
                || approval.actor.runtime != owner.registration().runtime
            {
                return Err(CoreError::new(
                    ErrorCode::TargetChanged,
                    "save approval client or runtime changed",
                ));
            }
            for bytes in [
                approval.operation.0.as_slice(),
                approval.request_digest.as_slice(),
                approval.actor.client.0.as_slice(),
                approval.actor.workspace.0.as_slice(),
                approval.actor.lease.0.as_slice(),
            ] {
                writer.append(bytes)?;
            }
        }
        writer.seal()
    }
    pub fn observation_alias_digest(
        &self,
        owner: &ObservationOwner,
        observation: [u8; 16],
    ) -> Result<[u8; 32], CoreError> {
        let mut reader = self.observation_reader(owner, observation)?;
        let mut hash = Sha256::new();
        hash.update(b"buntrail.original-aliases.v1\0");
        while let Some(record) = reader.next_record()? {
            if let Some(identity) = record.file_reference {
                hash.update(identity);
            }
        }
        Ok(hash.finalize().into())
    }
    pub fn prepare_worktree_sync(
        &self,
        owner: &ObservationOwner,
        original: &GitMutationRequest,
        observation: [u8; 16],
        alias_digest: [u8; 32],
        approvals: ObservationInput,
        cancel: &AtomicBool,
    ) -> Result<WorktreePreparation, CoreError> {
        if let Some(receipt) = self.existing_receipt_sync(original)? {
            return Ok(WorktreePreparation::Existing(Box::new(receipt)));
        }
        #[cfg(test)]
        if let Some(checkpoint) = &self.after_proof_lookup {
            checkpoint();
        }
        let mutex = super::mutations::repository_mutex(&original.worktree);
        let _repository = mutex.lock().map_err(io_error)?;
        if let Some(receipt) = self.existing_receipt_sync(original)? {
            return Ok(WorktreePreparation::Existing(Box::new(receipt)));
        }
        if !original.command.changes_worktree() {
            return Err(refused("only worktree changes use prepared execution"));
        }
        let store = self.observation_store()?;
        let pin = self.pin_observation(owner, observation)?;
        let (worktree, state) = pin.original_state()?;
        if worktree != &original.worktree
            || state != &original.expected
            || self.observation_alias_digest(owner, observation)? != alias_digest
        {
            return Err(refused(
                "request differs from its original owned observation or aliases",
            ));
        }
        let _work = store.verification()?;
        let plan = store.adopt_plan(owner, pin, original, alias_digest, approvals)?;
        let result = (|| {
            let evidence = self.freeze_evidence(owner, &plan, None, cancel)?;
            self.verify_worktree(&plan, &evidence, cancel)?;
            store.plan(owner, plan.id)?;
            Ok(WorktreePreparation::Prepared(plan.id))
        })();
        if result.is_err() {
            store.cancel_plan(owner, plan.id);
        }
        result
    }
    pub fn execute_worktree_sync(
        &self,
        owner: &ObservationOwner,
        original: GitMutationRequest,
        plan_id: [u8; 16],
        alias_digest: [u8; 32],
        approvals: ObservationInput,
        cancel: &AtomicBool,
    ) -> Result<OperationReceipt, CoreError> {
        if let Some(receipt) = self.existing_receipt_sync(&original)? {
            return Ok(receipt);
        }
        #[cfg(test)]
        if let Some(checkpoint) = &self.after_proof_lookup {
            checkpoint();
        }
        let digest = request_digest(&original)?;
        let operation = original.operation;
        let store = self.observation_store()?;
        let mut input = Some(approvals);
        let mut execution = None;
        let mut verify = |accepted: bool| {
            if !accepted {
                let plan = store.plan(owner, plan_id)?;
                if plan.request_digest != digest
                    || plan.operation != operation
                    || plan.alias_digest != alias_digest
                {
                    return Err(refused(
                        "prepared original request or alias identity changed",
                    ));
                }
                let work = store.verification()?;
                let additional = store.adopt_execution_input(
                    owner,
                    input
                        .take()
                        .ok_or_else(|| refused("execution input already consumed"))?,
                )?;
                let evidence = self.freeze_evidence(owner, &plan, Some(&additional), cancel)?;
                let expected = self.verify_worktree(&plan, &evidence, cancel)?;
                store.plan(owner, plan_id)?;
                execution = Some((plan, evidence, work));
                Ok(expected)
            } else {
                let (plan, evidence, _) = execution
                    .as_ref()
                    .ok_or_else(|| refused("missing accepted proof snapshot"))?;
                self.verify_worktree(plan, evidence, cancel)
            }
        };
        let expected = original.expected.clone();
        let authorize = || store.plan(owner, plan_id).map(|_| ());
        let receipt = self.mutate_guarded(
            original,
            expected,
            cancel,
            Some(super::mutations::WorktreeProofGuard {
                owner,
                verify: &mut verify,
                authorize: &authorize,
            }),
        );
        store.cancel_plan(owner, plan_id);
        receipt
    }
    pub fn cancel_worktree_plan(&self, owner: &ObservationOwner, plan: [u8; 16]) {
        if let Ok(store) = self.observation_store() {
            store.cancel_plan(owner, plan);
        }
    }

    fn freeze_evidence(
        &self,
        owner: &ObservationOwner,
        plan: &Plan,
        additional: Option<&Arc<Spool>>,
        cancel: &AtomicBool,
    ) -> Result<Arc<Spool>, CoreError> {
        let started = Instant::now();
        let mut writer = self.observation_input(owner)?;
        let mut approvals = approval_stream(plan, additional);
        let mut seen = 0u64;
        while let Some(approval) = read_approval(&mut approvals, owner)? {
            check_proof(cancel, started)?;
            let mut prior = approval_stream(plan, additional);
            for _ in 0..seen {
                check_proof(cancel, started)?;
                if read_approval(&mut prior, owner)?
                    .is_some_and(|old| old.operation == approval.operation)
                {
                    return Err(refused("duplicate approved Save operation"));
                }
            }
            seen += 1;
            let record = {
                let ledger = self.files.ledger.lock().map_err(io_error)?;
                let _lock = ledger.lock()?;
                let record = ledger
                    .read(approval.operation)?
                    .ok_or_else(|| refused("approved Save history is missing"))?;
                if ledger.expired(&record) {
                    return Err(refused("approved Save history expired"));
                }
                record
            };
            let proof = record
                .save_proof
                .as_ref()
                .ok_or_else(|| refused("Save has no authenticated history"))?;
            let after = proof
                .after
                .as_ref()
                .ok_or_else(|| refused("Save has no durable historical after"))?;
            let ExpectedState::File { file, version } = &record.envelope.expected else {
                return Err(refused("Save expected state is malformed"));
            };
            let OperationState::Confirmed(MutationResult::Saved(saved)) = &record.receipt.state
            else {
                return Err(refused("Save is not durably confirmed"));
            };
            let destination = record
                .destination
                .as_ref()
                .ok_or_else(|| refused("Save has no original destination"))?;
            let resolution_token: [u8; 32] =
                Sha256::digest(serde_json::to_vec(destination).map_err(io_error)?).into();
            if record.envelope.kind != MutationKind::Save
                || record.envelope.target != owner.target
                || file.target != owner.target
                || record.envelope.request_digest != approval.request_digest
                || proof.actor != approval.actor
                || proof.actor.client != owner.registration().client
                || proof.actor.runtime != owner.registration().runtime
                || saved.saved_revision != record.revision
                || saved.version != after.requested
                || !valid_endpoint(after, &owner.target)
                || after.requested.content_digest != record.requested_digest
                || after.resolved != destination.resolved
                || after.resolution_token != resolution_token
                || save_request_digest(file, version, record.revision, record.requested_digest)?
                    != approval.request_digest
            {
                return Err(refused(
                    "approved Save identity or historical result differs",
                ));
            }
            match (&proof.before, version) {
                (Some(before), Some(expected))
                    if before.requested == *expected
                        && valid_endpoint(before, &owner.target)
                        && before.resolved == after.resolved
                        && before.resolution_token == after.resolution_token => {}
                (None, None) => {}
                _ => return Err(refused("Save before/after chain is malformed")),
            }
            let mut original = plan.original();
            let mut covered = false;
            let mut captured_absence = false;
            while let Some(node) = ObservationRecord::read(&mut original)? {
                check_proof(cancel, started)?;
                if node.path != file.path
                    || node
                        .membership
                        .as_ref()
                        .is_some_and(|membership| !membership.affected)
                {
                    continue;
                }
                if node.membership.is_some() {
                    // Remote Save omits hints; original alias identity remains independently pinned.
                    if node.file_reference.is_none()
                        || (file.resolved_identity.is_some() && !node.matches_alias(file)?)
                    {
                        continue;
                    }
                } else if file.resolved_identity.is_some() {
                    continue;
                }
                if node.resolved.as_ref() != Some(&after.resolved) {
                    continue;
                }
                if node.regular.is_none()
                    && node.structural_token != absent_structure(&Some(destination.clone()))?
                {
                    continue;
                }
                if node
                    .regular
                    .as_ref()
                    .is_some_and(|regular| regular.resolution != resolution_token)
                {
                    continue;
                }
                covered = true;
                captured_absence = node.regular.is_none();
                break;
            }
            if !covered {
                return Err(refused(
                    "Save requested alias was not covered by the original observation",
                ));
            }
            let evidence = Evidence {
                operation: approval.operation,
                file: file.clone(),
                before: proof.before.clone(),
                after: after.clone(),
                captured_absence,
            };
            let bytes = serde_json::to_vec(&evidence).map_err(io_error)?;
            if bytes.len() > 128 * 1024 {
                return Err(refused("Save evidence exceeds its bounded durable record"));
            }
            writer.append(&(bytes.len() as u32).to_be_bytes())?;
            writer.append(&bytes)?;
        }
        self.observation_store()?
            .adopt_execution_input(owner, writer.seal()?)
    }

    fn compare_node(
        &self,
        original: &ObservationRecord,
        current: &ObservationRecord,
        current_absence: [u8; 32],
        evidence: &Arc<Spool>,
        cancel: &AtomicBool,
        started: Instant,
    ) -> Result<(), CoreError> {
        let unaffected = original
            .membership
            .as_ref()
            .is_some_and(|membership| !membership.affected);
        if original.path != current.path
            || original.resolved != current.resolved
            || original.membership != current.membership
            || original.file_reference != current.file_reference
        {
            return Err(refused("original path, alias or membership changed"));
        }
        if unaffected {
            return if original.structural_token == current.structural_token {
                Ok(())
            } else {
                Err(refused("unaffected alias structure changed"))
            };
        }
        // shortcut: scan evidence per node; add a byte-accounted disk index if measured deadline costs require it.
        let mut reader = cursor(evidence);
        let mut last: Option<Evidence> = None;
        let mut matches = 0;
        while let Some(save) = read_evidence(&mut reader)? {
            check_proof(cancel, started)?;
            if original.resolved.as_ref() != Some(&save.after.resolved) {
                continue;
            }
            if let Some(previous) = &last {
                if save
                    .before
                    .as_ref()
                    .is_none_or(|before| before.canonical != previous.after.canonical)
                {
                    return Err(refused("approved canonical Save chain is not contiguous"));
                }
            } else if save
                .before
                .as_ref()
                .is_some_and(|before| endpoint(original, &before.canonical))
                || (save.before.is_none()
                    && original.regular.is_none()
                    && original.structural_token == current_absence)
            {
                matches += 1;
            }
            if endpoint(original, &save.after.canonical) {
                matches += 1;
            }
            last = Some(save);
        }
        let Some(last) = last else {
            return if original == current {
                Ok(())
            } else {
                Err(refused(
                    "unapproved node changed since original observation",
                ))
            };
        };
        if matches != 1 || !endpoint(current, &last.after.canonical) {
            return Err(refused(
                "original or final node is not an exact Save-chain boundary",
            ));
        }
        if let Some(regular) = &original.regular {
            if original.structural_token != current.structural_token
                || regular.resolution != current.regular.as_ref().unwrap().resolution
            {
                return Err(refused("saved node structure or resolution changed"));
            }
        } else if original.structural_token != current_absence {
            return Err(refused("created node lost its original absence structure"));
        }
        if last.file.path == current.path
            && current.regular.as_ref().unwrap().requested.as_slice()
                != last.after.requested.opaque_token.as_slice()
        {
            return Err(refused(
                "saved requested endpoint differs from historical after",
            ));
        }
        Ok(())
    }

    fn verify_worktree(
        &self,
        plan: &Plan,
        evidence: &Arc<Spool>,
        cancel: &AtomicBool,
    ) -> Result<GitExpectedState, CoreError> {
        let worktree = &plan.pin.data.worktree;
        let root = self.validate(worktree, cancel)?;
        let started = Instant::now();
        let mut reader = plan.original();
        let mut next = ObservationRecord::read(&mut reader)?;
        let (state, _) = self.state_records(&root, cancel, |name, node| {
            use std::os::unix::ffi::OsStrExt;
            let current = ObservationRecord::from_node(
                target_path(&root.join(std::ffi::OsStr::from_bytes(name))),
                node,
                None,
            )?;
            if next.as_ref().is_some_and(|original| {
                original.membership.is_none() && original.path == current.path
            }) {
                self.compare_node(
                    next.as_ref().unwrap(),
                    &current,
                    absent_structure(&node.destination)?,
                    evidence,
                    cancel,
                    started,
                )?;
                next = ObservationRecord::read(&mut reader)?;
            } else {
                let mut approved = cursor(evidence);
                let mut created = false;
                let mut final_matches = false;
                while let Some(save) = read_evidence(&mut approved)? {
                    check_proof(cancel, started)?;
                    if save.after.resolved == current.path {
                        created |= save.before.is_none() && save.captured_absence;
                        final_matches = endpoint(&current, &save.after.canonical);
                    }
                }
                if !created || !final_matches {
                    return Err(refused("unexpected newly enumerated Git path"));
                }
            }
            Ok(())
        })?;
        if state.head != plan.pin.data.expected.head
            || state.index_fingerprint != plan.pin.data.expected.index_fingerprint
        {
            return Err(refused("original HEAD or index changed"));
        }
        while let Some(original) = next {
            if original.membership.is_none() {
                return Err(refused("original Git path disappeared"));
            }
            let (mut current, destination) = self.alias_node_record(
                worktree,
                FileRef {
                    target: worktree.target.clone(),
                    path: original.path.clone(),
                    resolved_identity: None,
                },
                cancel,
                started,
            )?;
            current.file_reference = original.file_reference;
            self.compare_node(
                &original,
                &current,
                absent_structure(&destination)?,
                evidence,
                cancel,
                started,
            )?;
            next = ObservationRecord::read(&mut reader)?;
        }
        if self.state(&root, cancel)? != state {
            return Err(refused("worktree changed during proof validation"));
        }
        check_proof(cancel, started)?;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{connections::local::LocalConnection, files::target_path};
    use std::{path::Path, sync::Arc};
    #[test]
    fn proof_scan_cannot_run_past_the_existing_git_deadline() {
        assert_eq!(
            check_proof(
                &AtomicBool::new(false),
                Instant::now() - std::time::Duration::from_secs(120)
            )
            .unwrap_err()
            .code,
            ErrorCode::Cancelled
        );
        assert!(check_proof(&AtomicBool::new(false), Instant::now()).is_ok());
    }
    fn git(root: &Path, args: &[&str]) {
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
    struct Fixture {
        dir: tempfile::TempDir,
        local: Arc<LocalConnection>,
        owner: ObservationOwner,
        worktree: WorktreeIdentity,
        file: FileRef,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("repo");
            std::fs::create_dir(&root).unwrap();
            git(&root, &["init", "-b", "main"]);
            git(&root, &["config", "user.name", "Fixture"]);
            git(&root, &["config", "user.email", "fixture@example.invalid"]);
            std::fs::write(root.join("file"), "original").unwrap();
            git(&root, &["add", "file"]);
            git(&root, &["commit", "-m", "initial"]);
            git(&root, &["branch", "other"]);
            let local = LocalConnection::open(dir.path().join("state")).unwrap();
            let lease = WorkspaceLeaseID([1; 16]);
            local.register(WorkspaceID([2; 16]), lease).unwrap();
            let owner = local.observation_owner(lease).unwrap();
            let file = FileRef {
                target: local.identity.clone(),
                path: target_path(&root.join("file")),
                resolved_identity: None,
            };
            let worktree = local
                .git
                .discover_sync(
                    FileRef {
                        path: target_path(&root),
                        ..file.clone()
                    },
                    &AtomicBool::new(false),
                )
                .unwrap()
                .unwrap();
            Self {
                dir,
                local: Arc::new(local),
                owner,
                worktree,
                file,
            }
        }
        fn save(&self, file: FileRef, id: u8, bytes: &[u8]) -> GitSaveApproval {
            self.save_as(self.owner.registration().lease, file, id, bytes)
        }
        fn save_as(
            &self,
            lease: WorkspaceLeaseID,
            file: FileRef,
            id: u8,
            bytes: &[u8],
        ) -> GitSaveApproval {
            let expected_version = self
                .local
                .files
                .read_sync(file.clone())
                .ok()
                .map(|snapshot| snapshot.version);
            let save = self
                .local
                .owned_files(lease)
                .unwrap()
                .prepare(SaveRequest {
                    operation: OperationID([id; 16]),
                    file,
                    expected_version,
                    submitted_revision: BufferRevision(id as u64),
                    source: ByteSource::Memory(Arc::from(bytes)),
                })
                .unwrap();
            let approval = save.approval().clone();
            assert!(matches!(save.execute().state, OperationState::Confirmed(_)));
            approval
        }
        fn capture(&self, aliases: Vec<FileRef>) -> (GitMutationRequest, [u8; 16], [u8; 32]) {
            let retained = self
                .local
                .git
                .observe_owned_sync(
                    &self.owner,
                    self.worktree.clone(),
                    aliases.into_iter().map(Ok),
                    &AtomicBool::new(false),
                )
                .unwrap();
            let digest = self
                .local
                .git
                .observation_alias_digest(&self.owner, retained.id)
                .unwrap();
            (
                GitMutationRequest {
                    operation: OperationID([90; 16]),
                    worktree: self.worktree.clone(),
                    expected: retained.snapshot.state,
                    command: GitMutation::Checkout {
                        reference: b"other".to_vec(),
                    },
                },
                retained.id,
                digest,
            )
        }
        fn execute(
            &self,
            original: GitMutationRequest,
            observation: [u8; 16],
            digest: [u8; 32],
            approvals: Vec<GitSaveApproval>,
        ) {
            let input = self
                .local
                .git
                .save_approval_input(&self.owner, approvals)
                .unwrap();
            let WorktreePreparation::Prepared(plan) = self
                .local
                .git
                .prepare_worktree_sync(
                    &self.owner,
                    &original,
                    observation,
                    digest,
                    input,
                    &AtomicBool::new(false),
                )
                .expect("durable save chain must prepare")
            else {
                panic!("unexpected duplicate")
            };
            let additional = self
                .local
                .git
                .save_approval_input(&self.owner, [])
                .expect("adopted approvals must release only the staging slot");
            let receipt = self
                .local
                .git
                .execute_worktree_sync(
                    &self.owner,
                    original.clone(),
                    plan,
                    digest,
                    additional,
                    &AtomicBool::new(false),
                )
                .unwrap();
            assert!(
                matches!(receipt.state, OperationState::Confirmed(_)),
                "{receipt:?}"
            );
            assert_eq!(
                self.local.git.existing_receipt_sync(&original).unwrap(),
                Some(receipt)
            );
        }
    }
    #[test]
    fn original_pending_save_chain_can_prepare_and_execute() {
        let f = Fixture::new();
        let (original, observation, digest) = f.capture(vec![f.file.clone()]);
        let approval = f.save(f.file.clone(), 20, b"saved");
        f.execute(original, observation, digest, vec![approval]);
    }
    #[test]
    fn already_reflected_save_is_not_applied_twice() {
        let f = Fixture::new();
        let first = f.save(f.file.clone(), 21, b"first");
        let (original, observation, digest) = f.capture(vec![f.file.clone()]);
        let second = f.save(f.file.clone(), 22, b"second");
        f.execute(original, observation, digest, vec![first, second]);
    }
    #[test]
    fn captured_absence_allows_only_the_actual_owned_creation() {
        let f = Fixture::new();
        let absent = FileRef {
            path: target_path(&f.dir.path().join("repo/new")),
            ..f.file.clone()
        };
        let (original, observation, digest) = f.capture(vec![absent.clone()]);
        let approval = f.save(absent, 23, b"created");
        f.execute(original, observation, digest, vec![approval]);
    }
    #[test]
    fn captured_creation_then_later_save_forms_one_contiguous_chain() {
        let f = Fixture::new();
        let absent = FileRef {
            path: target_path(&f.dir.path().join("repo/new")),
            ..f.file.clone()
        };
        let (original, observation, digest) = f.capture(vec![absent.clone()]);
        let first = f.save(absent.clone(), 24, b"created");
        let second = f.save(absent, 25, b"updated");
        f.execute(original, observation, digest, vec![first, second]);
    }
    #[test]
    fn interleaved_cross_window_saves_through_outside_aliases_are_contiguous() {
        let f = Fixture::new();
        let root = f.dir.path().join("repo");
        std::fs::write(root.join("second"), "second").unwrap();
        git(&root, &["add", "second"]);
        git(&root, &["commit", "-m", "second"]);
        git(&root, &["branch", "-f", "other"]);
        let second = FileRef {
            path: target_path(&root.join("second")),
            ..f.file.clone()
        };
        let alias_path = f.dir.path().join("outside");
        std::os::unix::fs::symlink(root.join("file"), &alias_path).unwrap();
        let alias = FileRef {
            path: target_path(&alias_path),
            ..f.file.clone()
        };
        let lease = WorkspaceLeaseID([3; 16]);
        f.local.register(WorkspaceID([4; 16]), lease).unwrap();
        let (original, observation, digest) =
            f.capture(vec![f.file.clone(), alias.clone(), second.clone()]);
        let first = f.save_as(lease, alias, 30, b"alias save");
        let other = f.save(second, 31, b"second save");
        let last = f.save(f.file.clone(), 32, b"last save");
        f.local.release(lease);
        f.execute(original, observation, digest, vec![first, other, last]);
    }
    #[test]
    fn external_changes_never_become_approved_save_history() {
        use std::os::unix::fs::PermissionsExt;
        for case in [
            "same-content",
            "mode",
            "head",
            "index",
            "new-path",
            "missing-chain",
            "duplicate",
            "reverse",
            "external-create",
        ] {
            let f = Fixture::new();
            let root = f.dir.path().join("repo");
            let file = if case == "external-create" {
                FileRef {
                    path: target_path(&root.join("new")),
                    ..f.file.clone()
                }
            } else {
                f.file.clone()
            };
            let (original, observation, digest) = f.capture(vec![file.clone()]);
            if case == "external-create" {
                std::fs::write(root.join("new"), "external").unwrap();
            }
            let first = f.save(file.clone(), 40, b"saved");
            let mut approvals = vec![first.clone()];
            match case {
                "same-content" => {
                    std::fs::write(root.join("replacement"), b"saved").unwrap();
                    std::fs::rename(root.join("replacement"), root.join("file")).unwrap();
                }
                "mode" => std::fs::set_permissions(
                    root.join("file"),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap(),
                "head" => git(&root, &["checkout", "other"]),
                "index" => git(&root, &["add", "file"]),
                "new-path" => std::fs::write(root.join("unapproved"), "external").unwrap(),
                "missing-chain" => approvals = vec![f.save(file, 41, b"later")],
                "duplicate" => approvals.push(first),
                "reverse" => approvals.insert(0, f.save(file, 41, b"later")),
                _ => {}
            }
            let input = f
                .local
                .git
                .save_approval_input(&f.owner, approvals)
                .unwrap();
            assert!(
                f.local
                    .git
                    .prepare_worktree_sync(
                        &f.owner,
                        &original,
                        observation,
                        digest,
                        input,
                        &AtomicBool::new(false)
                    )
                    .is_err(),
                "{case}"
            );
            assert!(
                f.local
                    .git
                    .existing_receipt_sync(&original)
                    .unwrap()
                    .is_none(),
                "{case}"
            );
        }
    }
    #[test]
    fn missing_expired_malformed_and_reconciled_records_cannot_prove_saves() {
        for case in [
            "missing", "expired", "legacy", "unknown", "no-after", "digest", "actor", "runtime",
            "kind", "revision", "result", "before",
        ] {
            let f = Fixture::new();
            let (original, observation, digest) = f.capture(vec![f.file.clone()]);
            let mut approval = f.save(f.file.clone(), 45, b"saved");
            {
                let ledger = f.local.files.ledger.lock().unwrap();
                let _lock = ledger.lock().unwrap();
                let mut record = ledger.read(approval.operation).unwrap().unwrap();
                match case {
                    "missing" => {
                        std::fs::remove_file(
                            ledger.directory.join(format!("{}.json", "2d".repeat(16))),
                        )
                        .unwrap();
                    }
                    "expired" => record.created = 0,
                    "legacy" => record.save_proof = None,
                    "unknown" => {
                        record.receipt = crate::operations::ledger::unknown(
                            record.envelope.id,
                            record.envelope.target.clone(),
                            "fixture uncertain",
                        )
                    }
                    "no-after" => record.save_proof.as_mut().unwrap().after = None,
                    "digest" => approval.request_digest[0] ^= 1,
                    "actor" => approval.actor.lease = WorkspaceLeaseID([9; 16]),
                    "runtime" => {
                        record
                            .save_proof
                            .as_mut()
                            .unwrap()
                            .actor
                            .runtime
                            .supervisor_boot[0] ^= 1
                    }
                    "kind" => record.envelope.kind = MutationKind::Git,
                    "revision" => record.revision = BufferRevision(99),
                    "result" => {
                        let OperationState::Confirmed(MutationResult::Saved(saved)) =
                            &mut record.receipt.state
                        else {
                            panic!()
                        };
                        saved.version.opaque_token[0] ^= 1;
                    }
                    "before" => {
                        record
                            .save_proof
                            .as_mut()
                            .unwrap()
                            .before
                            .as_mut()
                            .unwrap()
                            .canonical
                            .opaque_token[0] ^= 1
                    }
                    _ => unreachable!(),
                }
                if case != "missing" {
                    ledger.write(&record).unwrap();
                }
            }
            let input = f
                .local
                .git
                .save_approval_input(&f.owner, [approval])
                .unwrap();
            assert!(
                f.local
                    .git
                    .prepare_worktree_sync(
                        &f.owner,
                        &original,
                        observation,
                        digest,
                        input,
                        &AtomicBool::new(false)
                    )
                    .is_err(),
                "{case}"
            );
            assert!(
                f.local
                    .git
                    .existing_receipt_sync(&original)
                    .unwrap()
                    .is_none()
            );
        }
    }
    #[test]
    fn exact_registration_survives_durable_admission_or_refuses_without_effect() {
        for phase in ["before", "during", "after"] {
            let f = Fixture::new();
            let (original, observation, digest) = f.capture(vec![f.file.clone()]);
            let input = f.local.git.save_approval_input(&f.owner, []).unwrap();
            let WorktreePreparation::Prepared(plan) = f
                .local
                .git
                .prepare_worktree_sync(
                    &f.owner,
                    &original,
                    observation,
                    digest,
                    input,
                    &AtomicBool::new(false),
                )
                .unwrap()
            else {
                panic!()
            };
            let mut service = LocalGitService::new(f.local.files.clone());
            let local = f.local.clone();
            let lease = f.owner.registration().lease;
            let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || local.release(lease));
            match phase {
                "before" => service.before_accept = Some(hook),
                "during" => service.after_accept = Some(hook),
                _ => service.after_authorization = Some(hook),
            }
            let input = service.save_approval_input(&f.owner, []).unwrap();
            let result = service.execute_worktree_sync(
                &f.owner,
                original.clone(),
                plan,
                digest,
                input,
                &AtomicBool::new(false),
            );
            if phase == "before" {
                assert!(result.is_err());
                assert!(service.existing_receipt_sync(&original).unwrap().is_none());
            } else {
                let receipt = result.unwrap();
                assert!(
                    if phase == "after" {
                        matches!(receipt.state, OperationState::Confirmed(_))
                    } else {
                        matches!(receipt.state, OperationState::Failed(_))
                    },
                    "{phase}: {receipt:?}"
                );
                assert_eq!(
                    service.existing_receipt_sync(&original).unwrap(),
                    Some(receipt)
                );
            }
        }
    }
    #[test]
    fn historical_canonical_identity_must_agree_with_the_same_saved_descriptor() {
        let f = Fixture::new();
        let (original, observation, digest) = f.capture(vec![f.file.clone()]);
        let approval = f.save(f.file.clone(), 46, b"saved");
        {
            let ledger = f.local.files.ledger.lock().unwrap();
            let _lock = ledger.lock().unwrap();
            let mut record = ledger.read(approval.operation).unwrap().unwrap();
            record
                .save_proof
                .as_mut()
                .unwrap()
                .after
                .as_mut()
                .unwrap()
                .canonical
                .file_identity[0] ^= 1;
            ledger.write(&record).unwrap();
        }
        let input = f
            .local
            .git
            .save_approval_input(&f.owner, [approval])
            .unwrap();
        assert!(
            f.local
                .git
                .prepare_worktree_sync(
                    &f.owner,
                    &original,
                    observation,
                    digest,
                    input,
                    &AtomicBool::new(false)
                )
                .is_err(),
            "malformed canonical endpoint was accepted"
        );
    }
    #[test]
    fn duplicate_receipt_precedes_invalid_plan_owner_cancellation_and_store() {
        let f = Fixture::new();
        let (original, _, _) = f.capture(vec![]);
        let first_input = f.local.git.save_approval_input(&f.owner, []).unwrap();
        let other_lease = WorkspaceLeaseID([6; 16]);
        f.local.register(WorkspaceID([7; 16]), other_lease).unwrap();
        let other = f.local.observation_owner(other_lease).unwrap();
        let second_input = f.local.git.save_approval_input(&other, []).unwrap();
        let receipt = f
            .local
            .git
            .mutate_sync(original.clone(), &AtomicBool::new(false));
        assert!(matches!(receipt.state, OperationState::Confirmed(_)));
        f.local.release(f.owner.registration().lease);
        let mut service = LocalGitService::new(f.local.files.clone());
        service.observations = Err(io_error("fixture storage unavailable"));
        let WorktreePreparation::Existing(found) = service
            .prepare_worktree_sync(
                &f.owner,
                &original,
                [0; 16],
                [0; 32],
                first_input,
                &AtomicBool::new(true),
            )
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(*found, receipt);
        assert_eq!(
            service
                .execute_worktree_sync(
                    &f.owner,
                    original,
                    [0; 16],
                    [0; 32],
                    second_input,
                    &AtomicBool::new(true)
                )
                .unwrap(),
            receipt
        );
    }
    #[test]
    fn execute_accepts_later_approvals_but_keeps_the_original_request() {
        let f = Fixture::new();
        let (original, observation, digest) = f.capture(vec![f.file.clone()]);
        let first = f.save(f.file.clone(), 47, b"first");
        let input = f.local.git.save_approval_input(&f.owner, [first]).unwrap();
        let WorktreePreparation::Prepared(plan) = f
            .local
            .git
            .prepare_worktree_sync(
                &f.owner,
                &original,
                observation,
                digest,
                input,
                &AtomicBool::new(false),
            )
            .unwrap()
        else {
            panic!()
        };
        let second = f.save(f.file.clone(), 48, b"second");
        let input = f.local.git.save_approval_input(&f.owner, [second]).unwrap();
        let receipt = f
            .local
            .git
            .execute_worktree_sync(
                &f.owner,
                original.clone(),
                plan,
                digest,
                input,
                &AtomicBool::new(false),
            )
            .unwrap();
        assert!(matches!(receipt.state, OperationState::Confirmed(_)));
        let ledger = f.local.files.ledger.lock().unwrap();
        let record = ledger.read(original.operation).unwrap().unwrap();
        assert_eq!(
            record.envelope.request_digest,
            request_digest(&original).unwrap()
        );
    }
    #[test]
    fn prepared_sibling_worktree_can_save_and_prepare_independently() {
        let f = Fixture::new();
        let root = f.dir.path().join("repo");
        let linked = f.dir.path().join("linked");
        git(
            &root,
            &["worktree", "add", "-b", "linked", linked.to_str().unwrap()],
        );
        let sibling_file = FileRef {
            path: target_path(&linked.join("file")),
            ..f.file.clone()
        };
        let lease = WorkspaceLeaseID([6; 16]);
        f.local.register(WorkspaceID([7; 16]), lease).unwrap();
        let owner = f.local.observation_owner(lease).unwrap();
        let sibling_worktree = f
            .local
            .git
            .discover_sync(
                FileRef {
                    path: target_path(&linked),
                    ..f.file.clone()
                },
                &AtomicBool::new(false),
            )
            .unwrap()
            .unwrap();
        let (original, observation, digest) = f.capture(vec![f.file.clone(), sibling_file.clone()]);
        let input = f.local.git.save_approval_input(&f.owner, []).unwrap();
        let WorktreePreparation::Prepared(plan) = f
            .local
            .git
            .prepare_worktree_sync(
                &f.owner,
                &original,
                observation,
                digest,
                input,
                &AtomicBool::new(false),
            )
            .unwrap()
        else {
            panic!()
        };
        let sibling = f
            .local
            .git
            .observe_owned_sync(
                &owner,
                sibling_worktree.clone(),
                [Ok(sibling_file.clone())],
                &AtomicBool::new(false),
            )
            .unwrap();
        let sibling_digest = f
            .local
            .git
            .observation_alias_digest(&owner, sibling.id)
            .unwrap();
        let sibling_original = GitMutationRequest {
            operation: OperationID([91; 16]),
            worktree: sibling_worktree,
            expected: sibling.snapshot.state,
            command: GitMutation::Checkout {
                reference: b"linked".to_vec(),
            },
        };
        let input = f.local.git.save_approval_input(&owner, []).unwrap();
        let WorktreePreparation::Prepared(sibling_plan) = f
            .local
            .git
            .prepare_worktree_sync(
                &owner,
                &sibling_original,
                sibling.id,
                sibling_digest,
                input,
                &AtomicBool::new(false),
            )
            .unwrap()
        else {
            panic!()
        };
        f.save_as(lease, sibling_file, 49, b"sibling remains editable");
        let input = f.local.git.save_approval_input(&f.owner, []).unwrap();
        assert!(matches!(
            f.local
                .git
                .execute_worktree_sync(
                    &f.owner,
                    original,
                    plan,
                    digest,
                    input,
                    &AtomicBool::new(false)
                )
                .unwrap()
                .state,
            OperationState::Confirmed(_)
        ));
        f.local.git.cancel_worktree_plan(&owner, sibling_plan);
    }
    #[test]
    fn ignored_alias_is_rechecked_after_durable_acceptance() {
        let f = Fixture::new();
        let root = f.dir.path().join("repo");
        std::fs::write(root.join(".git/info/exclude"), "ignored\n").unwrap();
        std::fs::write(root.join("ignored"), "original").unwrap();
        let file = FileRef {
            path: target_path(&root.join("ignored")),
            ..f.file.clone()
        };
        let (original, observation, digest) = f.capture(vec![file]);
        let input = f.local.git.save_approval_input(&f.owner, []).unwrap();
        let WorktreePreparation::Prepared(plan) = f
            .local
            .git
            .prepare_worktree_sync(
                &f.owner,
                &original,
                observation,
                digest,
                input,
                &AtomicBool::new(false),
            )
            .unwrap()
        else {
            panic!()
        };
        let mut service = LocalGitService::new(f.local.files.clone());
        service.after_authorization = Some(Arc::new(move || {
            std::fs::write(root.join("ignored"), "external").unwrap()
        }));
        let input = service.save_approval_input(&f.owner, []).unwrap();
        let receipt = service
            .execute_worktree_sync(
                &f.owner,
                original.clone(),
                plan,
                digest,
                input,
                &AtomicBool::new(false),
            )
            .unwrap();
        assert!(matches!(
            receipt.state,
            OperationState::Failed(OperationFailure {
                effect: FailureEffect::ProvenNoEffect,
                ..
            })
        ));
        assert_eq!(
            service.existing_receipt_sync(&original).unwrap(),
            Some(receipt)
        );
    }
    #[test]
    fn concurrent_original_acceptance_wins_over_stale_cancelled_proof_after_preflight() {
        for preparing in [false, true] {
            let f = Fixture::new();
            let (original, _, _) = f.capture(vec![]);
            let input = f.local.git.save_approval_input(&f.owner, []).unwrap();
            let entered = Arc::new(std::sync::Barrier::new(2));
            let resume = Arc::new(std::sync::Barrier::new(2));
            let mut service = LocalGitService::new(f.local.files.clone());
            let (at_lookup, continue_lookup) = (entered.clone(), resume.clone());
            service.after_proof_lookup = Some(Arc::new(move || {
                at_lookup.wait();
                continue_lookup.wait();
            }));
            let owner = f.owner.clone();
            let duplicate = original.clone();
            let worker = std::thread::spawn(move || {
                if preparing {
                    let WorktreePreparation::Existing(receipt) = service
                        .prepare_worktree_sync(
                            &owner,
                            &duplicate,
                            [0; 16],
                            [0; 32],
                            input,
                            &AtomicBool::new(true),
                        )
                        .unwrap()
                    else {
                        panic!()
                    };
                    *receipt
                } else {
                    service
                        .execute_worktree_sync(
                            &owner,
                            duplicate,
                            [0; 16],
                            [0; 32],
                            input,
                            &AtomicBool::new(true),
                        )
                        .unwrap()
                }
            });
            entered.wait();
            let expected = f
                .local
                .git
                .mutate_sync(original.clone(), &AtomicBool::new(false));
            resume.wait();
            assert!(matches!(expected.state, OperationState::Confirmed(_)));
            assert_eq!(worker.join().unwrap(), expected);
            assert_eq!(
                f.local.git.existing_receipt_sync(&original).unwrap(),
                Some(expected)
            );
        }
    }
    #[test]
    fn legacy_lookup_never_waits_for_repository_execution_and_existing_receipt_wins() {
        let f = Fixture::new();
        let (original, _, _) = f.capture(vec![]);
        let mutex = super::super::mutations::repository_mutex(&original.worktree);
        let held = mutex.lock().unwrap();
        assert_eq!(
            f.local
                .git
                .refuse_unprepared_worktree_sync(&original)
                .unwrap_err()
                .code,
            ErrorCode::Unavailable
        );
        drop(held);
        let expected = f
            .local
            .git
            .mutate_sync(original.clone(), &AtomicBool::new(false));
        assert!(matches!(expected.state, OperationState::Confirmed(_)));
        let _held = mutex.lock().unwrap();
        assert_eq!(
            f.local
                .git
                .refuse_unprepared_worktree_sync(&original)
                .unwrap(),
            expected
        );
    }
    #[test]
    fn legacy_refusal_rechecks_original_accepted_after_fast_preflight() {
        let f = Fixture::new();
        let (original, _, _) = f.capture(vec![]);
        let local = f.local.clone();
        let concurrent = original.clone();
        let mut service = LocalGitService::new(f.local.files.clone());
        service.after_proof_lookup = Some(Arc::new(move || {
            assert!(matches!(
                local
                    .git
                    .mutate_sync(concurrent.clone(), &AtomicBool::new(false))
                    .state,
                OperationState::Confirmed(_)
            ));
        }));
        let receipt = service.refuse_unprepared_worktree_sync(&original).unwrap();
        assert_eq!(
            Some(receipt),
            f.local.git.existing_receipt_sync(&original).unwrap()
        );
    }
    #[test]
    fn legacy_existing_accepted_lookup_does_not_wait_for_the_executing_repository() {
        let f = Fixture::new();
        let (original, _, _) = f.capture(vec![]);
        let local = f.local.clone();
        let duplicate = original.clone();
        let mut service = LocalGitService::new(f.local.files.clone());
        service.after_authorization = Some(Arc::new(move || {
            let receipt = local
                .git
                .refuse_unprepared_worktree_sync(&duplicate)
                .unwrap();
            assert!(matches!(receipt.state, OperationState::Unknown(_)));
        }));
        let receipt = service.mutate_sync(original.clone(), &AtomicBool::new(false));
        assert!(matches!(receipt.state, OperationState::Confirmed(_)));
        assert_eq!(
            Some(receipt),
            f.local.git.existing_receipt_sync(&original).unwrap()
        );
    }
    #[test]
    fn hintless_owned_save_uses_captured_same_path_without_rewriting_alias_identity() {
        for changed_hint in [false, true] {
            let f = Fixture::new();
            let outside = f.dir.path().join("original-alias");
            std::os::unix::fs::symlink(f.dir.path().join("repo/file"), &outside).unwrap();
            let captured = FileRef {
                path: target_path(&outside),
                resolved_identity: Some(vec![7]),
                ..f.file.clone()
            };
            let (original, observation, digest) = f.capture(vec![captured.clone()]);
            let effective = FileRef {
                resolved_identity: if changed_hint { Some(vec![8]) } else { None },
                ..captured.clone()
            };
            let approval = f.save(effective, 48, b"owned save");
            let input = f
                .local
                .git
                .save_approval_input(&f.owner, [approval])
                .unwrap();
            let result = f.local.git.prepare_worktree_sync(
                &f.owner,
                &original,
                observation,
                digest,
                input,
                &AtomicBool::new(false),
            );
            if changed_hint {
                assert!(result.is_err());
            } else {
                let WorktreePreparation::Prepared(plan) = result.unwrap() else {
                    panic!("expected prepared")
                };
                assert_eq!(
                    f.local
                        .git
                        .observation_alias_digest(&f.owner, observation)
                        .unwrap(),
                    digest
                );
                let mut reader = f
                    .local
                    .git
                    .observation_reader(&f.owner, observation)
                    .unwrap();
                let mut found = false;
                while let Some(record) = reader.next_record().unwrap() {
                    if record.membership.is_some() {
                        assert!(record.matches_alias(&captured).unwrap());
                        found = true;
                    }
                }
                assert!(found);
                drop(reader);
                f.local.git.cancel_worktree_plan(&f.owner, plan);
            }
        }
    }
    #[test]
    fn original_alias_set_and_link_identity_cannot_be_reconstructed_later() {
        for case in [
            "uncovered",
            "same-target-link-replaced",
            "hint-changed",
            "membership-changed",
        ] {
            let f = Fixture::new();
            let root = f.dir.path().join("repo");
            let outside = f.dir.path().join("alias");
            let destination = if case == "membership-changed" {
                let path = f.dir.path().join("unrelated");
                std::fs::write(&path, "unrelated").unwrap();
                path
            } else {
                root.join("file")
            };
            std::os::unix::fs::symlink(&destination, &outside).unwrap();
            let mut alias = FileRef {
                path: target_path(&outside),
                ..f.file.clone()
            };
            let aliases = if case == "uncovered" {
                vec![f.file.clone()]
            } else {
                vec![f.file.clone(), alias.clone()]
            };
            let (original, observation, digest) = f.capture(aliases);
            let approvals = if case == "membership-changed" {
                vec![]
            } else {
                if case == "hint-changed" {
                    alias.resolved_identity = Some(vec![7]);
                }
                vec![f.save(alias, 50, b"saved through alias")]
            };
            if matches!(case, "same-target-link-replaced" | "membership-changed") {
                let replacement = f.dir.path().join("new-link");
                std::os::unix::fs::symlink(root.join("file"), &replacement).unwrap();
                std::fs::rename(replacement, outside).unwrap();
            }
            let input = f
                .local
                .git
                .save_approval_input(&f.owner, approvals)
                .unwrap();
            assert!(
                f.local
                    .git
                    .prepare_worktree_sync(
                        &f.owner,
                        &original,
                        observation,
                        digest,
                        input,
                        &AtomicBool::new(false)
                    )
                    .is_err(),
                "{case}"
            );
        }
    }
    #[test]
    fn owned_creation_through_original_directory_alias_is_verified() {
        let f = Fixture::new();
        let root = f.dir.path().join("repo");
        let alias = f.dir.path().join("alias-dir");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        let file = FileRef {
            path: target_path(&alias.join("new")),
            ..f.file.clone()
        };
        let (original, observation, digest) = f.capture(vec![file.clone()]);
        let approval = f.save(file, 51, b"created through original parent link");
        f.execute(original, observation, digest, vec![approval]);
    }
    #[test]
    fn nested_repository_and_submodule_aliases_preserve_original_membership() {
        let f = Fixture::new();
        let root = f.dir.path().join("repo");
        let nested = root.join("nested");
        std::fs::create_dir(&nested).unwrap();
        git(&nested, &["init", "-b", "nested"]);
        std::fs::write(nested.join("file"), "nested").unwrap();
        std::fs::write(root.join(".git/info/exclude"), "nested/\n").unwrap();
        let source = f.dir.path().join("source");
        std::fs::create_dir(&source).unwrap();
        git(&source, &["init", "-b", "main"]);
        git(&source, &["config", "user.name", "Fixture"]);
        git(
            &source,
            &["config", "user.email", "fixture@example.invalid"],
        );
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
                "sub",
            ],
        );
        git(&root, &["commit", "-am", "submodule"]);
        git(&root, &["branch", "-f", "other"]);
        let files = [nested.join("file"), root.join("sub/file")].map(|path| FileRef {
            path: target_path(&path),
            ..f.file.clone()
        });
        let (original, observation, digest) = f.capture(files.to_vec());
        let mut reader = f
            .local
            .git
            .observation_reader(&f.owner, observation)
            .unwrap();
        let mut unaffected = 0;
        while let Some(record) = reader.next_record().unwrap() {
            if let Some(membership) = record.membership {
                assert!(!membership.affected);
                assert!(membership.requested_repository.is_some());
                unaffected += 1;
            }
        }
        assert_eq!(unaffected, 2);
        drop(reader);
        f.execute(original, observation, digest, vec![]);
    }
    #[test]
    fn truncated_approval_input_cannot_publish_a_plan_or_leak_its_pin() {
        let f = Fixture::new();
        let (original, observation, digest) = f.capture(vec![]);
        let before = f.local.git.observation_storage_stats().unwrap().bytes;
        let mut input = f.local.git.observation_input(&f.owner).unwrap();
        input.append(&[0; 95]).unwrap();
        assert!(
            f.local
                .git
                .prepare_worktree_sync(
                    &f.owner,
                    &original,
                    observation,
                    digest,
                    input.seal().unwrap(),
                    &AtomicBool::new(false)
                )
                .is_err()
        );
        let stats = f.local.git.observation_storage_stats().unwrap();
        assert_eq!(stats.bytes, before);
        assert_eq!(stats.pins, 0);
        assert_eq!(stats.captures, 0);
    }
    #[test]
    fn plan_cancel_or_observation_release_must_survive_durable_admission() {
        for retirement in ["cancel", "release", "expire"] {
            for phase in ["before", "during", "after"] {
                let f = Fixture::new();
                let (original, observation, digest) = f.capture(vec![]);
                let input = f.local.git.save_approval_input(&f.owner, []).unwrap();
                let WorktreePreparation::Prepared(plan) = f
                    .local
                    .git
                    .prepare_worktree_sync(
                        &f.owner,
                        &original,
                        observation,
                        digest,
                        input,
                        &AtomicBool::new(false),
                    )
                    .unwrap()
                else {
                    panic!()
                };
                let mut service = LocalGitService::new(f.local.files.clone());
                let local = f.local.clone();
                let owner = f.owner.clone();
                let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || match retirement {
                    "release" => local.git.release_observation(&owner, observation),
                    "expire" => super::super::observation_store::testing::expire_owner(
                        local.git.observation_store().unwrap(),
                        &owner,
                    ),
                    _ => local.git.cancel_worktree_plan(&owner, plan),
                });
                match phase {
                    "before" => service.before_accept = Some(hook),
                    "during" => service.after_accept = Some(hook),
                    _ => service.after_authorization = Some(hook),
                }
                let input = service.save_approval_input(&f.owner, []).unwrap();
                let result = service.execute_worktree_sync(
                    &f.owner,
                    original.clone(),
                    plan,
                    digest,
                    input,
                    &AtomicBool::new(false),
                );
                if phase == "before" {
                    assert!(
                        result.is_err(),
                        "cancelled/released plan accepted before fsync"
                    );
                    assert!(service.existing_receipt_sync(&original).unwrap().is_none());
                } else {
                    let receipt = result.unwrap();
                    assert!(
                        if phase == "after" {
                            matches!(receipt.state, OperationState::Confirmed(_))
                        } else {
                            matches!(
                                receipt.state,
                                OperationState::Failed(OperationFailure {
                                    effect: FailureEffect::ProvenNoEffect,
                                    ..
                                })
                            )
                        },
                        "{phase}, {retirement}: {receipt:?}"
                    );
                }
            }
        }
    }
    #[test]
    fn unrecordable_revocation_remains_unknown_and_the_accepted_id_never_replays() {
        let f = Fixture::new();
        let (original, observation, digest) = f.capture(vec![]);
        let input = f.local.git.save_approval_input(&f.owner, []).unwrap();
        let WorktreePreparation::Prepared(plan) = f
            .local
            .git
            .prepare_worktree_sync(
                &f.owner,
                &original,
                observation,
                digest,
                input,
                &AtomicBool::new(false),
            )
            .unwrap()
        else {
            panic!()
        };
        let mut service = LocalGitService::new(f.local.files.clone());
        let directory = f.local.files.ledger.lock().unwrap().directory.clone();
        let relocated = directory.with_file_name("temporarily-unavailable-operations");
        let (original_directory, unavailable_directory) = (directory.clone(), relocated.clone());
        let local = f.local.clone();
        let lease = f.owner.registration().lease;
        service.after_accept = Some(Arc::new(move || {
            local.release(lease);
            std::fs::rename(&original_directory, &unavailable_directory).unwrap();
        }));
        let input = service.save_approval_input(&f.owner, []).unwrap();
        let receipt = service
            .execute_worktree_sync(
                &f.owner,
                original.clone(),
                plan,
                digest,
                input,
                &AtomicBool::new(false),
            )
            .unwrap();
        assert!(matches!(receipt.state, OperationState::Unknown(_)));
        std::fs::rename(relocated, directory).unwrap();
        assert!(matches!(
            service
                .mutate_sync(original.clone(), &AtomicBool::new(false))
                .state,
            OperationState::Unknown(_)
        ));
        assert_eq!(
            service
                .status_sync(original.worktree, &AtomicBool::new(false))
                .unwrap()
                .state,
            original.expected
        );
    }

    #[test]
    fn immutable_original_request_bytes_are_retained_and_charged_with_the_plan() {
        let f = Fixture::new();
        let (original, observation, digest) = f.capture(vec![]);
        let baseline = f.local.git.observation_storage_stats().unwrap().bytes;
        let input = f.local.git.save_approval_input(&f.owner, []).unwrap();
        let WorktreePreparation::Prepared(plan) = f
            .local
            .git
            .prepare_worktree_sync(
                &f.owner,
                &original,
                observation,
                digest,
                input,
                &AtomicBool::new(false),
            )
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(
            f.local.git.observation_storage_stats().unwrap().bytes,
            baseline + serde_json::to_vec(&original).unwrap().len() as u64,
            "full immutable request is missing from charged plan storage"
        );
        let store = f.local.git.observation_store().unwrap();
        let retained = store.plan(&f.owner, plan).unwrap();
        assert_eq!(retained.request_digest, request_digest(&original).unwrap());
        let mut bytes = Vec::new();
        cursor(&retained._original_request)
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, serde_json::to_vec(&original).unwrap());
        drop(retained);
        f.local.git.cancel_worktree_plan(&f.owner, plan);
        assert_eq!(
            f.local.git.observation_storage_stats().unwrap().bytes,
            baseline
        );
    }
    #[test]
    #[ignore = "explicit modest verifier geometry measurement"]
    fn actual_verifier_chain_and_alias_measurement() {
        fn rss() -> i64 {
            let mut usage = std::mem::MaybeUninit::uninit();
            assert_eq!(
                unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
                0
            );
            unsafe { usage.assume_init() }.ru_maxrss
        }
        let f = Fixture::new();
        let root = f.dir.path().join("repo");
        let mut files = vec![];
        for n in 0..64 {
            let path = root.join(format!("path-{n:026}"));
            std::fs::write(&path, b"original\n").unwrap();
            files.push(FileRef {
                path: target_path(&path),
                ..f.file.clone()
            });
        }
        git(&root, &["add", "."]);
        git(&root, &["commit", "-m", "geometry"]);
        git(&root, &["branch", "-f", "other"]);
        let mut destination = root.join("file");
        for n in 0..8 {
            let link = f.dir.path().join(format!("indirect-{n}"));
            std::os::unix::fs::symlink(destination, &link).unwrap();
            destination = link;
        }
        let mut aliases = vec![f.file.clone()];
        aliases.extend(files.iter().take(16).cloned());
        for n in 0..16 {
            let path = f.dir.path().join(format!("outside-{n}"));
            std::os::unix::fs::symlink(&destination, &path).unwrap();
            aliases.push(FileRef {
                path: target_path(&path),
                ..f.file.clone()
            });
        }
        let rss_before = rss();
        let capture_start = Instant::now();
        let (original, observation, digest) = f.capture(aliases);
        let capture_seconds = capture_start.elapsed().as_secs_f64();
        let original_bytes = f.local.git.observation_storage_stats().unwrap().bytes;
        let mut approvals = vec![f.save(f.file.clone(), 100, b"alias endpoint saved")];
        for round in 0..2 {
            for (n, file) in files.iter().take(16).enumerate() {
                approvals.push(f.save(
                    file.clone(),
                    (101 + round * 16 + n) as u8,
                    if round == 0 { b"first" } else { b"final" },
                ));
            }
        }
        let input = f
            .local
            .git
            .save_approval_input(&f.owner, approvals)
            .unwrap();
        let approval_bytes = input.len();
        let prepare_start = Instant::now();
        let WorktreePreparation::Prepared(plan_id) = f
            .local
            .git
            .prepare_worktree_sync(
                &f.owner,
                &original,
                observation,
                digest,
                input,
                &AtomicBool::new(false),
            )
            .unwrap()
        else {
            panic!()
        };
        let prepare_seconds = prepare_start.elapsed().as_secs_f64();
        let retained_plan_bytes = f.local.git.observation_storage_stats().unwrap().bytes;
        let store = f.local.git.observation_store().unwrap();
        let plan = store.plan(&f.owner, plan_id).unwrap();
        let evidence = f
            .local
            .git
            .freeze_evidence(&f.owner, &plan, None, &AtomicBool::new(false))
            .unwrap();
        let sampled_bytes = store.stats().bytes;
        let mut reader = cursor(&evidence);
        let mut max_record_bytes = 0;
        let mut records = 0;
        while let Some(record) = read_evidence(&mut reader).unwrap() {
            max_record_bytes = max_record_bytes.max(serde_json::to_vec(&record).unwrap().len());
            records += 1;
        }
        drop(reader);
        drop(evidence);
        drop(plan);
        let additional = f.local.git.save_approval_input(&f.owner, []).unwrap();
        let execute_start = Instant::now();
        let receipt = f
            .local
            .git
            .execute_worktree_sync(
                &f.owner,
                original,
                plan_id,
                digest,
                additional,
                &AtomicBool::new(false),
            )
            .unwrap();
        let execute_seconds = execute_start.elapsed().as_secs_f64();
        assert!(matches!(receipt.state, OperationState::Confirmed(_)));
        println!(
            "{}",
            serde_json::json!({"git_nodes":65,"supplemental_aliases":33,"outside_aliases":16,"indirect_links":8,"save_records":records,
            "original_bytes":original_bytes,"approval_bytes":approval_bytes,"retained_plan_bytes":retained_plan_bytes,"sampled_with_frozen_evidence_bytes":sampled_bytes,
            "max_encoded_evidence_record_bytes":max_record_bytes,"capture_seconds":capture_seconds,"prepare_seconds":prepare_seconds,"execute_seconds":execute_seconds,
            "rss_before":rss_before,"rss_after":rss(),"hash_scratch_bytes_per_worker":65536,"ledger_record_parse_bound":131072})
        );
        f.local.git.release_observation(&f.owner, observation);
        assert_eq!(store.stats().bytes, 0);
    }
}
