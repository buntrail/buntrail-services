use super::{adapter::LocalGitService, process};
use crate::{
    files::{digest, failure, io_error},
    operations::ledger::{Record, now, unknown},
};
use buntrail_core::contracts::*;
use std::{
    collections::HashMap,
    ffi::OsString,
    sync::{Arc, Mutex, OnceLock, Weak, atomic::AtomicBool},
};
type RepositoryLocks = HashMap<Vec<u8>, Weak<Mutex<()>>>;
static REPOSITORIES: OnceLock<Mutex<RepositoryLocks>> = OnceLock::new();
pub(super) struct WorktreeProofGuard<'a> {
    pub owner: &'a super::observation::ObservationOwner,
    pub verify: &'a mut dyn FnMut(bool) -> Result<GitExpectedState, CoreError>,
    pub authorize: &'a dyn Fn() -> Result<(), CoreError>,
}
impl WorktreeProofGuard<'_> {
    fn check(&self) -> Result<(), CoreError> {
        (self.authorize)()?;
        self.owner.check()
    }
}
pub(crate) fn repository_mutex(worktree: &WorktreeIdentity) -> Arc<Mutex<()>> {
    let mut repos = REPOSITORIES.get_or_init(Default::default).lock().unwrap();
    repos.retain(|_, v| v.strong_count() > 0);
    let key = worktree.common_git_directory_identity.clone();
    if let Some(lock) = repos.get(&key).and_then(Weak::upgrade) {
        lock
    } else {
        let lock = Arc::new(Mutex::new(()));
        repos.insert(key, Arc::downgrade(&lock));
        lock
    }
}
impl LocalGitService {
    /// Full original control lookup: stream the canonical serializer into the shared digest.
    /// Contention is unresolved, never a missing receipt or a no-effect outcome.
    pub fn existing_original_sync(
        &self,
        r: &GitMutationRequest,
    ) -> Result<Option<OperationReceipt>, CoreError> {
        let fingerprint = super::observation::serialized_digest(r)?;
        self.existing_receipt_digest_sync(r.operation, &r.worktree.target, fingerprint)
    }
    /// Trusted target adapter only: digest must be computed from the complete original request.
    pub fn existing_receipt_digest_sync(
        &self,
        operation: OperationID,
        target: &TargetIdentity,
        digest: [u8; 32],
    ) -> Result<Option<OperationReceipt>, CoreError> {
        self.receipt_target(target)?;
        let ledger = self.files.ledger.try_lock().map_err(|_| {
            CoreError::new(ErrorCode::Unavailable, "original operation lookup is busy")
        })?;
        let _lock = ledger.try_lock()?;
        existing_identity(&ledger, operation, target, digest)
    }
    fn receipt_target(&self, target: &TargetIdentity) -> Result<(), CoreError> {
        if target != self.files.target() {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "Git target changed",
            ));
        }
        Ok(())
    }
    pub fn existing_receipt_sync(
        &self,
        r: &GitMutationRequest,
    ) -> Result<Option<OperationReceipt>, CoreError> {
        self.receipt_target(&r.worktree.target)?;
        let fingerprint = digest(&serde_json::to_vec(r).map_err(io_error)?);
        let ledger = self.files.ledger.lock().unwrap();
        let _lock = ledger.lock()?;
        existing_identity(&ledger, r.operation, &r.worktree.target, fingerprint)
    }

    /// Lookup-only legacy wire guard; this never accepts a new mutation.
    pub fn refuse_unprepared_worktree_sync(
        &self,
        r: &GitMutationRequest,
    ) -> Result<OperationReceipt, CoreError> {
        if let Some(receipt) = self.existing_receipt_sync(r)? {
            return Ok(receipt);
        }
        #[cfg(test)]
        if let Some(checkpoint) = &self.after_proof_lookup {
            checkpoint();
        }
        let mutex = repository_mutex(&r.worktree);
        let _repository = mutex.try_lock().map_err(|_| {
            CoreError::new(
                ErrorCode::Unavailable,
                "repository execution is busy; original operation lookup remains unresolved",
            )
        })?;
        if let Some(receipt) = self.existing_receipt_sync(r)? {
            return Ok(receipt);
        }
        Ok(failure(
            r.operation,
            r.worktree.target.clone(),
            CoreError::new(
                ErrorCode::Unavailable,
                "worktree mutation requires target-owned preparation",
            ),
        ))
    }
    pub fn mutate_sync(&self, r: GitMutationRequest, cancel: &AtomicBool) -> OperationReceipt {
        let expected = r.expected.clone();
        self.mutate_after_document_saves_sync(r, expected, cancel)
    }
    /// The engine may update execution expectations after approved saves; durable request identity stays original.
    pub fn mutate_after_document_saves_sync(
        &self,
        r: GitMutationRequest,
        execution_expected: GitExpectedState,
        cancel: &AtomicBool,
    ) -> OperationReceipt {
        let id = r.operation;
        let target = r.worktree.target.clone();
        self.mutate_guarded(r, execution_expected, cancel, None)
            .unwrap_or_else(|error| failure(id, target, error))
    }
    pub(super) fn mutate_guarded(
        &self,
        r: GitMutationRequest,
        mut execution_expected: GitExpectedState,
        cancel: &AtomicBool,
        mut proof: Option<WorktreeProofGuard<'_>>,
    ) -> Result<OperationReceipt, CoreError> {
        let target = r.worktree.target.clone();
        let id = r.operation;
        (|| -> Result<OperationReceipt, CoreError> {
            if target != *self.files.target() {
                return Err(CoreError::new(
                    ErrorCode::TargetChanged,
                    "Git target changed",
                ));
            }
            let fingerprint = digest(&serde_json::to_vec(&r).map_err(io_error)?);
            let mutex = repository_mutex(&r.worktree);
            let _repository = mutex.lock().unwrap();
            {
                let ledger = self.files.ledger.lock().unwrap();
                let _lock = ledger.lock()?;
                if let Some(old) = ledger.read(id)? {
                    if old.envelope.request_digest != fingerprint || old.envelope.target != target {
                        return Err(CoreError::new(
                            ErrorCode::InvalidArgument,
                            "Operation ID reused with different Git request",
                        ));
                    }
                    return ledger.inspect(id, target.clone());
                }
            }
            if let Some(proof) = proof.as_mut() {
                execution_expected = (proof.verify)(false)?;
            }
            let root = self.validate(&r.worktree, cancel)?;
            let current = self.state(&root, cancel)?;
            if current != execution_expected {
                return Err(CoreError::new(
                    ErrorCode::StaleRevision,
                    "Repository changed; refresh before mutation",
                ));
            }
            let args = match &r.command {
                GitMutation::Repository(action) => {
                    self.repository_action_args(&r.worktree, action, cancel)?
                }
                GitMutation::Stage(paths) | GitMutation::Unstage(paths) => {
                    if paths.is_empty() {
                        return Err(CoreError::new(
                            ErrorCode::InvalidArgument,
                            "No selected paths",
                        ));
                    }
                    let mut args = match &r.command {
                        GitMutation::Stage(_) => process::args(&["add", "--all"]),
                        _ if matches!(current.head, GitHead::Unborn(_)) => {
                            process::args(&["rm", "--cached", "--force", "--ignore-unmatch"])
                        }
                        _ => process::args(&["reset", "-q", "HEAD"]),
                    };
                    let staged = if matches!(r.command, GitMutation::Unstage(_)) {
                        let snapshot = self.status_sync(r.worktree.clone(), cancel)?;
                        if snapshot.state != current {
                            return Err(CoreError::new(
                                ErrorCode::StaleRevision,
                                "Index changed before unstage",
                            ));
                        }
                        snapshot.staged
                    } else {
                        vec![]
                    };
                    args.push("--".into());
                    for p in paths {
                        args.push(self.selected(&root, p)?);
                        if let Some(previous) = staged
                            .iter()
                            .find(|e| &e.path == p)
                            .and_then(|e| e.previous_path.as_ref())
                        {
                            args.push(self.selected(&root, previous)?);
                        }
                    }
                    args
                }
                GitMutation::Commit { message } => {
                    if message.trim().is_empty()
                        || message.len() > 64 * 1024
                        || message.contains('\0')
                    {
                        return Err(CoreError::new(
                            ErrorCode::InvalidArgument,
                            "Enter a bounded nonempty commit message",
                        ));
                    }
                    let mut args = process::args(&["commit", "-m"]);
                    args.push(OsString::from(message));
                    args
                }
                GitMutation::Fetch { remote } => {
                    let mut args = process::args(&["fetch", "--"]);
                    args.push(argument(remote)?);
                    args
                }
                GitMutation::Push { remote, reference }
                | GitMutation::PullFastForward { remote, reference } => {
                    if reference.iter().any(|b| b"+:*?[]\\".contains(b)) {
                        return Err(CoreError::new(
                            ErrorCode::InvalidArgument,
                            "Select a single ref; force/delete/wildcard refspecs are not supported",
                        ));
                    }
                    let mut args = if matches!(r.command, GitMutation::Push { .. }) {
                        process::args(&["push", "--"])
                    } else {
                        process::args(&[
                            "pull",
                            "--ff-only",
                            "--no-rebase",
                            "--no-autostash",
                            "--no-recurse-submodules",
                            "--",
                        ])
                    };
                    args.push(argument(remote)?);
                    args.push(argument(reference)?);
                    args
                }
                GitMutation::Checkout { reference } => {
                    let mut args =
                        process::args(&["checkout", "--no-guess", "--no-recurse-submodules"]);
                    args.push(argument(reference)?);
                    args.push("--".into());
                    args
                }
            };
            let network_intent = super::network::intent(&root, &r.command, cancel);
            self.retain_merge_context(&r)?;
            let mut record = Record {
                envelope: OperationEnvelope {
                    id,
                    target: target.clone(),
                    request_digest: fingerprint,
                    kind: MutationKind::Git,
                    expected: ExpectedState::Git {
                        worktree: r.worktree.clone(),
                        state: execution_expected.clone(),
                    },
                },
                destination: None,
                save_proof: None,
                terminal_request: None,
                git_intent: network_intent.clone(),
                requested_digest: fingerprint,
                revision: BufferRevision(0),
                receipt: OperationReceipt {
                    id,
                    state: OperationState::Accepted,
                },
                created: now(),
            };
            #[cfg(test)]
            if let Some(checkpoint) = &self.before_accept {
                checkpoint();
            }
            {
                let ledger = self.files.ledger.lock().unwrap();
                let _lock = ledger.lock()?;
                if let Some(proof) = proof.as_ref() {
                    proof.check()?;
                }
                if let Some(existing) = ledger.accept(&record, &_lock)? {
                    return Ok(existing);
                }
                #[cfg(test)]
                if let Some(checkpoint) = &self.after_accept {
                    checkpoint();
                }
                if let Some(proof) = proof.as_ref()
                    && let Err(error) = proof.check()
                {
                    record.receipt = failure(id, target.clone(), error);
                    if ledger.write(&record).is_err() {
                        return Ok(unknown(
                            id,
                            target.clone(),
                            "revoked Git acceptance could not be recorded; inspect, never replay",
                        ));
                    }
                    return Ok(record.receipt);
                }
                record.receipt.state = OperationState::Running;
                ledger.write(&record)?;
            }
            #[cfg(test)]
            if let Some(checkpoint) = &self.after_authorization {
                checkpoint();
            }
            let before_execution = if let Some(proof) = proof.as_mut() {
                (proof.verify)(true)
            } else {
                self.state(&root, cancel)
            };
            let before_execution = before_execution.and_then(|state| {
                if let GitMutation::Repository(action) = &r.command {
                    self.repository_action_args(&r.worktree, action, cancel)?;
                }
                Ok(state)
            });
            if before_execution.as_ref() != Ok(&execution_expected) {
                record.receipt = match before_execution {
                    Ok(state) => OperationReceipt {
                        id,
                        state: OperationState::Failed(OperationFailure {
                            error: CoreError::new(
                                ErrorCode::StaleRevision,
                                "Repository changed after acceptance; no Git command executed",
                            ),
                            target: target.clone(),
                            observed: ObservedState::Git {
                                worktree: r.worktree.clone(),
                                state,
                            },
                            effect: FailureEffect::ProvenNoEffect,
                        }),
                    },
                    Err(error) => failure(id, target.clone(), error),
                };
                let ledger = self.files.ledger.lock().unwrap();
                let lock = ledger.lock();
                if lock.is_err() || ledger.write(&record).is_err() {
                    return Ok(unknown(
                        id,
                        target.clone(),
                        "Accepted Git operation could not record its refusal; inspect, never replay",
                    ));
                }
                return Ok(record.receipt);
            }
            let mut output = process::run(&root, &args, cancel);
            let diagnostic = output
                .as_ref()
                .ok()
                .filter(|v| !v.success)
                .map(|v| v.diagnostic());
            if output.as_ref().is_ok_and(|v| !v.interrupted)
                && self.reconcile_merge(&r, &AtomicBool::new(false), diagnostic)
                && let Ok(output) = &mut output
            {
                output.success = true;
            }
            // Reconciliation ignores cancellation: the original process has exited; never replay it.
            let observed = self.state(&root, &AtomicBool::new(false));
            let reconciliation_cancel = AtomicBool::new(false);
            let observation_cancel = if cancel.load(std::sync::atomic::Ordering::SeqCst) {
                &reconciliation_cancel
            } else {
                cancel
            };
            let network_observation = if output.as_ref().is_ok_and(|o| o.success) {
                None
            } else {
                network_intent.as_ref().map(|intent| {
                    super::network::observe(&root, intent, &r.command, observation_cancel)
                })
            };
            record.receipt = match (output, observed) {
                (Ok(output), Ok(state)) if output.success => {
                    match self.repository_outcome(&r, &state) {
                        Ok(outcome) => OperationReceipt {
                            id,
                            state: OperationState::Confirmed(MutationResult::GitChanged {
                                worktree: r.worktree.clone(),
                                state,
                                outcome,
                            }),
                        },
                        Err(error) => OperationReceipt {
                            id,
                            state: OperationState::Unknown(ReconciliationEvidence {
                                target: target.clone(),
                                observed: ObservedState::Git {
                                    worktree: r.worktree.clone(),
                                    state,
                                },
                                explanation: error.message,
                            }),
                        },
                    }
                }
                (Ok(output), Ok(state)) => {
                    let mut message = if network_intent.is_some() {
                        // Transport stderr may contain credential-bearing URLs.
                        "Git network action did not complete successfully; inspect its observed state".to_owned()
                    } else {
                        output.diagnostic()
                    };
                    let observed = if let Some(intent) = network_intent {
                        let observation = match network_observation {
                            Some(Ok(observation)) => Some(observation),
                            Some(Err(error)) => {
                                // Only adapter-owned policy messages are safe; transport stderr may echo credentials.
                                message.push('\n');
                                message.push_str(if error.code == ErrorCode::Unavailable {
                                    &error.message
                                } else {
                                    "Network observation unresolved; terminal handoff disabled"
                                });
                                None
                            }
                            None => None,
                        };
                        ObservedState::GitNetwork {
                            worktree: r.worktree.clone(),
                            state,
                            intent,
                            observation,
                        }
                    } else {
                        ObservedState::Git {
                            worktree: r.worktree.clone(),
                            state,
                        }
                    };
                    OperationReceipt {
                        id,
                        state: if output.interrupted
                            || matches!(
                                &observed,
                                ObservedState::GitNetwork {
                                    observation: None,
                                    ..
                                }
                            ) {
                            OperationState::Unknown(ReconciliationEvidence {
                                target: target.clone(),
                                observed,
                                explanation: message,
                            })
                        } else {
                            OperationState::Failed(OperationFailure {
                                error: io_error(message),
                                target: target.clone(),
                                observed,
                                effect: FailureEffect::PossiblePartialEffects,
                            })
                        },
                    }
                }
                _ => unknown(
                    id,
                    target.clone(),
                    "Git outcome could not be observed; never replay; inspect before terminal handoff",
                ),
            };
            {
                let ledger = self.files.ledger.lock().unwrap();
                let lock = ledger.lock();
                if lock.is_err() || ledger.write(&record).is_err() {
                    return Ok(unknown(
                        id,
                        target.clone(),
                        "Git finished but durable acknowledgement failed; inspect, never replay",
                    ));
                }
            }
            Ok(record.receipt)
        })()
    }
}

fn existing_identity(
    ledger: &crate::operations::ledger::Ledger,
    operation: OperationID,
    target: &TargetIdentity,
    fingerprint: [u8; 32],
) -> Result<Option<OperationReceipt>, CoreError> {
    let Some(record) = ledger.read(operation)? else {
        return Ok(None);
    };
    if record.envelope.request_digest != fingerprint || &record.envelope.target != target {
        return Err(CoreError::new(
            ErrorCode::InvalidArgument,
            "Operation ID reused with different Git request",
        ));
    }
    ledger.inspect(operation, target.clone()).map(Some)
}

fn argument(bytes: &[u8]) -> Result<OsString, CoreError> {
    use std::os::unix::ffi::OsStrExt;
    if bytes.is_empty() || bytes.contains(&0) || bytes[0] == b'-' {
        return Err(CoreError::new(
            ErrorCode::InvalidArgument,
            "Invalid remote or ref",
        ));
    }
    Ok(std::ffi::OsStr::from_bytes(bytes).to_owned())
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use std::{fs, path::Path, process::Command, sync::Barrier};
    fn git(root: &Path, args: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
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
        output.stdout
    }
    #[test]
    fn streamed_lookup_preserves_real_receipts_unknown_and_identity_without_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let local =
            crate::connections::local::LocalConnection::open(dir.path().join("state")).unwrap();
        let root = dir.path().join("repo");
        fs::create_dir(&root).unwrap();
        git(&root, &["init", "-b", "main"]);
        fs::write(root.join("file"), "data").unwrap();
        let root = fs::canonicalize(root).unwrap();
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
        let original = GitMutationRequest {
            operation: OperationID([117; 16]),
            expected: local
                .git
                .status_sync(worktree.clone(), &cancel)
                .unwrap()
                .state,
            worktree,
            command: GitMutation::Stage(vec![crate::files::target_path(&root.join("file"))]),
        };
        let sha = digest(&serde_json::to_vec(&original).unwrap());
        let lookup = || {
            local
                .git
                .existing_receipt_digest_sync(original.operation, &local.identity, sha)
        };
        assert_eq!(
            lookup().expect("streamed full original must be looked up"),
            None
        );
        let receipt = local.git.mutate_sync(original.clone(), &cancel);
        assert!(
            matches!(receipt.state, OperationState::Confirmed(_)),
            "{receipt:?}"
        );
        assert_eq!(lookup().unwrap(), Some(receipt.clone()));
        assert_eq!(
            local.git.existing_original_sync(&original).unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(
            local.git.existing_receipt_sync(&original).unwrap(),
            Some(receipt.clone())
        );
        assert!(
            local
                .git
                .existing_receipt_digest_sync(original.operation, &local.identity, [99; 32])
                .is_err()
        );
        let mut wrong_target = local.identity.clone();
        wrong_target.effective_user.push(0);
        assert!(
            local
                .git
                .existing_receipt_digest_sync(original.operation, &wrong_target, sha)
                .is_err()
        );
        assert_eq!(
            local
                .git
                .existing_receipt_digest_sync(OperationID([118; 16]), &local.identity, sha)
                .unwrap(),
            None
        );
        let directory = {
            let ledger = local.files.ledger.lock().unwrap();
            assert_eq!(
                lookup().unwrap_err().code,
                ErrorCode::Unavailable,
                "mutex contention must remain unresolved"
            );
            assert_eq!(
                local
                    .git
                    .existing_original_sync(&original)
                    .unwrap_err()
                    .code,
                ErrorCode::Unavailable
            );
            ledger.directory.clone()
        };
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.join("lock"))
            .unwrap();
        lock.lock().unwrap();
        assert_eq!(
            lookup().unwrap_err().code,
            ErrorCode::Unavailable,
            "disk contention must remain unresolved"
        );
        assert_eq!(
            local
                .git
                .existing_original_sync(&original)
                .unwrap_err()
                .code,
            ErrorCode::Unavailable
        );
        lock.unlock().unwrap();
        for state in [
            OperationState::Accepted,
            OperationState::Running,
            crate::operations::ledger::unknown(
                original.operation,
                local.identity.clone(),
                "uncertain",
            )
            .state,
        ] {
            let ledger = local.files.ledger.lock().unwrap();
            let guard = ledger.lock().unwrap();
            let mut record = ledger.read(original.operation).unwrap().unwrap();
            record.receipt.state = state;
            ledger.write(&record).unwrap();
            drop(guard);
            drop(ledger);
            assert!(matches!(
                lookup().unwrap().unwrap().state,
                OperationState::Unknown(_)
            ));
        }
        let ledger = local.files.ledger.lock().unwrap();
        let guard = ledger.lock().unwrap();
        let mut record = ledger.read(original.operation).unwrap().unwrap();
        record.created = 0;
        record.receipt = receipt;
        ledger.write(&record).unwrap();
        drop(guard);
        drop(ledger);
        let before = fs::read(directory.join(format!("{}.json", "75".repeat(16)))).unwrap();
        assert!(matches!(
            lookup().unwrap().unwrap().state,
            OperationState::Unknown(_)
        ));
        assert_eq!(
            fs::read(directory.join(format!("{}.json", "75".repeat(16)))).unwrap(),
            before
        );
    }
    #[test]
    fn file_admission_wins_while_git_waits_before_acceptance() {
        let dir = tempfile::tempdir().unwrap();
        let local =
            crate::connections::local::LocalConnection::open(dir.path().join("state")).unwrap();
        let root = dir.path().join("project");
        fs::create_dir(&root).unwrap();
        git(&root, &["init", "-b", "main"]);
        fs::write(root.join("file"), "bytes").unwrap();
        let root = fs::canonicalize(root).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let gate = barrier.clone();
        let mut service = LocalGitService::new(local.files.clone());
        service.before_accept = Some(Arc::new(move || {
            gate.wait();
            gate.wait();
        }));
        let worktree = service
            .discover_sync(
                FileRef {
                    target: local.identity.clone(),
                    path: crate::files::target_path(&root),
                    resolved_identity: None,
                },
                &AtomicBool::new(false),
            )
            .unwrap()
            .unwrap();
        let state = service
            .status_sync(worktree.clone(), &AtomicBool::new(false))
            .unwrap()
            .state;
        let id = OperationID([72; 16]);
        let selected = crate::files::target_path(&root.join("file"));
        let worker = std::thread::spawn(move || {
            service.mutate_sync(
                GitMutationRequest {
                    operation: id,
                    worktree,
                    expected: state,
                    command: GitMutation::Stage(vec![selected]),
                },
                &AtomicBool::new(false),
            )
        });
        barrier.wait();
        let request = FileMutationRequest {
            operation: id,
            file: FileRef {
                target: local.identity.clone(),
                path: crate::files::target_path(&dir.path().join("new-folder")),
                resolved_identity: None,
            },
            expected: ExpectedPathState::Absent,
            command: FileMutation::CreateDirectory,
        };
        let receipt = local.files.mutate_sync(request.clone());
        barrier.wait();
        let refused = worker.join().unwrap();
        assert!(matches!(receipt.state, OperationState::Confirmed(_)));
        assert!(matches!(refused.state, OperationState::Failed(_)));
        assert!(git(&root, &["ls-files", "--cached"]).is_empty());
        assert_eq!(
            local
                .files
                .inspect_sync(id, local.identity.clone())
                .unwrap(),
            receipt
        );
        assert_eq!(local.files.mutate_sync(request), receipt);
    }
    #[test]
    fn concurrent_different_repositories_same_id_have_one_effect_and_original_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let local =
            crate::connections::local::LocalConnection::open(dir.path().join("state")).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let mut service = LocalGitService::new(local.files.clone());
        service.before_accept = Some(Arc::new(move || {
            barrier.wait();
        }));
        let service = Arc::new(service);
        let id = OperationID([71; 16]);
        let mut requests = vec![];
        let mut roots = vec![];
        for name in ["one", "two"] {
            let root = dir.path().join(name);
            fs::create_dir(&root).unwrap();
            git(&root, &["init", "-b", "main"]);
            fs::write(root.join("file"), name).unwrap();
            let root = fs::canonicalize(root).unwrap();
            let file = FileRef {
                target: local.identity.clone(),
                path: crate::files::target_path(&root),
                resolved_identity: None,
            };
            let worktree = service
                .discover_sync(file, &AtomicBool::new(false))
                .unwrap()
                .unwrap();
            let state = service
                .status_sync(worktree.clone(), &AtomicBool::new(false))
                .unwrap()
                .state;
            requests.push(GitMutationRequest {
                operation: id,
                worktree,
                expected: state,
                command: GitMutation::Stage(vec![crate::files::target_path(&root.join("file"))]),
            });
            roots.push(root);
        }
        let joins: Vec<_> = requests
            .iter()
            .cloned()
            .map(|request| {
                let service = service.clone();
                std::thread::spawn(move || service.mutate_sync(request, &AtomicBool::new(false)))
            })
            .collect();
        let receipts: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
        let confirmed: Vec<_> = receipts
            .iter()
            .filter(|r| matches!(r.state, OperationState::Confirmed(_)))
            .collect();
        assert_eq!(
            confirmed.len(),
            1,
            "only one admission may execute: {receipts:?}"
        );
        assert_eq!(
            roots
                .iter()
                .filter(|p| !git(p, &["ls-files", "--cached"]).is_empty())
                .count(),
            1
        );
        let original = local
            .files
            .inspect_sync(id, local.identity.clone())
            .unwrap();
        assert_eq!(&original, confirmed[0]);
        let winner = receipts.iter().position(|r| r == &original).unwrap();
        assert_eq!(
            service.mutate_sync(requests[winner].clone(), &AtomicBool::new(false)),
            original
        );
        assert!(matches!(
            service
                .mutate_sync(requests[1 - winner].clone(), &AtomicBool::new(false))
                .state,
            OperationState::Failed(_)
        ));
        assert_eq!(
            local
                .files
                .inspect_sync(id, local.identity.clone())
                .unwrap(),
            original
        );
    }
}
