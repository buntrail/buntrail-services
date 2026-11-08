use super::{LocalGitService, process};
use crate::files::io_error;
use buntrail_core::contracts::*;
use std::sync::atomic::AtomicBool;

pub(super) fn oid(raw: &[u8]) -> Result<String, CoreError> {
    if !matches!(raw.len(), 40 | 64) || !raw.iter().all(u8::is_ascii_hexdigit) {
        return Err(io_error("Invalid Git object ID"));
    }
    Ok(String::from_utf8_lossy(raw).into_owned())
}
impl LocalGitService {
    pub fn repository_sync(
        &self,
        worktree: WorktreeIdentity,
        cancel: &AtomicBool,
    ) -> Result<GitRepositorySnapshot, CoreError> {
        let root = self.validate(&worktree, cancel)?;
        let snapshot = self.status_sync(worktree.clone(), cancel)?;
        let raw = self.command(
            &root,
            &process::args(&[
                "for-each-ref",
                "--format=%(refname)%00%(objectname)%00%(*objectname)%00%(HEAD)%00%(symref)",
                "refs/heads",
                "refs/tags",
                "refs/remotes",
            ]),
            cancel,
        )?;
        let mut refs = vec![];
        for row in raw.split(|b| *b == b'\n').filter(|r| !r.is_empty()) {
            let fields = row.split(|b| *b == 0).collect::<Vec<_>>();
            if fields.len() != 5 || !fields[0].starts_with(b"refs/") {
                return Err(io_error("Invalid repository reference"));
            }
            if !fields[4].is_empty() {
                continue;
            }
            refs.push(GitRef {
                name: fields[0].to_vec(),
                oid: oid(fields[1])?,
                peeled_oid: if fields[2].is_empty() {
                    None
                } else {
                    Some(oid(fields[2])?)
                },
                current: fields[3] == b"*",
            });
        }
        let raw = self.command(
            &root,
            &process::args(&["stash", "list", "--format=%H%x00%gd%x00%gs%x00"]),
            cancel,
        )?;
        let mut fields = raw.split(|b| *b == 0);
        let mut stashes = vec![];
        while let Some(id) = fields.next() {
            let id = id.strip_prefix(b"\n").unwrap_or(id);
            if id.is_empty() {
                break;
            }
            let selector = fields.next().ok_or_else(|| io_error("Incomplete stash"))?;
            let subject = fields.next().ok_or_else(|| io_error("Incomplete stash"))?;
            stashes.push(GitStash {
                oid: oid(id)?,
                selector: selector.to_vec(),
                subject: String::from_utf8_lossy(subject).into_owned(),
            });
        }
        let raw = self.command(&root, &process::args(&["remote"]), cancel)?;
        let remotes = raw
            .split(|b| *b == b'\n')
            .filter(|r| !r.is_empty())
            .map(|v| v.to_vec())
            .collect();
        let raw = self.command(
            &root,
            &process::args(&["worktree", "list", "--porcelain", "-z"]),
            cancel,
        )?;
        let mut worktrees: Vec<GitWorktree> = vec![];
        for record in raw.split(|b| *b == 0) {
            if let Some(path) = record.strip_prefix(b"worktree ") {
                worktrees.push(GitWorktree {
                    path: TargetPath::posix(path.to_vec())?,
                    branch: None,
                });
            } else if let Some(branch) = record.strip_prefix(b"branch ") {
                worktrees
                    .last_mut()
                    .ok_or_else(|| io_error("Invalid worktree record"))?
                    .branch = Some(branch.to_vec());
            }
        }
        let raw = process::run(
            &root,
            &process::args(&["rev-parse", "--verify", "--quiet", "MERGE_HEAD"]),
            cancel,
        )?;
        let mut merge = if raw.success {
            Some(GitMergeState {
                error: None,
                session: None,
                message: String::new(),
                heads: raw
                    .stdout
                    .split(|b| *b == b'\n')
                    .filter(|v| !v.is_empty())
                    .map(oid)
                    .collect::<Result<_, _>>()?,
                conflicts: snapshot.conflicts.iter().map(|v| v.path.clone()).collect(),
            })
        } else if raw.interrupted {
            return Err(io_error(raw.diagnostic()));
        } else {
            None
        };
        if let Some(merge) = &mut merge {
            if let Ok(context) = self.read_merge_context(&worktree)
                && context.head == snapshot.state.head
                && merge.heads.first() == Some(&context.source_oid)
                && context.marker.is_some()
                && self.merge_marker(&worktree, cancel).ok().as_ref() == context.marker.as_ref()
            {
                merge.error = context.error;
                if context.abort_authority && merge.heads == vec![context.source_oid] {
                    merge.session = Some(context.operation);
                }
            }
            let raw = process::run(
                &root,
                &process::args(&["rev-parse", "--git-path", "MERGE_MSG"]),
                cancel,
            )?;
            if raw.success {
                use std::os::unix::ffi::OsStrExt;
                let value = raw.stdout.strip_suffix(b"\n").unwrap_or(&raw.stdout);
                let path = std::path::Path::new(std::ffi::OsStr::from_bytes(value));
                let path = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    root.join(path)
                };
                let metadata = std::fs::metadata(&path).map_err(io_error)?;
                if metadata.len() > 1024 * 1024 {
                    return Err(io_error(
                        "Merge message exceeds the 1 MiB inspection limit; inspect it in the terminal",
                    ));
                }
                merge.message = std::fs::read_to_string(path).map_err(|_| {
                    io_error("Merge message cannot be read as UTF-8; inspect it in the terminal")
                })?;
            }
        }
        if self.state(&root, cancel)? != snapshot.state {
            return Err(CoreError::new(
                ErrorCode::StaleRevision,
                "Repository changed during inspection; refresh",
            ));
        }
        let mut changes = snapshot.staged.clone();
        for entry in snapshot.unstaged.iter().chain(&snapshot.conflicts) {
            if !changes.iter().any(|v| v.path == entry.path) {
                changes.push(entry.clone());
            }
        }
        Ok(GitRepositorySnapshot {
            changes,
            worktree,
            state: snapshot.state,
            refs,
            stashes,
            remotes,
            worktrees,
            merge,
        })
    }
}

impl LocalGitService {
    pub(super) fn repository_action_args(
        &self,
        worktree: &WorktreeIdentity,
        action: &RepositoryAction,
        cancel: &AtomicBool,
    ) -> Result<Vec<std::ffi::OsString>, CoreError> {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
        let root = self.validate(worktree, cancel)?;
        let snapshot = self.repository_sync(worktree.clone(), cancel)?;
        if snapshot.merge.is_some()
            && !matches!(
                action,
                RepositoryAction::ContinueMerge { .. } | RepositoryAction::AbortMerge { .. }
            )
        {
            return Err(io_error(
                "Finish or abort the current merge before changing branches or references",
            ));
        }
        let name_arg = |name: &[u8], prefix: &[u8]| -> Result<std::ffi::OsString, CoreError> {
            if name.is_empty() || name.len() > 4096 || name.starts_with(b"-") || name.contains(&0) {
                return Err(io_error("Invalid reference name"));
            }
            let full = [prefix, name].concat();
            let mut args = process::args(&["check-ref-format"]);
            args.push(OsStr::from_bytes(&full).to_owned());
            self.command(&root, &args, cancel)?;
            Ok(OsStr::from_bytes(name).to_owned())
        };
        let existing =
            |name: &[u8], expected: &str| -> Result<(), CoreError> {
                oid(expected.as_bytes())?;
                if !snapshot.refs.iter().any(|r| {
                    r.name == [b"refs/heads/".as_slice(), name].concat() && r.oid == expected
                }) {
                    return Err(CoreError::new(
                        ErrorCode::StaleRevision,
                        "Selected branch changed; refresh",
                    ));
                }
                Ok(())
            };
        let free = |name: &[u8], prefix: &[u8]| -> Result<(), CoreError> {
            if snapshot
                .refs
                .iter()
                .any(|r| r.name == [prefix, name].concat())
            {
                return Err(io_error("A reference with this name already exists"));
            }
            Ok(())
        };
        let elsewhere = |name: &[u8]| {
            snapshot.worktrees.iter().any(|w| {
                w.branch.as_deref() == Some([b"refs/heads/".as_slice(), name].concat().as_slice())
                    && w.path != worktree.canonical_path
            })
        };
        let args = match action {
            RepositoryAction::Merge {
                source_ref,
                source_oid,
            } => {
                if snapshot.merge.is_some() {
                    return Err(io_error("A merge is already in progress"));
                }
                let status = self.status_sync(worktree.clone(), cancel)?;
                if !status.staged.is_empty()
                    || !status.unstaged.is_empty()
                    || !status.untracked.is_empty()
                    || !status.conflicts.is_empty()
                {
                    return Err(io_error(
                        "Save and commit or stash working changes before merging",
                    ));
                }
                if !snapshot
                    .refs
                    .iter()
                    .any(|r| &r.name == source_ref && &r.oid == source_oid)
                {
                    return Err(CoreError::new(
                        ErrorCode::StaleRevision,
                        "Merge source changed; refresh",
                    ));
                }
                if !matches!(snapshot.state.head, GitHead::Branch { .. }) {
                    return Err(io_error("Check out a branch before merging"));
                }
                let mut args = process::args(&[
                    "-c",
                    "submodule.recurse=false",
                    "merge",
                    "--ff",
                    "--no-edit",
                    "--no-squash",
                    "--commit",
                    "--verify",
                    "--no-autostash",
                    "--no-overwrite-ignore",
                ]);
                args.push(source_oid.into());
                args
            }
            RepositoryAction::ContinueMerge {
                session,
                expected_heads,
                message,
            } => {
                let merge = snapshot
                    .merge
                    .as_ref()
                    .ok_or_else(|| io_error("No merge is in progress"))?;
                if merge.session.as_ref() != session.as_ref() || &merge.heads != expected_heads {
                    return Err(io_error("Merge identity changed; inspect the repository"));
                }
                if !merge.conflicts.is_empty() {
                    return Err(io_error(
                        "Resolve, save and stage all conflicts before continuing",
                    ));
                }
                if message.trim().is_empty() || message.len() > 64 * 1024 || message.contains('\0')
                {
                    return Err(io_error("Enter a bounded merge message"));
                }
                let mut args = process::args(&["commit", "-m"]);
                args.push(message.into());
                args
            }
            RepositoryAction::AbortMerge { session } => {
                let merge = snapshot
                    .merge
                    .as_ref()
                    .ok_or_else(|| io_error("No merge is in progress"))?;
                if merge.session.as_ref() != Some(session) {
                    return Err(io_error(
                        "No owned clean merge baseline; inspect this merge in the terminal",
                    ));
                }
                process::args(&["merge", "--abort"])
            }

            RepositoryAction::CreateBranch {
                name,
                source_ref,
                start_oid,
            }
            | RepositoryAction::CreateTag {
                name,
                source_ref,
                start_oid,
            } => {
                let prefix = if matches!(action, RepositoryAction::CreateTag { .. }) {
                    b"refs/tags/".as_slice()
                } else {
                    b"refs/heads/".as_slice()
                };
                name_arg(name, prefix)?;
                free(name, prefix)?;
                oid(start_oid.as_bytes())?;
                if !snapshot
                    .refs
                    .iter()
                    .any(|r| &r.name == source_ref && &r.oid == start_oid)
                {
                    return Err(CoreError::new(
                        ErrorCode::StaleRevision,
                        "Source reference changed; refresh",
                    ));
                }
                let mut args = process::args(&["update-ref"]);
                args.push(OsStr::from_bytes(&[prefix, name].concat()).to_owned());
                args.push(start_oid.into());
                args.push("".into());
                args
            }
            RepositoryAction::RenameBranch {
                name,
                new_name,
                expected_oid,
            } => {
                existing(name, expected_oid)?;
                if elsewhere(name) {
                    return Err(io_error("Branch is checked out in another worktree"));
                }
                let old = name_arg(name, b"refs/heads/")?;
                let new = name_arg(new_name, b"refs/heads/")?;
                free(new_name, b"refs/heads/")?;
                let mut args = process::args(&["branch", "-m", "--"]);
                args.push(old);
                args.push(new);
                args
            }
            RepositoryAction::DeleteBranch { name, expected_oid } => {
                existing(name, expected_oid)?;
                if snapshot.worktrees.iter().any(|w| {
                    w.branch.as_deref()
                        == Some(
                            [b"refs/heads/".as_slice(), name.as_ref()]
                                .concat()
                                .as_slice(),
                        )
                }) {
                    return Err(io_error("Cannot delete a checked-out branch"));
                }
                let mut ancestry = process::args(&["merge-base", "--is-ancestor"]);
                ancestry.push(expected_oid.into());
                ancestry.push("HEAD".into());
                self.command(&root, &ancestry, cancel).map_err(|_| {
                    io_error("Branch has commits not merged into HEAD; deletion refused")
                })?;
                let mut args = process::args(&["branch", "-d", "--"]);
                args.push(name_arg(name, b"refs/heads/")?);
                args
            }
            RepositoryAction::SwitchBranch { name, expected_oid } => {
                existing(name, expected_oid)?;
                if elsewhere(name) {
                    return Err(io_error("Branch is checked out in another worktree"));
                }
                let mut args =
                    process::args(&["checkout", "--no-guess", "--no-recurse-submodules"]);
                args.push(name_arg(name, b"refs/heads/")?);
                args.push("--".into());
                args
            }
        };
        Ok(args)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct MergeContext {
    pub operation: OperationID,
    pub head: GitHead,
    pub source_oid: String,
    #[serde(default)]
    pub marker: Option<FileVersion>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub abort_authority: bool,
}
impl LocalGitService {
    fn merge_context_path(
        &self,
        worktree: &WorktreeIdentity,
    ) -> Result<std::path::PathBuf, CoreError> {
        use sha2::{Digest, Sha256};
        let bytes = Sha256::digest(serde_json::to_vec(worktree).map_err(io_error)?);
        let name = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let ledger = self.files.ledger.lock().unwrap();
        Ok(ledger
            .directory
            .join("merge-contexts")
            .join(format!("{name}.json")))
    }
    pub(super) fn read_merge_context(
        &self,
        worktree: &WorktreeIdentity,
    ) -> Result<MergeContext, CoreError> {
        let path = self.merge_context_path(worktree)?;
        let metadata = std::fs::symlink_metadata(&path).map_err(io_error)?;
        if !metadata.is_file() || metadata.len() > 65536 {
            return Err(io_error("Invalid merge context"));
        }
        serde_json::from_slice(&std::fs::read(path).map_err(io_error)?).map_err(io_error)
    }
    pub(super) fn retain_merge_context(
        &self,
        request: &GitMutationRequest,
    ) -> Result<(), CoreError> {
        let GitMutation::Repository(RepositoryAction::Merge { source_oid, .. }) = &request.command
        else {
            return Ok(());
        };
        let path = self.merge_context_path(&request.worktree)?;
        self.write_merge_context(
            &path,
            &MergeContext {
                operation: request.operation,
                head: request.expected.head.clone(),
                source_oid: source_oid.clone(),
                marker: None,
                error: None,
                abort_authority: true,
            },
        )
    }
    fn write_merge_context(
        &self,
        path: &std::path::Path,
        context: &MergeContext,
    ) -> Result<(), CoreError> {
        crate::files::private_directory(path.parent().unwrap())?;
        crate::files::atomic_private(path, &serde_json::to_vec(context).map_err(io_error)?)
    }
    fn merge_marker(
        &self,
        worktree: &WorktreeIdentity,
        cancel: &AtomicBool,
    ) -> Result<FileVersion, CoreError> {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
        let root = crate::files::path(&worktree.canonical_path)?;
        let raw = self.command(
            &root,
            &process::args(&["rev-parse", "--git-path", "MERGE_HEAD"]),
            cancel,
        )?;
        let bytes = raw
            .strip_suffix(b"\n")
            .ok_or_else(|| io_error("Invalid merge marker path"))?;
        let path = std::path::Path::new(OsStr::from_bytes(bytes));
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            root.join(path)
        };
        if std::fs::metadata(&path).map_err(io_error)?.len() > 65536 {
            return Err(io_error("Merge marker exceeds bound"));
        }
        Ok(self
            .files
            .read_sync(FileRef {
                target: worktree.target.clone(),
                path: crate::files::target_path(&path),
                resolved_identity: None,
            })?
            .version)
    }
    pub(super) fn reconcile_merge(
        &self,
        request: &GitMutationRequest,
        cancel: &AtomicBool,
        diagnostic: Option<String>,
    ) -> bool {
        let GitMutation::Repository(action) = &request.command else {
            return false;
        };
        if !matches!(
            action,
            RepositoryAction::Merge { .. }
                | RepositoryAction::ContinueMerge { .. }
                | RepositoryAction::AbortMerge { .. }
        ) {
            return false;
        }
        let Ok(snapshot) = self.repository_sync(request.worktree.clone(), cancel) else {
            return false;
        };
        if let Some(merge) = snapshot.merge {
            if snapshot.state.head != request.expected.head {
                return false;
            }
            let Ok(marker) = self.merge_marker(&request.worktree, cancel) else {
                return false;
            };
            let Ok(path) = self.merge_context_path(&request.worktree) else {
                return false;
            };
            let mut context = match action {
                RepositoryAction::Merge { source_oid, .. }
                    if merge.heads == vec![source_oid.clone()] =>
                {
                    let Ok(context) = self.read_merge_context(&request.worktree) else {
                        return false;
                    };
                    if context.operation != request.operation {
                        return false;
                    }
                    context
                }
                RepositoryAction::ContinueMerge {
                    session,
                    expected_heads,
                    ..
                } if &merge.heads == expected_heads && &merge.session == session => self
                    .read_merge_context(&request.worktree)
                    .ok()
                    .filter(|c| c.marker.as_ref() == Some(&marker))
                    .unwrap_or(MergeContext {
                        operation: request.operation,
                        head: request.expected.head.clone(),
                        source_oid: merge.heads[0].clone(),
                        marker: None,
                        error: None,
                        abort_authority: false,
                    }),
                RepositoryAction::AbortMerge { session } if merge.session == Some(*session) => {
                    let Ok(context) = self.read_merge_context(&request.worktree) else {
                        return false;
                    };
                    context
                }
                _ => return false,
            };
            context.marker = Some(marker);
            context.error = diagnostic;
            return self.write_merge_context(&path, &context).is_ok();
        }
        if let Ok(path) = self.merge_context_path(&request.worktree) {
            let _ = std::fs::remove_file(path);
        }
        false
    }
    pub(super) fn repository_outcome(
        &self,
        request: &GitMutationRequest,
        state: &GitExpectedState,
    ) -> Result<Option<Box<RepositoryOutcome>>, CoreError> {
        let GitMutation::Repository(action) = &request.command else {
            return Ok(None);
        };
        let snapshot = self.repository_sync(request.worktree.clone(), &AtomicBool::new(false))?;
        if &snapshot.state != state {
            return Err(io_error(
                "Repository changed while confirming outcome; inspect pending operations",
            ));
        }
        if let Some(merge) = snapshot.merge {
            return Ok(Some(Box::new(RepositoryOutcome::MergePending { merge })));
        }
        let outcome = match action {
            RepositoryAction::Merge { .. } | RepositoryAction::ContinueMerge { .. } => {
                let oid = match &state.head {
                    GitHead::Branch { oid, .. } | GitHead::Detached(oid) => oid.clone(),
                    GitHead::Unborn(_) => return Err(io_error("Merge result has no commit")),
                };
                RepositoryOutcome::Merged { oid }
            }
            RepositoryAction::AbortMerge { .. } => RepositoryOutcome::MergeAborted,
            RepositoryAction::SwitchBranch { .. } => RepositoryOutcome::CheckedOut,
            _ => RepositoryOutcome::RefsUpdated,
        };
        Ok(Some(Box::new(outcome)))
    }
}
