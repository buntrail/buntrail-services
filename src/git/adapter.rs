use super::{output_parser, process};
use crate::{
    contracts::GitService,
    files::{LocalFileService, io_error, path, target_path},
};
use buntrail_core::contracts::{async_types::ServiceFuture, *};
use sha2::{Digest, Sha256};
use std::{
    ffi::{OsStr, OsString},
    fs,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
};
pub struct LocalGitService {
    pub(crate) files: Arc<LocalFileService>,
    pub(super) observations: Result<Arc<super::observation::Store>, CoreError>,
    #[cfg(test)]
    pub(crate) before_accept: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    pub(crate) after_accept: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    pub(crate) after_authorization: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    pub(crate) after_proof_lookup: Option<Arc<dyn Fn() + Send + Sync>>,
}
impl LocalGitService {
    pub fn new(files: Arc<LocalFileService>) -> Self {
        let directory = files
            .ledger
            .lock()
            .unwrap()
            .directory
            .parent()
            .unwrap()
            .join("git-observations");
        let observations = super::observation::Store::open(directory);
        Self {
            files,
            observations,
            #[cfg(test)]
            before_accept: None,
            #[cfg(test)]
            after_accept: None,
            #[cfg(test)]
            after_authorization: None,
            #[cfg(test)]
            after_proof_lookup: None,
        }
    }
    pub fn probe(&self) -> Result<(), CoreError> {
        self.command(
            Path::new("/"),
            &process::args(&["--version"]),
            &AtomicBool::new(false),
        )?;
        Ok(())
    }
    pub(crate) fn command(
        &self,
        root: &Path,
        args: &[OsString],
        cancel: &AtomicBool,
    ) -> Result<Vec<u8>, CoreError> {
        process::run(root, args, cancel)?.checked()
    }
    pub fn discover_sync(
        &self,
        root: FileRef,
        cancel: &AtomicBool,
    ) -> Result<Option<WorktreeIdentity>, CoreError> {
        if root.target != *self.files.target() {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "Git target changed",
            ));
        }
        let root = path(&root.path)?;
        let output = process::run(
            &root,
            &process::args(&["rev-parse", "--show-toplevel"]),
            cancel,
        )?;
        if !output.success {
            if !output.interrupted && output.stderr.windows(16).any(|w| w == b"not a git reposi") {
                return Ok(None);
            }
            return output.checked().map(|_| None);
        }
        let repo = fs::canonicalize(Path::new(OsStr::from_bytes(line(&output.stdout)?)))
            .map_err(io_error)?;
        let common = self.command(
            &repo,
            &process::args(&["rev-parse", "--path-format=absolute", "--git-common-dir"]),
            cancel,
        )?;
        let common =
            fs::canonicalize(Path::new(OsStr::from_bytes(line(&common)?))).map_err(io_error)?;
        let m = fs::metadata(&common).map_err(io_error)?;
        let identity = [
            common.as_os_str().as_bytes(),
            &[0],
            &m.dev().to_be_bytes(),
            &m.ino().to_be_bytes(),
        ]
        .concat();
        Ok(Some(WorktreeIdentity {
            target: self.files.target().clone(),
            canonical_path: target_path(&repo),
            common_git_directory_identity: identity,
        }))
    }
    pub fn contains_document_sync(
        &self,
        worktree: &WorktreeIdentity,
        file: FileRef,
        cancel: &AtomicBool,
    ) -> Result<bool, CoreError> {
        if file.target != worktree.target {
            return Ok(false);
        }
        let file_path = path(&file.path)?;
        let parent = file_path
            .parent()
            .ok_or_else(|| CoreError::new(ErrorCode::InvalidArgument, "Document has no parent"))?;
        let lexical = self.discover_sync(
            FileRef {
                target: file.target.clone(),
                path: target_path(parent),
                resolved_identity: None,
            },
            cancel,
        )?;
        if lexical.as_ref() == Some(worktree) {
            return Ok(true);
        }
        // A file symlink outside the worktree can still expose an affected authoritative buffer.
        let resolved = fs::canonicalize(&file_path).map_err(io_error)?;
        let resolved_parent = resolved.parent().ok_or_else(|| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                "Resolved document has no parent",
            )
        })?;
        if resolved_parent == parent {
            return Ok(false);
        }
        Ok(self
            .discover_sync(
                FileRef {
                    target: file.target,
                    path: target_path(resolved_parent),
                    resolved_identity: None,
                },
                cancel,
            )?
            .as_ref()
            == Some(worktree))
    }
    pub(crate) fn validate(
        &self,
        w: &WorktreeIdentity,
        cancel: &AtomicBool,
    ) -> Result<PathBuf, CoreError> {
        let actual = self.discover_sync(
            FileRef {
                target: w.target.clone(),
                path: w.canonical_path.clone(),
                resolved_identity: None,
            },
            cancel,
        )?;
        if actual.as_ref() != Some(w) {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "Repository identity changed",
            ));
        }
        path(&w.canonical_path)
    }
    pub fn status_sync(
        &self,
        w: WorktreeIdentity,
        cancel: &AtomicBool,
    ) -> Result<GitSnapshot, CoreError> {
        let root = self.validate(&w, cancel)?;
        let state = self.state(&root, cancel)?;
        let raw = self.command(
            &root,
            &process::args(&[
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ]),
            cancel,
        )?;
        let after = self.state(&root, cancel)?;
        if state != after {
            return Err(CoreError::new(
                ErrorCode::StaleRevision,
                "Repository changed while reading status; refresh",
            ));
        }
        let mut s = GitSnapshot {
            worktree: w,
            state,
            staged: vec![],
            unstaged: vec![],
            untracked: vec![],
            conflicts: vec![],
        };
        output_parser::status(&root, &raw, &mut s)?;
        Ok(s)
    }
    pub(crate) fn state(
        &self,
        root: &Path,
        cancel: &AtomicBool,
    ) -> Result<GitExpectedState, CoreError> {
        self.state_records(root, cancel, |_, _| Ok(()))
            .map(|(state, _)| state)
    }
    pub(crate) fn state_records(
        &self,
        root: &Path,
        cancel: &AtomicBool,
        mut record: impl FnMut(&[u8], &crate::files::NodeObservation) -> Result<(), CoreError>,
    ) -> Result<(GitExpectedState, Vec<u8>), CoreError> {
        let started = std::time::Instant::now();
        let symbolic = process::run(
            root,
            &process::args(&["symbolic-ref", "-q", "HEAD"]),
            cancel,
        )?;
        let oid = process::run(
            root,
            &process::args(&["rev-parse", "--verify", "HEAD"]),
            cancel,
        )?;
        if symbolic.interrupted || oid.interrupted {
            return Err(CoreError::new(
                ErrorCode::Cancelled,
                "Git snapshot interrupted",
            ));
        }
        let head = if symbolic.success {
            let name = line(&symbolic.stdout)?.to_vec();
            if oid.success {
                GitHead::Branch {
                    name,
                    oid: String::from_utf8_lossy(line(&oid.stdout)?).into(),
                }
            } else {
                GitHead::Unborn(name)
            }
        } else if oid.success {
            GitHead::Detached(String::from_utf8_lossy(line(&oid.stdout)?).into())
        } else {
            return Err(io_error("Cannot read Git HEAD"));
        };
        let index = self.command(root, &process::args(&["ls-files", "--stage", "-z"]), cancel)?;
        let names = self.command(
            root,
            &process::args(&[
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ]),
            cancel,
        )?;
        let mut names = names
            .split(|b| *b == 0)
            .filter(|b| !b.is_empty())
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        let mut hash = Sha256::new();
        hash.update(b"buntrail.git-worktree.v2\0");
        let status = self.command(
            root,
            &process::args(&[
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ]),
            cancel,
        )?;
        hash.update((status.len() as u64).to_be_bytes());
        hash.update(&status);
        for name in names {
            if cancel.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(CoreError::new(
                    ErrorCode::Cancelled,
                    "Git snapshot cancelled",
                ));
            }
            hash.update((name.len() as u64).to_be_bytes());
            hash.update(name);
            let p = root.join(OsStr::from_bytes(name));
            let node = self.files.observe_node_sync(
                FileRef {
                    target: self.files.target().clone(),
                    path: target_path(&p),
                    resolved_identity: None,
                },
                cancel,
                started,
            )?;
            record(name, &node)?;
            hash.update(node.structural_token);
            if let Some(regular) = node.regular {
                hash.update([1]);
                hash.update(&regular.version.opaque_token);
                hash.update(&regular.canonical_version.opaque_token);
            } else {
                hash.update([0]);
            }
        }
        Ok((
            GitExpectedState {
                head,
                index_fingerprint: Sha256::digest(index).into(),
                worktree_fingerprint: hash.finalize().into(),
            },
            status,
        ))
    }
    pub(crate) fn selected(&self, root: &Path, p: &TargetPath) -> Result<OsString, CoreError> {
        let p = path(p)?;
        let relative = p.strip_prefix(root).map_err(|_| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                "Selected path is outside the repository",
            )
        })?;
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "Select an individual repository path",
            ));
        }
        Ok(relative.as_os_str().to_owned())
    }
    pub fn diff_sync(
        &self,
        r: DiffRequest,
        cancel: &AtomicBool,
    ) -> Result<DiffSnapshot, CoreError> {
        let root = self.validate(&r.worktree, cancel)?;
        let snapshot = self.status_sync(r.worktree.clone(), cancel)?;
        let expected = snapshot.state;
        let selected = self.selected(&root, &r.path)?;
        let untracked = snapshot.untracked.iter().any(|e| e.path == r.path);
        let entry = if r.source == DiffSource::Index {
            snapshot.staged.iter().find(|e| e.path == r.path)
        } else {
            snapshot
                .unstaged
                .iter()
                .chain(&snapshot.untracked)
                .chain(&snapshot.conflicts)
                .find(|e| e.path == r.path)
        };
        let side = if r.source == DiffSource::Index { 0 } else { 1 };
        let status = entry.and_then(|e| e.status.as_bytes().get(side)).copied();
        let change = if snapshot.conflicts.iter().any(|e| e.path == r.path) {
            DiffChange::Conflicted
        } else if (untracked && r.source == DiffSource::Worktree) || status == Some(b'A') {
            DiffChange::Added
        } else if status == Some(b'R') {
            DiffChange::Renamed
        } else if status == Some(b'D') {
            DiffChange::Deleted
        } else {
            DiffChange::Modified
        };
        let previous_path = if change == DiffChange::Renamed {
            entry.and_then(|e| e.previous_path.clone())
        } else {
            None
        };
        let mut args = process::args(&[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--binary",
        ]);
        match &r.source {
            DiffSource::Index => args.push("--cached".into()),
            DiffSource::Worktree => {
                if untracked {
                    args.push("--no-index".into());
                }
            }
            DiffSource::Commit(_) => {
                return Err(CoreError::new(
                    ErrorCode::Unavailable,
                    "Commit diff awaits history",
                ));
            }
        };
        args.push("--".into());
        if untracked && r.source == DiffSource::Worktree {
            args.push("/dev/null".into());
        }
        args.push(selected);
        if let Some(previous) = &previous_path {
            args.push(self.selected(&root, previous)?);
        }
        let output = process::run(&root, &args, cancel)?;
        let content = if output.interrupted {
            DiffContent::Unavailable(
                "Diff exceeded its output/deadline bound or was cancelled".into(),
            )
        } else if output
            .stdout
            .windows(18)
            .any(|b| b == b"\nGIT binary patch\n")
        {
            DiffContent::Binary
        } else if !output.success && !(untracked && !output.stdout.is_empty()) {
            DiffContent::Unavailable(String::from_utf8_lossy(&output.stderr).into())
        } else {
            DiffContent::Text
        };
        let bytes = if matches!(content, DiffContent::Text) {
            output.stdout
        } else {
            vec![]
        };
        if self.state(&root, cancel)? != expected {
            return Err(CoreError::new(
                ErrorCode::StaleRevision,
                "Repository changed during diff",
            ));
        }
        Ok(DiffSnapshot {
            expected,
            bytes,
            source: r.source,
            content,
            change,
            previous_path,
        })
    }
}
fn line(bytes: &[u8]) -> Result<&[u8], CoreError> {
    bytes
        .strip_suffix(b"\n")
        .ok_or_else(|| io_error("Incomplete Git identity output"))
}
impl GitService for LocalGitService {
    fn read_query(
        &self,
        worktree: WorktreeIdentity,
        query: GitRead,
    ) -> ServiceFuture<'_, Result<GitReadOutput, CoreError>> {
        Box::pin(async move { self.read_sync(worktree, query, &AtomicBool::new(false)) })
    }

    fn existing_receipt(
        &self,
        request: GitMutationRequest,
    ) -> ServiceFuture<'_, Result<Option<OperationReceipt>, CoreError>> {
        Box::pin(async move { self.existing_receipt_sync(&request) })
    }
    fn discover(
        &self,
        r: FileRef,
    ) -> ServiceFuture<'_, Result<Option<WorktreeIdentity>, CoreError>> {
        Box::pin(async move { self.discover_sync(r, &AtomicBool::new(false)) })
    }
    fn status(&self, w: WorktreeIdentity) -> ServiceFuture<'_, Result<GitSnapshot, CoreError>> {
        Box::pin(async move { self.status_sync(w, &AtomicBool::new(false)) })
    }
    fn diff(&self, r: DiffRequest) -> ServiceFuture<'_, Result<DiffSnapshot, CoreError>> {
        Box::pin(async move { self.diff_sync(r, &AtomicBool::new(false)) })
    }
    fn history(&self, query: HistoryQuery) -> ServiceFuture<'_, Result<GraphPage, CoreError>> {
        Box::pin(async move { self.history_sync(query, &AtomicBool::new(false)) })
    }
    fn mutate(&self, r: GitMutationRequest) -> ServiceFuture<'_, OperationReceipt> {
        Box::pin(async move { self.mutate_sync(r, &AtomicBool::new(false)) })
    }
}
