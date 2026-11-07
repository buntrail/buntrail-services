#![cfg(unix)]
#![allow(non_snake_case)]
use buntrail_core::contracts::*;
use buntrail_services::{
    connections::local::LocalConnection,
    contracts::{GitService, ServiceAvailability},
};
use std::{
    fs,
    future::Future,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::Path,
    pin::pin,
    process::Command,
    sync::Arc,
    task::{Context, Poll, Waker},
};
fn run<T>(f: impl Future<Output = T>) -> T {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        _ => panic!("unexpected pending"),
    }
}
fn git(p: &Path, args: &[&str]) -> Vec<u8> {
    let o = Command::new("git")
        .arg("-C")
        .arg(p)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    o.stdout
}
fn path(p: &Path) -> TargetPath {
    TargetPath::posix(p.as_os_str().as_bytes().to_vec()).unwrap()
}
struct Fixture {
    dir: tempfile::TempDir,
    local: LocalConnection,
    service: Arc<dyn GitService>,
    root: FileRef,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        fs::create_dir(&project).unwrap();
        let project = fs::canonicalize(project).unwrap();
        git(&project, &["init", "-b", "main"]);
        git(&project, &["config", "user.name", "Fixture"]);
        git(
            &project,
            &["config", "user.email", "fixture@example.invalid"],
        );
        git(&project, &["config", "commit.gpgsign", "false"]);
        let local = LocalConnection::open(dir.path().join("state")).unwrap();
        let root = FileRef {
            target: local.identity.clone(),
            path: path(&project),
            resolved_identity: None,
        };
        let service = match local.environment().git {
            ServiceAvailability::Available(s) => s,
            ServiceAvailability::Unavailable(e) => panic!("Git must be composed: {e:?}"),
        };
        Self {
            dir,
            local,
            service,
            root,
        }
    }
    fn p(&self) -> std::path::PathBuf {
        fs::canonicalize(self.dir.path().join("project")).unwrap()
    }
    fn file(&self, name: &str, bytes: &[u8]) -> TargetPath {
        fs::write(self.p().join(name), bytes).unwrap();
        path(&self.p().join(name))
    }
    fn worktree(&self) -> WorktreeIdentity {
        run(self.service.discover(self.root.clone()))
            .unwrap()
            .unwrap()
    }
    fn status(&self) -> GitSnapshot {
        run(self.service.status(self.worktree())).unwrap()
    }
    fn mutate(&self, command: GitMutation) -> OperationReceipt {
        let snapshot = self.status();
        run(self.service.mutate(GitMutationRequest {
            operation: OperationID(buntrail_services::connections::local::new_id().unwrap()),
            worktree: snapshot.worktree,
            expected: snapshot.state,
            command,
        }))
    }
    fn commit(&self) {
        git(&self.p(), &["add", "--all"]);
        git(&self.p(), &["commit", "-m", "initial"]);
    }
}
#[test]
fn testSameFileStagedAndUnstaged() {
    let f = Fixture::new();
    let p = f.file("both.txt", b"base\n");
    f.commit();
    f.file("both.txt", b"index\n");
    assert!(matches!(
        f.mutate(GitMutation::Stage(vec![p.clone()])).state,
        OperationState::Confirmed(_)
    ));
    f.file("both.txt", b"disk\n");
    let s = f.status();
    assert!(s.staged.iter().any(|e| e.path == p));
    assert!(s.unstaged.iter().any(|e| e.path == p));
    let index = run(f.service.diff(DiffRequest {
        worktree: s.worktree.clone(),
        path: p.clone(),
        source: DiffSource::Index,
    }))
    .unwrap();
    let disk = run(f.service.diff(DiffRequest {
        worktree: s.worktree,
        path: p,
        source: DiffSource::Worktree,
    }))
    .unwrap();
    assert!(String::from_utf8_lossy(&index.bytes).contains("+index"));
    assert!(String::from_utf8_lossy(&disk.bytes).contains("+disk"));
    let r = f.mutate(GitMutation::Commit {
        message: "index only".into(),
    });
    assert!(matches!(r.state, OperationState::Confirmed(_)));
    assert_eq!(git(&f.p(), &["show", "HEAD:both.txt"]), b"index\n");
}

#[test]
fn retained_status_distinguishes_same_content_replacement() {
    let f = Fixture::new();
    f.file("identity.txt", b"same bytes\n");
    f.commit();
    let before = f.status();
    let temporary = f.p().join("replacement.tmp");
    fs::write(&temporary, b"same bytes\n").unwrap();
    fs::rename(temporary, f.p().join("identity.txt")).unwrap();
    let after = f.status();
    assert_eq!(before.state.head, after.state.head);
    assert_eq!(
        before.state.index_fingerprint,
        after.state.index_fingerprint
    );
    assert_ne!(
        before.state.worktree_fingerprint, after.state.worktree_fingerprint,
        "an original status observation must bind the replaced file identity"
    );
}

#[test]
fn git_status_streams_files_larger_than_document_spool_limit() {
    let f = Fixture::new();
    let file = fs::File::create(f.p().join("large.bin")).unwrap();
    file.set_len(64 * 1024 * 1024 + 1).unwrap();
    let before = f.status();
    assert_eq!(before.untracked.len(), 1);
    let after = f.status();
    assert_eq!(before.state, after.state);
}

#[test]
fn strong_status_preserves_deleted_parent_and_dangling_link_nodes() {
    let f = Fixture::new();
    fs::create_dir(f.p().join("nested")).unwrap();
    f.file("nested/file", b"tracked");
    std::os::unix::fs::symlink("missing/destination", f.p().join("dangling")).unwrap();
    f.commit();
    fs::remove_dir_all(f.p().join("nested")).unwrap();
    let snapshot = f.status();
    assert_eq!(snapshot.unstaged.len(), 1);
    assert!(snapshot.unstaged[0].path == path(&f.p().join("nested/file")));
}

#[test]
#[ignore = "explicit representative observation resource fixture"]
fn strong_status_observes_ten_thousand_paths_without_a_file_count_cap() {
    let f = Fixture::new();
    for n in 0..10_000 {
        f.file(&format!("source_{n:05}_implementation.txt"), b"fixture\n");
    }
    let started = std::time::Instant::now();
    let snapshot = f.status();
    assert_eq!(snapshot.untracked.len(), 10_000);
    println!(
        "actual_strong_status_paths=10000 elapsed_seconds={:.3} streamed_file_bytes_per_capture=80000",
        started.elapsed().as_secs_f64()
    );
}
#[test]
fn testHookFailureRetainsMessage() {
    let f = Fixture::new();
    f.file("file", b"base");
    f.commit();
    let p = f.file("file", b"changed");
    f.mutate(GitMutation::Stage(vec![p]));
    let hook = f.p().join(".git/hooks/pre-commit");
    fs::write(&hook, b"#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
    let message = "entered message".to_string();
    let command = GitMutation::Commit {
        message: message.clone(),
    };
    let r = f.mutate(command.clone());
    assert!(matches!(
        r.state,
        OperationState::Failed(_) | OperationState::Unknown(_)
    ));
    assert_eq!(command, GitMutation::Commit { message });
    assert_eq!(git(&f.p(), &["log", "-1", "--format=%s"]), b"initial\n");
}
#[test]
fn testCommitAcknowledgementLoss() {
    let f = Fixture::new();
    let p = f.file("file", b"initial");
    assert!(matches!(f.status().state.head, GitHead::Unborn(_)));
    f.mutate(GitMutation::Stage(vec![p]));
    let snapshot = f.status();
    let operation = OperationID([121; 16]);
    let request = GitMutationRequest {
        operation,
        worktree: snapshot.worktree,
        expected: snapshot.state,
        command: GitMutation::Commit {
            message: "once".into(),
        },
    };
    drop(run(f.service.mutate(request.clone())));

    let operations = match f.local.environment().operations {
        ServiceAvailability::Available(s) => s,
        _ => panic!(),
    };
    let inspected = run(operations.inspect(operation, f.local.identity.clone())).unwrap();
    assert!(!inspected.state.allows_automatic_replay());
    match inspected.state {
        OperationState::Confirmed(MutationResult::GitChanged { state, .. }) => {
            assert_eq!(state, f.status().state)
        }
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        run(f.service.mutate(request)).state,
        OperationState::Confirmed(_)
    ));
    assert_eq!(git(&f.p(), &["rev-list", "--count", "HEAD"]), b"1\n");
    let missing =
        run(operations.inspect(OperationID([222; 16]), f.local.identity.clone())).unwrap();
    assert!(matches!(missing.state, OperationState::Unknown(_)));
    assert!(!missing.state.allows_automatic_replay());
}
#[test]
fn testSelectedPathsAreLiteral() {
    let f = Fixture::new();
    let names = [
        "*.txt",
        "[ab].txt",
        ":(glob)*",
        "a.txt",
        "b.txt",
        "space name",
        "new\nline",
        "雪",
        "-leading",
    ];
    for name in names {
        f.file(name, b"new");
    }
    for name in names {
        let p = path(&f.p().join(name));
        assert!(matches!(
            f.mutate(GitMutation::Stage(vec![p.clone()])).state,
            OperationState::Confirmed(_)
        ));
        let s = f.status();
        assert_eq!(s.staged.len(), 1, "{name}");
        assert_eq!(s.staged[0].path, p);
        assert!(matches!(
            f.mutate(GitMutation::Unstage(vec![p])).state,
            OperationState::Confirmed(_)
        ));
        assert!(f.status().staged.is_empty());
    }
}
#[test]
fn linked_worktree_and_external_activity() {
    let f = Fixture::new();
    f.file("file", b"base");
    f.commit();
    let linked = f.dir.path().join("linked");
    git(
        &f.p(),
        &["worktree", "add", "-b", "linked", linked.to_str().unwrap()],
    );
    let w = run(f.service.discover(FileRef {
        path: path(&linked),
        ..f.root.clone()
    }))
    .unwrap()
    .unwrap();
    assert_eq!(
        w.common_git_directory_identity,
        f.worktree().common_git_directory_identity
    );
    assert_ne!(w.canonical_path, f.worktree().canonical_path);
    let before = f.status();
    f.file("file", b"external");
    let receipt = run(f.service.mutate(GitMutationRequest {
        operation: OperationID([33; 16]),
        worktree: before.worktree,
        expected: before.state,
        command: GitMutation::Stage(vec![path(&f.p().join("file"))]),
    }));
    assert!(matches!(receipt.state, OperationState::Failed(_)));
    assert!(f.status().staged.is_empty());
}
#[test]
fn local_remote_fetch_push_and_fast_forward_only() {
    let f = Fixture::new();
    f.file("base", b"base");
    f.commit();
    let bare = f.dir.path().join("origin.git");
    fs::create_dir(&bare).unwrap();
    git(&bare, &["init", "--bare"]);
    git(&f.p(), &["remote", "add", "origin", bare.to_str().unwrap()]);
    let push = || GitMutation::Push {
        remote: b"origin".to_vec(),
        reference: b"refs/heads/main".to_vec(),
    };
    let r = f.mutate(push());
    assert!(matches!(r.state, OperationState::Confirmed(_)), "{r:?}");
    let peer = f.dir.path().join("peer");
    git(
        f.dir.path(),
        &["clone", bare.to_str().unwrap(), peer.to_str().unwrap()],
    );
    git(&peer, &["checkout", "main"]);
    git(&peer, &["config", "user.name", "Fixture"]);
    git(&peer, &["config", "user.email", "fixture@example.invalid"]);
    git(&peer, &["config", "commit.gpgsign", "false"]);
    fs::write(peer.join("remote"), b"remote").unwrap();
    git(&peer, &["add", "--all"]);
    git(&peer, &["commit", "-m", "remote"]);
    git(&peer, &["push", "origin", "main"]);
    assert!(matches!(
        f.mutate(GitMutation::Fetch {
            remote: b"origin".to_vec()
        })
        .state,
        OperationState::Confirmed(_)
    ));
    assert!(matches!(f.mutate(push()).state, OperationState::Failed(_)));
    let pull = || GitMutation::PullFastForward {
        remote: b"origin".to_vec(),
        reference: b"refs/heads/main".to_vec(),
    };
    assert!(matches!(
        f.mutate(pull()).state,
        OperationState::Confirmed(_)
    ));
    assert_eq!(
        git(&f.p(), &["rev-parse", "HEAD"]),
        git(&peer, &["rev-parse", "HEAD"])
    );
    f.file("local", b"local");
    f.commit();
    fs::write(peer.join("other"), b"other").unwrap();
    git(&peer, &["add", "--all"]);
    git(&peer, &["commit", "-m", "other"]);
    git(&peer, &["push", "origin", "main"]);
    let old = git(&f.p(), &["rev-parse", "HEAD"]);
    assert!(matches!(f.mutate(pull()).state, OperationState::Failed(_)));
    assert_eq!(git(&f.p(), &["rev-parse", "HEAD"]), old);
}
#[test]
fn untracked_diff_and_binary_are_explicit() {
    let f = Fixture::new();
    let p = f.file("*.txt", b"untracked text\n");
    let d = run(f.service.diff(DiffRequest {
        worktree: f.worktree(),
        path: p,
        source: DiffSource::Worktree,
    }))
    .unwrap();
    assert!(String::from_utf8_lossy(&d.bytes).contains("untracked text"));
}
#[test]
fn cancellation_reconciles_hook_without_replay() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let f = Fixture::new();
    f.file("file", b"base");
    f.commit();
    let p = f.file("file", b"changed");
    f.mutate(GitMutation::Stage(vec![p]));
    let hook = f.p().join(".git/hooks/pre-commit");
    fs::write(&hook, b"#!/bin/sh\necho started > hook-started\nsleep 20\n").unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
    let snapshot = f.status();
    let service = f.local.git.clone();
    let cancel = Arc::new(AtomicBool::new(false));
    let signal = cancel.clone();
    let worker = std::thread::spawn(move || {
        service.mutate_sync(
            GitMutationRequest {
                operation: OperationID([92; 16]),
                worktree: snapshot.worktree,
                expected: snapshot.state,
                command: GitMutation::Commit {
                    message: "blocked hook".into(),
                },
            },
            &signal,
        )
    });
    for _ in 0..200 {
        if f.p().join("hook-started").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(f.p().join("hook-started").exists());
    cancel.store(true, Ordering::SeqCst);
    let r = worker.join().unwrap();
    assert!(matches!(r.state, OperationState::Unknown(_)));
    assert!(!r.state.allows_automatic_replay());
    assert_eq!(git(&f.p(), &["rev-list", "--count", "HEAD"]), b"1\n");
}
#[test]
fn binary_rename_delete_conflict_and_literal_diff() {
    let f = Fixture::new();
    let literal = f.file("*.txt", b"base\n");
    f.file("a.txt", b"other\n");
    f.file("binary", b"\0before");
    f.file("old", b"rename\n");
    f.file("deleted", b"delete\n");
    f.commit();
    f.file("*.txt", b"literal only\n");
    f.file("a.txt", b"must not appear\n");
    let d = run(f.service.diff(DiffRequest {
        worktree: f.worktree(),
        path: literal,
        source: DiffSource::Worktree,
    }))
    .unwrap();
    assert!(String::from_utf8_lossy(&d.bytes).contains("literal only"));
    assert!(!String::from_utf8_lossy(&d.bytes).contains("must not appear"));
    let binary = f.file("binary", b"\0after");
    let d = run(f.service.diff(DiffRequest {
        worktree: f.worktree(),
        path: binary,
        source: DiffSource::Worktree,
    }))
    .unwrap();
    assert_eq!(d.content, DiffContent::Binary);
    assert!(d.bytes.is_empty());
    git(&f.p(), &["mv", "old", "renamed"]);
    let d = run(f.service.diff(DiffRequest {
        worktree: f.worktree(),
        path: path(&f.p().join("renamed")),
        source: DiffSource::Index,
    }))
    .unwrap();
    assert_eq!(d.change, DiffChange::Renamed);
    assert_eq!(d.previous_path, Some(path(&f.p().join("old"))));
    fs::remove_file(f.p().join("deleted")).unwrap();
    let d = run(f.service.diff(DiffRequest {
        worktree: f.worktree(),
        path: path(&f.p().join("deleted")),
        source: DiffSource::Worktree,
    }))
    .unwrap();
    assert_eq!(d.change, DiffChange::Deleted);
}
#[test]
fn signing_input_failure_keeps_index_and_does_not_retry() {
    let f = Fixture::new();
    let p = f.file("file", b"initial");
    f.mutate(GitMutation::Stage(vec![p]));
    let signer = f.dir.path().join("signer");
    fs::write(
        &signer,
        b"#!/bin/sh\ncat >/dev/null\necho 'signing requires input' >&2\nexit 1\n",
    )
    .unwrap();
    fs::set_permissions(&signer, fs::Permissions::from_mode(0o700)).unwrap();
    git(&f.p(), &["config", "commit.gpgsign", "true"]);
    git(&f.p(), &["config", "gpg.program", signer.to_str().unwrap()]);
    let r = f.mutate(GitMutation::Commit {
        message: "retain this".into(),
    });
    assert!(matches!(r.state, OperationState::Failed(_)));
    assert!(!r.state.allows_automatic_replay());
    assert_eq!(f.status().staged.len(), 1);
    assert!(matches!(f.status().state.head, GitHead::Unborn(_)));
}
#[test]
fn conflicts_and_deleted_paths_are_operable() {
    let f = Fixture::new();
    let file = f.file("conflict", b"base\n");
    f.commit();
    git(&f.p(), &["checkout", "-b", "other"]);
    f.file("conflict", b"other\n");
    f.commit();
    git(&f.p(), &["checkout", "main"]);
    f.file("conflict", b"main\n");
    f.commit();
    let o = Command::new("git")
        .arg("-C")
        .arg(f.p())
        .args(["merge", "other"])
        .output()
        .unwrap();
    assert!(!o.status.success());
    let s = f.status();
    assert_eq!(s.conflicts.len(), 1);
    let d = run(f.service.diff(DiffRequest {
        worktree: s.worktree,
        path: file.clone(),
        source: DiffSource::Worktree,
    }))
    .unwrap();
    assert_eq!(d.change, DiffChange::Conflicted);
    f.file("conflict", b"resolved\n");
    assert!(matches!(
        f.mutate(GitMutation::Stage(vec![file.clone()])).state,
        OperationState::Confirmed(_)
    ));
    assert!(f.status().conflicts.is_empty());
    git(&f.p(), &["commit", "-m", "resolved"]);
    fs::remove_file(f.p().join("conflict")).unwrap();
    assert!(matches!(
        f.mutate(GitMutation::Stage(vec![file.clone()])).state,
        OperationState::Confirmed(_)
    ));
    assert_eq!(f.status().staged.len(), 1);
    assert!(matches!(
        f.mutate(GitMutation::Unstage(vec![file])).state,
        OperationState::Confirmed(_)
    ));
    assert!(!f.p().join("conflict").exists());
}
#[test]
fn linked_worktree_mutations_are_serialized() {
    use std::sync::atomic::AtomicBool;
    let f = Fixture::new();
    f.file("file", b"base");
    f.commit();
    let linked = f.dir.path().join("linked");
    git(
        &f.p(),
        &["worktree", "add", "-b", "linked", linked.to_str().unwrap()],
    );
    let p = f.file("file", b"changed");
    f.mutate(GitMutation::Stage(vec![p]));
    let hook = f.p().join(".git/hooks/pre-commit");
    fs::write(&hook,b"#!/bin/sh\necho started > hook-started\nwhile [ ! -f hook-release ]; do sleep 0.02; done\n").unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
    let first = f.status();
    let service = f.local.git.clone();
    let worker = std::thread::spawn(move || {
        service.mutate_sync(
            GitMutationRequest {
                operation: OperationID([90; 16]),
                worktree: first.worktree,
                expected: first.state,
                command: GitMutation::Commit {
                    message: "serialized".into(),
                },
            },
            &AtomicBool::new(false),
        )
    });
    for _ in 0..300 {
        if f.p().join("hook-started").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(f.p().join("hook-started").exists());
    fs::write(linked.join("new"), b"linked").unwrap();
    let w = run(f.service.discover(FileRef {
        path: path(&linked),
        ..f.root.clone()
    }))
    .unwrap()
    .unwrap();
    let s = run(f.service.status(w)).unwrap();
    let selected = match &s.worktree.canonical_path {
        TargetPath::PosixBytes(b) => {
            let mut b = b.clone();
            b.extend_from_slice(b"/new");
            TargetPath::posix(b).unwrap()
        }
        _ => unreachable!(),
    };
    let service = f.local.git.clone();
    let second = std::thread::spawn(move || {
        service.mutate_sync(
            GitMutationRequest {
                operation: OperationID([91; 16]),
                worktree: s.worktree,
                expected: s.state,
                command: GitMutation::Stage(vec![selected]),
            },
            &AtomicBool::new(false),
        )
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(git(&linked, &["diff", "--cached", "--name-only"]).is_empty());
    fs::write(f.p().join("hook-release"), b"release").unwrap();
    assert!(matches!(
        worker.join().unwrap().state,
        OperationState::Confirmed(_)
    ));
    assert!(matches!(
        second.join().unwrap().state,
        OperationState::Confirmed(_)
    ));
    assert_eq!(git(&linked, &["diff", "--cached", "--name-only"]), b"new\n");
}
#[test]
fn unborn_unstage_preserves_different_disk_bytes() {
    let f = Fixture::new();
    let p = f.file("file", b"index");
    f.mutate(GitMutation::Stage(vec![p.clone()]));
    f.file("file", b"disk");
    let r = f.mutate(GitMutation::Unstage(vec![p]));
    assert!(matches!(r.state, OperationState::Confirmed(_)), "{r:?}");
    assert!(f.status().staged.is_empty());
    assert_eq!(fs::read(f.p().join("file")).unwrap(), b"disk");
}
#[test]
fn unstaging_rename_restores_both_index_paths_and_diff_identity() {
    let f = Fixture::new();
    f.file("old", b"rename\n");
    f.commit();
    git(&f.p(), &["mv", "old", "new"]);
    let p = path(&f.p().join("new"));
    let d = run(f.service.diff(DiffRequest {
        worktree: f.worktree(),
        path: p.clone(),
        source: DiffSource::Index,
    }))
    .unwrap();
    assert!(String::from_utf8_lossy(&d.bytes).contains("rename from old"));
    let r = f.mutate(GitMutation::Unstage(vec![p]));
    assert!(matches!(r.state, OperationState::Confirmed(_)));
    assert!(f.status().staged.is_empty());
    assert_eq!(git(&f.p(), &["ls-files"]), b"old\n");
    assert_eq!(fs::read(f.p().join("new")).unwrap(), b"rename\n");
}
#[test]
fn diff_change_kind_uses_the_selected_side() {
    let f = Fixture::new();
    let p = f.file("file", b"base\n");
    f.commit();
    f.file("file", b"index\n");
    f.mutate(GitMutation::Stage(vec![p.clone()]));
    fs::remove_file(f.p().join("file")).unwrap();
    let w = f.worktree();
    let index = run(f.service.diff(DiffRequest {
        worktree: w.clone(),
        path: p.clone(),
        source: DiffSource::Index,
    }))
    .unwrap();
    let disk = run(f.service.diff(DiffRequest {
        worktree: w,
        path: p,
        source: DiffSource::Worktree,
    }))
    .unwrap();
    assert_eq!(index.change, DiffChange::Modified);
    assert_eq!(disk.change, DiffChange::Deleted);
}
#[test]
fn textual_binary_marker_is_not_binary_content() {
    let f = Fixture::new();
    let p = f.file("text", b"GIT binary patch\n");
    let d = run(f.service.diff(DiffRequest {
        worktree: f.worktree(),
        path: p,
        source: DiffSource::Worktree,
    }))
    .unwrap();
    assert_eq!(d.content, DiffContent::Text);
}

#[test]
fn interrupted_push_never_qualifies_local_snapshot_as_remote_reconciliation() {
    use std::sync::atomic::{AtomicBool, Ordering};
    for scenario in 0..7 {
        let unavailable = scenario != 0;
        let f = Fixture::new();
        f.file("file", b"pushed bytes");
        f.commit();
        let bare = f.dir.path().join("remote.git");
        git(f.dir.path(), &["init", "--bare", bare.to_str().unwrap()]);
        git(&f.p(), &["remote", "add", "origin", bare.to_str().unwrap()]);
        if scenario == 3 {
            let fetch_remote = f.dir.path().join("fetch.git");
            git(
                f.dir.path(),
                &["init", "--bare", fetch_remote.to_str().unwrap()],
            );
            git(
                &f.p(),
                &[
                    "remote",
                    "set-url",
                    "--push",
                    "origin",
                    bare.to_str().unwrap(),
                ],
            );
            git(
                &f.p(),
                &[
                    "remote",
                    "set-url",
                    "origin",
                    fetch_remote.to_str().unwrap(),
                ],
            );
        }
        if scenario == 4 || scenario == 5 {
            git(
                &f.p(),
                &[
                    "config",
                    "remote.origin.push",
                    "refs/heads/main:refs/heads/deploy",
                ],
            );
        }
        let hook = bare.join("hooks/post-receive");
        fs::write(&hook, b"#!/bin/sh\necho updated > received\nsleep 20\n").unwrap();
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
        let pre_push = f.p().join(".git/hooks/pre-push");
        fs::write(
            &pre_push,
            b"#!/bin/sh\necho attempt >> .git/push-attempts\n",
        )
        .unwrap();
        fs::set_permissions(&pre_push, fs::Permissions::from_mode(0o700)).unwrap();
        let snapshot = f.status();
        let request = GitMutationRequest {
            operation: OperationID([101 + u8::from(unavailable); 16]),
            worktree: snapshot.worktree,
            expected: snapshot.state,
            command: GitMutation::Push {
                remote: b"origin".to_vec(),
                reference: b"refs/heads/main".to_vec(),
            },
        };
        let signal = Arc::new(AtomicBool::new(false));
        let cancel = signal.clone();
        let service = f.local.git.clone();
        let submitted = request.clone();
        let worker = std::thread::spawn(move || service.mutate_sync(submitted, &cancel));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !bare.join("received").exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let updated = bare.join("received").exists();
        let moved = f.dir.path().join("moved.git");
        if scenario == 1 && updated {
            fs::rename(&bare, &moved).unwrap();
        } else if scenario == 2 && updated {
            git(f.dir.path(), &["init", "--bare", moved.to_str().unwrap()]);
            git(
                &f.p(),
                &["remote", "set-url", "origin", moved.to_str().unwrap()],
            );
        }
        if scenario == 5 && updated {
            git(&f.p(), &["config", "--unset-all", "remote.origin.push"]);
        } else if scenario == 6 && updated {
            git(
                &f.p(),
                &[
                    "config",
                    "remote.origin.push",
                    "refs/heads/main:refs/heads/deploy",
                ],
            );
        }
        signal.store(true, Ordering::SeqCst);
        let receipt = worker.join().unwrap();
        assert!(
            updated,
            "post-receive must prove remote update before cancelling"
        );
        let remote = if scenario == 1 { &moved } else { &bare };
        assert_eq!(
            git(
                remote,
                &[
                    "rev-parse",
                    if scenario == 4 || scenario == 5 {
                        "refs/heads/deploy"
                    } else {
                        "refs/heads/main"
                    }
                ]
            ),
            git(&f.p(), &["rev-parse", "HEAD"])
        );
        if scenario == 4 || scenario == 5 {
            assert_eq!(
                git(remote, &["for-each-ref", "--format=%(refname)"]),
                b"refs/heads/deploy\n"
            );
        }
        let OperationState::Unknown(evidence) = &receipt.state else {
            panic!("{receipt:?}")
        };
        if scenario == 3 {
            assert!(
                evidence
                    .explanation
                    .contains("Push and fetch endpoints differ")
            );
        }
        if scenario >= 4 {
            assert!(
                evidence.explanation.contains("Configured push mapping"),
                "{evidence:?}"
            );
        }
        let ObservedState::GitNetwork {
            intent,
            observation,
            ..
        } = &evidence.observed
        else {
            panic!("local state is not network reconciliation: {receipt:?}");
        };
        assert_eq!(intent.action, GitNetworkAction::Push);
        assert_eq!(intent.remote, b"origin");
        assert_eq!(intent.reference, b"refs/heads/main");
        assert_eq!(observation.is_none(), unavailable);
        if let Some(observation) = observation {
            assert_eq!(
                observation.remote_oid.as_deref(),
                Some(
                    String::from_utf8_lossy(&git(remote, &["rev-parse", "refs/heads/main"])).trim()
                )
            );
        }
        assert_eq!(
            f.local
                .files
                .inspect_sync(request.operation, f.local.identity.clone())
                .unwrap(),
            receipt
        );
        assert_eq!(
            f.local.git.mutate_sync(request, &AtomicBool::new(false)),
            receipt,
            "never replay"
        );
        assert_eq!(
            fs::read(f.p().join(".git/push-attempts")).unwrap(),
            b"attempt\n"
        );
    }
}

#[test]
fn interrupted_fetch_and_pull_record_fetched_refs_and_fetch_head() {
    use std::sync::atomic::{AtomicBool, Ordering};
    for pull in [false, true] {
        let f = Fixture::new();
        f.file("file", b"base");
        f.commit();
        let bare = f.dir.path().join("remote.git");
        git(
            f.dir.path(),
            &[
                "clone",
                "--bare",
                f.p().to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
        );
        git(&f.p(), &["remote", "add", "origin", bare.to_str().unwrap()]);
        let hook = f.p().join(".git/hooks/reference-transaction");
        fs::write(&hook, b"#!/bin/sh\ncat > /dev/null\nif [ \"$1\" = committed ]; then echo updated > .git/fetched; sleep 20; fi\n").unwrap();
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
        let snapshot = f.status();
        let request = GitMutationRequest {
            operation: OperationID([111 + u8::from(pull); 16]),
            worktree: snapshot.worktree,
            expected: snapshot.state,
            command: if pull {
                GitMutation::PullFastForward {
                    remote: b"origin".to_vec(),
                    reference: b"refs/heads/main".to_vec(),
                }
            } else {
                GitMutation::Fetch {
                    remote: b"origin".to_vec(),
                }
            },
        };
        let signal = Arc::new(AtomicBool::new(false));
        let cancel = signal.clone();
        let service = f.local.git.clone();
        let worker = std::thread::spawn(move || service.mutate_sync(request, &cancel));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !f.p().join(".git/fetched").exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let updated = f.p().join(".git/fetched").exists();
        signal.store(true, Ordering::SeqCst);
        let receipt = worker.join().unwrap();
        assert!(updated);
        let OperationState::Unknown(evidence) = receipt.state else {
            panic!("{receipt:?}")
        };
        let ObservedState::GitNetwork {
            intent,
            observation: Some(observed),
            ..
        } = evidence.observed
        else {
            panic!("{evidence:?}")
        };
        assert_eq!(
            intent.action,
            if pull {
                GitNetworkAction::PullFastForward
            } else {
                GitNetworkAction::Fetch
            }
        );
        assert_eq!(
            observed.fetch_head_oids,
            git(&bare, &["rev-parse", "refs/heads/main"])
        );
        assert!(
            observed.fetch_head_oids.starts_with(
                git(&bare, &["rev-parse", "refs/heads/main"])
                    .strip_suffix(b"\n")
                    .unwrap()
            )
        );
        assert_eq!(
            git(&f.p(), &["rev-parse", "refs/remotes/origin/main"]),
            git(&bare, &["rev-parse", "refs/heads/main"])
        );
    }
}
