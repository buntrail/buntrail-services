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
    os::unix::ffi::OsStrExt,
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
        Self { dir, service, root }
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
    fn commit(&self) {
        git(&self.p(), &["add", "--all"]);
        git(&self.p(), &["commit", "-m", "initial"]);
    }
}
#[test]
fn testHistoryFilterNeverChecksOut() {
    let f = Fixture::new();
    f.file("file", b"base\n");
    f.commit();
    git(&f.p(), &["branch", "topic"]);
    git(&f.p(), &["tag", "v1"]);
    let before = git(&f.p(), &["rev-parse", "HEAD"]);
    let page = run(f.service.history(HistoryQuery {
        worktree: f.worktree(),
        ref_filter: vec![b"refs/heads/topic".to_vec()],
        cursor: None,
    }))
    .unwrap();
    assert_eq!(page.commits.len(), 1);
    assert!(
        page.commits[0]
            .decorations
            .contains(&b"refs/tags/v1".to_vec())
    );
    assert_eq!(git(&f.p(), &["rev-parse", "HEAD"]), before);
}
#[test]
fn testGraphContinuationAcrossPages() {
    let f = Fixture::new();
    f.file("file", b"base");
    f.commit();
    for n in 0..204 {
        git(
            &f.p(),
            &["commit", "--allow-empty", "-m", &format!("commit {n}")],
        );
    }
    let first = run(f.service.history(HistoryQuery {
        worktree: f.worktree(),
        ref_filter: vec![],
        cursor: None,
    }))
    .unwrap();
    assert_eq!(first.commits.len(), 200);
    assert_eq!(first.continuation_edges.len(), 1);
    let second = run(f.service.history(HistoryQuery {
        worktree: f.worktree(),
        ref_filter: vec![],
        cursor: first.next_cursor.clone(),
    }))
    .unwrap();
    assert_eq!(second.commits.len(), 5);
    assert_eq!(first.continuation_edges[0].1, second.commits[0].oid);
    assert!(second.next_cursor.is_none());
    assert!(second.continuation_edges.is_empty());
}
#[test]
fn unborn_history_is_explicitly_empty() {
    let f = Fixture::new();
    let page = run(f.service.history(HistoryQuery {
        worktree: f.worktree(),
        ref_filter: vec![],
        cursor: None,
    }))
    .unwrap();
    assert!(page.commits.is_empty());
    assert!(page.next_cursor.is_none());
}
#[test]
fn merge_tags_detached_and_pinned_page_tips() {
    let f = Fixture::new();
    f.file("file", b"base");
    f.commit();
    git(&f.p(), &["checkout", "-b", "side"]);
    git(&f.p(), &["commit", "--allow-empty", "-m", "side"]);
    git(&f.p(), &["checkout", "main"]);
    git(&f.p(), &["commit", "--allow-empty", "-m", "main"]);
    git(&f.p(), &["merge", "--no-ff", "side", "-m", "merge"]);
    git(&f.p(), &["tag", "-a", "release", "-m", "tag"]);
    let page = run(f.service.history(HistoryQuery {
        worktree: f.worktree(),
        ref_filter: vec![],
        cursor: None,
    }))
    .unwrap();
    assert_eq!(page.commits[0].parents.len(), 2);
    assert_eq!(page.commits[0].parent_lanes.len(), 2);
    assert_ne!(
        page.commits[0].parent_lanes[0],
        page.commits[0].parent_lanes[1]
    );
    assert!(
        page.commits[0]
            .decorations
            .contains(&b"refs/tags/release".to_vec())
    );
    let head = page.commits[0].oid.clone();
    git(&f.p(), &["checkout", "--detach", &head]);
    let detached = run(f.service.history(HistoryQuery {
        worktree: f.worktree(),
        ref_filter: vec![],
        cursor: None,
    }))
    .unwrap();
    assert_eq!(detached.commits[0].oid, head);
    assert!(matches!(f.status().state.head, GitHead::Detached(_)));
}
#[test]
fn cursor_is_bound_to_filter_and_stable_lanes() {
    let f = Fixture::new();
    f.file("file", b"base");
    f.commit();
    for n in 0..200 {
        git(&f.p(), &["commit", "--allow-empty", "-m", &format!("{n}")]);
    }
    let first = run(f.service.history(HistoryQuery {
        worktree: f.worktree(),
        ref_filter: vec![],
        cursor: None,
    }))
    .unwrap();
    git(
        &f.p(),
        &["commit", "--allow-empty", "-m", "new tip after page one"],
    );
    let second = run(f.service.history(HistoryQuery {
        worktree: f.worktree(),
        ref_filter: vec![],
        cursor: first.next_cursor.clone(),
    }))
    .unwrap();
    assert_eq!(second.commits.len(), 1);
    assert_eq!(first.continuation_edges[0].1, second.commits[0].oid);
    assert_eq!(
        first.commits.last().unwrap().parent_lanes[0],
        second.commits[0].lane
    );
    assert!(
        run(f.service.history(HistoryQuery {
            worktree: f.worktree(),
            ref_filter: vec![b"main".to_vec()],
            cursor: first.next_cursor
        }))
        .is_err()
    );
}
