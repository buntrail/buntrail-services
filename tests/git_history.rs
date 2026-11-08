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
        filter: None,
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
        filter: None,
        worktree: f.worktree(),
        ref_filter: vec![],
        cursor: None,
    }))
    .unwrap();
    assert_eq!(first.commits.len(), 200);
    assert_eq!(first.continuation_edges.len(), 1);
    let second = run(f.service.history(HistoryQuery {
        filter: None,
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
        filter: None,
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
        filter: None,
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
        filter: None,
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
        filter: None,
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
        filter: None,
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
            filter: None,
            worktree: f.worktree(),
            ref_filter: vec![b"main".to_vec()],
            cursor: first.next_cursor
        }))
        .is_err()
    );
}

#[test]
fn history_filters_beyond_first_page() {
    let f = Fixture::new();
    f.file("file", b"base\r\n");
    f.commit();
    for n in 0..205 {
        git(
            &f.p(),
            &["commit", "--allow-empty", "-m", &format!("noise {n}")],
        );
    }
    let before = git(&f.p(), &["rev-parse", "HEAD"]);
    let query: HistoryQuery = serde_json::from_value(serde_json::json!({
        "worktree": f.worktree(), "ref_filter": [], "cursor": null,
        "filter": {"authored_since": null, "text": "INITIAL"}
    }))
    .unwrap();
    let page = run(f.service.history(query)).unwrap();
    assert_eq!(
        page.commits.len(),
        1,
        "Filter must search beyond the first unfiltered page"
    );
    assert_eq!(page.commits[0].subject, "initial");
    assert!(page.next_cursor.is_none());
    assert_eq!(git(&f.p(), &["rev-parse", "HEAD"]), before);
    assert_eq!(fs::read(f.p().join("file")).unwrap(), b"base\r\n");
}

#[test]
fn history_date_filter_is_authored_date() {
    let f = Fixture::new();
    f.file("file", b"base");
    f.commit();
    let query: HistoryQuery = serde_json::from_value(serde_json::json!({
        "worktree": f.worktree(), "ref_filter": [], "cursor": null,
        "filter": {"authored_since": 4102444800_i64, "text": ""}
    }))
    .unwrap();
    let page = run(f.service.history(query)).unwrap();
    assert!(
        page.commits.is_empty(),
        "Future cutoff must exclude authored commits"
    );
}

#[test]
fn repository_snapshot_preserves_ref_identity() {
    let f = Fixture::new();
    f.file("file", b"base\r\n");
    f.commit();
    git(&f.p(), &["branch", "feat/one"]);
    git(&f.p(), &["tag", "v1"]);
    let before = git(&f.p(), &["rev-parse", "HEAD"]);
    let snapshot = run(f.service.repository(f.worktree())).unwrap();
    assert!(
        snapshot
            .refs
            .iter()
            .any(|r| r.name == b"refs/heads/feat/one")
    );
    assert!(snapshot.refs.iter().any(|r| r.name == b"refs/tags/v1"));
    assert_eq!(snapshot.worktree, f.worktree());
    assert!(snapshot.merge.is_none());
    assert!(
        snapshot
            .worktrees
            .iter()
            .any(|w| w.branch.as_deref() == Some(b"refs/heads/main".as_slice()))
    );
    assert_eq!(git(&f.p(), &["rev-parse", "HEAD"]), before);
}

#[test]
fn commit_diff_handles_root_merge_and_rename() {
    let f = Fixture::new();
    let path = f.file("file", b"base\r\n");
    f.commit();
    let id = String::from_utf8(git(&f.p(), &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_owned();
    f.file("file", b"dirty working copy");
    let diff = run(f.service.diff(DiffRequest {
        worktree: f.worktree(),
        path,
        source: DiffSource::Commit(id),
    }))
    .unwrap();
    assert_eq!(diff.content, DiffContent::Text);
    assert_eq!(diff.change, DiffChange::Added);
    let patch = String::from_utf8(diff.bytes).unwrap();
    assert!(patch.contains("+base\r\n"));
    assert!(!patch.contains("dirty working copy"));
    assert_eq!(fs::read(f.p().join("file")).unwrap(), b"dirty working copy");
}

#[test]
fn commit_detail_is_independent_of_worktree() {
    let f = Fixture::new();
    f.file("🐇 file\nname", b"base\r\n");
    f.commit();
    let oid = String::from_utf8(git(&f.p(), &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_owned();
    let page = run(f.service.commit(CommitQuery {
        worktree: f.worktree(),
        oid: oid.clone(),
        cursor: None,
    }))
    .unwrap();
    assert_eq!(page.oid, oid);
    assert_eq!(page.author, "Fixture");
    assert_eq!(page.email, "fixture@example.invalid");
    assert!(page.message.starts_with("initial"));
    assert!(page.parents.is_empty());
    assert_eq!(page.files.len(), 1);
    assert_eq!(page.files[0].change, DiffChange::Added);
    assert!(page.next_cursor.is_none());
}

#[test]
fn commit_textual_binary_marker_is_text() {
    let f = Fixture::new();
    let path = f.file("marker", b"GIT binary patch\n");
    f.commit();
    let oid = String::from_utf8(git(&f.p(), &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_owned();
    let diff = run(f.service.diff(DiffRequest {
        worktree: f.worktree(),
        path,
        source: DiffSource::Commit(oid),
    }))
    .unwrap();
    assert_eq!(diff.content, DiffContent::Text);
}

#[test]
fn sparse_filtered_history_reads_every_page_without_artificial_topology() {
    use std::io::Write;
    use std::process::Stdio;
    let f = Fixture::new();
    let mut import = Command::new("git")
        .arg("-C")
        .arg(f.p())
        .args(["fast-import", "--quiet"])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut data = String::new();
    for index in 0..1400 {
        let message = if index % 2 == 0 { "MATCH" } else { "excluded" };
        data += &format!(
            "commit refs/heads/main\nauthor Fixture <fixture@example.invalid> {} +0000\ncommitter Fixture <fixture@example.invalid> {} +0000\ndata {}\n{}\n\n",
            1700000000 + index,
            1700000000 + index,
            message.len(),
            message
        );
    }
    import
        .stdin
        .take()
        .unwrap()
        .write_all(data.as_bytes())
        .unwrap();
    assert!(import.wait().unwrap().success());
    let mut cursor = None;
    let mut all = std::collections::HashSet::new();
    loop {
        let page = run(f.service.history(HistoryQuery {
            worktree: f.worktree(),
            ref_filter: vec![],
            cursor,
            filter: Some(HistoryFilter {
                authored_since: None,
                text: "MATCH".into(),
            }),
        }))
        .expect("simple filtered history must not exhaust graph lanes");
        for commit in page.commits {
            assert!(all.insert(commit.oid), "no duplicate commit across pages");
            assert_eq!(commit.subject, "MATCH");
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(all.len(), 700);
}
