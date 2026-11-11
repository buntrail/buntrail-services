#![cfg(unix)]
use buntrail_core::contracts::*;
use buntrail_services::{connections::local::LocalConnection, contracts::ServiceAvailability};
#[test]
fn local_composition_installs_production_search() {
    let d = tempfile::tempdir().unwrap();
    let c = LocalConnection::open(d.path().join("state")).unwrap();
    assert!(
        matches!(c.environment().search, ServiceAvailability::Available(_)),
        "local search must be available without a system rg"
    );
}
use std::sync::atomic::{AtomicBool, Ordering};
fn setup() -> (tempfile::TempDir, LocalConnection, SearchRequest) {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("project");
    std::fs::create_dir(&root).unwrap();
    let c = LocalConnection::open(d.path().join("state")).unwrap();
    let r = SearchRequest {
        request: RequestId(1),
        root: FileRef {
            target: c.identity.clone(),
            path: TargetPath::posix(
                std::os::unix::ffi::OsStrExt::as_bytes(root.as_os_str()).to_vec(),
            )
            .unwrap(),
            resolved_identity: None,
        },
        expression: "needle".into(),
        mode: SearchMode::Literal,
        case_sensitive: true,
        whole_word: false,
        includes: vec![],
        excludes: vec![],
        hidden: false,
        ignored: false,
    };
    (d, c, r)
}
fn collect(c: &LocalConnection, r: SearchRequest) -> Vec<SearchEvent> {
    let mut events = vec![];
    c.search.run(r, &AtomicBool::new(false), |e| {
        events.push(e);
        true
    });
    events
}
#[test]
fn test_cancelled_search_stays_incomplete() {
    let (d, c, r) = setup();
    std::fs::write(d.path().join("project/flood.txt"), "needle\n".repeat(50000)).unwrap();
    let cancel = AtomicBool::new(false);
    let mut events = vec![];
    c.search.run(r, &cancel, |e| {
        if matches!(e, SearchEvent::Match(_)) {
            cancel.store(true, Ordering::SeqCst);
        }
        events.push(e);
        true
    });
    assert!(events.iter().any(|e| matches!(e, SearchEvent::Match(_))));
    assert!(matches!(events.last(), Some(SearchEvent::Cancelled)));
    assert!(!events.iter().any(|e| matches!(e, SearchEvent::Complete)));
}
#[test]
fn output_flood_is_limited_and_target_removal_is_partial() {
    let (d, c, r) = setup();
    let root = d.path().join("project");
    std::fs::write(root.join("flood.txt"), "needle\n".repeat(20002)).unwrap();
    let e = collect(&c, r.clone());
    assert_eq!(
        e.iter()
            .filter(|e| matches!(e, SearchEvent::Match(_)))
            .count(),
        20000
    );
    assert!(matches!(
        e.last(),
        Some(SearchEvent::Limited { maximum: 20000 })
    ));
    let mut removed = false;
    let mut events = vec![];
    c.search.run(r, &AtomicBool::new(false), |e| {
        if !removed && matches!(e, SearchEvent::Match(_)) {
            std::fs::remove_dir_all(&root).unwrap();
            removed = true;
        }
        events.push(e);
        true
    });
    assert!(removed);
    assert!(matches!(events.last(), Some(SearchEvent::Failed(_))));
}
#[test]
fn ignore_hidden_globs_unicode_empty_and_errors() {
    let (d, c, mut r) = setup();
    let root = d.path().join("project");
    for dir in [".codex", ".claude", ".github", "node_modules"] {
        std::fs::create_dir(root.join(dir)).unwrap();
        std::fs::write(root.join(dir).join("agent.txt"), "needle\n").unwrap();
    }
    std::fs::write(root.join(".gitignore"), "ignored.txt\n").unwrap();
    std::fs::write(root.join("ignored.txt"), "needle\n").unwrap();
    std::fs::write(root.join("main.txt"), "😀 needle\n").unwrap();
    let e = collect(&c, r.clone());
    let m: Vec<_> = e
        .iter()
        .filter_map(|e| {
            if let SearchEvent::Match(m) = e {
                Some(m)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].preview_column_utf8, 5);
    assert!(!m[0].searched_version.opaque_token.is_empty());
    r.hidden = true;
    r.ignored = true;
    r.includes = vec!["*.txt".into()];
    r.excludes = vec!["main.txt".into()];
    let e = collect(&c, r.clone());
    assert_eq!(
        e.iter()
            .filter(|e| matches!(e, SearchEvent::Match(_)))
            .count(),
        5
    );
    assert!(matches!(e.last(), Some(SearchEvent::Complete)));
    r.expression = "missing".into();
    assert!(matches!(
        collect(&c, r.clone()).last(),
        Some(SearchEvent::Complete)
    ));
    r.expression = "[".into();
    r.mode = SearchMode::Regex;
    assert!(matches!(
        collect(&c, r).last(),
        Some(SearchEvent::Failed(CoreError {
            code: ErrorCode::InvalidArgument,
            ..
        }))
    ));
}
#[test]
fn test_stale_search_result_remaps() {
    let (d, c, r) = setup();
    std::fs::write(d.path().join("project/main.txt"), "😀 needle\n").unwrap();
    let e = collect(&c, r);
    let m = e
        .iter()
        .find_map(|e| {
            if let SearchEvent::Match(m) = e {
                Some(m)
            } else {
                None
            }
        })
        .unwrap();
    let options = buntrail_core::search::find::FindOptions {
        expression: "needle".into(),
        mode: SearchMode::Literal,
        case_sensitive: true,
        whole_word: false,
        scope: None,
    };
    let text = buntrail_core::Text::from("inserted\n😀 needle\n");
    let range =
        buntrail_core::search::find::resolve(&text, BufferRevision(5), &options, m).unwrap();
    assert_eq!(range.start, 12);
    assert_eq!(range.revision, BufferRevision(5));
    let changed = buntrail_core::Text::from("😀 gone\n");
    assert!(
        buntrail_core::search::find::resolve(&changed, BufferRevision(6), &options, m).is_err()
    );
}
#[test]
fn mapper_preserves_non_utf8_path_bytes() {
    let root = setup().2.root;
    let v = serde_json::json!({"data":{"path":{"bytes":"L3RtcC//"},"lines":{"text":"needle\n"},"line_number":1,"submatches":[{"start":0}]}});
    let m = buntrail_services::search::result_mapper::matches(&v, &root)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        m[0].file.path,
        TargetPath::posix(vec![b'/', b't', b'm', b'p', b'/', 255]).unwrap()
    );
}
#[test]
fn async_service_stream_is_bounded_and_drop_cancels_producer() {
    use buntrail_services::contracts::SearchService;
    use std::{
        task::{Context, Poll, Waker},
        time::{Duration, Instant},
    };
    let (d, c, r) = setup();
    std::fs::write(
        d.path().join("project/flood.txt"),
        "needle\n".repeat(100000),
    )
    .unwrap();
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = c.search.search(r);
    let mut stream = match future.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(s)) => s,
        _ => panic!("stream admission"),
    };
    drop(future);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Poll::Ready(Some(Ok(SearchEvent::Match(_)))) = stream.as_mut().poll_next(&mut cx) {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(c.search.active_searches(), 1);
    drop(stream);
    while c.search.active_searches() != 0 {
        assert!(
            Instant::now() < deadline,
            "dropped stream must kill/reap producer under backpressure"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}
#[test]
fn changed_duplicate_at_old_line_is_not_silently_selected() {
    let (d, c, r) = setup();
    std::fs::write(d.path().join("project/main.txt"), "😀 needle\n").unwrap();
    let e = collect(&c, r);
    let m = e
        .iter()
        .find_map(|e| {
            if let SearchEvent::Match(m) = e {
                Some(m)
            } else {
                None
            }
        })
        .unwrap();
    let options = buntrail_core::search::find::FindOptions {
        expression: "needle".into(),
        mode: SearchMode::Literal,
        case_sensitive: true,
        whole_word: false,
        scope: None,
    };
    let changed = buntrail_core::Text::from("😀 needle\n😀 needle\n");
    assert!(
        buntrail_core::search::find::resolve(&changed, BufferRevision(5), &options, m).is_err(),
        "a new identical line at the old coordinate is ambiguous after content changes"
    );
}
#[test]
fn real_process_preserves_unusual_path_bytes_and_search_options() {
    let (d, c, mut r) = setup();
    let path = d.path().join("project/café\n🐇.txt");
    std::fs::write(&path, "😀 NEEDLE needles needle_ needle.\r\n").unwrap();
    r.whole_word = true;
    r.case_sensitive = false;
    r.mode = SearchMode::Regex;
    r.expression = "n(e+)dle".into();
    let e = collect(&c, r.clone());
    let m: Vec<_> = e
        .iter()
        .filter_map(|e| {
            if let SearchEvent::Match(m) = e {
                Some(m)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(m.len(), 2);
    assert_eq!(m[0].preview_column_utf8, 5);
    assert_eq!(m[1].preview_column_utf8, 28);
    assert_eq!(
        m[0].file.path,
        TargetPath::posix(std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str()).to_vec())
            .unwrap()
    );
    assert!(matches!(e.last(), Some(SearchEvent::Complete)));
    r.case_sensitive = true;
    assert_eq!(
        collect(&c, r)
            .iter()
            .filter(|e| matches!(e, SearchEvent::Match(_)))
            .count(),
        1
    );
}

#[test]
fn fix1_independently_observed_duplicate_digest_cannot_disambiguate_old_output() {
    let (d, c, r) = setup();
    let path = d.path().join("project/race.txt");
    std::fs::write(&path, "needle\n").unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap().with_file_name("rg"))
        .args(["--no-config", "--json", "--regexp", "needle", "--"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let record: serde_json::Value = output
        .stdout
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice::<serde_json::Value>(l).unwrap())
        .find(|v| v["type"] == "match")
        .unwrap();
    // Deterministic adapter boundary: rg has searched/output old bytes; the live version read has not happened.
    std::fs::write(&path, "needle\nneedle\n").unwrap();
    let mut found = buntrail_services::search::result_mapper::matches(&record, &r.root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(found.preview, "needle\n");
    found.searched_version = c.files.path_version(found.file.clone()).unwrap();
    let current = buntrail_core::Text::from(std::fs::read_to_string(&path).unwrap());
    let options = buntrail_core::search::find::FindOptions {
        expression: "needle".into(),
        mode: SearchMode::Literal,
        case_sensitive: true,
        whole_word: false,
        scope: None,
    };
    assert_eq!(
        buntrail_core::search::find::resolve(&current, BufferRevision(1), &options, &found)
            .unwrap_err()
            .code,
        ErrorCode::StaleRevision
    );
}

fn assert_matching_policy(
    expression: &str,
    mode: SearchMode,
    whole_word: bool,
    text: &str,
    expected: &[(u64, u64)],
) {
    use buntrail_core::search::find::{FindOptions, find, resolve};
    let (d, c, mut request) = setup();
    std::fs::write(d.path().join("project/policy.txt"), text).unwrap();
    request.expression = expression.into();
    request.mode = mode.clone();
    request.whole_word = whole_word;
    let events = collect(&c, request);
    assert!(
        matches!(events.last(), Some(SearchEvent::Complete)),
        "{expression}: {events:?}"
    );
    let matches: Vec<_> = events
        .iter()
        .filter_map(|e| {
            if let SearchEvent::Match(m) = e {
                Some(m.as_ref())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(matches.len(), expected.len(), "workspace {expression:?}");
    let options = FindOptions {
        expression: expression.into(),
        mode,
        case_sensitive: true,
        whole_word,
        scope: None,
    };
    let current = buntrail_core::Text::from(text);
    let local = find(&current, BufferRevision(0), &options).unwrap();
    assert_eq!(
        local.iter().map(|r| (r.start, r.end)).collect::<Vec<_>>(),
        expected,
        "file find {expression:?}"
    );
    for (searched, expected) in matches.iter().zip(&local) {
        assert_eq!(
            &resolve(&current, BufferRevision(0), &options, searched).unwrap(),
            expected,
            "resolve {expression:?}"
        );
    }
}
#[test]
fn fix1_whole_word_punctuation_policy() {
    assert_matching_policy("@", SearchMode::Literal, true, "@\n", &[(0, 1)]);
    assert_matching_policy("-2", SearchMode::Literal, true, "foo -2 bar\n", &[(4, 6)]);
    assert_matching_policy("a|ab", SearchMode::Regex, true, "ab a\n", &[(0, 2), (3, 4)]);
    assert_matching_policy("café@", SearchMode::Literal, true, " café@ \r\n", &[(1, 6)]);
}
#[test]
fn fix1_crlf_anchor_policy() {
    assert_matching_policy(
        "^needle$",
        SearchMode::Regex,
        false,
        "needle\r\n",
        &[(0, 6)],
    );
}
#[test]
fn fix1_explicit_cr_policy() {
    assert_matching_policy(
        r"needle\r",
        SearchMode::Regex,
        false,
        "needle\r\n",
        &[(0, 7)],
    );
}
#[test]
fn fix1_crlf_zero_width_policy() {
    assert_matching_policy("$", SearchMode::Regex, false, "needle\r\n", &[(6, 6)]);
    assert_matching_policy("(?-R:$)", SearchMode::Regex, false, "needle\r\n", &[(7, 7)]);
    assert_matching_policy(
        "(?-m:^needle$)",
        SearchMode::Regex,
        false,
        "needle\n",
        &[(0, 6)],
    );
    assert_matching_policy(
        "(?s:needle.*)",
        SearchMode::Regex,
        false,
        "needle\r\n",
        &[(0, 7)],
    );
}

#[test]
fn explorer_review_selected_search_is_anchored_to_workspace_not_process_directory() {
    let (dir, connection, mut request) = setup();
    std::fs::write(dir.path().join("project/plain"), b"needle\n").unwrap();
    std::fs::write(dir.path().join("project/unselected"), b"needle\n").unwrap();
    request.includes = vec!["/plain".into()];
    let events = collect(&connection, request);
    let matches = events
        .iter()
        .filter_map(|event| {
            if let SearchEvent::Match(found) = event {
                Some(found)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "{events:?}");
    assert_eq!(
        matches[0].file.path,
        TargetPath::posix(
            std::os::unix::ffi::OsStrExt::as_bytes(dir.path().join("project/plain").as_os_str())
                .to_vec()
        )
        .unwrap()
    );
}
