#![cfg(unix)]
use buntrail_core::contracts::{async_types::EventStream, *};
use buntrail_services::{connections::local::LocalConnection, contracts::*};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
    time::{Duration, Instant},
};
struct Unpark(std::thread::Thread);
impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}
fn run<T>(mut f: Pin<Box<dyn Future<Output = T> + Send + '_>>) -> T {
    let w = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&w);
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        assert!(Instant::now() < until, "service timed out");
        std::thread::park_timeout(Duration::from_millis(5));
    }
}
fn next(s: &mut EventStream<TerminalEvent>) -> Option<TerminalEvent> {
    let w = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&w);
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if let Poll::Ready(v) = s.as_mut().poll_next(&mut cx) {
            return v.map(Result::unwrap);
        }
        assert!(Instant::now() < until, "output timed out");
        std::thread::park_timeout(Duration::from_millis(5));
    }
}
fn setup() -> (
    tempfile::TempDir,
    LocalConnection,
    Arc<dyn TerminalService>,
    TerminalOpenRequest,
) {
    let dir = tempfile::tempdir().unwrap();
    let c = LocalConnection::open(dir.path().join("state")).unwrap();
    let owner = WorkspaceLease {
        client: c.client,
        workspace: WorkspaceID([1; 16]),
        lease: WorkspaceLeaseID([2; 16]),
        runtime: c.runtime.clone(),
    };
    c.register(owner.workspace, owner.lease).unwrap();
    let ServiceAvailability::Available(service) = c.environment().terminal else {
        panic!("local TerminalService must be available");
    };
    let r = TerminalOpenRequest {
        operation: OperationID([3; 16]),
        session: TerminalSessionID([4; 16]),
        owner,
        target: c.identity.clone(),
        runtime: c.runtime.clone(),
        directory: TargetPath::posix(dir.path().as_os_str().as_encoded_bytes().to_vec()).unwrap(),
        shell: TargetPath::posix(b"/bin/bash".to_vec()).unwrap(),
        size: TerminalSize {
            columns: 80.try_into().unwrap(),
            rows: 24.try_into().unwrap(),
        },
    };
    (dir, c, service, r)
}
fn attach(s: &dyn TerminalService, r: &TerminalOpenRequest) -> EventStream<TerminalEvent> {
    run(s.attach(TerminalAttachRequest {
        session: r.session,
        owner: r.owner.clone(),
        runtime: r.runtime.clone(),
        last_output_sequence: 0,
    }))
    .unwrap()
}
fn confirmed(r: OperationReceipt) {
    assert!(
        matches!(
            r.state,
            OperationState::Confirmed(MutationResult::TerminalOpened { .. })
        ),
        "{r:?}"
    );
}
#[test]
#[allow(non_snake_case)]
fn testTerminalChunkingResizeAndExit() {
    let (dir, _c, s, r) = setup();
    confirmed(run(s.open(r.clone())));
    let mut stream = attach(&*s, &r);
    run(s.resize(
        r.session,
        TerminalSize {
            columns: 111.try_into().unwrap(),
            rows: 37.try_into().unwrap(),
        },
    ))
    .unwrap();
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/terminal/chunked-output.py")
        .canonicalize()
        .unwrap();
    let command = format!(
        "stty -echo; printf 'CWD='; pwd; stty size; /usr/bin/python3 '{}'; exit 7\n",
        fixture.display()
    );
    run(s.input(r.session, command.into_bytes())).unwrap();
    let mut bytes = vec![];
    loop {
        match next(&mut stream).unwrap() {
            TerminalEvent::Output { bytes: b, .. } => bytes.extend(b),
            TerminalEvent::ProcessExit { code } => {
                assert_eq!(code, Some(7));
                break;
            }
            TerminalEvent::Gap { .. } => panic!("unexpected gap"),
            _ => {}
        }
    }
    let text = String::from_utf8(bytes).unwrap();
    assert!(
        text.contains(&format!(
            "CWD={}\r\n",
            dir.path().canonicalize().unwrap().display()
        )),
        "{text:?}"
    );
    assert!(text.contains("37 111"), "{text:?}");
    assert!(
        text.contains("界😀e\u{301}\u{1b}[?1049hALT\u{1b}[?1049lTAIL"),
        "{text:?}"
    );
}
#[test]
fn one_open_command_creates_one_process() {
    let (dir, c, s, r) = setup();
    confirmed(run(s.open(r.clone())));
    confirmed(run(s.open(r.clone())));
    let ServiceAvailability::Available(operations) = c.environment().operations else {
        panic!()
    };
    confirmed(run(operations.inspect(r.operation, r.target.clone())).unwrap());
    let mut stream = attach(&*s, &r);
    run(s.input(
        r.session,
        b"printf '%s' $$ > pid; printf 'READY\\n'\n".to_vec(),
    ))
    .unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    while !dir.path().join("pid").exists() {
        assert!(Instant::now() < until);
        let _ = next(&mut stream);
    }
    let pid = std::fs::read_to_string(dir.path().join("pid")).unwrap();
    confirmed(run(s.open(r.clone())));
    let mut changed = r.clone();
    changed.size.rows = 40.try_into().unwrap();
    assert!(matches!(
        run(s.open(changed)).state,
        OperationState::Failed(_)
    ));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("pid")).unwrap(),
        pid
    );
    run(s.end(r.session, TerminalEndIntent::ExplicitClose)).unwrap();
}
#[test]
fn renderer_drop_keeps_session_alive_until_explicit_end() {
    let (dir, _c, s, r) = setup();
    confirmed(run(s.open(r.clone())));
    drop(attach(&*s, &r));
    run(s.input(
        r.session,
        b"sleep 600 & echo $! > child; echo $$ > parent; printf 'STILL_ALIVE\\n'\n".to_vec(),
    ))
    .unwrap();
    let mut stream = attach(&*s, &r);
    let mut text = String::new();
    while !text.contains("STILL_ALIVE\r\n") {
        if let TerminalEvent::Output { bytes, .. } = next(&mut stream).unwrap() {
            text.push_str(&String::from_utf8_lossy(&bytes));
        }
    }
    let pids = ["parent", "child"].map(|p| {
        std::fs::read_to_string(dir.path().join(p))
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap()
    });
    run(s.end(r.session, TerminalEndIntent::ExplicitClose)).unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    for pid in pids {
        while unsafe { libc::kill(pid, 0) } == 0 {
            assert!(Instant::now() < until, "process {pid} not reaped");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
#[test]
#[allow(non_snake_case)]
fn testTerminalFloodIsBounded() {
    let (_dir, _c, s, r) = setup();
    confirmed(run(s.open(r.clone())));
    run(s.input(r.session,b"stty -echo; /usr/bin/python3 -c 'import os; os.write(1,b\"x\"*20000000); os.write(1,b\"y\\n\"*30000)'; exit\n".to_vec())).unwrap();
    // No consumer: the owner must keep reading and evict, never grow an unbounded queue.
    std::thread::sleep(Duration::from_secs(2));
    let mut stream = attach(&*s, &r);
    let (mut bytes, mut lines, mut gap) = (0, 0, false);
    loop {
        match next(&mut stream).unwrap() {
            TerminalEvent::Output { bytes: b, .. } => {
                bytes += b.len();
                lines += b.iter().filter(|b| **b == b'\n').count()
            }
            TerminalEvent::Gap { .. } => gap = true,
            TerminalEvent::ProcessExit { .. } => break,
            _ => {}
        }
    }
    assert!(gap);
    assert!(bytes <= 8 * 1024 * 1024, "retained bytes {bytes}");
    assert!(lines <= 10000, "retained lines {lines}");
}
#[test]
fn failed_launch_is_durable_and_never_retried_with_another_shell() {
    let (_dir, c, s, mut r) = setup();
    r.shell = TargetPath::posix(b"/no/such/buntrail-shell".to_vec()).unwrap();
    let first = run(s.open(r.clone()));
    assert!(matches!(first.state, OperationState::Failed(_)));
    assert_eq!(run(s.open(r.clone())), first);
    let ServiceAvailability::Available(operations) = c.environment().operations else {
        panic!()
    };
    assert_eq!(
        run(operations.inspect(r.operation, r.target.clone())).unwrap(),
        first
    );
    r.shell = TargetPath::posix(b"/bin/bash".to_vec()).unwrap();
    assert!(matches!(run(s.open(r)).state, OperationState::Failed(_)));
}
#[test]
fn replacement_attachment_closes_old_cursor_and_rejects_other_owner() {
    let (_dir, c, s, r) = setup();
    confirmed(run(s.open(r.clone())));
    let mut old = attach(&*s, &r);
    let _new = attach(&*s, &r);
    assert!(next(&mut old).is_none());
    let mut owner = r.owner.clone();
    owner.workspace = WorkspaceID([8; 16]);
    owner.lease = WorkspaceLeaseID([9; 16]);
    c.register(owner.workspace, owner.lease).unwrap();
    assert!(
        run(s.attach(TerminalAttachRequest {
            session: r.session,
            owner,
            runtime: r.runtime.clone(),
            last_output_sequence: 0
        }))
        .is_err()
    );
    let mut duplicate = r.clone();
    duplicate.operation = OperationID([7; 16]);
    assert!(matches!(
        run(s.open(duplicate)).state,
        OperationState::Failed(_)
    ));
    run(s.end(r.session, TerminalEndIntent::ExplicitClose)).unwrap();
}
#[test]
fn resize_coalesces_to_latest_visible_size_and_input_admission_is_bounded() {
    let (_dir, c, s, r) = setup();
    confirmed(run(s.open(r.clone())));
    assert_eq!(
        run(s.input(r.session, vec![b'x'; 65537])).unwrap_err().code,
        ErrorCode::Busy
    );
    for n in 80..200 {
        run(s.resize(
            r.session,
            TerminalSize {
                columns: n.try_into().unwrap(),
                rows: 40.try_into().unwrap(),
            },
        ))
        .unwrap();
    }
    let expected = TerminalSize {
        columns: 199.try_into().unwrap(),
        rows: 40.try_into().unwrap(),
    };
    let until = Instant::now() + Duration::from_secs(2);
    while c.terminal.delivered_size(r.session).unwrap() != expected {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(2));
    }
    run(s.end(r.session, TerminalEndIntent::ExplicitClose)).unwrap();
}
#[test]
fn workspace_end_preserves_other_owners_and_view_detachment_preserves_session() {
    let (_dir, c, s, r) = setup();
    confirmed(run(s.open(r.clone())));
    let mut other = r.clone();
    other.operation = OperationID([5; 16]);
    other.session = TerminalSessionID([6; 16]);
    other.owner.workspace = WorkspaceID([7; 16]);
    other.owner.lease = WorkspaceLeaseID([8; 16]);
    c.register(other.owner.workspace, other.owner.lease)
        .unwrap();
    confirmed(run(s.open(other.clone())));
    let ServiceAvailability::Available(leases) = c.environment().leases else {
        panic!()
    };
    run(leases.release(r.owner.lease, LeaseReleaseIntent::ViewDetachment)).unwrap();
    assert!(run(s.input(r.session, b"true\n".to_vec())).is_ok());
    run(leases.release(r.owner.lease, LeaseReleaseIntent::ResolvedWorkspaceClosure)).unwrap();
    let mut stream = attach(&*s, &other);
    run(s.input(
        other.session,
        b"printf '\\117\\124\\110\\105\\122'; exit\n".to_vec(),
    ))
    .unwrap();
    let mut bytes = vec![];
    loop {
        match next(&mut stream).unwrap() {
            TerminalEvent::Output { bytes: b, .. } => bytes.extend(b),
            TerminalEvent::ProcessExit { .. } => break,
            _ => {}
        }
    }
    assert!(String::from_utf8_lossy(&bytes).contains("OTHER"));
}
#[test]
fn concurrent_duplicate_launches_start_exactly_one_process() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, _c, s, mut r) = setup();
    let program = dir.path().join("shell");
    std::fs::write(&program, b"#!/bin/sh\necho $$ >> launches\nexec /bin/cat\n").unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    r.shell = TargetPath::posix(program.as_os_str().as_encoded_bytes().to_vec()).unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let mut workers = vec![];
    for _ in 0..8 {
        let service = s.clone();
        let r = r.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            run(service.open(r))
        }));
    }
    for worker in workers {
        confirmed(worker.join().unwrap());
    }
    let until = Instant::now() + Duration::from_secs(2);
    while std::fs::read_to_string(dir.path().join("launches"))
        .unwrap_or_default()
        .lines()
        .count()
        == 0
    {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(
        std::fs::read_to_string(dir.path().join("launches"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    run(s.end(r.session, TerminalEndIntent::ExplicitClose)).unwrap();
}
#[test]
fn final_close_during_launch_admission_does_not_block_or_leave_an_owned_process() {
    let (_dir, c, s, r) = setup();
    let service = s.clone();
    let request = r.clone();
    let launch = std::thread::spawn(move || run(service.open(request)));
    let start = Instant::now();
    c.release(r.owner.lease);
    assert!(start.elapsed() < Duration::from_millis(100));
    let receipt = launch.join().unwrap();
    assert!(matches!(
        receipt.state,
        OperationState::Failed(_) | OperationState::Confirmed(_)
    ));
    let until = Instant::now() + Duration::from_secs(5);
    while !c.terminal.shutdown_ready() {
        assert!(
            Instant::now() < until,
            "closing lease left a running process"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn ended_session_identity_cannot_be_reused_by_a_new_operation() {
    let (_dir, _c, s, r) = setup();
    confirmed(run(s.open(r.clone())));
    run(s.end(r.session, TerminalEndIntent::ExplicitClose)).unwrap();
    let mut second = r.clone();
    second.operation = OperationID([15; 16]);
    assert!(matches!(
        run(s.open(second)).state,
        OperationState::Failed(_)
    ));
    confirmed(run(s.open(r))); // resolves the original outcome, does not launch again
}
#[test]
fn detached_closed_histories_still_count_toward_environment_replay_budget() {
    let (_dir, _c, s, r) = setup();
    let mut histories = vec![];
    for n in 1..=8 {
        let mut request = r.clone();
        request.operation = OperationID([n; 16]);
        request.session = TerminalSessionID([n; 16]);
        confirmed(run(s.open(request.clone())));
        histories.push(attach(&*s, &request));
        run(s.end(request.session, TerminalEndIntent::ExplicitClose)).unwrap();
    }
    let mut ninth = r.clone();
    ninth.operation = OperationID([19; 16]);
    ninth.session = TerminalSessionID([19; 16]);
    assert!(matches!(
        run(s.open(ninth.clone())).state,
        OperationState::Failed(OperationFailure {
            error: CoreError {
                code: ErrorCode::Busy,
                ..
            },
            ..
        })
    ));
    drop(histories);
    confirmed(run(s.open(ninth.clone())));
    run(s.end(ninth.session, TerminalEndIntent::ExplicitClose)).unwrap();
}

#[test]
fn resolved_workspace_close_recovers_capacity_and_waits_for_retired_owners() {
    let (_dir, c, s, r) = setup();
    for n in 20..30 {
        let mut request = r.clone();
        request.operation = OperationID([n; 16]);
        request.session = TerminalSessionID([n; 16]);
        request.owner.lease = WorkspaceLeaseID([n; 16]);
        c.register(request.owner.workspace, request.owner.lease)
            .unwrap();
        confirmed(run(s.open(request.clone())));
        // A quiet, live shell cannot have finished when owner close is requested.
        c.release(request.owner.lease);
        assert!(
            !c.terminal.shutdown_ready(),
            "retired worker still has to reap its shell"
        );
        let until = Instant::now() + Duration::from_secs(5);
        while !c.terminal.shutdown_ready() {
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

#[test]
fn resolved_workspace_histories_count_only_while_really_retained() {
    let (_dir, c, s, r) = setup();
    let mut histories = vec![];
    for n in 30..38 {
        let mut request = r.clone();
        request.operation = OperationID([n; 16]);
        request.session = TerminalSessionID([n; 16]);
        request.owner.lease = WorkspaceLeaseID([n; 16]);
        c.register(request.owner.workspace, request.owner.lease)
            .unwrap();
        confirmed(run(s.open(request.clone())));
        histories.push(attach(&*s, &request));
        c.release(request.owner.lease);
    }
    let until = Instant::now() + Duration::from_secs(5);
    while !c.terminal.shutdown_ready() {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(matches!(
        run(s.open(r.clone())).state,
        OperationState::Failed(OperationFailure {
            error: CoreError {
                code: ErrorCode::Busy,
                ..
            },
            ..
        })
    ));
    drop(histories);
    confirmed(run(s.open(r.clone())));
    run(s.end(r.session, TerminalEndIntent::ExplicitClose)).unwrap();
}

#[test]
fn compacted_terminal_receipt_preserves_session_anti_reuse() {
    let (dir, _c, s, r) = setup();
    confirmed(run(s.open(r.clone())));
    run(s.end(r.session, TerminalEndIntent::ExplicitClose)).unwrap();
    let ledger = buntrail_services::operations::ledger::Ledger::open(
        dir.path().join("state/files/operations"),
    )
    .unwrap();
    {
        let lock = ledger.lock().unwrap();
        let mut record = ledger.read(r.operation).unwrap().unwrap();
        record.created = 0;
        ledger.write(&record).unwrap();
        ledger.recover_and_compact(&lock).unwrap();
    }
    assert!(matches!(
        ledger.inspect(r.operation, r.target.clone()).unwrap().state,
        OperationState::Unknown(_)
    ));
    let mut second = r.clone();
    second.operation = OperationID([15; 16]);
    assert!(matches!(
        run(s.open(second)).state,
        OperationState::Failed(_)
    ));
    assert!(matches!(run(s.open(r)).state, OperationState::Unknown(_)));
}
