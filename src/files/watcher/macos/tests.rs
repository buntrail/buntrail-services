use super::*;

// Native fixtures share the process and macOS FSEvents service.
static SERIAL: Mutex<()> = Mutex::new(());

#[test]
fn concurrent_native_roots_wake_their_own_streams_and_retire_workers() {
    use std::task::{Wake, Waker};
    struct Notice(std::sync::mpsc::Sender<()>);
    impl Wake for Notice {
        fn wake(self: Arc<Self>) {
            let _ = self.0.send(());
        }
    }
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut admissions = Vec::new();
    for identity in [1, 2] {
        let dir = tempfile::tempdir().unwrap();
        let target = TargetIdentity {
            security_binding: vec![identity],
            effective_user: vec![2],
            filesystem_namespace: vec![3],
            container: None,
        };
        let root = FileRef {
            target: target.clone(),
            path: TargetPath::posix(dir.path().as_os_str().as_bytes().to_vec()).unwrap(),
            resolved_identity: None,
        };
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        instrumentation::barrier(dir.path(), entered_tx, resume_rx);
        let watched_root = root.clone();
        let job = std::thread::spawn(move || super::super::watch(target, watched_root).unwrap());
        admissions.push((dir, root, entered_rx, resume_tx, job));
    }
    for (dir, _, entered, _, _) in &admissions {
        entered.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(instrumentation::workers(dir.path()), 1);
    }
    // Both independent workers must reach admission before either is released.
    for (_, _, _, resume, _) in &admissions {
        resume.send(()).unwrap();
    }
    let mut watches = Vec::new();
    for (dir, root, _, _, job) in admissions {
        let stream = job.join().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let waker = Waker::from(Arc::new(Notice(tx)));
        watches.push((dir, root, stream, rx, waker));
    }
    for revision in ["first", "second"] {
        for (_, root, stream, rx, waker) in &mut watches {
            let mut context = Context::from_waker(waker);
            while let Poll::Ready(Some(event)) = stream.as_mut().poll_next(&mut context) {
                assert!(
                    matches!(event.unwrap(), FileEvent::RescanRequired(ref file) if file == root)
                );
            }
            while rx.try_recv().is_ok() {}
        }
        for (dir, _, _, _, _) in &watches {
            fs::write(dir.path().join(revision), revision).unwrap();
        }
        for (_, root, stream, rx, waker) in &mut watches {
            let mut context = Context::from_waker(waker);
            rx.recv_timeout(Duration::from_secs(3))
                .expect("each native root must wake its own owner");
            assert!(matches!(stream.as_mut().poll_next(&mut context),
                    Poll::Ready(Some(Ok(FileEvent::RescanRequired(ref file)))) if file == root));
        }
    }
    let dirs: Vec<_> = watches
        .into_iter()
        .map(|(dir, _, stream, _, _)| {
            drop(stream);
            dir
        })
        .collect();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while dirs
        .iter()
        .any(|dir| instrumentation::workers(dir.path()) != 0)
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(
            Duration::from_millis(10)
                .min(deadline.saturating_duration_since(std::time::Instant::now())),
        );
    }
    for dir in dirs {
        assert_eq!(instrumentation::workers(dir.path()), 0);
    }
}

#[test]
fn actual_watch_stream_wakes_its_owner_after_a_native_scan_change() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    use std::task::{Wake, Waker};
    struct Notice(std::sync::mpsc::Sender<()>);
    impl Wake for Notice {
        fn wake(self: Arc<Self>) {
            let _ = self.0.send(());
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    fs::write(&file, b"initial").unwrap();
    let target = TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    let root = FileRef {
        target: target.clone(),
        path: TargetPath::posix(dir.path().as_os_str().as_bytes().to_vec()).unwrap(),
        resolved_identity: None,
    };
    let mut stream = super::super::watch(target, root.clone()).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let waker = Waker::from(Arc::new(Notice(tx)));
    let mut context = Context::from_waker(&waker);
    assert!(stream.as_mut().poll_next(&mut context).is_pending());
    fs::write(file, b"changed native content").unwrap();
    rx.recv_timeout(std::time::Duration::from_secs(3))
        .expect("quiet owner must be woken by the watch worker");
    let event = stream.as_mut().poll_next(&mut context);
    assert!(
        matches!(event, Poll::Ready(Some(Ok(FileEvent::Changed(ref file) | FileEvent::RescanRequired(ref file)))) if file == &root)
    );
    drop(stream);
}

#[test]
fn quiet_watch_does_not_repeat_tree_scans() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let target = TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    let root = FileRef {
        target: target.clone(),
        path: TargetPath::posix(dir.path().as_os_str().as_bytes().to_vec()).unwrap(),
        resolved_identity: None,
    };
    let stream = super::super::watch(target, root).unwrap();
    let after_admission = instrumentation::scans(dir.path());
    std::thread::sleep(Duration::from_millis(900));
    assert_eq!(
        instrumentation::scans(dir.path()),
        after_admission,
        "quiet native watch must not scan periodically"
    );
    drop(stream);
}

#[test]
fn root_rename_away_and_back_still_observes_later_write() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    use std::task::{Wake, Waker};
    struct Notice(std::sync::mpsc::Sender<()>);
    impl Wake for Notice {
        fn wake(self: Arc<Self>) {
            let _ = self.0.send(());
        }
    }
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("root");
    let moved = parent.path().join("moved");
    fs::create_dir(&dir).unwrap();
    let target = TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    let root = FileRef {
        target: target.clone(),
        path: TargetPath::posix(dir.as_os_str().as_bytes().to_vec()).unwrap(),
        resolved_identity: None,
    };
    let mut stream = super::super::watch(target, root).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let waker = Waker::from(Arc::new(Notice(tx)));
    let mut context = Context::from_waker(&waker);
    assert!(stream.as_mut().poll_next(&mut context).is_pending());
    fs::rename(&dir, &moved).unwrap();
    fs::rename(&moved, &dir).unwrap();
    rx.recv_timeout(Duration::from_secs(3))
        .expect("root move must wake watch");
    assert!(stream.as_mut().poll_next(&mut context).is_ready());
    assert!(stream.as_mut().poll_next(&mut context).is_pending());
    fs::write(dir.join("later"), b"changed").unwrap();
    rx.recv_timeout(Duration::from_secs(3))
        .expect("later write must still wake watch");
    assert!(stream.as_mut().poll_next(&mut context).is_ready());
}

#[test]
fn synthetic_large_callback_coalesces_and_context_releases() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    for _ in 0..20 {
        let native = Native::start(dir.path()).expect("native stream must start");
        let signal = Arc::downgrade(&native.signal);
        unsafe {
            callback(
                native.stream,
                Arc::as_ptr(&native.signal) as *mut _,
                usize::MAX,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            );
            callback(
                native.stream,
                Arc::as_ptr(&native.signal) as *mut _,
                usize::MAX,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            );
        }
        assert!(native.take_dirty());
        assert!(!native.take_dirty());
        drop(native);
        for _ in 0..100 {
            if signal.upgrade().is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            signal.upgrade().is_none(),
            "stream callback context must be released"
        );
    }
}

#[test]
fn native_rejects_final_symlink_and_non_utf8_path() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    use std::os::unix::ffi::OsStringExt;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    fs::create_dir(&target).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(Native::start(&link).is_none());
    let invalid = dir.path().join(std::ffi::OsString::from_vec(vec![0xff]));
    assert!(
        utf8_path(&invalid).is_none(),
        "synthetic non-UTF8 bytes are rejected before conversion"
    );
}

#[test]
fn deleting_root_reports_error_then_replacement_is_polled() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    use std::task::{Wake, Waker};
    struct Notice(std::sync::mpsc::Sender<()>);
    impl Wake for Notice {
        fn wake(self: Arc<Self>) {
            let _ = self.0.send(());
        }
    }
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("root");
    fs::create_dir(&dir).unwrap();
    let target = TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    let root = FileRef {
        target: target.clone(),
        path: TargetPath::posix(dir.as_os_str().as_bytes().to_vec()).unwrap(),
        resolved_identity: None,
    };
    let mut stream = super::super::watch(target, root).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let waker = Waker::from(Arc::new(Notice(tx)));
    let mut context = Context::from_waker(&waker);
    assert!(stream.as_mut().poll_next(&mut context).is_pending());
    fs::remove_dir(&dir).unwrap();
    rx.recv_timeout(Duration::from_secs(3))
        .expect("deletion must wake watch");
    assert!(matches!(
        stream.as_mut().poll_next(&mut context),
        Poll::Ready(Some(Err(_)))
    ));
    assert!(stream.as_mut().poll_next(&mut context).is_pending());
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("replacement"), b"changed").unwrap();
    rx.recv_timeout(Duration::from_secs(3))
        .expect("fallback must poll original path");
    assert!(matches!(
        stream.as_mut().poll_next(&mut context),
        Poll::Ready(Some(Ok(_)))
    ));
}

#[test]
fn registration_keeps_a_change_while_admission_scan_is_blocked() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    use std::task::{Wake, Waker};
    struct Notice(std::sync::mpsc::Sender<()>);
    impl Wake for Notice {
        fn wake(self: Arc<Self>) {
            let _ = self.0.send(());
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let target = TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    let root = FileRef {
        target: target.clone(),
        path: TargetPath::posix(dir.path().as_os_str().as_bytes().to_vec()).unwrap(),
        resolved_identity: None,
    };
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    instrumentation::barrier(dir.path(), entered_tx, resume_rx);
    let job = std::thread::spawn(move || super::super::watch(target, root).unwrap());
    entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    fs::write(dir.path().join("during-admission"), b"change").unwrap();
    std::thread::sleep(Duration::from_millis(600));
    resume_tx.send(()).unwrap();
    let mut stream = job.join().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let waker = Waker::from(Arc::new(Notice(tx)));
    let mut context = Context::from_waker(&waker);
    match stream.as_mut().poll_next(&mut context) {
        Poll::Pending => {
            rx.recv_timeout(Duration::from_secs(3))
                .expect("pending admission hint must wake");
            assert!(stream.as_mut().poll_next(&mut context).is_ready());
        }
        Poll::Ready(Some(Ok(_))) => (),
        _ => panic!("admission hint was lost"),
    }
}

#[test]
fn dropped_watches_stop_workers_and_release_descriptors() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    if std::env::var_os("BUNTRAIL_WATCH_FD_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "files::watcher::macos::tests::dropped_watches_stop_workers_and_release_descriptors", "--nocapture"])
            .env("BUNTRAIL_WATCH_FD_CHILD", "1")
            .output().unwrap();
        print!("{}", String::from_utf8_lossy(&output.stdout));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        return;
    }
    fn descriptors() -> Vec<(i32, u64, u64, u32)> {
        let numbers: Vec<i32> = fs::read_dir("/dev/fd")
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().to_string_lossy().parse().ok())
            .collect();
        let mut result = Vec::new();
        for fd in numbers {
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut stat) } == 0 {
                result.push((fd, stat.st_dev as u64, stat.st_ino, stat.st_mode as u32));
            }
        }
        result.sort();
        result
    }
    let dir = tempfile::tempdir().unwrap();
    let cold = descriptors();
    let mut checkpoints = Vec::new();
    for cycle in 1..=20 {
        let target = TargetIdentity {
            security_binding: vec![1],
            effective_user: vec![2],
            filesystem_namespace: vec![3],
            container: None,
        };
        let root = FileRef {
            target: target.clone(),
            path: TargetPath::posix(dir.path().as_os_str().as_bytes().to_vec()).unwrap(),
            resolved_identity: None,
        };
        let stream = super::super::watch(target, root).unwrap();
        fs::write(dir.path().join("queued"), b"event").unwrap();
        drop(stream);
        if [1, 5, 20].contains(&cycle) {
            let started = std::time::Instant::now();
            let worker_deadline = started + Duration::from_millis(2000);
            let deadline = started + Duration::from_millis(2500);
            while instrumentation::workers(dir.path()) != 0
                && std::time::Instant::now() < worker_deadline
            {
                std::thread::sleep(
                    Duration::from_millis(10)
                        .min(worker_deadline.saturating_duration_since(std::time::Instant::now())),
                );
            }
            assert_eq!(instrumentation::workers(dir.path()), 0);
            // Native teardown can return before resource retirement; keep the original grace.
            let eligible = std::time::Instant::now() + Duration::from_millis(500);
            std::thread::sleep(
                Duration::from_millis(500)
                    .min(deadline.saturating_duration_since(std::time::Instant::now())),
            );
            assert!(
                std::time::Instant::now() >= eligible,
                "worker retirement left no grace within the checkpoint deadline"
            );
            let first = descriptors();
            let mut checkpoint = first.clone();
            while (instrumentation::workers(dir.path()) != 0 || checkpoint != cold)
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(
                    Duration::from_millis(10)
                        .min(deadline.saturating_duration_since(std::time::Instant::now())),
                );
                checkpoint = descriptors();
            }
            assert_eq!(instrumentation::workers(dir.path()), 0);
            assert_eq!(
                checkpoint,
                cold,
                "watch descriptors did not retire at cycle {cycle}; first={first:?}; elapsed={:?}",
                started.elapsed()
            );
            checkpoints.push(checkpoint);
        }
    }
    println!(
        "cold={cold:?}; after1={:?}; after5={:?}; after20={:?}; workers=0",
        checkpoints[0], checkpoints[1], checkpoints[2]
    );
    assert_eq!(
        checkpoints[0], checkpoints[1],
        "descriptors changed after initialized baseline"
    );
    assert_eq!(
        checkpoints[1], checkpoints[2],
        "descriptors retained across repeated watches"
    );
}

#[test]
fn change_during_reconciliation_keeps_a_followup_scan() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let target = TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    let root = FileRef {
        target: target.clone(),
        path: TargetPath::posix(dir.path().as_os_str().as_bytes().to_vec()).unwrap(),
        resolved_identity: None,
    };
    let stream = super::super::watch(target, root).unwrap();
    let before = instrumentation::scans(dir.path());
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    instrumentation::barrier(dir.path(), entered_tx, resume_rx);
    fs::write(dir.path().join("first"), b"first").unwrap();
    entered_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("first hint must enter reconciliation");
    fs::write(dir.path().join("second"), b"second").unwrap();
    std::thread::sleep(Duration::from_millis(600));
    resume_tx.send(()).unwrap();
    for _ in 0..300 {
        if instrumentation::scans(dir.path()) >= before + 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        instrumentation::scans(dir.path()) >= before + 2,
        "a hint during reconciliation must remain pending"
    );
    drop(stream);
}

#[test]
fn symlink_root_falls_back_to_polling_without_following_it() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    use std::task::{Wake, Waker};
    struct Notice(std::sync::mpsc::Sender<()>);
    impl Wake for Notice {
        fn wake(self: Arc<Self>) {
            let _ = self.0.send(());
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    let link = dir.path().join("root");
    std::os::unix::fs::symlink(&first, &link).unwrap();
    let target = TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    };
    let root = FileRef {
        target: target.clone(),
        path: TargetPath::posix(link.as_os_str().as_bytes().to_vec()).unwrap(),
        resolved_identity: None,
    };
    let mut stream = super::super::watch(target, root).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let waker = Waker::from(Arc::new(Notice(tx)));
    let mut context = Context::from_waker(&waker);
    assert!(stream.as_mut().poll_next(&mut context).is_pending());
    fs::write(first.join("ignored"), b"change").unwrap();
    assert!(
        rx.recv_timeout(Duration::from_millis(600)).is_err(),
        "poll must not follow the final symlink"
    );
    fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&second, &link).unwrap();
    rx.recv_timeout(Duration::from_secs(3))
        .expect("fallback must detect link replacement");
    assert!(stream.as_mut().poll_next(&mut context).is_ready());
}
