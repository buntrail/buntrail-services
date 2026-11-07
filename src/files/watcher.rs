use super::local::{io_error, path, target_path};
use buntrail_core::contracts::{async_types::EventStream, *};
use futures_core::Stream;
use std::{
    ffi::OsString,
    fs,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::MetadataExt,
    },
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
// shortcut: metadata polling avoids platform watcher loss, replace after T19 measures large-tree budgets.
const MAX_ENTRIES: usize = 100_000;
const MAX_PATH_BYTES: usize = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 128;
struct ScanBudget {
    entries: usize,
    path_bytes: usize,
    max_depth: usize,
}
impl ScanBudget {
    fn reserve(&mut self, path_bytes: usize, depth: usize) -> Result<(), CoreError> {
        if self.entries == 0 || path_bytes > self.path_bytes || depth > self.max_depth {
            return Err(CoreError::new(
                ErrorCode::Unavailable,
                "rescan exceeds entry, aggregate path-byte, or depth budget",
            ));
        }
        self.entries -= 1;
        self.path_bytes -= path_bytes;
        Ok(())
    }
}
pub fn fingerprint(root: &Path) -> Result<Vec<u8>, CoreError> {
    fingerprint_bounded(
        root,
        ScanBudget {
            entries: MAX_ENTRIES,
            path_bytes: MAX_PATH_BYTES,
            max_depth: MAX_DEPTH,
        },
    )
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanStage {
    BeforeMetadata,
    AfterMetadata,
    BeforeReadDir,
}

fn fingerprint_bounded(root: &Path, budget: ScanBudget) -> Result<Vec<u8>, CoreError> {
    fingerprint_coordinated(
        root,
        budget,
        #[cfg(test)]
        &mut |_, _| Ok(()),
    )
}
fn fingerprint_coordinated(
    root: &Path,
    mut budget: ScanBudget,
    #[cfg(test)] seam: &mut impl FnMut(ScanStage, &Path) -> std::io::Result<()>,
) -> Result<Vec<u8>, CoreError> {
    let mut result = vec![];
    budget.reserve(root.as_os_str().len(), 0)?;
    let mut path = root.to_path_buf();
    scan(
        &mut path,
        &mut result,
        &mut budget,
        0,
        #[cfg(test)]
        seam,
    )?;
    Ok(result)
}
// Each child is charged before retaining its name and is never charged again in recursion.
fn scan(
    path: &mut PathBuf,
    out: &mut Vec<u8>,
    budget: &mut ScanBudget,
    depth: usize,
    #[cfg(test)] seam: &mut impl FnMut(ScanStage, &Path) -> std::io::Result<()>,
) -> Result<(), CoreError> {
    #[cfg(test)]
    seam(ScanStage::BeforeMetadata, path).map_err(io_error)?;
    let m = fs::symlink_metadata(&*path).map_err(io_error)?;
    #[cfg(test)]
    seam(ScanStage::AfterMetadata, path).map_err(io_error)?;
    out.extend_from_slice(path.as_os_str().as_bytes());
    out.push(0);
    for n in [
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime() as u64,
        m.mtime_nsec() as u64,
        m.ctime() as u64,
        m.ctime_nsec() as u64,
    ] {
        out.extend_from_slice(&n.to_be_bytes());
    }
    if m.is_dir() {
        #[cfg(test)]
        seam(ScanStage::BeforeReadDir, path).map_err(io_error)?;
        let mut children = child_names(
            path,
            fs::read_dir(&*path).map_err(io_error)?,
            budget,
            depth + 1,
            |entry| entry.file_name(),
        )?;
        children.sort();
        let parent_len = path.as_os_str().len();
        for name in children {
            path.push(name);
            scan(
                path,
                out,
                budget,
                depth + 1,
                #[cfg(test)]
                seam,
            )?;
            // pop() normalizes spelling; restore the caller's exact raw parent instead.
            let mut bytes = std::mem::take(path).into_os_string().into_vec();
            bytes.truncate(parent_len);
            *path = PathBuf::from(OsString::from_vec(bytes));
        }
    }
    Ok(())
}
fn child_names<T>(
    parent: &Path,
    entries: impl Iterator<Item = std::io::Result<T>>,
    budget: &mut ScanBudget,
    depth: usize,
    filename: impl Fn(T) -> OsString,
) -> Result<Vec<OsString>, CoreError> {
    let mut children = Vec::new();
    for entry in entries {
        // Inspect one overflow witness before handling its error/name, as the original collector did.
        if budget.entries == 0 || depth > budget.max_depth {
            return Err(CoreError::new(
                ErrorCode::Unavailable,
                "rescan exceeds entry or depth budget",
            ));
        }
        let name = filename(entry.map_err(io_error)?);
        let bytes = parent
            .as_os_str()
            .len()
            .saturating_add(usize::from(!parent.as_os_str().as_bytes().ends_with(b"/")))
            .saturating_add(name.len());
        budget.reserve(bytes, depth)?;
        children.push(name);
    }
    Ok(children)
}
#[cfg(test)]
pub(super) fn reference_fingerprint(root: &Path) -> Result<Vec<u8>, CoreError> {
    reference_fingerprint_bounded(
        root,
        ScanBudget {
            entries: MAX_ENTRIES,
            path_bytes: MAX_PATH_BYTES,
            max_depth: MAX_DEPTH,
        },
    )
}
#[cfg(test)]
fn reference_fingerprint_bounded(
    root: &Path,
    mut budget: ScanBudget,
) -> Result<Vec<u8>, CoreError> {
    let mut result = Vec::new();
    budget.reserve(root.as_os_str().len(), 0)?;
    original_scan(root, &mut result, &mut budget, 0)?;
    Ok(result)
}
// Each path is reserved before it is joined/retained; recursion never charges it twice.
#[cfg(test)]
fn original_scan(
    path: &Path,
    out: &mut Vec<u8>,
    budget: &mut ScanBudget,
    depth: usize,
) -> Result<(), CoreError> {
    let m = fs::symlink_metadata(path).map_err(io_error)?;
    out.extend_from_slice(path.as_os_str().as_bytes());
    out.push(0);
    for n in [
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime() as u64,
        m.mtime_nsec() as u64,
        m.ctime() as u64,
        m.ctime_nsec() as u64,
    ] {
        out.extend_from_slice(&n.to_be_bytes());
    }
    if m.is_dir() {
        let mut children = original_child_paths(
            path,
            fs::read_dir(path).map_err(io_error)?,
            budget,
            depth + 1,
            |entry| entry.file_name(),
        )?;
        children.sort();
        for p in children {
            original_scan(&p, out, budget, depth + 1)?;
        }
    }
    Ok(())
}
#[cfg(test)]
fn original_child_paths<T>(
    parent: &Path,
    entries: impl Iterator<Item = std::io::Result<T>>,
    budget: &mut ScanBudget,
    depth: usize,
    filename: impl Fn(T) -> OsString,
) -> Result<Vec<std::path::PathBuf>, CoreError> {
    let mut children = Vec::new();
    for entry in entries {
        // Inspect only one overflow witness, without allocating its name or full path.
        if budget.entries == 0 || depth > budget.max_depth {
            return Err(CoreError::new(
                ErrorCode::Unavailable,
                "rescan exceeds entry or depth budget",
            ));
        }
        let name = filename(entry.map_err(io_error)?);
        let bytes = parent
            .as_os_str()
            .len()
            .saturating_add(usize::from(!parent.as_os_str().as_bytes().ends_with(b"/")))
            .saturating_add(name.len());
        budget.reserve(bytes, depth)?;
        children.push(parent.join(name));
    }
    Ok(children)
}

#[cfg(target_os = "macos")]
mod macos;

fn watch_fingerprint(root: &Path) -> Result<Vec<u8>, CoreError> {
    #[cfg(all(test, target_os = "macos"))]
    {
        macos::record_scan(root);
    }
    fingerprint(root)
}

struct Shared {
    pending: Option<Result<FileEvent, CoreError>>,
    waker: Option<Waker>,
}
struct Watch {
    shared: Arc<Mutex<Shared>>,
    stopped: Arc<AtomicBool>,
    #[cfg(target_os = "macos")]
    worker: std::thread::Thread,
}
impl Drop for Watch {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        #[cfg(target_os = "macos")]
        self.worker.unpark();
    }
}
impl Stream for Watch {
    type Item = Result<FileEvent, CoreError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut s = self.shared.lock().unwrap();
        if let Some(e) = s.pending.take() {
            Poll::Ready(Some(e))
        } else {
            s.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}
#[cfg(target_os = "macos")]
pub fn watch(target: TargetIdentity, root: FileRef) -> Result<EventStream<FileEvent>, CoreError> {
    if root.target != target {
        return Err(CoreError::new(
            ErrorCode::TargetChanged,
            "watch target mismatch",
        ));
    }
    let p = path(&root.path)?;
    let shared = Arc::new(Mutex::new(Shared {
        pending: None,
        waker: None,
    }));
    let stopped = Arc::new(AtomicBool::new(false));
    let state = shared.clone();
    let cancelled = stopped.clone();
    let (admission, result) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("buntrail-watch".into())
        .spawn(move || {
            #[cfg(all(test, target_os = "macos"))]
            let _worker_guard = macos::WorkerGuard::new(&p);
            let mut native = macos::Native::start(&p);
            if let Some(n) = native.as_ref() {
                n.take_dirty();
            }
            let mut previous = match watch_fingerprint(&p) {
                Ok(value) => value,
                Err(error) => {
                    let _ = admission.send(Err(error));
                    return;
                }
            };
            if native.as_ref().is_some_and(|n| !n.identity_matches(&p)) {
                native = None;
            }
            if admission.send(Ok(())).is_err() {
                return;
            }
            let mut last_error = None;
            let mut last_scan = std::time::Instant::now();
            while !cancelled.load(Ordering::SeqCst) {
                let hinted = if let Some(n) = native.as_ref() {
                    if !n.take_dirty() {
                        std::thread::park();
                        continue;
                    }
                    let wait = Duration::from_millis(250).saturating_sub(last_scan.elapsed());
                    if !wait.is_zero() {
                        std::thread::park_timeout(wait);
                        if cancelled.load(Ordering::SeqCst) {
                            break;
                        }
                        // Preserve the hint across early wakeups and enforce the cadence.
                        while last_scan.elapsed() < Duration::from_millis(250) {
                            std::thread::park_timeout(
                                Duration::from_millis(250).saturating_sub(last_scan.elapsed()),
                            );
                            if cancelled.load(Ordering::SeqCst) {
                                return;
                            }
                        }
                    }
                    n.take_dirty();
                    true
                } else {
                    std::thread::park_timeout(Duration::from_millis(250));
                    false
                };
                if cancelled.load(Ordering::SeqCst) {
                    break;
                }
                {
                    if native.as_ref().is_some_and(|n| !n.identity_matches(&p)) {
                        native = None;
                    }
                    last_scan = std::time::Instant::now();
                }
                let next = watch_fingerprint(&p);
                if native.as_ref().is_some_and(|n| !n.identity_matches(&p)) {
                    native = None;
                }
                let event = match next {
                    Ok(next) => {
                        last_error = None;
                        if hinted {
                            previous = next;
                            Ok(FileEvent::RescanRequired(root.clone()))
                        } else if next == previous {
                            continue;
                        } else {
                            previous = next;
                            Ok(FileEvent::Changed(root.clone()))
                        }
                    }
                    Err(e) => {
                        if last_error.as_ref() == Some(&e) {
                            continue;
                        }
                        last_error = Some(e.clone());
                        Err(e)
                    }
                };
                let wake = {
                    let mut s = state.lock().unwrap();
                    s.pending = Some(if s.pending.is_some() {
                        Ok(FileEvent::RescanRequired(FileRef {
                            path: target_path(&p),
                            ..root.clone()
                        }))
                    } else {
                        event
                    });
                    s.waker.take()
                };
                if let Some(w) = wake {
                    w.wake();
                }
            }
        })
        .map_err(io_error)?;
    let worker = worker.thread().clone();
    result.recv().map_err(|_| {
        io_error(std::io::Error::other(
            "watch worker stopped during admission",
        ))
    })??;
    Ok(Box::pin(Watch {
        shared,
        stopped,
        worker,
    }))
}

#[cfg(not(target_os = "macos"))]
pub fn watch(target: TargetIdentity, root: FileRef) -> Result<EventStream<FileEvent>, CoreError> {
    if root.target != target {
        return Err(CoreError::new(
            ErrorCode::TargetChanged,
            "watch target mismatch",
        ));
    }
    let p = path(&root.path)?;
    let mut previous = watch_fingerprint(&p)?;
    let shared = Arc::new(Mutex::new(Shared {
        pending: None,
        waker: None,
    }));
    let stopped = Arc::new(AtomicBool::new(false));
    let state = shared.clone();
    let cancelled = stopped.clone();
    std::thread::Builder::new()
        .name("buntrail-watch".into())
        .spawn(move || {
            let mut last_error = None;
            while !cancelled.load(Ordering::SeqCst) {
                std::thread::park_timeout(Duration::from_millis(500));
                let next = watch_fingerprint(&p);
                let event = match next {
                    Ok(next) if next == previous => {
                        last_error = None;
                        continue;
                    }
                    Ok(next) => {
                        last_error = None;
                        previous = next;
                        Ok(FileEvent::Changed(root.clone()))
                    }
                    Err(e) => {
                        if last_error.as_ref() == Some(&e) {
                            continue;
                        }
                        last_error = Some(e.clone());
                        Err(e)
                    }
                };
                let wake = {
                    let mut s = state.lock().unwrap();
                    s.pending = Some(if s.pending.is_some() {
                        Ok(FileEvent::RescanRequired(FileRef {
                            path: target_path(&p),
                            ..root.clone()
                        }))
                    } else {
                        event
                    });
                    s.waker.take()
                };
                if let Some(w) = wake {
                    w.wake();
                }
            }
        })
        .map_err(io_error)?;
    Ok(Box::pin(Watch { shared, stopped }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[cfg(target_os = "linux")]
    #[test]
    fn polling_watch_coalesces_burst_without_losing_final_change() {
        use std::task::{Wake, Waker};
        struct Notice(std::sync::mpsc::Sender<()>);
        impl Wake for Notice {
            fn wake(self: Arc<Self>) {
                let _ = self.0.send(());
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("nested").join("file");
        fs::create_dir(file.parent().unwrap()).unwrap();
        fs::write(&file, b"initial").unwrap();
        let target = TargetIdentity {
            security_binding: vec![1],
            effective_user: vec![2],
            filesystem_namespace: vec![3],
            container: None,
        };
        let root = FileRef {
            target: target.clone(),
            path: target_path(dir.path()),
            resolved_identity: None,
        };
        let mut stream = watch(target, root.clone()).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let waker = Waker::from(Arc::new(Notice(tx)));
        let mut context = Context::from_waker(&waker);
        assert!(stream.as_mut().poll_next(&mut context).is_pending());
        let writer_file = file.clone();
        let writer = std::thread::spawn(move || {
            for revision in 0..65 {
                fs::write(&writer_file, revision.to_string()).unwrap();
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let start = std::time::Instant::now();
        let mut notifications = 0;
        while start.elapsed() < Duration::from_millis(1300) {
            let _ = rx.recv_timeout(Duration::from_millis(20));
            if let Poll::Ready(Some(event)) = stream.as_mut().poll_next(&mut context) {
                assert!(
                    matches!(event.unwrap(), FileEvent::Changed(ref f) | FileEvent::RescanRequired(ref f) if f == &root)
                );
                notifications += 1;
            }
        }
        writer.join().unwrap();
        assert!(
            notifications > 0 && notifications <= 3,
            "bursty writes must coalesce instead of repeatedly scanning: {notifications}"
        );
        while stream.as_mut().poll_next(&mut context).is_ready() {}
        while rx.try_recv().is_ok() {}
        fs::write(file, b"settled final change").unwrap();
        rx.recv_timeout(Duration::from_secs(3))
            .expect("settled write must wake its owner");
        assert!(matches!(stream.as_mut().poll_next(&mut context),
            Poll::Ready(Some(Ok(FileEvent::Changed(ref f) | FileEvent::RescanRequired(ref f)))) if f == &root));
    }

    #[test]
    fn public_fingerprint_matches_original_raw_tree() {
        use std::os::unix::ffi::OsStringExt;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("sub")).unwrap();
        let name = if cfg!(target_os = "macos") {
            eprintln!(
                "raw invalid-UTF8 filename subcase unavailable on macOS; using valid non-ASCII name"
            );
            OsString::from("café")
        } else {
            OsString::from_vec(vec![0xff, b'x'])
        };
        fs::write(root.join("sub").join(name), b"raw").unwrap();
        fs::write(root.join("a"), b"first").unwrap();
        std::os::unix::fs::symlink("sub", root.join("link")).unwrap();
        for path in [
            root.clone(),
            root.join("."),
            root.join("a"),
            root.join("link"),
        ] {
            assert_eq!(
                fingerprint(&path).unwrap(),
                reference_fingerprint(&path).unwrap()
            );
        }
    }
    #[test]
    fn scanner_applies_one_budget_across_siblings_and_nested_levels() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("a")).unwrap();
        fs::create_dir(root.path().join("b")).unwrap();
        fs::write(root.path().join("a/file"), b"content").unwrap();
        let bytes = root.path().as_os_str().len() * 4 + 2 + 2 + 7;
        let budget = |entries, path_bytes, max_depth| ScanBudget {
            entries,
            path_bytes,
            max_depth,
        };
        let first = fingerprint_bounded(root.path(), budget(4, bytes, 2)).unwrap();
        assert_eq!(
            first,
            fingerprint_bounded(root.path(), budget(4, bytes, 2)).unwrap()
        );
        assert!(fingerprint_bounded(root.path(), budget(3, bytes, 2)).is_err());
        assert!(fingerprint_bounded(root.path(), budget(4, bytes - 1, 2)).is_err());
        assert!(fingerprint_bounded(root.path(), budget(4, bytes, 1)).is_err());
    }
    #[test]
    fn scanner_stops_enumeration_at_entry_boundary() {
        let read = Cell::new(0);
        let entries = (0..1_000_000).map(|i| {
            read.set(read.get() + 1);
            Ok(OsString::from(format!("child{i}")))
        });
        assert!(
            child_names(
                Path::new("/root"),
                entries,
                &mut ScanBudget {
                    entries: 2,
                    path_bytes: 1024,
                    max_depth: 4
                },
                1,
                std::convert::identity
            )
            .is_err()
        );
        assert_eq!(
            read.get(),
            3,
            "read only the bounded children and one overflow witness"
        );
    }
    #[test]
    fn scanner_stops_enumeration_at_path_byte_boundary() {
        let read = Cell::new(0);
        let entries = (0..100).map(|_| {
            read.set(read.get() + 1);
            Ok(OsString::from("child"))
        });
        assert!(
            child_names(
                Path::new("/root"),
                entries,
                &mut ScanBudget {
                    entries: 100,
                    path_bytes: 22,
                    max_depth: 4
                },
                1,
                std::convert::identity
            )
            .is_err()
        );
        assert_eq!(
            read.get(),
            3,
            "two 11-byte paths fit; third is rejected before joining"
        );
    }
    #[test]
    fn scanner_stops_before_reading_beyond_depth_boundary() {
        let read = Cell::new(0);
        let entries = (0..100).map(|_| {
            read.set(read.get() + 1);
            Ok(OsString::from("child"))
        });
        assert!(
            child_names(
                Path::new("/root"),
                entries,
                &mut ScanBudget {
                    entries: 100,
                    path_bytes: 1024,
                    max_depth: 4
                },
                5,
                std::convert::identity
            )
            .is_err()
        );
        assert_eq!(
            read.get(),
            1,
            "only the witness of an excessive child level is inspected"
        );
    }
}
