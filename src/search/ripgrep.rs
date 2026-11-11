use crate::contracts::SearchService;
use buntrail_core::contracts::{async_types::*, *};
use futures_core::Stream;
use std::{
    collections::VecDeque,
    io::Read,
    os::fd::AsRawFd,
    path::PathBuf,
    pin::Pin,
    process::{Command, Stdio},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
pub const DEFAULT_EXCLUSIONS: &[&str] = &[
    "**/node_modules/**",
    "**/vendor/**",
    "**/target/**",
    "**/.build/**",
    "**/dist/**",
    "**/build/**",
    "**/coverage/**",
    "**/.git/**",
];
pub const MAX_MATCHES: u64 = 20_000;
#[derive(Clone)]
pub struct LocalSearchService {
    target: TargetIdentity,
    executable: PathBuf,
    active: Arc<AtomicUsize>,
    files: Arc<crate::files::LocalFileService>,
}
impl LocalSearchService {
    pub fn bundled(files: Arc<crate::files::LocalFileService>) -> Self {
        let executable = std::env::current_exe()
            .ok()
            .and_then(|p| {
                let directory = p.parent()?;
                let adjacent = directory.join("rg");
                if adjacent.is_file() {
                    return Some(adjacent);
                }
                let bundle = directory.parent()?.parent()?;
                (bundle.extension() == Some(std::ffi::OsStr::new("app")))
                    .then(|| directory.join("../Resources/Search/rg"))
            })
            .unwrap_or_else(|| {
                std::env::current_exe()
                    .expect("current executable")
                    .with_file_name("rg")
            });
        Self::with_executable(files, executable)
    }
    /// Use a caller-selected ripgrep executable, without invoking a shell.
    pub fn with_executable(
        files: Arc<crate::files::LocalFileService>,
        executable: PathBuf,
    ) -> Self {
        let target = files.target().clone();
        Self {
            target,
            executable,
            active: Arc::new(AtomicUsize::new(0)),
            files,
        }
    }
    pub fn active_searches(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
    pub fn run(
        &self,
        request: SearchRequest,
        cancel: &AtomicBool,
        mut emit: impl FnMut(SearchEvent) -> bool,
    ) {
        if self
            .active
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < 2).then_some(n + 1)
            })
            .is_err()
        {
            emit(SearchEvent::Failed(CoreError::new(
                ErrorCode::Busy,
                "Two searches are still finishing; retry shortly",
            )));
            return;
        }
        struct Permit<'a>(&'a AtomicUsize);
        impl Drop for Permit<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let _permit = Permit(&self.active);
        let outcome = self.execute(&request, cancel, &mut emit);
        let outcome = outcome.unwrap_or_else(SearchEvent::Failed);
        emit(
            if cancel.load(Ordering::SeqCst)
                && matches!(outcome, SearchEvent::Complete | SearchEvent::Limited { .. })
            {
                SearchEvent::Cancelled
            } else {
                outcome
            },
        );
    }
    fn execute(
        &self,
        r: &SearchRequest,
        cancel: &AtomicBool,
        emit: &mut impl FnMut(SearchEvent) -> bool,
    ) -> Result<SearchEvent, CoreError> {
        if r.root.target != self.target {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "Search target changed",
            ));
        }
        let options = buntrail_core::search::find::FindOptions {
            expression: r.expression.clone(),
            mode: r.mode.clone(),
            case_sensitive: r.case_sensitive,
            whole_word: r.whole_word,
            scope: None,
        };
        let matcher = buntrail_core::search::find::pattern(&options)?;
        let expression = buntrail_core::search::find::pattern_source(&options)?;
        if r.includes.len() + r.excludes.len() > 256
            || r.includes.iter().chain(&r.excludes).any(|g| g.len() > 4096)
        {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "Too many or oversized search globs",
            ));
        }
        let root = crate::files::path(&r.root.path)?;
        let mut command = Command::new(&self.executable);
        command.current_dir(&root);
        command.args([
            "--no-config",
            "--json",
            "--line-number",
            "--color=never",
            "--threads=1",
            "--no-mmap",
            "--no-require-git",
        ]);
        command.arg(if r.case_sensitive {
            "--case-sensitive"
        } else {
            "--ignore-case"
        });
        if r.hidden {
            command.arg("--hidden");
        }
        if r.ignored {
            command.arg("--no-ignore");
        } else {
            for g in DEFAULT_EXCLUSIONS {
                command.arg("--glob").arg(format!("!{g}"));
            }
        }
        for g in &r.includes {
            command.arg("--glob").arg(g);
        }
        for g in &r.excludes {
            command.arg("--glob").arg(format!("!{g}"));
        }
        let mut child = command
            .arg("--regexp")
            .arg(&expression)
            .arg("--")
            .arg(".")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| {
                CoreError::new(
                    ErrorCode::Unavailable,
                    "Bundled ripgrep could not start; reinstall the application",
                )
            })?;
        let result = (|| {
            let mut out = child.stdout.take().unwrap();
            let mut err = child.stderr.take().unwrap();
            for fd in [out.as_raw_fd(), err.as_raw_fd()] {
                if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
                    return Err(crate::files::io_error(std::io::Error::last_os_error()));
                }
            }
            let mut version_cache: Option<(TargetPath, FileVersion)> = None;
            let mut pending = vec![];
            let mut diagnostics = false;
            let mut count = 0;
            let mut files = 0;
            let mut eof = false;
            let mut chunk = [0; 8192];
            loop {
                if cancel.load(Ordering::SeqCst) {
                    return Ok(SearchEvent::Cancelled);
                }
                loop {
                    match err.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(_) => diagnostics = true,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(crate::files::io_error(e)),
                    }
                }
                match out.read(&mut chunk) {
                    Ok(0) => eof = true,
                    Ok(n) => pending.extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(crate::files::io_error(e)),
                }
                while let Some(end) = pending.iter().position(|b| *b == b'\n') {
                    if end > 256 * 1024 {
                        return Err(super::result_mapper::invalid());
                    }
                    let value: serde_json::Value = serde_json::from_slice(&pending[..end])
                        .map_err(|_| super::result_mapper::invalid())?;
                    pending.drain(..=end);
                    match value["type"].as_str() {
                        Some("match") => {
                            for m in super::result_mapper::matches(&value, &r.root)? {
                                let mut m = m?;
                                let column = m.preview_column_utf8 as usize;
                                if !buntrail_core::search::find::line_match_allowed(
                                    &matcher, &m.preview, column, column,
                                ) {
                                    continue;
                                }
                                if cancel.load(Ordering::SeqCst) {
                                    return Ok(SearchEvent::Cancelled);
                                }
                                if version_cache
                                    .as_ref()
                                    .is_none_or(|(p, _)| *p != m.file.path)
                                {
                                    version_cache = Some((
                                        m.file.path.clone(),
                                        self.files.path_version(m.file.clone())?,
                                    ));
                                }
                                // Independently sampled evidence never certifies the coordinates of rg's read.
                                m.searched_version = version_cache.as_ref().unwrap().1.clone();
                                if count == MAX_MATCHES {
                                    std::fs::metadata(crate::files::path(&r.root.path)?)
                                        .map_err(crate::files::io_error)?;
                                    return Ok(SearchEvent::Limited {
                                        maximum: MAX_MATCHES,
                                    });
                                }
                                if !emit(SearchEvent::Match(Box::new(m))) {
                                    return Ok(SearchEvent::Cancelled);
                                }
                                count += 1;
                            }
                        }
                        Some("end") => {
                            files += 1;
                            if !emit(SearchEvent::Progress {
                                files,
                                matches: count,
                            }) {
                                return Ok(SearchEvent::Cancelled);
                            }
                        }
                        Some("begin" | "summary") => {}
                        _ => return Err(super::result_mapper::invalid()),
                    }
                }
                if pending.len() > 256 * 1024 {
                    return Err(super::result_mapper::invalid());
                }
                if eof && let Some(status) = child.try_wait().map_err(crate::files::io_error)? {
                    if cancel.load(Ordering::SeqCst) {
                        return Ok(SearchEvent::Cancelled);
                    }
                    while let Ok(n) = err.read(&mut chunk) {
                        if n == 0 {
                            break;
                        }
                        diagnostics = true;
                    }
                    if !pending.is_empty() || diagnostics || !matches!(status.code(), Some(0 | 1)) {
                        return Err(CoreError::new(
                            ErrorCode::Io,
                            "Search interrupted or some files could not be read; results are incomplete",
                        ));
                    }
                    std::fs::metadata(crate::files::path(&r.root.path)?).map_err(|_| {
                        CoreError::new(
                            ErrorCode::Io,
                            "Search root disappeared; results are incomplete",
                        )
                    })?;
                    return Ok(SearchEvent::Complete);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        })();
        // All exits, including parsing failure, backpressure cancellation and target removal, reap the child.
        let _ = child.kill();
        let _ = child.wait();
        result
    }
}
struct State {
    events: VecDeque<SearchEvent>,
    done: bool,
    waker: Option<Waker>,
}
struct Shared {
    state: Mutex<State>,
    space: Condvar,
    cancel: AtomicBool,
}
struct SearchStream(Arc<Shared>);
impl Drop for SearchStream {
    fn drop(&mut self) {
        self.0.cancel.store(true, Ordering::SeqCst);
        self.0.space.notify_all();
    }
}
impl Stream for SearchStream {
    type Item = Result<SearchEvent, CoreError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut s = self.0.state.lock().unwrap();
        if let Some(e) = s.events.pop_front() {
            self.0.space.notify_all();
            Poll::Ready(Some(Ok(e)))
        } else if s.done {
            Poll::Ready(None)
        } else {
            s.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}
impl SearchService for LocalSearchService {
    fn search(
        &self,
        r: SearchRequest,
    ) -> ServiceFuture<'_, Result<EventStream<SearchEvent>, CoreError>> {
        Box::pin(async move {
            let shared = Arc::new(Shared {
                state: Mutex::new(State {
                    events: VecDeque::new(),
                    done: false,
                    waker: None,
                }),
                space: Condvar::new(),
                cancel: AtomicBool::new(false),
            });
            let producer = shared.clone();
            let service = self.clone();
            std::thread::Builder::new()
                .name("buntrail-search".into())
                .spawn(move || {
                    service.run(r, &producer.cancel, |e| {
                        let mut s = producer.state.lock().unwrap();
                        while s.events.len() >= 32 && !producer.cancel.load(Ordering::SeqCst) {
                            s = producer.space.wait(s).unwrap();
                        }
                        if producer.cancel.load(Ordering::SeqCst) {
                            return false;
                        }
                        s.events.push_back(e);
                        if let Some(w) = s.waker.take() {
                            w.wake();
                        }
                        true
                    });
                    let mut s = producer.state.lock().unwrap();
                    s.done = true;
                    if let Some(w) = s.waker.take() {
                        w.wake();
                    }
                })
                .map_err(crate::files::io_error)?;
            Ok(Box::pin(SearchStream(shared)) as EventStream<SearchEvent>)
        })
    }
}

#[cfg(test)]
mod standalone_tests {
    use super::*;
    #[test]
    fn explicit_search_executable_is_retained() {
        let directory = tempfile::tempdir().unwrap();
        let files = Arc::new(
            crate::files::LocalFileService::new(
                crate::connections::local::identity().unwrap(),
                directory.path().join("files"),
            )
            .unwrap(),
        );
        let executable = directory.path().join("missing-rg");
        let search = LocalSearchService::with_executable(files, executable.clone());
        assert_eq!(search.executable, executable);
        assert!(Command::new(&search.executable).spawn().is_err());
    }
}
