use super::*;
use std::{
    ffi::{CString, c_char, c_void},
    ptr,
    thread::Thread,
};

type CFRef = *const c_void;
type StreamRef = *mut c_void;
type Queue = *mut c_void;
#[repr(C)]
struct StreamContext {
    version: isize,
    info: *mut c_void,
    retain: Option<unsafe extern "C" fn(*const c_void) -> *const c_void>,
    release: Option<unsafe extern "C" fn(*const c_void)>,
    description: Option<unsafe extern "C" fn(*const c_void) -> CFRef>,
}
#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn FSEventStreamCreate(
        allocator: CFRef,
        callback: unsafe extern "C" fn(
            StreamRef,
            *mut c_void,
            usize,
            *mut c_void,
            *const u32,
            *const u64,
        ),
        context: *mut StreamContext,
        paths: CFRef,
        since: u64,
        latency: f64,
        flags: u32,
    ) -> StreamRef;
    fn FSEventStreamSetDispatchQueue(stream: StreamRef, queue: Queue);
    fn FSEventStreamStart(stream: StreamRef) -> bool;
    fn FSEventStreamStop(stream: StreamRef);
    fn FSEventStreamInvalidate(stream: StreamRef);
    fn FSEventStreamRelease(stream: StreamRef);
}
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithBytes(
        alloc: CFRef,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        external: bool,
    ) -> CFRef;
    fn CFArrayCreate(
        alloc: CFRef,
        values: *const CFRef,
        count: isize,
        callbacks: *const c_void,
    ) -> CFRef;
    fn CFRelease(value: CFRef);
    static kCFTypeArrayCallBacks: c_void;
}
unsafe extern "C" {
    fn dispatch_queue_create(label: *const c_char, attr: *const c_void) -> Queue;
    fn dispatch_release(queue: Queue);
}
struct Signal {
    dirty: AtomicBool,
    active: AtomicBool,
    worker: Thread,
}
unsafe extern "C" fn retain(info: *const c_void) -> *const c_void {
    unsafe {
        Arc::increment_strong_count(info.cast::<Signal>());
    }
    info
}
unsafe extern "C" fn release(info: *const c_void) {
    unsafe {
        Arc::decrement_strong_count(info.cast::<Signal>());
    }
}
unsafe extern "C" fn callback(
    _: StreamRef,
    info: *mut c_void,
    _: usize,
    _: *mut c_void,
    _: *const u32,
    _: *const u64,
) {
    let signal = unsafe { &*info.cast::<Signal>() };
    if signal.active.load(Ordering::Acquire) && !signal.dirty.swap(true, Ordering::AcqRel) {
        signal.worker.unpark();
    }
}

pub(super) struct Native {
    stream: StreamRef,
    queue: Queue,
    signal: Arc<Signal>,
    identity: (u64, u64),
}
fn utf8_path(path: &Path) -> Option<&[u8]> {
    let bytes = path.as_os_str().as_bytes();
    std::str::from_utf8(bytes).ok()?;
    Some(bytes)
}
impl Native {
    pub(super) fn start(path: &Path) -> Option<Self> {
        let metadata = fs::symlink_metadata(path).ok()?;
        if !metadata.is_dir() {
            return None;
        }
        let bytes = utf8_path(path)?;
        let cpath = CString::new(bytes).ok()?;
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statfs(cpath.as_ptr(), &mut stat) } != 0
            || stat.f_flags & libc::MNT_LOCAL as u32 == 0
        {
            return None;
        }
        let signal = Arc::new(Signal {
            dirty: AtomicBool::new(false),
            active: AtomicBool::new(true),
            worker: std::thread::current(),
        });
        let mut context = StreamContext {
            version: 0,
            info: Arc::as_ptr(&signal) as *mut c_void,
            retain: Some(retain),
            release: Some(release),
            description: None,
        };
        unsafe {
            let string = CFStringCreateWithBytes(
                ptr::null(),
                bytes.as_ptr(),
                bytes.len().try_into().ok()?,
                0x0800_0100,
                false,
            );
            if string.is_null() {
                return None;
            }
            let paths = CFArrayCreate(ptr::null(), &string, 1, &kCFTypeArrayCallBacks);
            CFRelease(string);
            if paths.is_null() {
                return None;
            }
            let stream = FSEventStreamCreate(
                ptr::null(),
                callback,
                &mut context,
                paths,
                u64::MAX,
                0.25,
                0x04 | 0x02,
            );
            CFRelease(paths);
            if stream.is_null() {
                return None;
            }
            let queue = dispatch_queue_create(c"buntrail.fsevents".as_ptr(), ptr::null());
            if queue.is_null() {
                FSEventStreamRelease(stream);
                return None;
            }
            FSEventStreamSetDispatchQueue(stream, queue);
            if !FSEventStreamStart(stream) {
                FSEventStreamInvalidate(stream);
                FSEventStreamRelease(stream);
                dispatch_release(queue);
                return None;
            }
            Some(Self {
                stream,
                queue,
                signal,
                identity: (metadata.dev(), metadata.ino()),
            })
        }
    }
    pub(super) fn take_dirty(&self) -> bool {
        self.signal.dirty.swap(false, Ordering::AcqRel)
    }
    pub(super) fn identity_matches(&self, path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok_and(|m| m.is_dir() && (m.dev(), m.ino()) == self.identity)
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        self.signal.active.store(false, Ordering::Release);
        unsafe {
            FSEventStreamStop(self.stream);
            FSEventStreamInvalidate(self.stream);
            FSEventStreamRelease(self.stream);
            dispatch_release(self.queue);
        }
    }
}
#[cfg(test)]
mod instrumentation {
    use super::*;
    use std::{
        collections::HashMap,
        path::PathBuf,
        sync::{OnceLock, mpsc},
    };
    type Barrier = (mpsc::Sender<()>, mpsc::Receiver<()>);
    #[derive(Default)]
    struct State {
        scans: HashMap<PathBuf, usize>,
        workers: HashMap<PathBuf, usize>,
        barriers: HashMap<PathBuf, Barrier>,
    }
    fn state() -> &'static Mutex<State> {
        static STATE: OnceLock<Mutex<State>> = OnceLock::new();
        STATE.get_or_init(|| Mutex::new(State::default()))
    }
    pub(crate) fn record_scan(path: &Path) {
        let barrier = {
            let mut s = state().lock().unwrap();
            *s.scans.entry(path.to_owned()).or_default() += 1;
            s.barriers.remove(path)
        };
        if let Some((entered, resume)) = barrier {
            let _ = entered.send(());
            let _ = resume.recv();
        }
    }
    pub(crate) fn scans(path: &Path) -> usize {
        *state().lock().unwrap().scans.get(path).unwrap_or(&0)
    }
    pub(crate) fn workers(path: &Path) -> usize {
        *state().lock().unwrap().workers.get(path).unwrap_or(&0)
    }
    pub(crate) fn barrier(path: &Path, entered: mpsc::Sender<()>, resume: mpsc::Receiver<()>) {
        state()
            .lock()
            .unwrap()
            .barriers
            .insert(path.to_owned(), (entered, resume));
    }
    pub(crate) struct WorkerGuard(PathBuf);
    impl WorkerGuard {
        pub(crate) fn new(path: &Path) -> Self {
            *state()
                .lock()
                .unwrap()
                .workers
                .entry(path.to_owned())
                .or_default() += 1;
            Self(path.to_owned())
        }
    }
    impl Drop for WorkerGuard {
        fn drop(&mut self) {
            *state().lock().unwrap().workers.get_mut(&self.0).unwrap() -= 1;
        }
    }
}
#[cfg(test)]
pub(super) use instrumentation::{WorkerGuard, record_scan};
#[cfg(test)]
mod tests;
