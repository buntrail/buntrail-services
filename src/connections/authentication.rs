//! Native capability boundary. Secrets travel only through the owned askpass socket/stdout.
use crate::files::io_error;
use buntrail_core::contracts::*;
use std::{
    collections::{HashSet, VecDeque},
    fs,
    io::{Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
const LIMIT: usize = 4096;
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthenticationKind {
    Secret,
    Confirm,
    Information,
}
pub struct AuthenticationRequest {
    pub id: u64,
    pub kind: AuthenticationKind,
    pub prompt: String,
}
pub enum AuthenticationResponse {
    Cancelled,
    Confirm(bool),
    Secret(Vec<u8>),
}
impl Drop for AuthenticationResponse {
    fn drop(&mut self) {
        if let Self::Secret(bytes) = self {
            bytes.fill(0);
        }
    }
}
struct Pending {
    id: u64,
    response: Option<AuthenticationResponse>,
}
struct Shared {
    sessions: Mutex<HashSet<String>>,
    cancel: AtomicBool,
    finished: AtomicBool,
    waker: Mutex<Option<std::task::Waker>>,
    queue: Mutex<VecDeque<AuthenticationRequest>>,
    pending: Mutex<Option<Pending>>,
}
/// One visible prompt at a time. Create on a worker; polling, responses and Drop never join.
pub struct AuthenticationBroker {
    askpass: PathBuf,
    socket: PathBuf,
    shared: Arc<Shared>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Prompt {
    token: String,
    kind: AuthenticationKind,
    prompt: String,
}
impl AuthenticationBroker {
    pub fn new(askpass: PathBuf) -> Result<Arc<Self>, CoreError> {
        if !askpass.is_absolute() || !askpass.is_file() {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "Bundled SSH askpass executable unavailable",
            ));
        }
        let directory = tempfile::Builder::new()
            .prefix("buntrail-auth-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .map_err(io_error)?;
        let socket = directory.path().join("prompt");
        let listener = UnixListener::bind(&socket).map_err(io_error)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).map_err(io_error)?;
        listener.set_nonblocking(true).map_err(io_error)?;
        let shared = Arc::new(Shared {
            sessions: Mutex::new(HashSet::new()),
            cancel: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            waker: Mutex::new(None),
            queue: Mutex::new(VecDeque::new()),
            pending: Mutex::new(None),
        });
        let state = shared.clone();
        let worker = thread::Builder::new()
            .name("buntrail-auth".into())
            .spawn(move || {
                let mut id = 0;
                while !state.cancel.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                            let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
                            let mut bytes = Vec::new();
                            if (&mut stream)
                                .take((LIMIT + 1024) as u64)
                                .read_to_end(&mut bytes)
                                .is_err()
                                || bytes.len() >= LIMIT + 1024
                            {
                                continue;
                            }
                            let Ok(prompt) = serde_json::from_slice::<Prompt>(&bytes) else {
                                continue;
                            };
                            if !state.sessions.lock().unwrap().contains(&prompt.token)
                                || prompt.prompt.len() > LIMIT
                            {
                                continue;
                            }
                            id += 1;
                            *state.pending.lock().unwrap() = Some(Pending { id, response: None });
                            state
                                .queue
                                .lock()
                                .unwrap()
                                .push_back(AuthenticationRequest {
                                    id,
                                    kind: prompt.kind,
                                    prompt: prompt.prompt,
                                });
                            let deadline = Instant::now() + Duration::from_secs(120);
                            let response = loop {
                                if state.cancel.load(Ordering::SeqCst)
                                    || !state.sessions.lock().unwrap().contains(&prompt.token)
                                    || Instant::now() >= deadline
                                {
                                    break AuthenticationResponse::Cancelled;
                                }
                                if let Some(response) = state
                                    .pending
                                    .lock()
                                    .unwrap()
                                    .as_mut()
                                    .and_then(|p| p.response.take())
                                {
                                    break response;
                                }
                                thread::sleep(Duration::from_millis(10));
                            };
                            state.queue.lock().unwrap().retain(|r| r.id != id);
                            *state.pending.lock().unwrap() = None;
                            let value = match &response {
                                AuthenticationResponse::Cancelled => None,
                                AuthenticationResponse::Confirm(true) => Some(b"yes".as_slice()),
                                AuthenticationResponse::Confirm(false) => Some(b"no".as_slice()),
                                AuthenticationResponse::Secret(bytes) => Some(bytes.as_slice()),
                            };
                            if let Some(value) = value.filter(|v| {
                                v.len() <= LIMIT && !v.contains(&0) && !v.contains(&b'\n')
                            }) {
                                let _ = stream.write_all(&[1]);
                                let _ = stream.write_all(&(value.len() as u32).to_be_bytes());
                                let _ = stream.write_all(value);
                            } else {
                                let _ = stream.write_all(&[0]);
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10))
                        }
                        Err(_) => break,
                    }
                }
                drop(listener);
                drop(directory);
                state.finished.store(true, Ordering::SeqCst);
                if let Some(waker) = state.waker.lock().unwrap().take() {
                    waker.wake();
                }
            })
            .map_err(io_error)?;
        Ok(Arc::new(Self {
            askpass,
            socket,
            shared,
            worker: Mutex::new(Some(worker)),
        }))
    }
    pub fn take_request(&self) -> Option<AuthenticationRequest> {
        self.shared.queue.lock().unwrap().pop_front()
    }
    pub fn respond(&self, id: u64, response: AuthenticationResponse) -> bool {
        let mut pending = self.shared.pending.lock().unwrap();
        if let Some(p) = pending
            .as_mut()
            .filter(|p| p.id == id && p.response.is_none())
        {
            p.response = Some(response);
            true
        } else {
            false
        }
    }
    pub fn close(&self) -> AuthenticationShutdown {
        self.cancel();
        AuthenticationShutdown(self.shared.clone())
    }
    pub fn cancel(&self) {
        self.shared.cancel.store(true, Ordering::SeqCst);
    }
    pub(crate) fn configure(
        self: &Arc<Self>,
        command: &mut Command,
    ) -> Result<AuthenticationSession, CoreError> {
        let token = super::bootstrap::hex(&super::local::new_id()?);
        let mut sessions = self.shared.sessions.lock().unwrap();
        if sessions.len() >= 8 {
            return Err(CoreError::new(
                ErrorCode::Busy,
                "SSH authentication sessions are busy",
            ));
        }
        sessions.insert(token.clone());
        command
            .args(["-oBatchMode=no", "-oNumberOfPasswordPrompts=1"])
            .env("SSH_ASKPASS", &self.askpass)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", "buntrail-native")
            .env("BUNTRAIL_ASKPASS_SOCKET", &self.socket)
            .env("BUNTRAIL_ASKPASS_TOKEN", &token);
        Ok(AuthenticationSession {
            broker: self.clone(),
            token,
        })
    }
}
impl Drop for AuthenticationBroker {
    fn drop(&mut self) {
        self.cancel();
        self.worker.lock().unwrap().take();
    }
}
/// Entry point of the bundled askpass executable; never writes diagnostics or secret arguments.
pub fn askpass() -> Result<(), CoreError> {
    let prompt = std::env::args().nth(1).ok_or_else(|| {
        CoreError::new(ErrorCode::InvalidArgument, "Missing authentication prompt")
    })?;
    if prompt.len() > LIMIT {
        return Err(CoreError::new(
            ErrorCode::InvalidArgument,
            "Authentication prompt too large",
        ));
    }
    let kind = match std::env::var("SSH_ASKPASS_PROMPT").as_deref() {
        Ok("confirm") => AuthenticationKind::Confirm,
        Ok("none") => AuthenticationKind::Information,
        _ => AuthenticationKind::Secret,
    };
    let mut stream =
        UnixStream::connect(std::env::var_os("BUNTRAIL_ASKPASS_SOCKET").ok_or_else(|| {
            CoreError::new(
                ErrorCode::Unavailable,
                "Authentication capability unavailable",
            )
        })?)
        .map_err(io_error)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(125)))
        .map_err(io_error)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .map_err(io_error)?;
    let request = Prompt {
        token: std::env::var("BUNTRAIL_ASKPASS_TOKEN").map_err(io_error)?,
        kind,
        prompt,
    };
    stream
        .write_all(&serde_json::to_vec(&request).map_err(io_error)?)
        .map_err(io_error)?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(io_error)?;
    let mut flag = [0];
    stream.read_exact(&mut flag).map_err(io_error)?;
    if flag[0] != 1 {
        return Err(CoreError::new(
            ErrorCode::Cancelled,
            "Authentication cancelled",
        ));
    }
    let mut length = [0; 4];
    stream.read_exact(&mut length).map_err(io_error)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > LIMIT {
        return Err(CoreError::new(
            ErrorCode::InvalidArgument,
            "Authentication response too large",
        ));
    }
    let mut secret = vec![0; length];
    stream.read_exact(&mut secret).map_err(io_error)?;
    let result = std::io::stdout().lock().write_all(&secret);
    secret.fill(0);
    result.map_err(io_error)
}

pub(crate) struct AuthenticationSession {
    broker: Arc<AuthenticationBroker>,
    token: String,
}
impl Drop for AuthenticationSession {
    fn drop(&mut self) {
        self.broker
            .shared
            .sessions
            .lock()
            .unwrap()
            .remove(&self.token);
    }
}

pub struct AuthenticationShutdown(Arc<Shared>);
impl std::future::Future for AuthenticationShutdown {
    type Output = ();
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        let mut waker = self.0.waker.lock().unwrap();
        if self.0.finished.load(Ordering::SeqCst) {
            std::task::Poll::Ready(())
        } else {
            *waker = Some(cx.waker().clone());
            std::task::Poll::Pending
        }
    }
}
