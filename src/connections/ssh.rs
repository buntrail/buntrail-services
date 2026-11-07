//! System OpenSSH only. Construction, waits and destruction belong on a service worker.
use crate::files::io_error;
use buntrail_core::contracts::*;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{OpenOptionsExt, PermissionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
const DEADLINE: Duration = Duration::from_secs(120);
const MAX_DIAGNOSTICS: usize = 1024 * 1024;
#[derive(Clone)]
pub struct SshProfile {
    pub name: String,
    pub config: Option<PathBuf>,
}
#[derive(Clone)]
pub struct SshConnector {
    profile: SshProfile,
    auth: Option<Arc<super::authentication::AuthenticationBroker>>,
    cancel: Arc<AtomicBool>,
}
pub struct Probe {
    pub os: String,
    pub peer_key: String,
    pub architecture: String,
    pub libc: String,
    pub identity: Option<TargetIdentity>,
}
struct State {
    peer: Option<String>,
    result: Option<Result<(), CoreError>>,
    shutdown_waker: Option<std::task::Waker>,
}
struct ProcessState {
    state: Mutex<State>,
    wake: Condvar,
    cancel: AtomicBool,
    startup_complete: AtomicBool,
    socket: UnixStream,
    writer: UnixStream,
}
/// Drop only signals shutdown. The backend manager owns reaping and pump retirement.
pub struct SshChannel {
    pub(crate) stream: UnixStream,
    pub peer_key: String,
    state: Arc<ProcessState>,
    worker: Option<thread::JoinHandle<()>>,
    authentication: Option<super::authentication::AuthenticationSession>,
}
impl Drop for SshChannel {
    fn drop(&mut self) {
        self.request_stop();
        self.worker.take();
    }
}
impl SshChannel {
    pub(crate) fn finish_input(&self) -> Result<(), CoreError> {
        match self.stream.shutdown(std::net::Shutdown::Write) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotConnected => Ok(()),
            Err(error) => Err(io_error(error)),
        }
    }
    pub(crate) fn complete_startup(&self) {
        self.state.startup_complete.store(true, Ordering::SeqCst);
    }
    pub(crate) fn request_stop(&mut self) {
        self.authentication.take();
        self.state.cancel.store(true, Ordering::SeqCst);
        let _ = self.state.socket.shutdown(std::net::Shutdown::Both);
    }
    pub fn close(self) -> SshShutdown {
        SshShutdown(self.state.clone())
    }
    /// Clone the byte endpoint while retaining this channel as its lifetime owner.
    pub fn stream(&self) -> Result<UnixStream, CoreError> {
        self.stream.try_clone().map_err(io_error)
    }
    pub(crate) fn finish(&self) -> Result<(), CoreError> {
        let mut s = self.state.state.lock().unwrap();
        let deadline = Instant::now() + DEADLINE;
        loop {
            if let Some(r) = &s.result {
                return r.clone();
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(failed("SSH operation deadline exceeded"));
            }
            s = self.state.wake.wait_timeout(s, remaining).unwrap().0;
        }
    }
}
fn failed(s: &str) -> CoreError {
    CoreError::new(ErrorCode::Unavailable, s)
}
const PROBE: &str = r#"set -eu
os=$(uname -s)
arch=$(uname -m)
printf '%s\n%s\n' "$os" "$arch"
if [ "$os" != Linux ]; then exit 0; fi
if getconf GNU_LIBC_VERSION >/dev/null 2>&1; then printf 'gnu\n'; elif ldd --version 2>&1 | grep -q musl; then printf 'musl\n'; else printf 'unknown\n'; fi
id -u
stat -c '%d %i' /
base64 < /etc/machine-id
"#;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipePurpose {
    Request,
    Bootstrap,
    Bridge,
}
pub(crate) enum Entry {
    Probe,
    Bootstrap,
    Bridge,
    Engine(PipePurpose),
    EngineEnvironment,
    EngineHome,
}
impl Entry {
    fn configure_compression(&self, command: &mut Command) {
        if matches!(self, Self::Engine(PipePurpose::Bootstrap)) {
            command.arg("-oCompression=yes");
        }
    }
    fn script(&self) -> &'static str {
        match self {
            Self::Probe => PROBE,
            Self::Bootstrap => super::bootstrap::INSTALL_ENTRY,
            Self::Bridge => super::bootstrap::BRIDGE_ENTRY,
            Self::Engine(_) => super::container_transport::ENGINE_ENTRY,
            Self::EngineEnvironment => super::container_transport::ENVIRONMENT_ENTRY,
            Self::EngineHome => super::container_transport::HOME_ENTRY,
        }
    }
}
impl SshConnector {
    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }
    pub fn new(
        profile: SshProfile,
        auth: Option<Arc<super::authentication::AuthenticationBroker>>,
        cancel: Arc<AtomicBool>,
    ) -> Result<Self, CoreError> {
        if profile.name.is_empty()
            || profile.name.len() > 255
            || profile.name.starts_with('-')
            || profile.name.chars().any(char::is_control)
            || profile.config.as_ref().is_some_and(|p| !p.is_absolute())
        {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "Choose a bounded saved SSH profile and absolute config path",
            ));
        }
        Ok(Self {
            profile,
            auth,
            cancel,
        })
    }
    /// Only explicit integration fixtures: verified real SSH bytes using the existing fixed entry.
    #[cfg(feature = "test-support")]
    pub fn fixture_byte_channel(&self) -> Result<SshChannel, CoreError> {
        let channel = self.start(Entry::Probe, None)?;
        channel.complete_startup();
        Ok(channel)
    }
    pub fn probe(&self) -> Result<Probe, CoreError> {
        let (bytes, peer_key) = self.run(Entry::Probe, Vec::new(), None)?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| failed("Invalid SSH platform response"))?;
        let mut lines = text.lines();
        let os = match lines.next() {
            Some("Linux") => "linux",
            Some("Darwin") => "macos",
            _ => return Err(failed("Unsupported SSH target OS")),
        }
        .to_string();
        let architecture = lines
            .next()
            .ok_or_else(|| failed("Missing SSH architecture"))?
            .to_owned();
        let mut libc = String::new();
        let mut identity = None;
        if os == "linux" {
            use base64::Engine;
            libc = lines
                .next()
                .ok_or_else(|| failed("Missing target libc"))?
                .to_owned();
            let uid: u32 = lines
                .next()
                .unwrap_or("")
                .parse()
                .map_err(|_| failed("Invalid target user"))?;
            let root = lines
                .next()
                .unwrap_or("")
                .split_whitespace()
                .map(str::parse::<u64>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| failed("Invalid filesystem namespace"))?;
            if root.len() != 2 {
                return Err(failed("Invalid filesystem namespace"));
            }
            let machine = base64::engine::general_purpose::STANDARD
                .decode(lines.collect::<String>())
                .map_err(|_| failed("Invalid machine binding"))?;
            if machine.is_empty() || machine.len() > 4096 {
                return Err(failed("Invalid machine binding"));
            }
            identity = Some(super::bootstrap::ssh_identity(
                TargetIdentity {
                    security_binding: machine,
                    effective_user: uid.to_be_bytes().to_vec(),
                    filesystem_namespace: [root[0].to_be_bytes(), root[1].to_be_bytes()].concat(),
                    container: None,
                },
                &peer_key,
            )?);
        }
        Ok(Probe {
            os,
            peer_key,
            architecture,
            libc,
            identity,
        })
    }
    pub(crate) fn run(
        &self,
        entry: Entry,
        input: Vec<u8>,
        expected_peer: Option<&str>,
    ) -> Result<(Vec<u8>, String), CoreError> {
        let mut channel = self.start(entry, expected_peer)?;
        let result = (|| {
            channel.stream.write_all(&input).map_err(io_error)?;
            channel.finish_input()?;
            let mut bytes = Vec::new();
            (&mut channel.stream)
                .take(65537)
                .read_to_end(&mut bytes)
                .map_err(io_error)?;
            if bytes.len() > 65536 {
                return Err(failed("SSH bootstrap response exceeded its bound"));
            }
            channel.finish()?;
            Ok((bytes, channel.peer_key.clone()))
        })();
        if result.is_err() {
            channel.request_stop();
            let _ = channel.finish();
        }
        result
    }

    pub(crate) fn start(
        &self,
        entry: Entry,
        expected_peer: Option<&str>,
    ) -> Result<SshChannel, CoreError> {
        if self.cancel.load(Ordering::SeqCst) {
            return Err(CoreError::new(
                ErrorCode::Cancelled,
                "SSH connection cancelled",
            ));
        }
        let temporary = tempfile::Builder::new()
            .prefix("buntrail-ssh-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .map_err(io_error)?;
        let diagnostics = temporary.path().join("diagnostics");
        let name = std::ffi::CString::new(diagnostics.as_os_str().as_bytes()).map_err(io_error)?;
        if unsafe { libc::mkfifo(name.as_ptr(), 0o600) } != 0 {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        let diagnostic = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(&diagnostics)
            .map_err(io_error)?;
        let mut command = Command::new("/usr/bin/ssh");
        command.args(["-T", "-v", "-E"]).arg(&diagnostics);
        if let Some(config) = &self.profile.config {
            command.arg("-F").arg(config);
        }
        command.args([
            "-oLogVerbose=none",
            "-oFingerprintHash=sha256",
            "-oRemoteCommand=none",
            "-oSessionType=default",
            "-oStdinNull=no",
            "-oForkAfterAuthentication=no",
            "-oStrictHostKeyChecking=yes",
            "-oControlMaster=no",
            "-oControlPath=none",
            "-oPermitLocalCommand=no",
            "-oClearAllForwardings=yes",
            "-oConnectionAttempts=1",
            "-oConnectTimeout=15",
            "-oServerAliveInterval=15",
            "-oServerAliveCountMax=2",
        ]);
        entry.configure_compression(&mut command);
        let authentication = if let Some(auth) = &self.auth {
            Some(auth.configure(&mut command)?)
        } else {
            command.arg("-oBatchMode=yes");
            None
        };
        // Only fixed app-owned scripts enter shell text; all variable data travels on stdin.
        command
            .arg("--")
            .arg(&self.profile.name)
            .arg(format!("sh -c '{}'", entry.script().replace('\'', "'\\''")))
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut channel = spawn_pipe(
            command,
            self.cancel.clone(),
            Some((diagnostic, temporary)),
            authentication,
            matches!(
                entry,
                Entry::Probe
                    | Entry::Bootstrap
                    | Entry::EngineEnvironment
                    | Entry::EngineHome
                    | Entry::Engine(PipePurpose::Request | PipePurpose::Bootstrap)
            ),
        )?;
        let outcome = {
            let mut s = channel.state.state.lock().unwrap();
            loop {
                if let Some(r) = &s.result {
                    break r.clone().and_then(|_| {
                        s.peer
                            .clone()
                            .ok_or_else(|| failed("Missing verified SSH peer"))
                    });
                }
                if let Some(peer) = &s.peer {
                    break Ok(peer.clone());
                }
                s = channel
                    .state
                    .wake
                    .wait_timeout(s, Duration::from_millis(50))
                    .unwrap()
                    .0;
            }
        };
        channel.peer_key = outcome?;
        if expected_peer.is_some_and(|key| key != channel.peer_key) {
            channel.request_stop();
            let _ = channel.finish();
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "Verified SSH host key changed",
            ));
        }
        Ok(channel)
    }
}

/// Shared child/pump owner; local engine exec uses the same cancellation and retirement path.
pub(crate) fn local_pipe(
    mut command: Command,
    cancel: Arc<AtomicBool>,
    purpose: PipePurpose,
) -> Result<SshChannel, CoreError> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    spawn_pipe(command, cancel, None, None, purpose != PipePurpose::Bridge)
}
fn spawn_pipe(
    mut command: Command,
    cancel: Arc<AtomicBool>,
    diagnostics: Option<(std::fs::File, tempfile::TempDir)>,
    authentication: Option<super::authentication::AuthenticationSession>,
    bounded: bool,
) -> Result<SshChannel, CoreError> {
    let require_peer = diagnostics.is_some();
    let mut child = OwnedChild(command.spawn().map_err(io_error)?);
    let input = child.stdin.take().unwrap();
    let output = child.stdout.take().unwrap();
    let error = child.stderr.take().unwrap();
    if unsafe { libc::fcntl(error.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io_error(std::io::Error::last_os_error()));
    }
    let (stream, pipe) = UnixStream::pair().map_err(io_error)?;
    if bounded {
        stream.set_read_timeout(Some(DEADLINE)).map_err(io_error)?;
        stream.set_write_timeout(Some(DEADLINE)).map_err(io_error)?;
    }
    let state = Arc::new(ProcessState {
        state: Mutex::new(State {
            peer: if require_peer {
                None
            } else {
                Some(String::new())
            },
            result: None,
            shutdown_waker: None,
        }),
        wake: Condvar::new(),
        cancel: AtomicBool::new(false),
        startup_complete: AtomicBool::new(false),
        socket: pipe.try_clone().map_err(io_error)?,
        writer: stream.try_clone().map_err(io_error)?,
    });
    let shared = state.clone();
    let external_cancel = cancel;
    let worker = thread::Builder::new()
        .name("buntrail-ssh".into())
        .spawn(move || {
            let mut process = ProcessGuard {
                child,
                input: None,
                output: None,
                shared: shared.clone(),
                result: None,
            };
            let mut source = pipe.try_clone().unwrap();
            let mut destination = pipe;
            process.input = Some(thread::spawn(move || {
                let mut input = input;
                let _ = std::io::copy(&mut source, &mut input);
            }));
            process.output = Some(thread::spawn(move || {
                let mut output = output;
                let _ = std::io::copy(&mut output, &mut destination);
                let _ = destination.shutdown(std::net::Shutdown::Write);
            }));
            let mut diagnostic = diagnostics;
            let mut error = error;
            let mut parser = Diagnostics::default();
            let started = Instant::now();
            let mut reason = None;
            let mut bytes = [0; 8192];
            let status = loop {
                // Bound each drain turn so a noisy peer cannot starve cancellation.
                for _ in 0..8 {
                    let Some((diagnostic, _)) = diagnostic.as_mut() else {
                        break;
                    };
                    match diagnostic.read(&mut bytes) {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Err(e) = parser.feed(&bytes[..n]) {
                                reason = Some(e);
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => {
                            reason = Some(failed("SSH diagnostics channel failed"));
                            break;
                        }
                    }
                }
                for _ in 0..8 {
                    if !matches!(error.read(&mut bytes),Ok(n) if n>0) {
                        break;
                    }
                }
                if let Some(peer) = parser.verified.as_ref() {
                    let mut state = shared.state.lock().unwrap();
                    if state.peer.is_none() {
                        state.peer = Some(peer.clone());
                        shared.wake.notify_all();
                    }
                }
                if shared.cancel.load(Ordering::SeqCst) || external_cancel.load(Ordering::SeqCst) {
                    reason = Some(CoreError::new(
                        ErrorCode::Cancelled,
                        "SSH connection cancelled",
                    ));
                }
                if !shared.startup_complete.load(Ordering::SeqCst) && started.elapsed() >= DEADLINE
                {
                    reason = Some(failed("SSH authentication deadline exceeded"));
                }
                if reason.is_some() {
                    let _ = shared.socket.shutdown(std::net::Shutdown::Both);
                    unsafe {
                        libc::kill(-(process.child.id() as i32), libc::SIGKILL);
                    }
                    let _ = process.child.kill();
                    break process.child.wait();
                }
                match process.child.try_wait() {
                    Ok(Some(status)) => break Ok(status),
                    Ok(None) => thread::sleep(Duration::from_millis(10)),
                    Err(e) => break Err(e),
                }
            };
            let _ = shared.socket.shutdown(std::net::Shutdown::Read);
            // Darwin peer shutdown does not wake an upload already blocked on this endpoint.
            let _ = shared.writer.shutdown(std::net::Shutdown::Write);
            if let Some(worker) = process.input.take() {
                let _ = worker.join();
            }
            if let Some(worker) = process.output.take() {
                let _ = worker.join();
            }
            process.result = Some(reason.map_or_else(
                || match status {
                    Ok(status)
                        if status.success() && (!require_peer || parser.verified.is_some()) =>
                    {
                        Ok(())
                    }
                    _ => Err(failed(
                        "SSH failed; verify host key, credentials, target tools and helper storage",
                    )),
                },
                Err,
            ));
        })
        .map_err(io_error)?;
    let channel = SshChannel {
        stream,
        peer_key: String::new(),
        state,
        worker: Some(worker),
        authentication,
    };
    Ok(channel)
}
#[derive(Default)]
struct Diagnostics {
    pending: Vec<u8>,
    total: usize,
    key: Option<String>,
    verified: Option<String>,
    discarding_line: bool,
}
impl Diagnostics {
    fn feed(&mut self, bytes: &[u8]) -> Result<(), CoreError> {
        if self.verified.is_none() {
            self.total += bytes.len();
        }
        if self.total > MAX_DIAGNOSTICS {
            return Err(failed("SSH diagnostics exceeded their bound"));
        }
        let bytes = if self.discarding_line {
            match bytes.iter().position(|b| *b == b'\n') {
                Some(end) => {
                    self.discarding_line = false;
                    &bytes[end + 1..]
                }
                None => return Ok(()),
            }
        } else {
            bytes
        };
        self.pending.extend_from_slice(bytes);
        while let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
            let bytes = self.pending.drain(..=end).collect::<Vec<_>>();
            let line = std::str::from_utf8(&bytes)
                .map_err(|_| failed("Unrecognized SSH diagnostics"))?
                .trim_end_matches(['\r', '\n']);
            // OpenSSH's client log can contain multiline SSH_MSG_DEBUG data. Reject it
            // before the first key; later auth-looking text is only a hint, never readiness.
            if self.key.is_none()
                && (line.starts_with("debug1: Remote:")
                    || line.starts_with("Remote:")
                    || line.starts_with("Received disconnect from "))
            {
                return Err(failed("Untrusted SSH diagnostics preceded the host key"));
            }
            if line == "Host key verification failed." {
                return Err(CoreError::new(
                    ErrorCode::TargetChanged,
                    "SSH host-key verification failed; verify the saved known_hosts entry",
                ));
            }
            if let Some(key) = line
                .strip_prefix("debug1: Server host key: ")
                .or_else(|| line.strip_prefix("debug1: Server host certificate: "))
            {
                let fingerprint = key
                    .split_whitespace()
                    .nth(1)
                    .ok_or_else(|| failed("Missing SSH host key fingerprint"))?;
                if !super::bootstrap::valid_peer_key(fingerprint) {
                    return Err(failed("Unrecognized SSH host key fingerprint"));
                }
                if let Some(verified) = &self.verified {
                    if verified != fingerprint {
                        return Err(failed("SSH peer key changed during rekey"));
                    }
                } else if self.key.is_some() {
                    return Err(failed("Ambiguous SSH host-key diagnostics"));
                }
                self.key = Some(fingerprint.into());
            }
            if line.starts_with("Authenticated to ") {
                if self.verified.is_some() {
                    return Err(failed("Ambiguous SSH authentication diagnostics"));
                }
                self.verified = Some(
                    self.key
                        .clone()
                        .ok_or_else(|| failed("Missing authenticated SSH host key"))?,
                );
            }
        }
        if self.pending.len() > 16384 {
            if self.verified.is_none() || self.pending.starts_with(b"debug1: Server host ") {
                return Err(failed("SSH diagnostic line exceeded its bound"));
            }
            self.pending.clear();
            self.discarding_line = true;
        }
        Ok(())
    }
}

struct OwnedChild(std::process::Child);
impl std::ops::Deref for OwnedChild {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for OwnedChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            };
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
struct ProcessGuard {
    child: OwnedChild,
    input: Option<thread::JoinHandle<()>>,
    output: Option<thread::JoinHandle<()>>,
    shared: Arc<ProcessState>,
    result: Option<Result<(), CoreError>>,
}
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.shared.socket.shutdown(std::net::Shutdown::Both);
        let _ = self.shared.writer.shutdown(std::net::Shutdown::Write);
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            };
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(worker) = self.input.take() {
            let _ = worker.join();
        }
        if let Some(worker) = self.output.take() {
            let _ = worker.join();
        }
        let mut state = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.result.is_none() {
            state.result = Some(
                self.result
                    .take()
                    .unwrap_or_else(|| Err(failed("SSH worker stopped unexpectedly"))),
            );
        }
        if let Some(w) = state.shutdown_waker.take() {
            w.wake();
        }
        self.shared.wake.notify_all();
    }
}
/// Resolves only after the owned child and byte pumps have retired; safe to poll on any thread.
pub struct SshShutdown(Arc<ProcessState>);
impl std::future::Future for SshShutdown {
    type Output = ();
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        let mut state = self.0.state.lock().unwrap();
        if state.result.is_some() {
            std::task::Poll::Ready(())
        } else {
            state.shutdown_waker = Some(cx.waker().clone());
            std::task::Poll::Pending
        }
    }
}
#[cfg(test)]
mod fixture_tests {
    use super::*;
    #[test]
    fn compression_is_confined_to_ssh_container_bootstrap() {
        for entry in [
            Entry::Probe,
            Entry::Bootstrap,
            Entry::Bridge,
            Entry::EngineEnvironment,
            Entry::EngineHome,
            Entry::Engine(PipePurpose::Request),
            Entry::Engine(PipePurpose::Bootstrap),
            Entry::Engine(PipePurpose::Bridge),
        ] {
            let mut command = Command::new("/usr/bin/ssh");
            entry.configure_compression(&mut command);
            let arguments: Vec<_> = command.get_args().collect();
            if matches!(entry, Entry::Engine(PipePurpose::Bootstrap)) {
                assert_eq!(arguments, ["-oCompression=yes"]);
            } else {
                assert!(
                    arguments.is_empty(),
                    "ordinary SSH entries preserve configured defaults"
                );
            }
        }
    }
    #[test]
    #[ignore = "Run through the owned real sshd fixture; no engine command is dispatched"]
    fn byte_endpoint_engine_purpose_is_bounded_before_dispatch_and_cancel_retires() {
        let connector = SshConnector::new(
            SshProfile {
                name: "fixture".into(),
                config: Some(PathBuf::from(
                    std::env::var_os("BUNTRAIL_SSH_FIXTURE_CONFIG").unwrap(),
                )),
            },
            None,
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        for purpose in [
            PipePurpose::Request,
            PipePurpose::Bootstrap,
            PipePurpose::Bridge,
        ] {
            let mut channel = connector.start(Entry::Engine(purpose), None).unwrap();
            assert_eq!(
                channel.stream.read_timeout().unwrap(),
                if purpose != PipePurpose::Bridge {
                    Some(DEADLINE)
                } else {
                    None
                }
            );
            assert_eq!(
                channel.stream.write_timeout().unwrap(),
                if purpose != PipePurpose::Bridge {
                    Some(DEADLINE)
                } else {
                    None
                }
            );
            let started = Instant::now();
            channel.request_stop();
            assert_eq!(channel.finish().unwrap_err().code, ErrorCode::Cancelled);
            assert!(started.elapsed() < Duration::from_secs(2));
        }
        let mut channel = connector.start(Entry::EngineEnvironment, None).unwrap();
        assert_eq!(channel.stream.read_timeout().unwrap(), Some(DEADLINE));
        channel.request_stop();
        let _ = channel.finish();
    }
    #[test]
    fn engine_request_bounds_precede_early_exit_and_bridge_has_no_lifetime_timeout() {
        for purpose in [
            PipePurpose::Request,
            PipePurpose::Bootstrap,
            PipePurpose::Bridge,
        ] {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "exit 0"]);
            let mut channel =
                local_pipe(command, Arc::new(AtomicBool::new(false)), purpose).unwrap();
            assert_eq!(
                channel.stream.read_timeout().unwrap(),
                if purpose != PipePurpose::Bridge {
                    Some(DEADLINE)
                } else {
                    None
                }
            );
            assert_eq!(
                channel.stream.write_timeout().unwrap(),
                if purpose != PipePurpose::Bridge {
                    Some(DEADLINE)
                } else {
                    None
                }
            );
            let started = Instant::now();
            assert!(channel.stream.write_all(&vec![0; 8 * 1024 * 1024]).is_err());
            assert!(started.elapsed() < Duration::from_millis(1500));
            channel.finish().unwrap();
        }
    }
    #[test]
    fn engine_request_late_output_and_cancellation_retire_owned_pumps() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "dd if=/dev/zero bs=1024 count=60 2>/dev/null"]);
        let mut channel = local_pipe(
            command,
            Arc::new(AtomicBool::new(false)),
            PipePurpose::Request,
        )
        .unwrap();
        channel.finish_input().unwrap();
        let mut bytes = vec![];
        channel.stream.read_to_end(&mut bytes).unwrap();
        channel.finish().unwrap();
        assert_eq!(bytes, vec![0; 60 * 1024]);
        let cancel = Arc::new(AtomicBool::new(false));
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exec sleep 20"]);
        let channel = local_pipe(command, cancel.clone(), PipePurpose::Request).unwrap();
        let started = Instant::now();
        cancel.store(true, Ordering::SeqCst);
        assert_eq!(channel.finish().unwrap_err().code, ErrorCode::Cancelled);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
    #[test]
    #[ignore = "Run through the owned real sshd upload fixture"]
    fn byte_endpoint_upload_late_success_can_configure_and_drain_stdout() {
        let broker = super::super::authentication::AuthenticationBroker::new(PathBuf::from(
            std::env::var_os("BUNTRAIL_ASKPASS_BINARY").unwrap(),
        ))
        .unwrap();
        let connector = SshConnector::new(
            SshProfile {
                name: "complete-stdout".into(),
                config: Some(PathBuf::from(
                    std::env::var_os("BUNTRAIL_SSH_FIXTURE_CONFIG").unwrap(),
                )),
            },
            Some(broker),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let mut channel = connector.start(Entry::Probe, None).unwrap();
        let mut bytes = vec![0; 59 * 1024];
        channel.stream.read_exact(&mut bytes).unwrap();
        channel.finish().unwrap();
        channel.finish_input().unwrap();
        channel.finish_input().unwrap();
        channel.stream.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, vec![0; 60 * 1024]);
    }
    #[test]
    #[ignore = "Run through the owned real sshd upload fixture"]
    fn byte_endpoint_upload_early_exit_interrupts_blocked_writer() {
        for (profile, success) in [("early-exit", false), ("early-success", true)] {
            let connector = SshConnector::new(
                SshProfile {
                    name: profile.into(),
                    config: Some(PathBuf::from(
                        std::env::var_os("BUNTRAIL_SSH_FIXTURE_CONFIG").unwrap(),
                    )),
                },
                None,
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap();
            let mut channel = connector.start(Entry::Probe, None).unwrap();
            channel
                .stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let started = Instant::now();
            assert!(channel.stream.write_all(&vec![0; 8 * 1024 * 1024]).is_err());
            assert!(
                started.elapsed() < Duration::from_millis(1500),
                "retired child must interrupt upload, not wait for socket timeout: {:?}",
                started.elapsed()
            );
            assert_eq!(channel.finish().is_ok(), success);
        }
    }
    #[test]
    #[ignore = "Run through the owned real sshd upload fixture"]
    fn byte_endpoint_upload_complete_stdout_survives_child_exit() {
        let connector = SshConnector::new(
            SshProfile {
                name: "complete-stdout".into(),
                config: Some(PathBuf::from(
                    std::env::var_os("BUNTRAIL_SSH_FIXTURE_CONFIG").unwrap(),
                )),
            },
            None,
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(
            connector.run(Entry::Probe, vec![], None).unwrap().0,
            vec![0; 60 * 1024]
        );
    }
    #[test]
    #[ignore = "Run through the owned real sshd integration fixture"]
    fn byte_endpoint_ignores_stdin_null_and_keeps_quoted_binary_data() {
        let connector = SshConnector::new(
            SshProfile {
                name: "stdin-option".into(),
                config: Some(PathBuf::from(
                    std::env::var_os("BUNTRAIL_SSH_FIXTURE_CONFIG").unwrap(),
                )),
            },
            None,
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let mut channel = connector.start(Entry::Probe, None).unwrap();
        channel
            .stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let bytes = b"quoted '\n$(touch NEVER); *\xff";
        channel.stream.write_all(bytes).unwrap();
        channel.stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut output = Vec::new();
        channel.stream.read_to_end(&mut output).unwrap();
        channel.finish().unwrap();
        assert_eq!(output, bytes);
    }

    #[test]
    #[ignore = "Run through the owned real sshd integration fixture"]
    fn byte_endpoint_handoff_and_midflight_shutdown_retire_all_workers() {
        let connector = SshConnector::new(
            SshProfile {
                name: "hold".into(),
                config: Some(PathBuf::from(
                    std::env::var_os("BUNTRAIL_SSH_FIXTURE_CONFIG").unwrap(),
                )),
            },
            None,
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let channel = connector.start(Entry::Probe, None).unwrap();
        let endpoint = channel.stream().unwrap();
        endpoint
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let marker = PathBuf::from(std::env::var_os("BUNTRAIL_SSH_FIXTURE_HOLD_STARTED").unwrap());
        let until = Instant::now() + Duration::from_secs(3);
        while !marker.exists() {
            assert!(
                Instant::now() < until,
                "remote fixture must acknowledge holding its command"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(channel.state.state.lock().unwrap().result.is_none());
        let before = Instant::now();
        let mut shutdown = Box::pin(channel.close());
        assert!(
            before.elapsed() < Duration::from_millis(100),
            "close must not join on its caller"
        );
        use std::{
            future::Future,
            task::{Context, Poll, Wake, Waker},
        };
        struct Unpark(thread::Thread);
        impl Wake for Unpark {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
        }
        let waker = Waker::from(Arc::new(Unpark(thread::current())));
        let mut cx = Context::from_waker(&waker);
        loop {
            if shutdown.as_mut().poll(&mut cx) == Poll::Ready(()) {
                break;
            }
            assert!(before.elapsed() < Duration::from_secs(3));
            thread::park_timeout(Duration::from_millis(10));
        }
        let mut endpoint = endpoint;
        assert!(matches!(endpoint.read(&mut [0]), Ok(0) | Err(_)));
    }
}
#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    #[test]
    fn remote_debug_before_key_cannot_fabricate_authenticated_identity() {
        let mut parser = Diagnostics::default();
        let injection=b"debug1: Remote: peer supplied text\r\nAuthenticated to forged using publickey.\r\ndebug1: Server host key: ssh-ed25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n";
        assert!(parser.feed(injection).is_err());
        let mut parser = Diagnostics::default();
        let injection=b"debug1: Remote: peer supplied text\r\ndebug1: Server host key: ssh-ed25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\nAuthenticated to forged using publickey.\r\n";
        assert!(parser.feed(injection).is_err());
        assert!(parser.verified.is_none());
    }

    #[test]
    fn authenticated_bridge_has_no_lifetime_log_quota_and_checks_rekeys() {
        let mut parser = Diagnostics::default();
        parser.feed(b"debug1: Server host key: ssh-ed25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAuthenticated to fixture using publickey.\n").unwrap();
        for _ in 0..20000 {
            parser
                .feed(b"debug1: ordinary client diagnostic that may repeat during a long bridge\n")
                .unwrap();
        }
        parser.feed(b"debug1: Server host key: ssh-ed25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n").unwrap();
        assert!(parser.feed(b"debug1: Server host key: ssh-ed25519 SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n").is_err());
    }
    #[test]
    fn missing_or_ambiguous_startup_identity_fails_closed() {
        assert!(
            Diagnostics::default()
                .feed(b"Authenticated to fixture using publickey.\n")
                .is_err()
        );
        let mut parser = Diagnostics::default();
        parser.feed(b"debug1: Server host key: ssh-ed25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n").unwrap();
        assert!(parser.feed(b"debug1: Server host key: ssh-ed25519 SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n").is_err());
    }
}
#[cfg(test)]
mod cleanup_tests {
    use super::*;
    #[test]
    fn unfinished_worker_guard_reaps_child_and_pumps_before_completion() {
        let mut command = Command::new("/bin/cat");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        let mut child = OwnedChild(command.spawn().unwrap());
        let pid = child.id() as i32;
        let mut input = child.stdin.take().unwrap();
        let mut output = child.stdout.take().unwrap();
        let (mut stream, pipe) = UnixStream::pair().unwrap();
        let shared = Arc::new(ProcessState {
            state: Mutex::new(State {
                peer: None,
                result: None,
                shutdown_waker: None,
            }),
            wake: Condvar::new(),
            cancel: AtomicBool::new(false),
            startup_complete: AtomicBool::new(false),
            socket: pipe.try_clone().unwrap(),
            writer: stream.try_clone().unwrap(),
        });
        let mut source = pipe.try_clone().unwrap();
        let mut destination = pipe;
        let guard = ProcessGuard {
            child,
            input: Some(thread::spawn(move || {
                let _ = std::io::copy(&mut source, &mut input);
            })),
            output: Some(thread::spawn(move || {
                let _ = std::io::copy(&mut output, &mut destination);
            })),
            shared: shared.clone(),
            result: None,
        };
        thread::spawn(move || drop(guard)).join().unwrap();
        assert!(
            shared
                .state
                .lock()
                .unwrap()
                .result
                .as_ref()
                .unwrap()
                .is_err()
        );
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    }
}
