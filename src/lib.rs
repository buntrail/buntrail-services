//! Filesystem, Git, terminal, search and connection services.
//!
//! See the repository README for usage, prerequisites and platform limitations.
//! Blocking workspace services. Call these away from the GUI thread.
mod capture;
#[cfg(unix)]
mod file_compat;
#[cfg(unix)]
pub use file_compat::FileBinding;
mod terminal_input;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const MAX_FILE: u64 = 64 * 1024 * 1024;
const MAX_OUTPUT: usize = 4 * 1024 * 1024;
const MAX_MATCHES: usize = 10_000;
const MAX_TERMINAL_READ: usize = 256 * 1024;
mod remote;

pub struct Services {
    terminals: Mutex<HashMap<String, legacy_terminal::Session>>,
    next_id: AtomicU64,
    #[cfg(unix)]
    files: std::sync::OnceLock<Result<file_compat::Files, String>>,
    #[cfg(unix)]
    state_directory: Option<PathBuf>,
    #[cfg(unix)]
    local: std::sync::OnceLock<Result<Arc<connections::local::LocalConnection>, String>>,
    remotes: Mutex<HashMap<String, remote::Session>>,
}
impl Default for Services {
    fn default() -> Self {
        Self::new()
    }
}
impl Services {
    pub fn new() -> Self {
        Self {
            terminals: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            #[cfg(unix)]
            files: std::sync::OnceLock::new(),
            #[cfg(unix)]
            state_directory: None,
            #[cfg(unix)]
            local: std::sync::OnceLock::new(),
            remotes: Mutex::new(HashMap::new()),
        }
    }
    #[cfg(unix)]
    pub fn with_state_directory(directory: PathBuf) -> Self {
        Self {
            state_directory: Some(directory),
            ..Self::new()
        }
    }
    #[cfg(unix)]
    pub fn storage_directory(&self) -> Result<PathBuf, String> {
        self.state_directory
            .clone()
            .map(Ok)
            .unwrap_or_else(file_compat::default_directory)
    }
    #[cfg(unix)]
    pub fn local_connection(&self) -> Result<Arc<connections::local::LocalConnection>, String> {
        self.local
            .get_or_init(|| {
                let files = self.files()?.service.clone();
                connections::local::LocalConnection::with_files(
                    self.storage_directory()?.join("context"),
                    files,
                )
                .map(Arc::new)
                .map_err(|e| e.message)
            })
            .as_ref()
            .cloned()
            .map_err(Clone::clone)
    }
    #[cfg(unix)]
    pub fn rebound_version(previous: &str, observed: &str, path: &str) -> Result<String, String> {
        file_compat::rebound_version(previous, observed, path)
    }
    #[cfg(unix)]
    pub fn file_binding(token: &str) -> Result<FileBinding, String> {
        FileBinding::parse(token)
    }
    #[cfg(unix)]
    pub fn save_document(&self, request: &Value) -> Result<Value, String> {
        self.files()?.save_document(request)
    }
    #[cfg(unix)]
    pub fn inspect_save(
        &self,
        version: &str,
        operation: buntrail_core::contracts::OperationID,
    ) -> Result<Value, String> {
        self.files()?.inspect_save(version, operation)
    }
    #[cfg(unix)]
    pub fn write_recovery(
        &self,
        journal: &recovery::journal::Journal,
        snapshot: buntrail_core::documents::RecoverySnapshot,
    ) -> Result<(), String> {
        journal
            .write(self.files()?.recovery(), snapshot)
            .map_err(|e| e.message)
    }
    #[cfg(unix)]
    pub fn read_recovery(
        &self,
        document: buntrail_core::contracts::DocumentID,
    ) -> Result<Value, String> {
        let (draft, _budget) = self
            .files()?
            .recovery()
            .preview_budgeted(document)
            .map_err(|e| e.message)?;
        let local = self.files()?.is_local(&draft.file.target);
        let version = FileBinding {
            file: draft.file.clone(),
            version: draft.version,
            encoding: draft.snapshot.encoding,
        }
        .token()?;
        Ok(
            json!({"document":document,"text":draft.snapshot.text.as_str(),"file":draft.file,"version":version,"provisional":draft.provisional_composition,"pending_operation":draft.pending_operation,"local":local}),
        )
    }
    #[cfg(unix)]
    pub fn discard_recovery(
        &self,
        document: buntrail_core::contracts::DocumentID,
    ) -> Result<(), String> {
        self.files()?
            .recovery()
            .discard(document)
            .map_err(|e| e.message)
    }
    #[cfg(unix)]
    pub fn shutdown_local(&self) -> Result<(), String> {
        let Some(Ok(local)) = self.local.get() else {
            return Ok(());
        };
        local
            .close_connection(buntrail_core::contracts::ConnectionCloseReason::ApplicationShutdown);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !local.terminal.shutdown_ready() {
            if Instant::now() >= deadline {
                return Err("Local terminal shutdown is still pending".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }
    #[cfg(unix)]
    pub fn inspect_recovery(
        &self,
        document: buntrail_core::contracts::DocumentID,
        inspect: impl FnOnce(
            buntrail_core::contracts::OperationID,
            buntrail_core::contracts::TargetIdentity,
        ) -> Result<
            buntrail_core::contracts::OperationReceipt,
            buntrail_core::contracts::CoreError,
        >,
    ) -> Result<Value, String> {
        let receipt = self
            .files()?
            .recovery()
            .inspect_pending(document, inspect)
            .map_err(|e| e.message)?;
        Ok(json!({"receipt":receipt}))
    }
    #[cfg(unix)]
    pub fn inspect_operation(
        &self,
        operation: buntrail_core::contracts::OperationID,
        target: buntrail_core::contracts::TargetIdentity,
    ) -> Result<buntrail_core::contracts::OperationReceipt, buntrail_core::contracts::CoreError>
    {
        self.files()
            .map_err(|e| {
                buntrail_core::contracts::CoreError::new(
                    buntrail_core::contracts::ErrorCode::Unavailable,
                    &e,
                )
            })?
            .service
            .inspect_sync(operation, target)
    }
    #[cfg(unix)]
    fn files(&self) -> Result<&file_compat::Files, String> {
        self.files
            .get_or_init(|| {
                let directory = match &self.state_directory {
                    Some(p) => p.clone(),
                    None => file_compat::default_directory()?,
                };
                file_compat::Files::new(directory.join("files"))
            })
            .as_ref()
            .map_err(Clone::clone)
    }
    pub fn call(&self, request: &Value) -> Result<Value, String> {
        #[cfg(not(unix))]
        if request["command"] == "capabilities" {
            return Ok(
                json!({"files":true,"search":true,"git":true,"terminal":true,"sessions":false,"owned_terminals":false,"encoded_documents":false}),
            );
        }
        #[cfg(unix)]
        match string(request, "command")? {
            "recovery.list" => {
                let store = self.files()?.recovery();
                let entries = self.files()?.recovery().inventory().map_err(|e|e.message)?.into_iter()
                    .map(|e|json!({"document":e.document,"file":e.file,"provisional":e.provisional,"unknown_save":e.unknown_save,"error":e.error,"active":store.active(e.document).unwrap_or(true)})).collect::<Vec<_>>();
                return Ok(json!({"entries":entries}));
            }
            "recovery.discard" => {
                self.discard_recovery(
                    serde_json::from_value(request["document"].clone()).map_err(error)?,
                )?;
                return Ok(Value::Null);
            }
            "recovery.inspect" => {
                return self.inspect_recovery(
                    serde_json::from_value(request["document"].clone()).map_err(error)?,
                    |op, target| self.inspect_operation(op, target),
                );
            }
            "recovery.read" => {
                return self.read_recovery(
                    serde_json::from_value(request["document"].clone()).map_err(error)?,
                );
            }
            "git" => {
                let args = request["args"]
                    .as_array()
                    .ok_or("args must be an array")?
                    .iter()
                    .map(|v| v.as_str().ok_or("args must be strings"))
                    .collect::<Result<Vec<_>, _>>()?;
                let query=buntrail_core::contracts::GitRead::from_args(&args).or_else(||(args==["status","--porcelain"]).then_some(buntrail_core::contracts::GitRead::StatusPorcelain)).ok_or("Git mutation requires the engine's document admission and inspection coordinator")?;
                let local = self.local_connection()?;
                let root = files::target_path(
                    &std::path::absolute(string(request, "root")?).map_err(error)?,
                );
                let cancel = AtomicBool::new(false);
                let worktree = local
                    .git
                    .discover_sync(
                        buntrail_core::contracts::FileRef {
                            target: local.identity.clone(),
                            path: root,
                            resolved_identity: None,
                        },
                        &cancel,
                    )
                    .map_err(|e| e.message)?
                    .ok_or("Not a Git worktree")?;
                let output = local
                    .git
                    .read_sync(worktree, query, &cancel)
                    .map_err(|e| e.message)?;
                return Ok(
                    json!({"stdout":String::from_utf8_lossy(&output.stdout),"stderr":String::from_utf8_lossy(&output.stderr),"status":if output.success {0}else{1},"truncated":false}),
                );
            }
            "fs.read" => return self.files()?.read(request),
            "fs.write" => return self.files()?.write(request),
            "fs.create" => return self.files()?.create(request),
            "fs.observe" => return self.files()?.observe(request),
            "fs.mkdir" | "fs.rename" | "fs.remove" => return self.files()?.mutate(request),
            "fs.validate_version" => {
                let observed = FileBinding::parse(string(request, "version")?)?;
                let expected: buntrail_core::contracts::FileVersion =
                    serde_json::from_value(request["expected"].clone()).map_err(error)?;
                if observed.version != expected {
                    return Err("Search result is stale; search again before navigating".into());
                }
                return Ok(Value::Null);
            }
            _ => {}
        }

        match string(request, "command")? {
            "fs.read" => {
                let data = read_file(Path::new(string(request, "path")?))?;
                if data.contains(&0) {
                    return Err("binary files containing NUL are not editable".into());
                }
                let version = digest(&data);
                let text =
                    String::from_utf8(data).map_err(|_| "file is not valid UTF-8".to_owned())?;
                Ok(json!({"text": text, "version": version}))
            }
            "fs.list" => {
                let mut entries = fs::read_dir(string(request, "path")?).map_err(error)?.map(|item| {
                    let item = item.map_err(error)?;
                    let path = item.path();
                    let path = path.to_str().ok_or("directory contains a path that is not UTF-8")?;
                    Ok(json!({"name":item.file_name().to_string_lossy(),"path":path,"directory":item.file_type().map_err(error)?.is_dir()}))
                }).collect::<Result<Vec<Value>, String>>()?;
                entries.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
                Ok(json!({"entries":entries}))
            }
            "fs.write" => write_file(request),
            "fs.create" => create_file(request),
            "fs.mkdir" => {
                fs::create_dir(string(request, "path")?).map_err(error)?;
                Ok(Value::Null)
            }
            "fs.rename" => {
                rename_exclusive(string(request, "path")?, string(request, "to")?)?;
                Ok(Value::Null)
            }
            "fs.remove" => {
                let path = Path::new(string(request, "path")?);
                let metadata = fs::symlink_metadata(path).map_err(error)?;
                #[cfg(windows)]
                {
                    use std::os::windows::fs::FileTypeExt;
                    if metadata.file_type().is_symlink_dir() {
                        fs::remove_dir(path).map_err(error)?;
                        return Ok(Value::Null);
                    }
                }
                if metadata.is_dir() {
                    fs::remove_dir(path).map_err(error)?;
                } else if metadata.is_file() || metadata.file_type().is_symlink() {
                    fs::remove_file(path).map_err(error)?;
                } else {
                    return Err(
                        "remove supports only files, symlinks, and empty directories".into(),
                    );
                }
                Ok(Value::Null)
            }
            "git" => {
                let root = directory(request)?;
                let args = request["args"]
                    .as_array()
                    .ok_or("args must be an array of strings")?
                    .iter()
                    .map(|arg| arg.as_str().ok_or("args must contain only strings"))
                    .collect::<Result<Vec<_>, _>>()?;
                let mut command = Command::new("git");
                command.env("GIT_TERMINAL_PROMPT", "0");
                command.arg("-C").arg(root).args(args);
                run(&mut command)
            }
            "search" => search(request),
            "remote.start" => {
                let session = remote::Session::start(request)?;
                let instance = session.instance().to_owned();
                let id = format!("remote-{}", self.next_id.fetch_add(1, Ordering::Relaxed));
                self.remotes
                    .lock()
                    .map_err(error)?
                    .insert(id.clone(), session);
                Ok(json!({"id":id,"instance":instance}))
            }
            "remote.call" => {
                let nested = request
                    .get("request")
                    .filter(|v| v.is_object())
                    .ok_or("request must be an object")?;
                if nested["command"]
                    .as_str()
                    .is_some_and(|c| c.starts_with("remote."))
                {
                    return Err("nested remote transport is not supported".into());
                }
                let mut sessions = self.remotes.lock().map_err(error)?;
                let id = string(request, "id")?;
                let session = sessions.get_mut(id).ok_or("unknown remote id")?;
                let result = session.call(nested);
                if !session.healthy() {
                    sessions.remove(id);
                }
                result
            }
            "remote.close" => {
                self.remotes
                    .lock()
                    .map_err(error)?
                    .remove(string(request, "id")?)
                    .ok_or("unknown remote id")?;
                Ok(Value::Null)
            }
            "terminal.start" => {
                let root = directory(request)?;
                #[cfg(windows)]
                let default_shell = std::env::var("ComSpec")
                    .unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".into());
                #[cfg(not(windows))]
                let default_shell = "/bin/sh".to_owned();
                let shell = request
                    .get("shell")
                    .map(|v| v.as_str().ok_or("shell must be a string"))
                    .transpose()?
                    .unwrap_or(&default_shell);
                let session = legacy_terminal::Session::start(&root, shell)?;
                let id = format!("terminal-{}", self.next_id.fetch_add(1, Ordering::Relaxed));
                self.terminals
                    .lock()
                    .map_err(error)?
                    .insert(id.clone(), session);
                Ok(json!({"id":id}))
            }
            "terminal.read" | "terminal.write" | "terminal.resize" | "terminal.close" => {
                let id = string(request, "id")?;
                let mut sessions = self.terminals.lock().map_err(error)?;
                let session = sessions.get_mut(id).ok_or("unknown terminal id")?;
                match string(request, "command")? {
                    "terminal.read" => session.read(),
                    "terminal.write" => {
                        session.write(&terminal_input(request)?)?;
                        Ok(Value::Null)
                    }
                    "terminal.resize" => {
                        let columns = dimension(request, "columns")?;
                        let rows = dimension(request, "rows")?;
                        session.resize(columns, rows)?;
                        Ok(Value::Null)
                    }
                    _ => {
                        sessions.remove(id);
                        Ok(Value::Null)
                    }
                }
            }
            _ => Err("unknown service command".into()),
        }
    }
}
fn error(err: impl std::fmt::Display) -> String {
    err.to_string()
}
fn string<'a>(request: &'a Value, key: &str) -> Result<&'a str, String> {
    request[key]
        .as_str()
        .ok_or_else(|| format!("{key} must be a string"))
}
fn dimension(request: &Value, key: &str) -> Result<u16, String> {
    request[key]
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .filter(|v| *v > 0)
        .ok_or_else(|| format!("{key} must be between 1 and 65535"))
}
fn terminal_input(request: &Value) -> Result<Vec<u8>, String> {
    const LIMIT: usize = 1024 * 1024;
    match (request.get("bytes"), request.get("text")) {
        (Some(bytes), None) => {
            let bytes = bytes
                .as_array()
                .ok_or("bytes must be an array of integers from 0 through 255")?;
            if bytes.len() > LIMIT {
                return Err("terminal input exceeds 1 MiB limit".into());
            }
            bytes
                .iter()
                .map(|byte| {
                    byte.as_u64()
                        .and_then(|v| u8::try_from(v).ok())
                        .ok_or_else(|| {
                            "bytes must contain only integers from 0 through 255".to_owned()
                        })
                })
                .collect()
        }
        (None, Some(text)) => {
            let text = text.as_str().ok_or("text must be a string")?;
            if text.len() > LIMIT {
                return Err("terminal input exceeds 1 MiB limit".into());
            }
            Ok(text.as_bytes().to_vec())
        }
        _ => Err("provide exactly one terminal input: text or bytes".into()),
    }
}
fn directory(request: &Value) -> Result<PathBuf, String> {
    let path = PathBuf::from(string(request, "root")?);
    if !path.is_dir() {
        return Err("root must be an existing directory".into());
    }
    Ok(path)
}
fn open_regular_file(path: &Path) -> Result<File, String> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    // Validate the opened descriptor: a path check alone races FIFO replacement.
    let file = options.open(path).map_err(error)?;
    if !file.metadata().map_err(error)?.is_file() {
        return Err("path is not a regular file".into());
    }
    Ok(file)
}
fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    let file = open_regular_file(path)?;
    let mut data = Vec::new();
    file.take(MAX_FILE + 1)
        .read_to_end(&mut data)
        .map_err(error)?;
    if data.len() as u64 > MAX_FILE {
        return Err("file exceeds 64 MiB limit".into());
    }
    Ok(data)
}
fn write_file(request: &Value) -> Result<Value, String> {
    let path = Path::new(string(request, "path")?);
    let text = string(request, "text")?;
    if text.contains('\0') {
        return Err("binary files containing NUL are not editable".into());
    }
    let expected = string(request, "version")?;
    if text.len() as u64 > MAX_FILE {
        return Err("file exceeds 64 MiB limit".into());
    }
    let metadata = fs::symlink_metadata(path).map_err(error)?;
    if !metadata.is_file() {
        return Err("write requires a regular file, not a symlink".into());
    }
    let lock = open_regular_file(path)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("file is locked by another writer".into());
        }
    }
    if digest(&read_file(path)?) != expected {
        return Err("file version conflict: external changes preserved".into());
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut replacement = tempfile::NamedTempFile::new_in(parent).map_err(error)?;
    replacement.write_all(text.as_bytes()).map_err(error)?;
    replacement
        .as_file()
        .set_permissions(metadata.permissions())
        .map_err(error)?;
    replacement.as_file().sync_all().map_err(error)?;
    // shortcut: advisory locking cannot coordinate uncooperative writers; recheck immediately before atomic rename.
    if digest(&read_file(path)?) != expected {
        return Err("file version conflict: external changes preserved".into());
    }
    replacement.persist(path).map_err(error)?;
    #[cfg(unix)]
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(error)?;
    drop(lock);
    Ok(json!({"version":digest(text.as_bytes())}))
}

fn create_file(request: &Value) -> Result<Value, String> {
    let path = Path::new(string(request, "path")?);
    let text = string(request, "text")?;
    if text.contains('\0') {
        return Err("binary files containing NUL are not editable".into());
    }
    if text.len() as u64 > MAX_FILE {
        return Err("file exceeds 64 MiB limit".into());
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(error)?;
    file.write_all(text.as_bytes()).map_err(error)?;
    file.as_file().sync_all().map_err(error)?;
    file.persist_noclobber(path).map_err(error)?;
    #[cfg(unix)]
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(error)?;
    Ok(json!({"version":digest(text.as_bytes())}))
}
fn rename_exclusive(from: &str, to: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        files::rename_exclusive(Path::new(from), Path::new(to)).map_err(|e| e.message)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let wide = |path: &str| -> Result<Vec<u16>, String> {
            let mut value: Vec<_> = std::ffi::OsStr::new(path).encode_wide().collect();
            if value.contains(&0) {
                return Err("path contains NUL".into());
            }
            value.push(0);
            Ok(value)
        };
        let from = wide(from)?;
        let to = wide(to)?;
        if unsafe {
            windows_sys::Win32::Storage::FileSystem::MoveFileExW(from.as_ptr(), to.as_ptr(), 0)
        } == 0
        {
            return Err(error(std::io::Error::last_os_error()));
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (from, to);
        Err("atomic exclusive rename is unsupported on this platform".into())
    }
}

fn run(command: &mut Command) -> Result<Value, String> {
    run_limited(command, false)
}
fn run_limited(command: &mut Command, truncate: bool) -> Result<Value, String> {
    run_limited_timeout(command, truncate, Duration::from_secs(30))
}
fn run_limited_timeout(
    command: &mut Command,
    truncate: bool,
    timeout: Duration,
) -> Result<Value, String> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(error)?;
    let overflow = Arc::new(AtomicBool::new(false));
    let readers = capture::Readers::start(
        child.stdout.take().unwrap(),
        child.stderr.take().unwrap(),
        overflow.clone(),
    );
    let deadline = Instant::now() + timeout;
    let mut failure = None;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(error)? {
            break status;
        }
        if overflow.load(Ordering::Relaxed) || Instant::now() >= deadline {
            failure = Some(if overflow.load(Ordering::Relaxed) {
                "command output exceeds 4 MiB limit"
            } else {
                "command timed out after its deadline"
            });
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            child.kill().map_err(error)?;
            break child.wait().map_err(error)?;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    while !readers.is_finished() {
        if overflow.load(Ordering::Relaxed) || Instant::now() >= deadline {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            failure = Some(if overflow.load(Ordering::Relaxed) {
                "command output exceeds 4 MiB limit"
            } else {
                "command descendants kept output pipes open past the timeout"
            });
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let (stdout, stderr) = readers.finish()?;
    let truncated = overflow.load(Ordering::Relaxed);
    if let Some(failure) = failure
        && (!truncate || !truncated)
    {
        return Err(failure.into());
    }
    if truncated && !truncate {
        return Err("command output exceeds 4 MiB limit".into());
    }
    Ok(
        json!({"stdout":String::from_utf8_lossy(&stdout),"stderr":String::from_utf8_lossy(&stderr),"status":status.code().unwrap_or(-1),"truncated":truncated}),
    )
}
fn search(request: &Value) -> Result<Value, String> {
    let root = directory(request)?;
    let query = string(request, "query")?;
    if query.is_empty() {
        return Err("query must not be empty".into());
    }
    let mut command = Command::new("rg");
    command.current_dir(&root).args([
        "--json",
        "--fixed-strings",
        "--line-number",
        "--",
        query,
        ".",
    ]);
    let output = run_limited(&mut command, true)
        .map_err(|e| format!("ripgrep search unavailable or failed: {e}"))?;
    let status = output["status"].as_i64().unwrap_or(-1);
    let mut truncated = output["truncated"] == true;
    if status != 0 && status != 1 && !truncated {
        return Err(format!(
            "ripgrep failed: {}",
            output["stderr"].as_str().unwrap_or("")
        ));
    }
    let mut matches = Vec::new();
    for line in output["stdout"]
        .as_str()
        .unwrap_or("")
        .split_inclusive('\n')
    {
        if !line.ends_with('\n') && truncated {
            break;
        }
        let event: Value = serde_json::from_str(line).map_err(error)?;
        if event["type"] != "match" {
            continue;
        }
        if matches.len() == MAX_MATCHES {
            truncated = true;
            break;
        }
        let data = &event["data"];
        let path = data["path"]["text"]
            .as_str()
            .ok_or("search result path is not UTF-8")?;
        matches.push(json!({"path":root.join(path),"line":data["line_number"],"text":data["lines"]["text"].as_str().unwrap_or("").trim_end_matches(['\r','\n'])}));
    }
    Ok(json!({"matches":matches,"truncated":truncated}))
}

#[cfg(unix)]
mod legacy_terminal {
    use super::*;
    use std::{
        fs::OpenOptions,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::process::CommandExt,
        },
        process::Child,
    };
    struct Buffer {
        data: Vec<u8>,
        truncated: bool,
    }
    static PTY_NAMES: Mutex<()> = Mutex::new(());
    pub struct Session {
        master: File,
        child: Child,
        output: Arc<Mutex<Buffer>>,
        stop: Arc<AtomicBool>,
        reader: Option<std::thread::JoinHandle<()>>,
        input: Option<super::terminal_input::InputPump>,
    }
    impl Session {
        pub fn start(root: &Path, shell: &str) -> Result<Self, String> {
            if !Path::new(shell).is_absolute() {
                return Err("shell must be an absolute executable path".into());
            }
            let fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
            if fd < 0 {
                return Err(error(std::io::Error::last_os_error()));
            }
            let master = unsafe { File::from_raw_fd(fd) };
            if unsafe { libc::grantpt(fd) } != 0 || unsafe { libc::unlockpt(fd) } != 0 {
                return Err(error(std::io::Error::last_os_error()));
            }
            let names_lock = PTY_NAMES.lock().map_err(error)?;
            let name = unsafe { libc::ptsname(fd) };
            if name.is_null() {
                return Err(error(std::io::Error::last_os_error()));
            }
            let name = unsafe { std::ffi::CStr::from_ptr(name) }
                .to_str()
                .map_err(error)?
                .to_owned();
            drop(names_lock);
            let slave = OpenOptions::new()
                .read(true)
                .write(true)
                .open(name)
                .map_err(error)?;
            let mut command = Command::new(shell);
            command
                .arg("-i")
                .current_dir(root)
                .env("TERM", "xterm-256color")
                .stdin(slave.try_clone().map_err(error)?)
                .stdout(slave.try_clone().map_err(error)?)
                .stderr(slave);
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let child = command.spawn().map_err(error)?;
            let output = Arc::new(Mutex::new(Buffer {
                data: Vec::new(),
                truncated: false,
            }));
            let input = super::terminal_input::InputPump::new(master.try_clone().map_err(error)?)?;
            let mut reader = master.try_clone().map_err(error)?;
            let sink = output.clone();
            let stop = Arc::new(AtomicBool::new(false));
            let reader_stop = stop.clone();
            let reader_thread = std::thread::spawn(move || {
                let mut bytes = [0; 8192];
                while !reader_stop.load(Ordering::Relaxed) {
                    let mut fd = libc::pollfd {
                        fd: reader.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    if unsafe { libc::poll(&mut fd, 1, 50) } <= 0 {
                        continue;
                    }
                    let n = match reader.read(&mut bytes) {
                        Ok(n) => n,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                || error.kind() == std::io::ErrorKind::Interrupted =>
                        {
                            continue;
                        }
                        Err(_) => break,
                    };
                    if n == 0 {
                        break;
                    }
                    let Ok(mut buffer) = sink.lock() else {
                        break;
                    };
                    let available = MAX_OUTPUT.saturating_sub(buffer.data.len());
                    buffer.data.extend_from_slice(&bytes[..n.min(available)]);
                    if n > available {
                        buffer.truncated = true;
                    }
                }
            });
            let session = Self {
                master,
                child,
                output,
                stop,
                reader: Some(reader_thread),
                input: Some(input),
            };
            session.resize(80, 24)?;
            Ok(session)
        }
        pub fn read(&mut self) -> Result<Value, String> {
            let alive = self.child.try_wait().map_err(error)?.is_none();
            let mut output = self.output.lock().map_err(error)?;
            let count = output.data.len().min(MAX_TERMINAL_READ);
            let data: Vec<u8> = output.data.drain(..count).collect();
            let truncated = std::mem::take(&mut output.truncated);
            let drained = !alive
                && output.data.is_empty()
                && self
                    .reader
                    .as_ref()
                    .is_none_or(|reader| reader.is_finished());
            Ok(
                json!({"output":String::from_utf8_lossy(&data),"bytes":data,"alive":alive,"drained":drained,"truncated":truncated}),
            )
        }
        pub fn write(&mut self, text: &[u8]) -> Result<(), String> {
            self.input
                .as_ref()
                .ok_or("Terminal input closed")?
                .write(text)
        }
        pub fn resize(&self, columns: u16, rows: u16) -> Result<(), String> {
            let size = libc::winsize {
                ws_row: rows,
                ws_col: columns,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            if unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ as _, &size) } < 0 {
                return Err(error(std::io::Error::last_os_error()));
            }
            Ok(())
        }
    }
    impl Drop for Session {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            let foreground = unsafe { libc::tcgetpgrp(self.master.as_raw_fd()) };
            if foreground > 0 {
                unsafe {
                    libc::kill(-foreground, libc::SIGKILL);
                }
            }
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.input.take();
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
        }
    }
}
#[cfg(windows)]
#[path = "terminal_windows.rs"]
mod legacy_terminal;
#[cfg(not(any(unix, windows)))]
mod legacy_terminal {
    use super::*;
    pub struct Session;
    impl Session {
        pub fn start(_: &Path, _: &str) -> Result<Self, String> {
            Err("terminal unsupported: this build requires a ConPTY adapter".into())
        }
        pub fn read(&mut self) -> Result<Value, String> {
            Err("terminal unsupported".into())
        }
        pub fn write(&mut self, _: &[u8]) -> Result<(), String> {
            Err("terminal unsupported".into())
        }
        pub fn resize(&self, _: u16, _: u16) -> Result<(), String> {
            Err("terminal unsupported".into())
        }
    }
}

fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
#[cfg(test)]
mod tests {
    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            super::digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            super::digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

pub mod contracts;
#[cfg(unix)]
mod pty;
#[cfg(unix)]
pub use pty::Pty;
#[cfg(unix)]
pub mod files;
#[cfg(unix)]
pub mod operations;
#[cfg(unix)]
pub mod recovery;

#[cfg(unix)]
pub mod leases;

#[cfg(unix)]
pub mod connections;
#[cfg(unix)]
pub mod workspaces;

#[cfg(unix)]
pub mod search;

#[cfg(unix)]
pub mod preferences;
#[cfg(unix)]
pub mod terminal;

#[cfg(unix)]
pub mod git;
