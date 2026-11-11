use super::process_owner::LaunchFailure;
use super::*;
#[cfg(test)]
thread_local! { static STARTUP_FAULT: std::cell::RefCell<Option<(std::path::PathBuf,bool)>>=const{std::cell::RefCell::new(None)}; }
#[cfg(test)]
thread_local! {
    static FIRST_TURN_GATE: std::cell::RefCell<Option<super::process_owner::WorkerGate>>=const{std::cell::RefCell::new(None)};
    static FIRST_WRITE_GATE: std::cell::RefCell<Option<super::process_owner::WorkerGate>>=const{std::cell::RefCell::new(None)};
}
/// Local lifetime is the application session. The worker owns each child; views own cursors only.
pub struct LocalTerminalService {
    files: Arc<LocalFileService>,
    runtime_guard: Arc<crate::connections::runtime_liveness::RuntimeGuard>,
    runtime: RuntimeGeneration,
    leases: RegisteredLeases,
    sessions: Mutex<HashMap<TerminalSessionID, Arc<Session>>>,
    closed: AtomicBool,
    retained: Mutex<Vec<std::sync::Weak<Session>>>,
}
impl LocalTerminalService {
    pub(crate) fn new(
        files: Arc<LocalFileService>,
        runtime: RuntimeGeneration,
        leases: RegisteredLeases,
        runtime_guard: Arc<crate::connections::runtime_liveness::RuntimeGuard>,
    ) -> Self {
        Self {
            files,
            runtime_guard,
            runtime,
            leases,
            sessions: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
            retained: Mutex::new(Vec::new()),
        }
    }
    /// Creates a real supervisor runtime guard; the caller owns the lifetime and registered leases.
    pub fn for_supervisor(
        files: Arc<LocalFileService>,
        runtime: RuntimeGeneration,
        directory: &std::path::Path,
    ) -> Result<Self, CoreError> {
        let guard = Arc::new(crate::connections::runtime_liveness::RuntimeGuard::create(
            directory, &runtime,
        )?);
        Ok(Self::new(
            files,
            runtime,
            Arc::new(Mutex::new(HashMap::new())),
            guard,
        ))
    }
    pub fn register_owner(&self, owner: WorkspaceLease) -> Result<(), CoreError> {
        if owner.runtime != self.runtime {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "terminal runtime changed",
            ));
        }
        let mut leases = self.leases.lock().map_err(io_error)?;
        if leases.get(&owner.lease).is_some_and(|old| old != &owner) {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "terminal lease changed owner",
            ));
        }
        if leases.len() >= 256 && !leases.contains_key(&owner.lease) {
            return Err(CoreError::new(
                ErrorCode::Busy,
                "terminal lease capacity reached",
            ));
        }
        leases.insert(owner.lease, owner);
        Ok(())
    }
    pub fn revoke_owner(&self, lease: WorkspaceLeaseID, intent: TerminalEndIntent) {
        self.leases.lock().unwrap().remove(&lease);
        self.stop_owner(lease, intent);
    }
    pub fn verify_session(
        &self,
        id: TerminalSessionID,
        owner: &WorkspaceLease,
    ) -> Result<(), CoreError> {
        self.owner(owner, &owner.runtime)?;
        if self.session(id)?.request.owner != *owner {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "terminal belongs to another owner",
            ));
        }
        Ok(())
    }
    pub fn has_sessions(&self) -> bool {
        !self.sessions.lock().unwrap().is_empty() || !self.shutdown_ready()
    }
    pub fn end_sync(
        &self,
        id: TerminalSessionID,
        intent: TerminalEndIntent,
    ) -> Result<(), CoreError> {
        let session = self.session(id)?;
        {
            let mut state = session.state.lock().map_err(io_error)?;
            if state.exit.is_none() {
                state.end_intent = Some(intent);
            }
        }
        session.stop.store(true, Ordering::SeqCst);
        while session.worker_active.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let result = session
            .state
            .lock()
            .map_err(io_error)?
            .exit
            .clone()
            .ok_or_else(|| CoreError::new(ErrorCode::Io, "terminal cleanup incomplete"))?;
        self.sessions.lock().map_err(io_error)?.remove(&id);
        result.map(|_| ())
    }
    fn owner(&self, owner: &WorkspaceLease, runtime: &RuntimeGeneration) -> Result<(), CoreError> {
        if runtime != &self.runtime || &owner.runtime != runtime {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "terminal runtime changed",
            ));
        }
        if self.leases.lock().map_err(io_error)?.get(&owner.lease) != Some(owner) {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "terminal owner is not registered",
            ));
        }
        Ok(())
    }
    fn session(&self, id: TerminalSessionID) -> Result<Arc<Session>, CoreError> {
        self.sessions
            .lock()
            .map_err(io_error)?
            .get(&id)
            .cloned()
            .ok_or_else(|| CoreError::new(ErrorCode::Unavailable, "terminal session not found"))
    }
    pub fn open_sync(&self, request: TerminalOpenRequest) -> OperationReceipt {
        self.open_environment(request, None)
    }
    pub fn open_authenticated(
        &self,
        request: TerminalOpenRequest,
        authentication: Option<std::ffi::OsString>,
    ) -> OperationReceipt {
        self.open_environment(request, Some(authentication))
    }
    fn open_environment(
        &self,
        request: TerminalOpenRequest,
        authentication: Option<Option<std::ffi::OsString>>,
    ) -> OperationReceipt {
        let id = request.operation;
        let target = request.target.clone();
        let result = (|| {
            self.owner(&request.owner, &request.runtime)?;
            if target != *self.files.target() {
                return Err(CoreError::new(
                    ErrorCode::TargetChanged,
                    "terminal target changed",
                ));
            }
            let serialized = serde_json::to_vec(&request).map_err(io_error)?;
            if serialized.len() > 64 * 1024 {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "terminal request too large",
                ));
            }
            let hash = digest(&serialized);
            if self.closed.load(Ordering::SeqCst) {
                return Err(CoreError::new(ErrorCode::Closed, "terminal service closed"));
            }
            let ledger = self.files.ledger.lock().map_err(io_error)?;
            let _lock = ledger.lock()?;
            if let Some(old) = ledger.read(id)? {
                if old.envelope.request_digest != hash || old.envelope.target != target {
                    return Err(CoreError::new(
                        ErrorCode::InvalidArgument,
                        "launch ID has different request",
                    ));
                }
                return ledger.inspect(id, target.clone());
            }
            let mut sessions = self.sessions.lock().map_err(io_error)?;
            if self.closed.load(Ordering::SeqCst) {
                return Err(CoreError::new(ErrorCode::Closed, "terminal service closed"));
            }
            self.owner(&request.owner, &request.runtime)?;
            if sessions.contains_key(&request.session) {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "session ID already used",
                ));
            }
            // Eight 8 MiB replay stores enforce the 64 MiB environment replay ceiling.
            let mut retained = self.retained.lock().map_err(io_error)?;
            retained.retain(|s| s.strong_count() > 0);
            if retained.len() >= 8 {
                return Err(CoreError::new(
                    ErrorCode::Busy,
                    "local terminal session capacity reached",
                ));
            }
            let mut record = Record {
                envelope: OperationEnvelope {
                    id,
                    target: target.clone(),
                    request_digest: hash,
                    kind: MutationKind::TerminalOpen,
                    expected: ExpectedState::Runtime(request.runtime.clone()),
                },
                destination: None,
                save_proof: None,
                terminal_request: Some(request.clone()),
                git_intent: None,
                file_destination: None,
                requested_digest: hash,
                revision: BufferRevision(0),
                receipt: OperationReceipt {
                    id,
                    state: OperationState::Accepted,
                },
                created: now(),
            };
            let session = Arc::new(Session {
                request: request.clone(),
                _runtime_guard: self.runtime_guard.clone(),
                stop: AtomicBool::new(false),
                worker_active: AtomicBool::new(false),
                state: Mutex::new(State {
                    started: false,
                    output: Default::default(),
                    input: VecDeque::new(),
                    input_bytes: 0,
                    resize: None,
                    delivered_size: request.size,
                    exit: None,
                    end_intent: None,
                    error: None,
                    generation: 0,
                    waker: None,
                    end_wakers: Vec::new(),
                }),
            });
            retained.push(Arc::downgrade(&session));
            drop(retained);
            sessions.insert(request.session, session.clone());
            drop(sessions);
            match ledger.accept(&record, &_lock) {
                Ok(None) => {}
                Ok(Some(existing)) => {
                    self.sessions
                        .lock()
                        .map_err(io_error)?
                        .remove(&request.session);
                    return Ok(existing);
                }
                Err(e) => {
                    self.sessions
                        .lock()
                        .map_err(io_error)?
                        .remove(&request.session);
                    session.finish(Err(e.clone()));
                    return Err(e);
                }
            }
            let work = session.clone();
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            session.worker_active.store(true, Ordering::SeqCst);
            #[cfg(test)]
            let fault = STARTUP_FAULT.with(|f| f.borrow_mut().take());
            #[cfg(test)]
            let first_turn_gate = FIRST_TURN_GATE.with(|g| g.borrow_mut().take());
            #[cfg(test)]
            let first_write_gate = FIRST_WRITE_GATE.with(|g| g.borrow_mut().take());
            let launch = std::thread::Builder::new()
                .name("buntrail-pty-owner".into())
                .spawn(move || {
                    let _lifetime = WorkerLifetime(work.clone());
                    let launch = if work.stop.load(Ordering::SeqCst) {
                        Err(CoreError::new(
                            ErrorCode::Closed,
                            "workspace closed before terminal launch",
                        )
                        .into())
                    } else {
                        PTYProcessOwner::launch(&work.request, authentication)
                    };
                    match launch {
                        Ok(owner) => {
                            #[cfg(test)]
                            if let Some((marker, lose_ack)) = fault {
                                let until =
                                    std::time::Instant::now() + std::time::Duration::from_secs(3);
                                while !std::fs::read(&marker).is_ok_and(|b| !b.is_empty()) {
                                    assert!(
                                        std::time::Instant::now() < until,
                                        "fault fixture child did not execute"
                                    );
                                    std::thread::sleep(std::time::Duration::from_millis(2));
                                }
                                if !lose_ack {
                                    let error = LaunchFailure::uncertain(CoreError::new(
                                        ErrorCode::Io,
                                        "injected post-spawn setup failure",
                                    ));
                                    work.finish(Err(error.error.clone()));
                                    let _ = tx.send(Err(error));
                                }
                                return;
                            }
                            work.state.lock().unwrap().started = true;
                            let _ = tx.send(Ok(()));
                            owner.run(
                                work,
                                #[cfg(test)]
                                first_turn_gate,
                                #[cfg(test)]
                                first_write_gate,
                            )
                        }
                        Err(e) => {
                            work.finish(Err(e.error.clone()));
                            let _ = tx.send(Err(e));
                        }
                    }
                })
                .map_err(|e| {
                    session.worker_active.store(false, Ordering::SeqCst);
                    LaunchFailure::from(io_error(e))
                })
                .and_then(|_| {
                    rx.recv()
                        .map_err(|e| LaunchFailure::uncertain(io_error(e)))?
                });
            match launch {
                Ok(()) => {
                    record.receipt = OperationReceipt {
                        id,
                        state: OperationState::Confirmed(MutationResult::TerminalOpened {
                            session: request.session,
                            runtime: request.runtime,
                        }),
                    };
                }
                Err(e) => {
                    self.sessions
                        .lock()
                        .map_err(io_error)?
                        .remove(&request.session);
                    session.finish(Err(e.error.clone()));
                    record.receipt = e.receipt(id, target.clone())
                }
            }
            if ledger.write(&record).is_err() {
                return Ok(unknown(
                    id,
                    target.clone(),
                    "launch outcome could not be recorded; inspect, never replay",
                ));
            }
            Ok(record.receipt)
        })();
        result.unwrap_or_else(|e| failure(id, target, e))
    }
    pub fn input_sync(&self, id: TerminalSessionID, bytes: Vec<u8>) -> Result<(), CoreError> {
        let session = self.session(id)?;
        let mut s = session.state.lock().map_err(io_error)?;
        if !s.started || s.exit.is_some() || session.stop.load(Ordering::SeqCst) {
            return Err(CoreError::new(
                ErrorCode::Closed,
                "terminal exited; input not replayed",
            ));
        }
        if bytes.len() > 65536 || s.input_bytes + bytes.len() > 65536 || s.input.len() >= 16 {
            return Err(CoreError::new(
                ErrorCode::Busy,
                "terminal input budget reached; input not replayed",
            ));
        }
        s.input_bytes += bytes.len();
        s.input.push_back(bytes);
        Ok(())
    }
    pub fn resize_sync(&self, id: TerminalSessionID, size: TerminalSize) -> Result<(), CoreError> {
        let session = self.session(id)?;
        let mut s = session.state.lock().map_err(io_error)?;
        if s.exit.is_some() {
            return Err(CoreError::new(ErrorCode::Closed, "terminal exited"));
        }
        s.resize = Some(size);
        Ok(())
    }
    pub fn delivered_size(&self, id: TerminalSessionID) -> Result<TerminalSize, CoreError> {
        Ok(self
            .session(id)?
            .state
            .lock()
            .map_err(io_error)?
            .delivered_size)
    }
    pub fn end_owner(&self, lease: WorkspaceLeaseID) {
        self.stop_owner(lease, TerminalEndIntent::FinalWorkspaceClose);
    }
    fn stop_owner(&self, lease: WorkspaceLeaseID, intent: TerminalEndIntent) {
        self.sessions.lock().unwrap().retain(|_, s| {
            if s.request.owner.lease == lease {
                {
                    let mut state = s.state.lock().unwrap();
                    if state.exit.is_none() {
                        state.end_intent = Some(intent);
                    }
                }
                s.stop.store(true, Ordering::SeqCst);
                // The resolved lease can no longer attach. Workers/cursors retain
                // their own stores until cleanup; the weak registry still counts them.
                false
            } else {
                true
            }
        });
    }
    pub fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // Serialize with reservation admission. Retired owners already have stop
        // set; their workers are still included by shutdown_ready's weak registry.
        for s in self.sessions.lock().unwrap().values() {
            s.stop.store(true, Ordering::SeqCst);
        }
    }
    /// Includes removed sessions retained by startup, process workers or output consumers.
    pub fn observe_owner_retirement(&self, owner: &WorkspaceLease) -> Result<bool, CoreError> {
        if owner.runtime != self.runtime {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "terminal runtime changed",
            ));
        }
        if self
            .leases
            .lock()
            .map_err(io_error)?
            .get(&owner.lease)
            .is_some_and(|known| known != owner)
        {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "terminal lease owner mismatch",
            ));
        }
        let retained = self.retained.lock().map_err(io_error)?;
        let mut retired = true;
        for session in retained
            .iter()
            .filter_map(|s| s.upgrade())
            .filter(|s| s.request.owner.lease == owner.lease)
        {
            if &session.request.owner != owner {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "retained worker owner mismatch",
                ));
            }
            retired &= session.state.lock().map_err(io_error)?.exit.is_some()
                && !session.worker_active.load(Ordering::SeqCst);
        }
        Ok(retired)
    }
    pub fn owner_shutdown_ready(&self, lease: WorkspaceLeaseID) -> bool {
        self.retained
            .lock()
            .unwrap()
            .iter()
            .filter_map(|s| s.upgrade())
            .filter(|s| s.request.owner.lease == lease)
            .all(|s| {
                s.state.lock().unwrap().exit.is_some() && !s.worker_active.load(Ordering::SeqCst)
            })
    }
    pub fn shutdown_ready(&self) -> bool {
        self.retained
            .lock()
            .unwrap()
            .iter()
            .filter_map(|s| s.upgrade())
            .all(|s| {
                s.state.lock().unwrap().exit.is_some() && !s.worker_active.load(Ordering::SeqCst)
            })
    }
}
impl Drop for LocalTerminalService {
    fn drop(&mut self) {
        self.shutdown();
    }
}
impl TerminalService for LocalTerminalService {
    fn open(&self, r: TerminalOpenRequest) -> ServiceFuture<'_, OperationReceipt> {
        Box::pin(async move { self.open_sync(r) })
    }
    fn attach(
        &self,
        r: TerminalAttachRequest,
    ) -> ServiceFuture<'_, Result<EventStream<TerminalEvent>, CoreError>> {
        Box::pin(async move {
            self.owner(&r.owner, &r.runtime)?;
            let session = self.session(r.session)?;
            if session.request.owner != r.owner {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "terminal belongs to another owner",
                ));
            }
            let mut s = session.state.lock().map_err(io_error)?;
            if r.last_output_sequence > s.output.sequence {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "terminal cursor is ahead of output",
                ));
            }
            s.generation += 1;
            if let Some(w) = s.waker.take() {
                w.wake();
            }
            let generation = s.generation;
            drop(s);
            Ok(Box::pin(Attachment {
                session,
                cursor: r.last_output_sequence,
                generation,
                finished: false,
                reattached: false,
            }) as EventStream<TerminalEvent>)
        })
    }
    fn input(&self, id: TerminalSessionID, b: Vec<u8>) -> ServiceFuture<'_, Result<(), CoreError>> {
        Box::pin(async move { self.input_sync(id, b) })
    }
    fn resize(
        &self,
        id: TerminalSessionID,
        size: TerminalSize,
    ) -> ServiceFuture<'_, Result<(), CoreError>> {
        Box::pin(async move { self.resize_sync(id, size) })
    }
    fn end(
        &self,
        id: TerminalSessionID,
        intent: TerminalEndIntent,
    ) -> ServiceFuture<'_, Result<(), CoreError>> {
        Box::pin(async move {
            let s = self.session(id)?;
            {
                let mut state = s.state.lock().map_err(io_error)?;
                if state.exit.is_none() {
                    state.end_intent = Some(intent);
                }
            }
            s.stop.store(true, Ordering::SeqCst);
            Ended(s).await?;
            self.sessions.lock().map_err(io_error)?.remove(&id);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };
    #[test]
    fn resize_admitted_before_input_reaches_pty_before_that_input() {
        let dir = tempfile::tempdir().unwrap();
        let target = fixture_target();
        let files =
            Arc::new(LocalFileService::new(target.clone(), dir.path().join("files")).unwrap());
        let runtime = RuntimeGeneration {
            supervisor_boot: crate::connections::local::new_id().unwrap(),
            container_start: None,
        };
        let service = LocalTerminalService::for_supervisor(
            files,
            runtime.clone(),
            &dir.path().join("runtime"),
        )
        .unwrap();
        let owner = WorkspaceLease {
            client: ClientID([1; 16]),
            workspace: WorkspaceID([2; 16]),
            lease: WorkspaceLeaseID([3; 16]),
            runtime: runtime.clone(),
        };
        service.register_owner(owner.clone()).unwrap();
        let shell = dir.path().join("shell");
        std::fs::write(
            &shell,
            b"#!/bin/sh\n/bin/stty -echo\nprintf '%s\\n' \"$$\" > ready\nIFS= read -r go\n/bin/stty size > observed\n/bin/cat observed\nIFS= read -r end\n",
        )
        .unwrap();
        std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o700)).unwrap();
        let request = TerminalOpenRequest {
            operation: OperationID([4; 16]),
            session: TerminalSessionID([5; 16]),
            owner,
            target,
            runtime,
            directory: TargetPath::posix(dir.path().as_os_str().as_encoded_bytes().to_vec())
                .unwrap(),
            shell: TargetPath::posix(shell.as_os_str().as_encoded_bytes().to_vec()).unwrap(),
            size: TerminalSize {
                columns: 80.try_into().unwrap(),
                rows: 24.try_into().unwrap(),
            },
        };
        let (entered, entry) = std::sync::mpsc::sync_channel(1);
        let (resume, resumed) = std::sync::mpsc::sync_channel(1);
        let (written, write_entry) = std::sync::mpsc::sync_channel(1);
        let (sampled, sample_resume) = std::sync::mpsc::sync_channel(1);
        FIRST_TURN_GATE.with(|g| g.replace(Some((entered, resumed))));
        FIRST_WRITE_GATE.with(|g| g.replace(Some((written, sample_resume))));
        let receipt = service.open_sync(request.clone());
        let output = (|| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            entry.recv_timeout(Duration::from_secs(5))?;
            let until = Instant::now() + Duration::from_secs(5);
            while !dir.path().join("ready").exists() {
                if Instant::now() >= until {
                    return Err("PTY child did not become ready".into());
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            service.resize_sync(
                request.session,
                TerminalSize {
                    columns: 100.try_into().unwrap(),
                    rows: 40.try_into().unwrap(),
                },
            )?;
            service.input_sync(request.session, b"\n".to_vec())?;
            resume.send(())?;
            write_entry.recv_timeout(Duration::from_secs(5))?;
            let until = Instant::now() + Duration::from_secs(5);
            while !std::fs::read(dir.path().join("observed"))
                .is_ok_and(|bytes| bytes.ends_with(b"\n"))
            {
                if Instant::now() >= until {
                    return Err("PTY child did not sample its size".into());
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            sampled.send(())?;
            let session = service.session(request.session)?;
            let mut cursor = 0;
            let mut output = Vec::new();
            let until = Instant::now() + Duration::from_secs(5);
            while !output.contains(&b'\n') {
                if Instant::now() >= until {
                    return Err(format!("PTY output timed out: {output:?}").into());
                }
                if let Some(TerminalEvent::Output { bytes, .. }) =
                    session.state.lock().unwrap().output.after(&mut cursor)
                {
                    output.extend(bytes);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Ok(output)
        })();
        drop(resume);
        drop(sampled);
        let ended = service.end_sync(request.session, TerminalEndIntent::ExplicitClose);
        let ready = std::fs::read_to_string(dir.path().join("ready"));
        assert!(ended.is_ok(), "{ended:?}");
        assert!(service.shutdown_ready());
        let pid = ready.unwrap().trim().parse::<i32>().unwrap();
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            -1,
            "owned child {pid} not reaped"
        );
        let output = output.unwrap();
        eprintln!(
            "PTY_GRID_OUTPUT={:?}; child={pid}; worker_stopped=true; child_reaped=true",
            String::from_utf8_lossy(&output)
        );
        assert!(
            matches!(receipt.state, OperationState::Confirmed(_)),
            "{receipt:?}"
        );
        let grid = String::from_utf8(output)
            .unwrap()
            .split_whitespace()
            .map(|n| n.parse::<u16>().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(grid, [40, 100]);
    }
    #[test]
    fn executed_child_setup_failure_and_lost_ack_are_unknown_reaped_and_never_relaunched() {
        for lose_ack in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let target = fixture_target();
            let files =
                Arc::new(LocalFileService::new(target.clone(), dir.path().join("files")).unwrap());
            let runtime = RuntimeGeneration {
                supervisor_boot: crate::connections::local::new_id().unwrap(),
                container_start: None,
            };
            let service = LocalTerminalService::for_supervisor(
                files.clone(),
                runtime.clone(),
                &dir.path().join("runtime"),
            )
            .unwrap();
            let owner = WorkspaceLease {
                client: ClientID([1; 16]),
                workspace: WorkspaceID([2; 16]),
                lease: WorkspaceLeaseID([3; 16]),
                runtime: runtime.clone(),
            };
            service.register_owner(owner.clone()).unwrap();
            let shell = dir.path().join("shell");
            let marker = dir.path().join("launches");
            std::fs::write(
                &shell,
                b"#!/bin/sh\nsleep 60 &\necho \"$$ $!\" >> launches\nwait\n",
            )
            .unwrap();
            std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o700)).unwrap();
            let request = TerminalOpenRequest {
                operation: OperationID([4; 16]),
                session: TerminalSessionID([5; 16]),
                owner,
                target: target.clone(),
                runtime,
                directory: TargetPath::posix(dir.path().as_os_str().as_encoded_bytes().to_vec())
                    .unwrap(),
                shell: TargetPath::posix(shell.as_os_str().as_encoded_bytes().to_vec()).unwrap(),
                size: TerminalSize {
                    columns: 80.try_into().unwrap(),
                    rows: 24.try_into().unwrap(),
                },
            };
            STARTUP_FAULT.with(|f| f.replace(Some((marker.clone(), lose_ack))));
            let result = service.open_sync(request.clone());
            let until = Instant::now() + Duration::from_secs(5);
            while !service.shutdown_ready() {
                assert!(
                    Instant::now() < until,
                    "lose_ack={lose_ack}, retained={:?}",
                    service
                        .retained
                        .lock()
                        .unwrap()
                        .iter()
                        .filter_map(|s| s.upgrade())
                        .map(|s| (
                            s.worker_active.load(Ordering::SeqCst),
                            s.state.lock().unwrap().exit.clone()
                        ))
                        .collect::<Vec<_>>()
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            let pids = std::fs::read_to_string(&marker).unwrap();
            let owned = pids
                .split_whitespace()
                .map(|p| p.parse::<i32>().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(owned.len(), 2);
            for pid in owned {
                assert_eq!(
                    unsafe { libc::kill(pid, 0) },
                    -1,
                    "owned descendant {pid} was not reaped"
                );
            }
            assert!(
                matches!(result.state, OperationState::Unknown(_)),
                "{result:?}"
            );
            assert_eq!(
                files.inspect_sync(request.operation, target).unwrap(),
                result
            );
            assert_eq!(service.open_sync(request), result);
            assert_eq!(std::fs::read_to_string(&marker).unwrap(), pids);
        }
    }
}
