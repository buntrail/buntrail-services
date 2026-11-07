//! The worker is the only owner of the PTY/Child and the only thread allowed to wait.
use super::*;
use std::{
    io::{Read, Write},
    os::fd::AsRawFd,
    time::{Duration, Instant},
};
#[cfg(test)]
pub(super) type WorkerGate = (
    std::sync::mpsc::SyncSender<()>,
    std::sync::mpsc::Receiver<()>,
);

pub(super) struct LaunchFailure {
    pub error: CoreError,
    pub may_have_started: bool,
}
impl From<CoreError> for LaunchFailure {
    fn from(error: CoreError) -> Self {
        Self {
            error,
            may_have_started: false,
        }
    }
}
impl LaunchFailure {
    pub fn uncertain(error: CoreError) -> Self {
        Self {
            error,
            may_have_started: true,
        }
    }
    pub fn receipt(self, id: OperationID, target: TargetIdentity) -> OperationReceipt {
        if self.may_have_started {
            unknown(
                id,
                target,
                "PTY startup acknowledgement lost after possible execution; inspect, never replay",
            )
        } else {
            failure(id, target, self.error)
        }
    }
}
pub(super) struct PTYProcessOwner {
    pty: crate::Pty,
}
impl PTYProcessOwner {
    pub fn launch(
        request: &TerminalOpenRequest,
        authentication: Option<Option<std::ffi::OsString>>,
    ) -> Result<Self, LaunchFailure> {
        let pty = crate::Pty::spawn_in_with_authentication(
            &path(&request.shell)?,
            &[],
            Some(&path(&request.directory)?),
            request.size.rows.get(),
            request.size.columns.get(),
            authentication,
        )
        .map_err(io_error)?;
        let owner = Self { pty };
        let fd = owner.pty.master_fd();
        if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            return Err(LaunchFailure::uncertain(io_error(
                std::io::Error::last_os_error(),
            )));
        }
        Ok(owner)
    }
    fn stop_descendants(&self) {
        terminate_descendants(self.pty.process_id() as i32);
        let foreground = unsafe { libc::tcgetpgrp(self.pty.master_fd()) };
        if foreground > 0 && foreground != self.pty.process_id() as i32 {
            unsafe {
                libc::kill(-foreground, libc::SIGKILL);
            }
        }
    }
    pub fn run(
        mut self,
        session: Arc<Session>,
        #[cfg(test)] mut first_turn_gate: Option<WorkerGate>,
        #[cfg(test)] mut first_write_gate: Option<WorkerGate>,
    ) {
        let mut reader = match self.pty.reader() {
            Ok(r) => r,
            Err(e) => {
                session.finish(Err(io_error(e)));
                return;
            }
        };
        let mut pending = Vec::new();
        let mut offset = 0;
        let mut status = None;
        let mut eof = false;
        let mut stopping = None;
        let mut bytes = [0; output_buffer::CHUNK_BYTES];
        loop {
            if session.stop.load(Ordering::SeqCst) && stopping.is_none() {
                // Stop foreground/background descendants before the shell so it can reap them.
                self.stop_descendants();
                stopping = Some(Instant::now());
            }
            if stopping.is_some_and(|t| t.elapsed() > Duration::from_millis(100))
                && status.is_none()
            {
                let _ = self.pty.stop();
            }
            let resize = {
                let mut state = session.state.lock().unwrap();
                let resize = state.resize.take();
                if pending.is_empty() && status.is_none() {
                    pending = state.input.pop_front().unwrap_or_default();
                    // The queue budget includes this worker's in-flight write until fully written.
                }
                resize
            };
            #[cfg(test)]
            if let Some((entered, resume)) = first_turn_gate.take() {
                let _ = entered.try_send(());
                let _ = resume.recv_timeout(Duration::from_secs(5));
            }
            if let Some(size) = resize {
                match self.pty.resize(size.rows.get(), size.columns.get()) {
                    Ok(()) => session.state.lock().unwrap().delivered_size = size,
                    Err(e) => session.error(io_error(e)),
                }
            }
            if offset < pending.len() && status.is_none() && stopping.is_none() {
                match self.pty.write(&pending[offset..]) {
                    Ok(n) => offset += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        session.error(io_error(e));
                        offset = pending.len();
                    }
                }
            }
            if offset == pending.len() && !pending.is_empty() {
                #[cfg(test)]
                if let Some((entered, resume)) = first_write_gate.take() {
                    let _ = entered.try_send(());
                    let _ = resume.recv_timeout(Duration::from_secs(5));
                }
                session.state.lock().unwrap().input_bytes -= pending.len();
                pending.clear();
                offset = 0;
            }
            // At most 64 KiB per turn: flood cannot starve input, resize or explicit end.
            for _ in 0..8 {
                match reader.read(&mut bytes) {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(n) => session.output(&bytes[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.raw_os_error() == Some(libc::EIO) => {
                        eof = true;
                        break;
                    }
                    Err(e) => {
                        session.error(io_error(e));
                        eof = true;
                        break;
                    }
                }
            }
            if status.is_none() {
                match self.pty.try_wait() {
                    Ok(Some(s)) => status = Some(s),
                    Ok(None) => {}
                    Err(e) => {
                        session.finish(Err(io_error(e)));
                        return;
                    }
                }
            }
            if let Some(status) = status
                && (eof || stopping.is_some())
            {
                session.finish(Ok(status.code()));
                return;
            }
            let mut poll = libc::pollfd {
                fd: reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            unsafe {
                libc::poll(&mut poll, 1, 10);
            }
        }
    }
}
impl Drop for PTYProcessOwner {
    fn drop(&mut self) {
        if self.pty.try_wait().is_ok_and(|s| s.is_none()) {
            self.stop_descendants();
            // Also cover startup/reader failure before the worker run loop owns cleanup.
            std::thread::sleep(Duration::from_millis(100));
            let _ = self.pty.stop();
        }
    }
}
#[cfg(target_os = "macos")]
fn children(parent: i32) -> Vec<i32> {
    // PROC_PPID_ONLY, libproc public API. A fixed buffer keeps cleanup allocation bounded.
    let mut pids = vec![0i32; 4096];
    let n = unsafe {
        libc::proc_listpids(
            6,
            parent as u32,
            pids.as_mut_ptr().cast(),
            (pids.len() * 4) as i32,
        )
    };
    pids.truncate(n.max(0) as usize / 4);
    pids.retain(|p| *p > 0);
    pids
}
#[cfg(not(target_os = "macos"))]
fn children(parent: i32) -> Vec<i32> {
    std::fs::read_to_string(format!("/proc/{parent}/task/{parent}/children"))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .take(4096)
        .collect()
}
fn terminate_descendants(parent: i32) {
    let mut pending = children(parent);
    let mut all = Vec::new();
    while let Some(pid) = pending.pop() {
        if all.len() >= 4096 {
            break;
        }
        pending.extend(children(pid));
        all.push(pid);
    }
    for pid in all.into_iter().rev() {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_failure_proof_distinguishes_failed_exec_from_lost_worker_acknowledgement() {
        let target = fixture_target();
        let id = OperationID([1; 16]);
        let error = CoreError::new(ErrorCode::Io, "startup failure");
        assert!(matches!(
            LaunchFailure::from(error.clone())
                .receipt(id, target.clone())
                .state,
            OperationState::Failed(OperationFailure {
                effect: FailureEffect::ProvenNoEffect,
                ..
            })
        ));
        assert!(matches!(
            LaunchFailure::uncertain(error).receipt(id, target).state,
            OperationState::Unknown(_)
        ));
    }
}
