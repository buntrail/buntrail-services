mod local_pty;
mod output_buffer;
mod process_owner;
use crate::{
    contracts::*,
    files::{LocalFileService, digest, failure, io_error, path},
    operations::ledger::{Record, now, unknown},
};
use buntrail_core::contracts::{
    async_types::{EventStream, ServiceFuture},
    *,
};
use futures_core::Stream;
pub use local_pty::LocalTerminalService;
use output_buffer::OutputBuffer;
use process_owner::PTYProcessOwner;
use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};
pub(crate) type RegisteredLeases = Arc<Mutex<HashMap<WorkspaceLeaseID, WorkspaceLease>>>;
#[cfg(test)]
fn fixture_target() -> TargetIdentity {
    TargetIdentity {
        security_binding: vec![1],
        effective_user: vec![2],
        filesystem_namespace: vec![3],
        container: None,
    }
}
struct Session {
    _runtime_guard: Arc<crate::connections::runtime_liveness::RuntimeGuard>,
    request: TerminalOpenRequest,
    state: Mutex<State>,
    stop: AtomicBool,
    worker_active: AtomicBool,
}
// Dropped only after the worker's PTY owner (including its blocking cleanup).
struct WorkerLifetime(Arc<Session>);
impl Drop for WorkerLifetime {
    fn drop(&mut self) {
        self.0.worker_active.store(false, Ordering::SeqCst);
        let mut state = self.0.state.lock().unwrap();
        if let Some(w) = state.waker.take() {
            w.wake();
        }
        for w in state.end_wakers.drain(..) {
            w.wake();
        }
    }
}
struct State {
    started: bool,
    output: OutputBuffer,
    input: VecDeque<Vec<u8>>,
    input_bytes: usize,
    resize: Option<TerminalSize>,
    delivered_size: TerminalSize,
    exit: Option<Result<Option<i32>, CoreError>>,
    end_intent: Option<TerminalEndIntent>,
    error: Option<CoreError>,
    generation: u64,
    waker: Option<Waker>,
    end_wakers: Vec<Waker>,
}
impl Session {
    fn output(&self, bytes: &[u8]) {
        let mut s = self.state.lock().unwrap();
        s.output.push(bytes);
        if let Some(w) = s.waker.take() {
            w.wake();
        }
    }
    fn error(&self, e: CoreError) {
        let mut s = self.state.lock().unwrap();
        s.error = Some(e);
        if let Some(w) = s.waker.take() {
            w.wake();
        }
    }
    fn finish(&self, e: Result<Option<i32>, CoreError>) {
        let mut s = self.state.lock().unwrap();
        s.exit = Some(e);
        s.input.clear();
        s.input_bytes = 0;
        if let Some(w) = s.waker.take() {
            w.wake();
        }
        for w in s.end_wakers.drain(..) {
            w.wake();
        }
    }
}
struct Attachment {
    session: Arc<Session>,
    cursor: u64,
    generation: u64,
    finished: bool,
    reattached: bool,
}
impl Stream for Attachment {
    type Item = Result<TerminalEvent, CoreError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.finished {
            return Poll::Ready(None);
        }
        let session = self.session.clone();
        let mut state = session.state.lock().unwrap();
        if state.generation != self.generation {
            return Poll::Ready(None);
        }
        if !self.reattached {
            self.reattached = true;
            return Poll::Ready(Some(Ok(TerminalEvent::Reattached)));
        }
        if let Some(e) = state.output.after(&mut self.cursor) {
            return Poll::Ready(Some(Ok(e)));
        }
        if let Some(e) = state.error.take() {
            return Poll::Ready(Some(Err(e)));
        }
        if let Some(e) = &state.exit {
            if state.end_intent.is_some() && session.worker_active.load(Ordering::SeqCst) {
                state.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            self.finished = true;
            return Poll::Ready(Some(e.clone().map(|code| match state.end_intent {
                Some(TerminalEndIntent::RetentionExpiry) => TerminalEvent::Expired,
                Some(intent) => TerminalEvent::Ended { intent },
                None => TerminalEvent::ProcessExit { code },
            })));
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}
impl Drop for Attachment {
    fn drop(&mut self) {
        let mut s = self.session.state.lock().unwrap();
        if s.generation == self.generation {
            s.waker = None;
        }
    }
}
struct Ended(Arc<Session>);
impl std::future::Future for Ended {
    type Output = Result<(), CoreError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut s = self.0.state.lock().unwrap();
        if !self.0.worker_active.load(Ordering::SeqCst)
            && let Some(e) = &s.exit
        {
            return Poll::Ready(e.clone().map(|_| ()));
        }
        if !s.end_wakers.iter().any(|w| w.will_wake(cx.waker())) {
            if s.end_wakers.len() >= 64 {
                return Poll::Ready(Err(CoreError::new(
                    ErrorCode::Busy,
                    "too many terminal end waiters",
                )));
            }
            s.end_wakers.push(cx.waker().clone());
        }
        Poll::Pending
    }
}
