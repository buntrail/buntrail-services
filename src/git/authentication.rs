//! Per-command connection credentials; never mutates the process environment or existing PTYs.
use std::{cell::RefCell, ffi::OsString, process::Command};
thread_local! {static SOCKET:RefCell<Option<Option<OsString>>>=const{RefCell::new(None)};}
pub fn with_authentication<T>(socket: Option<OsString>, run: impl FnOnce() -> T) -> T {
    struct Restore(Option<Option<OsString>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            SOCKET.with(|s| {
                s.replace(self.0.take());
            });
        }
    }
    let _restore = Restore(SOCKET.with(|s| s.replace(Some(socket))));
    run()
}
pub(super) fn apply(command: &mut Command) {
    SOCKET.with(|s| {
        if let Some(socket) = &*s.borrow() {
            command.env_remove("SSH_AUTH_SOCK");
            if let Some(socket) = socket {
                command.env("SSH_AUTH_SOCK", socket);
            }
        }
    });
}
