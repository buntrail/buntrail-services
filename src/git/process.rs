use crate::files::io_error;
use buntrail_core::contracts::*;
use std::{
    ffi::OsString,
    io::Read,
    os::unix::{io::AsRawFd, process::CommandExt},
    path::Path,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
pub const DEADLINE: Duration = Duration::from_secs(120);
const OUTPUT_LIMIT: usize = 512 * 1024;
pub struct Output {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub interrupted: bool,
}
impl Output {
    pub fn diagnostic(&self) -> String {
        let bytes = if self.stderr.is_empty() {
            &self.stdout
        } else {
            &self.stderr
        };
        let mut message =
            String::from_utf8_lossy(&bytes[..bytes.len().min(16 * 1024)]).into_owned();
        if bytes.len() > 16 * 1024 {
            message.push_str("\n[Git diagnostic truncated]");
        }
        if message.is_empty() {
            message.push_str("Git command failed without a diagnostic");
        }
        message
    }
    pub fn checked(self) -> Result<Vec<u8>, CoreError> {
        if self.success {
            Ok(self.stdout)
        } else {
            Err(CoreError::new(
                if self.interrupted {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::Io
                },
                &self.diagnostic(),
            ))
        }
    }
}
pub fn run(root: &Path, args: &[OsString], cancel: &AtomicBool) -> Result<Output, CoreError> {
    run_with_limits(root, args, cancel, DEADLINE, OUTPUT_LIMIT)
}
pub(super) fn run_with_limits(
    root: &Path,
    args: &[OsString],
    cancel: &AtomicBool,
    deadline: Duration,
    limit: usize,
) -> Result<Output, CoreError> {
    if cancel.load(Ordering::SeqCst) {
        return Err(CoreError::new(
            ErrorCode::Cancelled,
            "Git cancelled before launch",
        ));
    }
    let mut command = Command::new("git");
    command
        .arg("--literal-pathspecs")
        .arg("-C")
        .arg(root)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("GIT_TERMINAL_PROMPT", "0")
        .process_group(0);
    for key in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ] {
        command.env_remove(key);
    }
    command.env("GIT_OPTIONAL_LOCKS", "0");
    super::authentication::apply(&mut command);
    let mut child = command.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CoreError::new(
                ErrorCode::Unavailable,
                "Installed Git is unavailable on this target",
            )
        } else {
            io_error(e)
        }
    })?;
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    for fd in [out.as_raw_fd(), err.as_raw_fd()] {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
                let _ = child.wait();
                return Err(io_error(std::io::Error::last_os_error()));
            }
        }
    }
    let start = Instant::now();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut interrupted = false;
    let mut exit = None;
    let mut eof = [false, false];
    loop {
        for (i, (reader, bytes)) in [
            (&mut out as &mut dyn Read, &mut stdout),
            (&mut err as &mut dyn Read, &mut stderr),
        ]
        .into_iter()
        .enumerate()
        {
            let mut buffer = [0; 8192];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => {
                        eof[i] = true;
                        break;
                    }
                    Ok(n) => {
                        if bytes.len() + n > limit {
                            interrupted = true;
                            break;
                        }
                        bytes.extend_from_slice(&buffer[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        interrupted = true;
                        break;
                    }
                }
            }
        }
        if cancel.load(Ordering::SeqCst) || start.elapsed() >= deadline {
            interrupted = true;
        }
        if interrupted {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
            stderr.extend_from_slice(b"\nGit cancelled, timed out, or exceeded bounded output; inspect outcome before terminal handoff");
            return Ok(Output {
                success: false,
                stdout,
                stderr,
                interrupted: true,
            });
        }
        if exit.is_none() {
            exit = child.try_wait().map_err(io_error)?;
        }
        if let Some(status) = exit
            && eof[0]
            && eof[1]
        {
            return Ok(Output {
                success: status.success(),
                stdout,
                stderr,
                interrupted: false,
            });
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
pub fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deadline_and_output_limit_kill_and_report_incomplete() {
        let d = tempfile::tempdir().unwrap();
        let output = run_with_limits(
            d.path(),
            &args(&["-c", "alias.pause=!sleep 5", "pause"]),
            &AtomicBool::new(false),
            Duration::from_millis(30),
            1024,
        )
        .unwrap();
        assert!(output.interrupted);
        assert!(!output.success);
        let output = run_with_limits(
            d.path(),
            &args(&["--version"]),
            &AtomicBool::new(false),
            Duration::from_secs(1),
            2,
        )
        .unwrap();
        assert!(output.interrupted);
        assert!(!output.success);
        assert!(output.stdout.is_empty());
    }
}
