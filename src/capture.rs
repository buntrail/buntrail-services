//! Cancellable subprocess pipe readers; inherited writers cannot pin a join forever.
use super::{MAX_OUTPUT, error};
use std::{
    io::{self, Read},
    process::{ChildStderr, ChildStdout},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

trait Pipe: Read + Send + 'static {
    // None means EOF; zero means no bytes currently available.
    fn available(&self) -> io::Result<Option<usize>>;
}
#[cfg(unix)]
impl<T: Read + Send + std::os::fd::AsRawFd + 'static> Pipe for T {
    fn available(&self) -> io::Result<Option<usize>> {
        let mut fd = libc::pollfd {
            fd: self.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let status = unsafe { libc::poll(&mut fd, 1, 20) };
        if status < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(Some(0));
            }
            return Err(error);
        }
        if fd.revents & libc::POLLNVAL != 0 {
            return Err(io::Error::other("invalid subprocess output pipe"));
        }
        Ok(Some(
            if fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                8192
            } else {
                0
            },
        ))
    }
}
#[cfg(windows)]
impl<T: Read + Send + std::os::windows::io::AsRawHandle + 'static> Pipe for T {
    fn available(&self) -> io::Result<Option<usize>> {
        let mut bytes = 0;
        if unsafe {
            windows_sys::Win32::System::Pipes::PeekNamedPipe(
                self.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut bytes,
                std::ptr::null_mut(),
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(109 | 232)) {
                return Ok(None);
            }
            return Err(error);
        }
        Ok(Some(bytes as usize))
    }
}
#[cfg(not(any(unix, windows)))]
impl<T: Read + Send + 'static> Pipe for T {
    fn available(&self) -> io::Result<Option<usize>> {
        Err(io::Error::other(
            "cancellable process capture is unsupported on this platform",
        ))
    }
}

type Reader = JoinHandle<Result<Vec<u8>, String>>;
pub(super) struct Readers {
    stop: Arc<AtomicBool>,
    stdout: Option<Reader>,
    stderr: Option<Reader>,
}
impl Readers {
    pub(super) fn start(
        stdout: ChildStdout,
        stderr: ChildStderr,
        overflow: Arc<AtomicBool>,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        Self {
            stdout: Some(collect(stdout, overflow.clone(), stop.clone())),
            stderr: Some(collect(stderr, overflow, stop.clone())),
            stop,
        }
    }
    pub(super) fn is_finished(&self) -> bool {
        self.stdout
            .as_ref()
            .is_none_or(|reader| reader.is_finished())
            && self
                .stderr
                .as_ref()
                .is_none_or(|reader| reader.is_finished())
    }
    pub(super) fn finish(mut self) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.stop.store(true, Ordering::Relaxed);
        let stdout = self
            .stdout
            .take()
            .unwrap()
            .join()
            .map_err(|_| "stdout reader panicked")?;
        let stderr = self
            .stderr
            .take()
            .unwrap()
            .join()
            .map_err(|_| "stderr reader panicked")?;
        Ok((stdout?, stderr?))
    }
}
impl Drop for Readers {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(reader) = self.stdout.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr.take() {
            let _ = reader.join();
        }
    }
}
fn collect(mut input: impl Pipe, overflow: Arc<AtomicBool>, stop: Arc<AtomicBool>) -> Reader {
    thread::spawn(move || {
        let mut output = Vec::new();
        let mut buffer = [0; 8192];
        while !stop.load(Ordering::Relaxed) {
            let Some(available) = input.available().map_err(error)? else {
                break;
            };
            if available == 0 {
                thread::sleep(Duration::from_millis(2));
                continue;
            }
            let count = available.min(buffer.len());
            let count = match input.read(&mut buffer[..count]) {
                Ok(0) => break,
                Ok(count) => count,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error.to_string()),
            };
            let available = MAX_OUTPUT.saturating_sub(output.len());
            output.extend_from_slice(&buffer[..count.min(available)]);
            if count > available {
                overflow.store(true, Ordering::Relaxed);
            }
        }
        Ok(output)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        process::{Command, Stdio},
        time::Instant,
    };

    #[test]
    fn detached_descendant_cannot_hold_capture_past_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let pidfile = directory.path().join("holder.pid");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "capture::tests::spawn_output_holder_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("BUNTRAIL_CAPTURE_TEST_PID", &pidfile);
        let started = Instant::now();
        let result =
            super::super::run_limited_timeout(&mut command, false, Duration::from_millis(400));
        let elapsed = started.elapsed();
        let pid: u32 = fs::read_to_string(&pidfile).unwrap().parse().unwrap();
        #[cfg(unix)]
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::{Foundation::CloseHandle, System::Threading::*};
            let process = OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, pid);
            if !process.is_null() {
                TerminateProcess(process, 1);
                WaitForSingleObject(process, 1000);
                CloseHandle(process);
            }
        }
        assert!(result.unwrap_err().contains("timeout"));
        assert!(
            elapsed < Duration::from_secs(2),
            "capture exceeded its deadline: {elapsed:?}"
        );
    }
    #[test]
    #[ignore = "subprocess fixture invoked only by the capture regression test"]
    // The parent must exit first; the outer regression owns and terminates this detached child.
    #[allow(clippy::zombie_processes)]
    fn spawn_output_holder_fixture() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "capture::tests::hold_output_fixture",
                "--ignored",
                "--nocapture",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let child = command.spawn().unwrap();
        fs::write(
            std::env::var_os("BUNTRAIL_CAPTURE_TEST_PID").unwrap(),
            child.id().to_string(),
        )
        .unwrap();
    }
    #[test]
    #[ignore = "subprocess fixture invoked only by the capture regression test"]
    fn hold_output_fixture() {
        thread::sleep(Duration::from_secs(4));
    }
}
