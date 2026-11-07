//! Bounded input transport; callers never wait for a terminal child to read.
use super::*;
use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};

pub(super) struct InputPump {
    sender: Option<SyncSender<Vec<u8>>>,
    stop: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<String>>>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl InputPump {
    pub(super) fn new(mut sink: File) -> Result<Self, String> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let flags = unsafe { libc::fcntl(sink.as_raw_fd(), libc::F_GETFL) };
            if flags < 0
                || unsafe { libc::fcntl(sink.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                    < 0
            {
                return Err(error(std::io::Error::last_os_error()));
            }
        }
        let (sender, receiver) = sync_channel::<Vec<u8>>(8);
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(Mutex::new(None));
        let worker_stop = stop.clone();
        let worker_failure = failure.clone();
        let worker = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::Relaxed) {
                let bytes = match receiver.recv_timeout(Duration::from_millis(25)) {
                    Ok(bytes) => bytes,
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(RecvTimeoutError::Disconnected) => break,
                };
                let mut offset = 0;
                while offset < bytes.len() && !worker_stop.load(Ordering::Relaxed) {
                    match sink.write(&bytes[offset..bytes.len().min(offset + 4096)]) {
                        Ok(0) => {
                            if let Ok(mut error) = worker_failure.lock() {
                                *error = Some("Terminal input closed".into());
                            }
                            return;
                        }
                        Ok(written) => offset += written,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2))
                        }
                        Err(error) => {
                            if let Ok(mut failure) = worker_failure.lock() {
                                *failure = Some(error.to_string());
                            }
                            return;
                        }
                    }
                }
            }
        });
        Ok(Self {
            sender: Some(sender),
            stop,
            failure,
            worker: Some(worker),
        })
    }
    pub(super) fn write(&self, bytes: &[u8]) -> Result<(), String> {
        if let Some(failure) = self.failure.lock().map_err(error)?.as_ref() {
            return Err(failure.clone());
        }
        self.sender
            .as_ref()
            .ok_or("Terminal input closed")?
            .try_send(bytes.to_vec())
            .map_err(|_| {
                "Terminal input queue is full or closed; these bytes were not accepted".into()
            })
    }
}
impl Drop for InputPump {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.sender.take();
        #[cfg(windows)]
        if let Some(worker) = &self.worker {
            use std::os::windows::io::AsRawHandle;
            unsafe {
                windows_sys::Win32::System::IO::CancelSynchronousIo(worker.as_raw_handle());
            }
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::{
        fd::{FromRawFd, IntoRawFd},
        unix::net::UnixStream,
    };
    #[test]
    fn unreading_terminal_has_bounded_input_and_shutdown() {
        let (writer, _unreading) = UnixStream::pair().unwrap();
        let writer = unsafe { File::from_raw_fd(writer.into_raw_fd()) };
        let pump = InputPump::new(writer).unwrap();
        let bytes = vec![b'x'; 1024 * 1024];
        let started = Instant::now();
        let mut rejected = false;
        for _ in 0..20 {
            if pump.write(&bytes).is_err() {
                rejected = true;
                break;
            }
        }
        assert!(rejected, "input must have a finite queue");
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(pump);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "close must not wait for the reader"
        );
    }
}
