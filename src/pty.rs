use std::{
    fs::File,
    io::{self, Write},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::process::CommandExt,
    process::{Child, Command, ExitStatus, Stdio},
};

pub struct Pty {
    master: Option<File>,
    child: Child,
}
impl Pty {
    pub fn spawn(program: &str, args: &[&str], rows: u16, cols: u16) -> io::Result<Self> {
        Self::spawn_in(std::path::Path::new(program), args, None, rows, cols)
    }
    pub fn spawn_in(
        program: &std::path::Path,
        args: &[&str],
        directory: Option<&std::path::Path>,
        rows: u16,
        cols: u16,
    ) -> io::Result<Self> {
        Self::spawn_in_with_authentication(program, args, directory, rows, cols, None)
    }
    pub(crate) fn spawn_in_with_authentication(
        program: &std::path::Path,
        args: &[&str],
        directory: Option<&std::path::Path>,
        rows: u16,
        cols: u16,
        authentication: Option<Option<std::ffi::OsString>>,
    ) -> io::Result<Self> {
        if rows == 0 || cols == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty PTY size",
            ));
        }
        let mut master = -1;
        let mut slave = -1;
        let mut size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        if unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        unsafe {
            libc::fcntl(master.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
        }
        let mut command = Command::new(program);
        if let Some(socket) = authentication {
            command.env_remove("SSH_AUTH_SOCK");
            if let Some(socket) = socket {
                command.env("SSH_AUTH_SOCK", socket);
            }
        }
        if let Some(directory) = directory {
            command.current_dir(directory);
        }
        command
            .args(args)
            .env("TERM", "xterm-256color")
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave));
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(Self {
            master: Some(master),
            child: command.spawn()?,
        })
    }
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }
    pub fn master_fd(&self) -> std::os::fd::RawFd {
        self.master.as_ref().unwrap().as_raw_fd()
    }
    pub fn process_id(&self) -> u32 {
        self.child.id()
    }
    pub fn reader(&self) -> io::Result<File> {
        self.master.as_ref().unwrap().try_clone()
    }
    pub fn resize(&self, rows: u16, cols: u16) -> io::Result<()> {
        if rows == 0 || cols == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty PTY size",
            ));
        }
        let size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        if unsafe {
            libc::ioctl(
                self.master.as_ref().unwrap().as_raw_fd(),
                libc::TIOCSWINSZ,
                &size,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub fn stop(&mut self) -> io::Result<()> {
        if self.child.try_wait()?.is_none()
            && unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        self.child.wait()
    }
}
impl Write for Pty {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.master.as_mut().unwrap().write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.master.as_mut().unwrap().flush()
    }
}
impl Drop for Pty {
    fn drop(&mut self) {
        let _ = self.stop();
        // Release the PTY before waiting: Darwin can block terminal teardown until the master closes.
        self.master.take();
        let _ = self.wait();
    }
}
