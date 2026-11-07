//! Windows process ownership through ConPTY and a kill-on-close job object.
use super::*;
use std::os::windows::{
    ffi::OsStrExt,
    io::{AsRawHandle, FromRawHandle},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::{Console::*, JobObjects::*, Pipes::*, Threading::*},
};

struct Handle(usize);
impl Handle {
    fn new(raw: HANDLE) -> Result<Self, String> {
        if raw.is_null() {
            Err(error(std::io::Error::last_os_error()))
        } else {
            Ok(Self(raw as usize))
        }
    }
    fn raw(&self) -> HANDLE {
        self.0 as HANDLE
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.raw());
        }
    }
}
struct Console(HPCON);
impl Drop for Console {
    fn drop(&mut self) {
        unsafe {
            ClosePseudoConsole(self.0);
        }
    }
}
struct Attributes(Vec<usize>);
impl Attributes {
    fn new(console: HPCON) -> Result<Self, String> {
        let mut bytes = 0;
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(error(std::io::Error::last_os_error()));
        }
        let mut memory = vec![0; bytes.div_ceil(std::mem::size_of::<usize>())];
        let raw = memory.as_mut_ptr().cast();
        if unsafe { InitializeProcThreadAttributeList(raw, 1, 0, &mut bytes) } == 0 {
            return Err(error(std::io::Error::last_os_error()));
        }
        let mut value = Self(memory);
        if unsafe {
            UpdateProcThreadAttribute(
                value.raw(),
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                console as *const _,
                std::mem::size_of::<HPCON>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(error(std::io::Error::last_os_error()));
        }
        Ok(value)
    }
    fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.0.as_mut_ptr().cast()
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.raw());
        }
    }
}
fn wide(path: &std::ffi::OsStr) -> Result<Vec<u16>, String> {
    let mut units: Vec<_> = path.encode_wide().collect();
    if units.contains(&0) {
        return Err("path contains NUL".into());
    }
    units.push(0);
    Ok(units)
}
fn pipe() -> Result<(File, File), String> {
    let (mut read, mut write) = (std::ptr::null_mut(), std::ptr::null_mut());
    if unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) } == 0 {
        return Err(error(std::io::Error::last_os_error()));
    }
    Ok(unsafe { (File::from_raw_handle(read), File::from_raw_handle(write)) })
}
struct Buffer {
    data: Vec<u8>,
    truncated: bool,
}
pub struct Session {
    input: Option<super::terminal_input::InputPump>,
    process: Handle,
    job: Option<Handle>,
    console: Option<Console>,
    output: Arc<Mutex<Buffer>>,
    stop: Arc<AtomicBool>,
    reader: Option<std::thread::JoinHandle<()>>,
}
impl Session {
    pub fn start(root: &Path, shell: &str) -> Result<Self, String> {
        let shell = Path::new(shell);
        if !shell.is_absolute() {
            return Err("shell must be an absolute executable path".into());
        }
        let (read_input, input) = pipe()?;
        let (mut output, write_output) = pipe()?;
        let mut console = 0;
        let status = unsafe {
            CreatePseudoConsole(
                COORD { X: 80, Y: 24 },
                read_input.as_raw_handle(),
                write_output.as_raw_handle(),
                0,
                &mut console,
            )
        };
        if status < 0 {
            return Err(format!("CreatePseudoConsole failed: {status:#x}"));
        }
        let console = Console(console);
        drop(read_input);
        drop(write_output);
        let mut attributes = Attributes::new(console.0)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attributes.raw();
        let executable = wide(shell.as_os_str())?;
        let directory = wide(root.as_os_str())?;
        // ApplicationName fixes the executable; this quoted argv[0] never contains user commands.
        let mut command = vec![b'"' as u16];
        command.extend_from_slice(&executable[..executable.len() - 1]);
        command.extend_from_slice(&[b'"' as u16, 0]);
        let mut info = PROCESS_INFORMATION::default();
        if unsafe {
            CreateProcessW(
                executable.as_ptr(),
                command.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
                std::ptr::null(),
                directory.as_ptr(),
                &startup.StartupInfo,
                &mut info,
            )
        } == 0
        {
            return Err(error(std::io::Error::last_os_error()));
        }
        let process = Handle::new(info.hProcess)?;
        let thread = Handle::new(info.hThread)?;
        let job = match Self::job(process.raw()) {
            Ok(job) => job,
            Err(error) => {
                unsafe {
                    TerminateProcess(process.raw(), 1);
                    WaitForSingleObject(process.raw(), 5000);
                }
                return Err(error);
            }
        };
        if unsafe { ResumeThread(thread.raw()) } == u32::MAX {
            unsafe {
                TerminateProcess(process.raw(), 1);
            }
            return Err(error(std::io::Error::last_os_error()));
        }
        let sink = Arc::new(Mutex::new(Buffer {
            data: Vec::new(),
            truncated: false,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread_sink = sink.clone();
        let reader = std::thread::spawn(move || {
            let mut bytes = [0; 8192];
            while !thread_stop.load(Ordering::Relaxed) {
                let mut available = 0;
                if unsafe {
                    PeekNamedPipe(
                        output.as_raw_handle(),
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        &mut available,
                        std::ptr::null_mut(),
                    )
                } == 0
                {
                    break;
                }
                if available == 0 {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                let amount = (available as usize).min(bytes.len());
                let Ok(amount) = output.read(&mut bytes[..amount]) else {
                    break;
                };
                if amount == 0 {
                    break;
                }
                let Ok(mut buffer) = thread_sink.lock() else {
                    break;
                };
                let room = MAX_OUTPUT.saturating_sub(buffer.data.len());
                buffer.data.extend_from_slice(&bytes[..amount.min(room)]);
                if amount > room {
                    buffer.truncated = true;
                }
            }
        });
        let input = super::terminal_input::InputPump::new(input)?;
        Ok(Self {
            input: Some(input),
            process,
            job: Some(job),
            console: Some(console),
            output: sink,
            stop,
            reader: Some(reader),
        })
    }
    fn job(process: HANDLE) -> Result<Handle, String> {
        let job = Handle::new(unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) })?;
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
            || unsafe { AssignProcessToJobObject(job.raw(), process) } == 0
        {
            return Err(error(std::io::Error::last_os_error()));
        }
        Ok(job)
    }
    pub fn read(&mut self) -> Result<Value, String> {
        let alive = unsafe { WaitForSingleObject(self.process.raw(), 0) } == 258;
        if !alive {
            drop(self.job.take());
            // ConPTY keeps its output pipe open until the console reference is
            // released. Leave the reader running, without its buffer lock held.
            drop(self.console.take());
            self.input.take();
        }
        let mut buffer = self.output.lock().map_err(error)?;
        let count = buffer.data.len().min(MAX_TERMINAL_READ);
        let data: Vec<u8> = buffer.data.drain(..count).collect();
        let truncated = std::mem::take(&mut buffer.truncated);
        Ok(
            json!({"output":String::from_utf8_lossy(&data),"bytes":data,"alive":alive,"drained":!alive && buffer.data.is_empty() && self.reader.as_ref().is_none_or(|reader|reader.is_finished()),"truncated":truncated}),
        )
    }
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.input
            .as_ref()
            .ok_or("Terminal input closed")?
            .write(bytes)
    }
    pub fn resize(&mut self, columns: u16, rows: u16) -> Result<(), String> {
        let x = i16::try_from(columns).map_err(|_| "ConPTY columns exceed 32767")?;
        let y = i16::try_from(rows).map_err(|_| "ConPTY rows exceed 32767")?;
        let console = self.console.as_ref().ok_or("Terminal process has ended")?;
        let status = unsafe { ResizePseudoConsole(console.0, COORD { X: x, Y: y }) };
        if status < 0 {
            Err(format!("ResizePseudoConsole failed: {status:#x}"))
        } else {
            Ok(())
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        drop(self.job.take());
        unsafe {
            WaitForSingleObject(self.process.raw(), 5000);
        }
        // Keep draining output while ConPTY closes; its close can wait for the reader.
        drop(self.console.take());
        self.input.take();
        self.stop.store(true, Ordering::Relaxed);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
