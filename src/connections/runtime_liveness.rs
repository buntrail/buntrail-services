use crate::files::{io_error, private_directory};
use buntrail_core::contracts::{CoreError, RuntimeGeneration};
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub(crate) struct RuntimeGuard {
    file: File,
}
fn name(runtime: &RuntimeGeneration) -> String {
    runtime
        .supervisor_boot
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn open(path: PathBuf) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}
impl RuntimeGuard {
    pub fn create(directory: &Path, runtime: &RuntimeGeneration) -> Result<Self, CoreError> {
        private_directory(directory)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.join(name(runtime)))
            .map_err(io_error)?;
        file.lock().map_err(io_error)?;
        Ok(Self { file })
    }
    pub fn dead(directory: &Path, runtime: &RuntimeGeneration) -> bool {
        if runtime.container_start.is_some() {
            return false;
        }
        let Ok(file) = open(directory.join(name(runtime))) else {
            return false;
        };
        if file.try_lock().is_err() {
            return false;
        }
        let _ = file.unlock();
        true
    }
    pub fn clean_unreferenced(directory: &Path, referenced: &HashSet<String>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if name.len() != 32
                || !name.bytes().all(|byte| byte.is_ascii_hexdigit())
                || referenced.contains(&name)
            {
                continue;
            }
            let Ok(file) = open(entry.path()) else {
                continue;
            };
            if file.try_lock().is_ok() {
                let _ = std::fs::remove_file(entry.path());
                let _ = file.unlock();
            }
        }
    }
}
impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}
pub(crate) fn runtime_name(runtime: &RuntimeGeneration) -> String {
    name(runtime)
}
