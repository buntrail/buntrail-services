//! Trusted immutable application resources, loaded only on the selected connection worker.
use super::{Artifact, HelperPackage, MAX_ARTIFACT_BYTES, Platform, invalid};
use buntrail_core::contracts::{CoreError, ErrorCode};
use serde::Deserialize;
use std::{
    ffi::CStr,
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::PathBuf,
    sync::{
        Mutex, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
// Same bound as the existing trusted bootstrap descriptor/prelude.
const MAX_METADATA: usize = 64 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    packages: Vec<Descriptor>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    platform: Platform,
    helper_sha256: String,
    search_sha256: String,
}
/// Four existing supported platform slots; successful immutable bytes are shared across attempts.
/// Construction performs no filesystem I/O. Failed/cancelled loads never poison later attempts.
pub struct BundledPackages {
    directory: PathBuf,
    verified: [Mutex<Option<HelperPackage>>; 4],
}
fn cancelled(cancel: &AtomicBool) -> Result<(), CoreError> {
    if cancel.load(Ordering::SeqCst) {
        Err(CoreError::new(
            ErrorCode::Cancelled,
            "bundled package loading cancelled",
        ))
    } else {
        Ok(())
    }
}
fn io(error: impl std::fmt::Display) -> CoreError {
    invalid(&format!(
        "trusted bundled helper/search package unavailable: {error}"
    ))
}
fn location(platform: &Platform) -> (usize, &'static CStr) {
    match platform {
        Platform::LinuxX86Gnu => (0, c"linux-x86_64-gnu"),
        Platform::LinuxX86Musl => (1, c"linux-x86_64-musl"),
        Platform::LinuxArmGnu => (2, c"linux-arm64-gnu"),
        Platform::LinuxArmMusl => (3, c"linux-arm64-musl"),
    }
}
fn open_at(parent: &File, name: &CStr, directory: bool) -> Result<File, CoreError> {
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io(std::io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn read_bounded(mut file: File, limit: usize, cancel: &AtomicBool) -> Result<Vec<u8>, CoreError> {
    cancelled(cancel)?;
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(invalid(
            "trusted bundled resource must be a regular file within its size bound",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut chunk = [0; 64 * 1024];
    loop {
        cancelled(cancel)?;
        let count = file.read(&mut chunk).map_err(io)?;
        if count == 0 {
            return Ok(bytes);
        }
        if count > limit - bytes.len() {
            return Err(invalid(
                "trusted bundled resource grew beyond its size bound",
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
}
impl BundledPackages {
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            verified: std::array::from_fn(|_| Mutex::new(None)),
        }
    }
    /// Worker-only I/O/hash/validation. No global route/owner/control lock is held here.
    pub fn load(
        &self,
        platform: Platform,
        cancel: &AtomicBool,
    ) -> Result<HelperPackage, CoreError> {
        let (slot, subdirectory) = location(&platform);
        let mut cached = loop {
            cancelled(cancel)?;
            match self.verified[slot].try_lock() {
                Ok(value) => break value,
                Err(TryLockError::Poisoned(_)) => {
                    return Err(invalid("bundled package cache poisoned"));
                }
                Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        if let Some(package) = cached.as_ref() {
            cancelled(cancel)?;
            return Ok(package.clone());
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&self.directory)
            .map_err(io)?;
        let metadata = read_bounded(
            open_at(&directory, c"packages.json", false)?,
            MAX_METADATA,
            cancel,
        )?;
        let manifest: Manifest = serde_json::from_slice(&metadata).map_err(io)?;
        if manifest.schema != 1 || manifest.packages.len() > 4 {
            return Err(invalid(
                "unsupported bundled package manifest schema or platform count",
            ));
        }
        for (index, descriptor) in manifest.packages.iter().enumerate() {
            if manifest.packages[..index]
                .iter()
                .any(|prior| prior.platform == descriptor.platform)
            {
                return Err(invalid("duplicate trusted platform package"));
            }
            for digest in [&descriptor.helper_sha256, &descriptor.search_sha256] {
                if digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(invalid("bundled package digest is not a canonical SHA-256"));
                }
            }
        }
        let descriptor=manifest.packages.into_iter().find(|d|d.platform==platform).ok_or_else(||invalid("trusted Linux helper/search artifacts for the verified architecture and libc are unavailable in this application"))?;
        let selected = open_at(&directory, subdirectory, true)?;
        let helper = Artifact::verified(
            read_bounded(
                open_at(&selected, c"buntrail-helper", false)?,
                MAX_ARTIFACT_BYTES,
                cancel,
            )?,
            &descriptor.helper_sha256,
        )?;
        cancelled(cancel)?;
        let search = Artifact::verified(
            read_bounded(
                open_at(&selected, c"rg", false)?,
                MAX_ARTIFACT_BYTES,
                cancel,
            )?,
            &descriptor.search_sha256,
        )?;
        let package = HelperPackage {
            platform,
            helper,
            search,
        };
        package.validate()?;
        cancelled(cancel)?;
        *cached = Some(package.clone());
        Ok(package)
    }
}
