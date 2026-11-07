//! Worker-owned filesystem leases. Core/native values retain only an Arc<()> token.
//! Last-token drop performs no I/O; this bounded pool reaps released/orphaned files.
use crate::files::{io_error, private_directory};
use buntrail_core::contracts::{CoreError, ErrorCode};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
    time::Duration,
};
struct Entry {
    _file: File,
    token: Weak<()>,
}
pub struct LeasePool {
    directory: PathBuf,
    entries: Mutex<HashMap<PathBuf, Entry>>,
    // Owner lookup holds only this short memory lock, never the disk/worker lock.
    tokens: Mutex<HashMap<PathBuf, Weak<()>>>,
}
static POOLS: OnceLock<Mutex<HashMap<PathBuf, Weak<LeasePool>>>> = OnceLock::new();
struct DiskLock(File);
impl Drop for DiskLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
impl LeasePool {
    pub fn open(directory: PathBuf) -> Result<Arc<Self>, CoreError> {
        private_directory(&directory)?;
        let directory = fs::canonicalize(directory).map_err(io_error)?;
        let mut pools = POOLS
            .get_or_init(Default::default)
            .lock()
            .map_err(io_error)?;
        pools.retain(|_, p| p.strong_count() > 0);
        if let Some(pool) = pools.get(&directory).and_then(Weak::upgrade) {
            return Ok(pool);
        }
        let pool = Arc::new(Self {
            directory: directory.clone(),
            entries: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
        });
        pool.sweep()?;
        let worker = pool.clone();
        std::thread::Builder::new()
            .name("buntrail-lease-reaper".into())
            .spawn(move || {
                loop {
                    // Errors leave the files in place; subsequent admission retries reclamation.
                    let _ = worker.sweep_idle();
                    // Synchronize retirement with open(): a new caller must not acquire a pool
                    // whose reaper has already decided to exit.
                    if let Ok(mut pools) = POOLS.get().unwrap().lock()
                        && Arc::strong_count(&worker) == 1
                        && worker.tokens.lock().is_ok_and(|t| t.is_empty())
                    {
                        pools.remove(&worker.directory);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(if cfg!(target_os = "macos") {
                        250
                    } else {
                        100
                    }));
                }
            })
            .map_err(io_error)?;
        pools.insert(directory, Arc::downgrade(&pool));
        Ok(pool)
    }
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    fn disk_lock(&self) -> Result<DiskLock, CoreError> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.directory.join("lock"))
            .map_err(io_error)?;
        f.lock().map_err(io_error)?;
        Ok(DiskLock(f))
    }
    pub fn retain(&self, path: &Path) -> Option<Arc<()>> {
        self.tokens.lock().ok()?.get(path)?.upgrade()
    }
    pub(crate) fn sweep(&self) -> Result<(), CoreError> {
        let mut entries = self.entries.lock().map_err(io_error)?;
        let released: Vec<_> = entries
            .iter()
            .filter(|(_, e)| e.token.strong_count() == 0)
            .map(|(p, _)| p.clone())
            .collect();
        for p in released {
            // No successful upgrade is possible after the last strong token is gone.
            self.tokens.lock().map_err(io_error)?.remove(&p);
            entries.remove(&p); // File close/unlock happens here on this worker.
        }
        let _lock = self.disk_lock()?;
        for item in fs::read_dir(&self.directory).map_err(io_error)? {
            let p = item.map_err(io_error)?.path();
            if p.file_name().is_some_and(|n| n == "lock") || entries.contains_key(&p) {
                continue;
            }
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&p)
                .map_err(io_error)?;
            match file.try_lock() {
                Ok(()) => fs::remove_file(p).map_err(io_error)?,
                Err(std::fs::TryLockError::WouldBlock) => {} // Another live service/process owns it.
                Err(e) => return Err(io_error(e)),
            }
        }
        Ok(())
    }
    fn sweep_idle(&self) -> Result<(), CoreError> {
        let entries = self.entries.lock().map_err(io_error)?;
        let mut needed = entries
            .values()
            .any(|entry| entry.token.strong_count() == 0);
        if !needed {
            for item in fs::read_dir(&self.directory).map_err(io_error)? {
                let path = item.map_err(io_error)?.path();
                if path.file_name().is_some_and(|name| name == "lock")
                    || entries.contains_key(&path)
                {
                    continue;
                }
                needed = true;
                break;
            }
        }
        drop(entries);
        // The optimistic scan never deletes; unknown/released files get a fresh locked sweep.
        if needed { self.sweep() } else { Ok(()) }
    }
    pub fn create_spool(&self) -> Result<(File, PathBuf, Arc<()>), CoreError> {
        self.sweep()?;
        let mut entries = self.entries.lock().map_err(io_error)?;
        let _lock = self.disk_lock()?;
        if fs::read_dir(&self.directory)
            .map_err(io_error)?
            .filter_map(Result::ok)
            .filter(|e| e.file_name() != "lock")
            .take(64)
            .count()
            >= 64
        {
            return Err(CoreError::new(
                ErrorCode::Busy,
                "private spool capacity reached",
            ));
        }
        let temporary = tempfile::NamedTempFile::new_in(&self.directory).map_err(io_error)?;
        temporary.as_file().lock().map_err(io_error)?;
        let (file, path) = temporary.keep().map_err(io_error)?;
        let writer = file.try_clone().map_err(io_error)?;
        let token = Arc::new(());
        self.tokens
            .lock()
            .map_err(io_error)?
            .insert(path.clone(), Arc::downgrade(&token));
        entries.insert(
            path.clone(),
            Entry {
                _file: file,
                token: Arc::downgrade(&token),
            },
        );
        Ok((writer, path, token))
    }
    pub fn session(&self, name: &str) -> Result<Arc<()>, CoreError> {
        self.sweep()?;
        let mut entries = self.entries.lock().map_err(io_error)?;
        let path = self.directory.join(name);
        if let Some(token) = self.retain(&path) {
            return Ok(token);
        }
        let _lock = self.disk_lock()?;
        if entries.len() >= 64 {
            return Err(CoreError::new(
                ErrorCode::Busy,
                "live recovery session capacity reached",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(io_error)?;
        file.lock_shared().map_err(io_error)?;
        let token = Arc::new(());
        self.tokens
            .lock()
            .map_err(io_error)?
            .insert(path.clone(), Arc::downgrade(&token));
        entries.insert(
            path,
            Entry {
                _file: file,
                token: Arc::downgrade(&token),
            },
        );
        Ok(token)
    }
    pub(crate) fn exclusive_session(&self, name: &str) -> Result<File, CoreError> {
        use std::os::unix::fs::MetadataExt;
        if name.len() != 32 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(io_error("invalid recovery session identity"));
        }
        self.sweep()?;
        let _lock = self.disk_lock()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.directory.join(name))
            .map_err(io_error)?;
        let metadata = file.metadata().map_err(io_error)?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(io_error("recovery session is not private and owned"));
        }
        file.try_lock().map_err(|_| {
            CoreError::new(
                ErrorCode::Busy,
                "Recovery draft is still owned by an active session",
            )
        })?;
        Ok(file)
    }
    pub fn session_is_live(&self, name: &str) -> Result<bool, CoreError> {
        let _lock = self.disk_lock()?;
        let path = self.directory.join(name);
        let f = match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(io_error(e)),
        };
        match f.try_lock() {
            Ok(()) => Ok(false),
            Err(std::fs::TryLockError::WouldBlock) => Ok(true),
            Err(e) => Err(io_error(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn clean_idle_tick_does_not_wait_for_an_unneeded_disk_lock() {
        let directory = tempfile::tempdir().unwrap();
        let pool = LeasePool::open(directory.path().join("leases")).unwrap();
        let held = OpenOptions::new()
            .read(true)
            .write(true)
            .open(pool.directory().join("lock"))
            .unwrap();
        held.lock().unwrap();
        let worker_pool = pool.clone();
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || send.send(worker_pool.sweep_idle()).unwrap());
        let finished = receive.recv_timeout(Duration::from_secs(1));
        held.unlock().unwrap();
        if finished.is_err() {
            receive
                .recv_timeout(Duration::from_secs(3))
                .unwrap()
                .unwrap();
        }
        worker.join().unwrap();
        assert!(
            finished.is_ok(),
            "a fresh clean scan needs no exclusive disk lock"
        );
        finished.unwrap().unwrap();
    }

    #[test]
    fn idle_tick_preserves_foreign_lock_then_reaps_new_orphans_and_released_local_tokens() {
        let directory = tempfile::tempdir().unwrap();
        let pool = LeasePool::open(directory.path().join("leases")).unwrap();
        let foreign_path = pool.directory().join("foreign");
        let disk = pool.disk_lock().unwrap();
        let foreign = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&foreign_path)
            .unwrap();
        foreign.lock().unwrap();
        drop(disk);
        pool.sweep_idle().unwrap();
        assert!(foreign_path.exists());
        foreign.unlock().unwrap();
        pool.sweep_idle().unwrap();
        assert!(!foreign_path.exists());
        let orphan = pool.directory().join("new-after-clean-scan");
        fs::write(&orphan, b"orphan").unwrap();
        pool.sweep_idle().unwrap();
        assert!(!orphan.exists());
        let (file, path, token) = pool.create_spool().unwrap();
        pool.sweep_idle().unwrap();
        assert!(path.exists());
        drop(file);
        drop(token);
        pool.sweep_idle().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn idle_scan_errors_preserve_unknown_entries_and_next_tick_retries() {
        let directory = tempfile::tempdir().unwrap();
        let pool = LeasePool::open(directory.path().join("leases")).unwrap();
        let unknown = pool.directory().join("unexpected-directory");
        fs::create_dir(&unknown).unwrap();
        assert!(pool.sweep_idle().is_err());
        assert!(unknown.is_dir());
        fs::remove_dir(&unknown).unwrap();
        let orphan = pool.directory().join("retry-orphan");
        fs::write(&orphan, b"orphan").unwrap();
        pool.sweep_idle().unwrap();
        assert!(!orphan.exists());
    }
    #[test]
    fn background_worker_reaps_releases_and_orphans_then_retires() {
        use std::time::Instant;
        let directory = tempfile::tempdir().unwrap();
        let pool = LeasePool::open(directory.path().join("leases")).unwrap();
        let (writer, local, token) = pool.create_spool().unwrap();
        drop(writer);
        let foreign_path = pool.directory().join("foreign");
        let orphan = pool.directory().join("orphan");
        let disk = pool.disk_lock().unwrap();
        let foreign = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&foreign_path)
            .unwrap();
        foreign.lock().unwrap();
        fs::write(&orphan, b"orphan").unwrap();
        drop(disk);
        let until = |condition: &dyn Fn() -> bool| {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !condition() {
                assert!(Instant::now() < deadline, "background cleanup timed out");
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        until(&|| !orphan.exists());
        assert!(
            local.exists(),
            "retained local source must survive worker sweep"
        );
        assert!(
            foreign_path.exists(),
            "foreign locked source must survive worker sweep"
        );

        let entries = pool.entries.lock().unwrap();
        let tokens = pool.tokens.lock().unwrap();
        let disk = pool.disk_lock().unwrap();
        let (send, receive) = mpsc::channel();
        let dropper = std::thread::spawn(move || {
            drop(token);
            send.send(()).unwrap();
        });
        let released_without_locks = receive.recv_timeout(Duration::from_secs(1));
        drop(disk);
        drop(tokens);
        drop(entries);
        dropper.join().unwrap();
        assert!(
            released_without_locks.is_ok(),
            "last token drop must not wait for filesystem or pool locks"
        );
        until(&|| !local.exists());
        foreign.unlock().unwrap();
        drop(foreign);
        until(&|| !foreign_path.exists());
        let weak = Arc::downgrade(&pool);
        drop(pool);
        until(&|| weak.upgrade().is_none());
    }
}
