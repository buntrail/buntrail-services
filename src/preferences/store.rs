use crate::files::{atomic_private, io_error, private_directory};
use buntrail_core::{
    contracts::{CoreError, WorkspaceID},
    preferences::{Preferences, PreferencesOverride},
};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[derive(serde::Serialize, serde::Deserialize)]
struct State {
    schema: u32,
    defaults: Preferences,
    overrides: Vec<(WorkspaceID, PreferencesOverride)>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            schema: 1,
            defaults: Preferences::default(),
            overrides: vec![],
        }
    }
}
pub struct PreferencesStore {
    directory: PathBuf,
    lock: Mutex<File>,
    workspaces: Arc<crate::workspaces::store::WorkspaceStore>,
    next_revision: std::sync::atomic::AtomicU64,
    applied_revision: Mutex<u64>,
}
impl PreferencesStore {
    pub fn new(
        directory: PathBuf,
        workspaces: Arc<crate::workspaces::store::WorkspaceStore>,
    ) -> Result<Self, CoreError> {
        private_directory(&directory)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.join("preferences.lock"))
            .map_err(io_error)?;
        let store = Self {
            directory,
            lock: Mutex::new(lock),
            workspaces,
            next_revision: std::sync::atomic::AtomicU64::new(0),
            applied_revision: Mutex::new(0),
        };
        store.with_state(|_| Ok(((), false)))?;
        Ok(store)
    }
    fn with_state<T>(
        &self,
        action: impl FnOnce(&mut State) -> Result<(T, bool), CoreError>,
    ) -> Result<T, CoreError> {
        let lock = self.lock.lock().map_err(io_error)?;
        lock.lock().map_err(io_error)?;
        struct Guard<'a>(&'a File);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                let _ = self.0.unlock();
            }
        }
        let _guard = Guard(&lock);
        let mut state = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.directory.join("preferences.json"))
        {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(1024 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(io_error)?;
                if bytes.len() > 1024 * 1024 {
                    return Err(io_error("preferences exceed limit"));
                }
                serde_json::from_slice::<State>(&bytes).map_err(io_error)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(io_error(e)),
        };
        if state.schema != 1
            || state.overrides.len() > 100
            || !state.defaults.valid()
            || state.overrides.iter().any(|(_, v)| {
                let mut p = state.defaults.clone();
                p.apply(v);
                !p.valid()
            })
        {
            return Err(io_error("invalid preferences"));
        }
        let (value, changed) = action(&mut state)?;
        if changed {
            let bytes = serde_json::to_vec(&state).map_err(io_error)?;
            if bytes.len() > 1024 * 1024 {
                return Err(io_error("preferences exceed limit"));
            }
            atomic_private(&self.directory.join("preferences.json"), &bytes)?;
        }
        Ok(value)
    }
    pub fn effective(&self, workspace: WorkspaceID) -> Result<Preferences, CoreError> {
        let mut effective = self.with_state(|state| {
            let mut p = state.defaults.clone();
            if let Some((_, v)) = state.overrides.iter().find(|(id, _)| *id == workspace) {
                p.apply(v);
            }
            Ok((p, false))
        })?;
        if let Some(record) = self
            .workspaces
            .load()?
            .records
            .iter()
            .find(|r| r.id == workspace)
        {
            effective.show_icons = record.show_icons;
        }
        Ok(effective)
    }
    pub fn reserve_defaults(&self) -> Result<u64, CoreError> {
        self.next_revision
            .try_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |value| value.checked_add(1),
            )
            .map(|old| old + 1)
            .map_err(io_error)
    }
    pub fn set_defaults_ordered(
        &self,
        revision: u64,
        defaults: Preferences,
    ) -> Result<(), CoreError> {
        let mut applied = self.applied_revision.lock().map_err(io_error)?;
        if revision <= *applied {
            return Ok(());
        }
        self.with_state(|state| {
            if !defaults.valid()
                || state.overrides.iter().any(|(_, value)| {
                    let mut effective = defaults.clone();
                    effective.apply(value);
                    !effective.valid()
                })
            {
                return Err(io_error("invalid preferences"));
            }
            state.defaults = defaults;
            Ok(((), true))
        })?;
        *applied = revision;
        Ok(())
    }
    pub fn set_defaults(&self, defaults: Preferences) -> Result<(), CoreError> {
        let revision = self.reserve_defaults()?;
        self.set_defaults_ordered(revision, defaults)
    }
    pub fn set_override(
        &self,
        workspace: WorkspaceID,
        value: PreferencesOverride,
    ) -> Result<(), CoreError> {
        self.with_state(|state| {
            let mut p = state.defaults.clone();
            p.apply(&value);
            if !p.valid() {
                return Err(io_error("invalid preferences"));
            }
            if let Some((_, old)) = state.overrides.iter_mut().find(|(id, _)| *id == workspace) {
                *old = value;
            } else {
                if state.overrides.len() >= 100 {
                    return Err(io_error("too many workspace preferences"));
                }
                state.overrides.push((workspace, value));
            }
            Ok(((), true))
        })
    }
}
