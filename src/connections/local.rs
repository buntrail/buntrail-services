use crate::files::io_error;
use buntrail_core::contracts::*;
#[cfg(not(target_os = "macos"))]
use std::os::unix::fs::MetadataExt;
use std::{fs, io::Read};
pub fn new_id() -> Result<[u8; 16], CoreError> {
    let mut id = [0; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut id))
        .map_err(io_error)?;
    id[6] = (id[6] & 15) | 64;
    id[8] = (id[8] & 63) | 128;
    Ok(id)
}
pub fn identity() -> Result<TargetIdentity, CoreError> {
    #[cfg(target_os = "macos")]
    let binding = {
        let mut bytes = [0u8; 16];
        let timeout = libc::timespec {
            tv_sec: 2,
            tv_nsec: 0,
        };
        if unsafe { libc::gethostuuid(bytes.as_mut_ptr(), &timeout) } != 0 {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        bytes.to_vec()
    };
    #[cfg(not(target_os = "macos"))]
    let binding = fs::read("/etc/machine-id").map_err(io_error)?;
    #[cfg(not(target_os = "macos"))]
    let root = fs::metadata("/").map_err(io_error)?;
    Ok(TargetIdentity {
        security_binding: binding,
        effective_user: unsafe { libc::geteuid() }.to_be_bytes().to_vec(),
        #[cfg(target_os = "macos")]
        filesystem_namespace: super::macos_identity::filesystem_namespace()?,
        #[cfg(not(target_os = "macos"))]
        filesystem_namespace: [root.dev().to_be_bytes(), root.ino().to_be_bytes()].concat(),
        container: None,
    })
}
use crate::{contracts::*, files::LocalFileService, workspaces::store::WorkspaceStore};
use buntrail_core::contracts::async_types::{EventStream, ServiceFuture};
use futures_core::Stream;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
type ObservationMarkers = Arc<Mutex<HashMap<WorkspaceLeaseID, Arc<std::sync::atomic::AtomicBool>>>>;
fn revoke_marker(markers: &ObservationMarkers, lease: WorkspaceLeaseID) {
    if let Some(active) = markers.lock().unwrap().remove(&lease) {
        active.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}
pub struct LocalConnection {
    pub files: Arc<LocalFileService>,
    pub git: Arc<crate::git::LocalGitService>,
    pub git_available: bool,
    pub terminal: Arc<crate::terminal::LocalTerminalService>,
    pub search: Arc<crate::search::LocalSearchService>,
    pub store: Arc<WorkspaceStore>,
    pub preferences: Arc<crate::preferences::store::PreferencesStore>,
    pub identity: TargetIdentity,
    pub client: ClientID,
    pub runtime: RuntimeGeneration,
    pub dead_local_runtimes: HashSet<RuntimeGeneration>,
    owner: Arc<Owner>,
    leases: Arc<Leases>,
}
impl LocalConnection {
    pub fn open(directory: PathBuf) -> Result<Self, CoreError> {
        crate::files::private_directory(&directory)?;
        let files = Arc::new(LocalFileService::new(identity()?, directory.join("files"))?);
        Self::with_files(directory, files)
    }
    pub(crate) fn with_files(
        directory: PathBuf,
        files: Arc<LocalFileService>,
    ) -> Result<Self, CoreError> {
        crate::files::private_directory(&directory)?;
        let target = identity()?;
        if files.target() != &target {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "Local file service identity changed",
            ));
        }

        let store = Arc::new(WorkspaceStore::new(directory.join("workspace-state"))?);
        let client = store.load()?.client;
        let preferences = Arc::new(crate::preferences::store::PreferencesStore::new(
            directory.join("preferences"),
            store.clone(),
        )?);
        let runtime = RuntimeGeneration {
            supervisor_boot: new_id()?,
            container_start: None,
        };
        let guard_directory = directory.join("local-runtimes");
        let runtime_guard = Arc::new(super::runtime_liveness::RuntimeGuard::create(
            &guard_directory,
            &runtime,
        )?);
        let catalog = store.load()?;
        let referenced: HashSet<String> = catalog
            .records
            .iter()
            .flat_map(|record| {
                record
                    .terminal_layout
                    .runtimes
                    .iter()
                    .map(|(_, _, runtime)| runtime)
                    .chain(
                        record
                            .terminal_layout
                            .retired
                            .iter()
                            .map(|(_, _, runtime)| runtime),
                    )
            })
            .map(super::runtime_liveness::runtime_name)
            .collect();
        super::runtime_liveness::RuntimeGuard::clean_unreferenced(&guard_directory, &referenced);
        let dead_local_runtimes = catalog
            .records
            .iter()
            .filter(|record| record.locator.environment.route == RouteKind::Local)
            .flat_map(|record| {
                record
                    .terminal_layout
                    .retired
                    .iter()
                    .map(|(_, _, runtime)| runtime.clone())
            })
            .filter(|old| {
                old != &runtime
                    && super::runtime_liveness::RuntimeGuard::dead(&guard_directory, old)
            })
            .collect();
        let values = Arc::new(Mutex::new(HashMap::new()));
        let observation_markers = ObservationMarkers::default();
        let terminal = Arc::new(crate::terminal::LocalTerminalService::new(
            files.clone(),
            runtime.clone(),
            values.clone(),
            runtime_guard,
        ));
        let git = Arc::new(crate::git::LocalGitService::new(files.clone()));
        let git_available = git.probe().is_ok();
        let owner = Arc::new(Owner(
            Mutex::new(OwnerState {
                state: ConnectionState::Ready,
                subscribers: vec![],
            }),
            observation_markers.clone(),
        ));
        Ok(Self {
            git,
            git_available,
            terminal: terminal.clone(),
            files: files.clone(),
            search: Arc::new(crate::search::LocalSearchService::bundled(files)),
            store,
            preferences,
            identity: target,
            client,
            runtime: runtime.clone(),
            dead_local_runtimes,
            owner: owner.clone(),
            leases: Arc::new(Leases {
                client,
                runtime,
                values,
                terminal,
                observation_markers,
                owner,
            }),
        })
    }
    pub fn environment(&self) -> ConnectedEnvironment {
        let mut capabilities = vec![
            Capability::Terminal,
            Capability::Files,
            Capability::Search,
            Capability::Watch,
            Capability::Operations,
            Capability::Leases,
        ];
        if self.git_available {
            capabilities.push(Capability::Git);
        }
        ConnectedEnvironment {
            identity: self.identity.clone(),
            runtime: self.runtime.clone(),
            capabilities: Capabilities(capabilities),
            owner: self.owner.clone(),
            leases: ServiceAvailability::Available(self.leases.clone()),
            files: ServiceAvailability::Available(self.files.clone()),
            operations: ServiceAvailability::Available(self.files.clone()),
            search: ServiceAvailability::Available(self.search.clone()),
            git: if self.git_available {
                ServiceAvailability::Available(self.git.clone())
            } else {
                ServiceAvailability::Unavailable(CoreError::new(
                    ErrorCode::Unavailable,
                    "Target Git capability probe failed",
                ))
            },
            terminal: ServiceAvailability::Available(self.terminal.clone()),
        }
    }
    pub fn register(
        &self,
        workspace: WorkspaceID,
        lease: WorkspaceLeaseID,
    ) -> Result<(), CoreError> {
        self.leases.register_sync(WorkspaceLease {
            client: self.client,
            workspace,
            lease,
            runtime: self.runtime.clone(),
        })
    }
    pub fn close_connection(&self, reason: ConnectionCloseReason) {
        if reason == ConnectionCloseReason::ApplicationShutdown {
            self.terminal.shutdown();
        }
        self.owner.close_sync(reason);
    }
    pub fn release(&self, lease: WorkspaceLeaseID) {
        let mut values = self.leases.values.lock().unwrap();
        revoke_marker(&self.leases.observation_markers, lease);
        values.remove(&lease);
        drop(values);
        self.terminal.end_owner(lease);
    }
    pub fn observation_owner(
        &self,
        lease: WorkspaceLeaseID,
    ) -> Result<crate::git::observation::ObservationOwner, CoreError> {
        let state = self.owner.0.lock().unwrap();
        if state.state != ConnectionState::Ready {
            return Err(CoreError::new(ErrorCode::Closed, "local connection closed"));
        }
        let values = self.leases.values.lock().unwrap();
        let owner = values
            .get(&lease)
            .cloned()
            .ok_or_else(|| CoreError::new(ErrorCode::Closed, "workspace registration missing"))?;
        let active = self
            .leases
            .observation_markers
            .lock()
            .unwrap()
            .get(&lease)
            .cloned()
            .ok_or_else(|| CoreError::new(ErrorCode::Closed, "workspace view detached"))?;
        Ok(crate::git::observation::ObservationOwner::authenticated(
            self.identity.clone(),
            owner,
            active,
        ))
    }
    pub fn owned_files(
        &self,
        lease: WorkspaceLeaseID,
    ) -> Result<crate::files::OwnedLocalFiles, CoreError> {
        Ok(crate::files::OwnedLocalFiles::new(
            self.files.clone(),
            self.observation_owner(lease)?,
        ))
    }
}
impl EnvironmentService for LocalConnection {
    fn connect(
        &self,
        locator: EnvironmentLocator,
        expected: Option<TargetIdentity>,
    ) -> ServiceFuture<'_, Result<ConnectedEnvironment, CoreError>> {
        Box::pin(async move {
            if locator.route != RouteKind::Local
                || locator.ssh_profile.is_some()
                || locator.engine.is_some()
                || locator.container_selector.is_some()
            {
                return Err(CoreError::new(
                    ErrorCode::Unavailable,
                    "local connection requires local locator",
                ));
            }
            if expected.as_ref().is_some_and(|e| e != &self.identity) {
                return Err(CoreError::new(
                    ErrorCode::TargetChanged,
                    "local target changed",
                ));
            }
            Ok(self.environment())
        })
    }
}
struct Subscription {
    pending: Option<ConnectionState>,
    closed: bool,
    waker: Option<std::task::Waker>,
}
struct States(Arc<Mutex<Subscription>>);
impl Stream for States {
    type Item = Result<ConnectionState, CoreError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut s = self.0.lock().unwrap();
        if let Some(state) = s.pending.take() {
            Poll::Ready(Some(Ok(state)))
        } else if s.closed {
            Poll::Ready(None)
        } else {
            s.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}
struct OwnerState {
    state: ConnectionState,
    subscribers: Vec<std::sync::Weak<Mutex<Subscription>>>,
}
struct Owner(Mutex<OwnerState>, ObservationMarkers);
impl Drop for Owner {
    fn drop(&mut self) {
        for (_, active) in self.1.lock().unwrap().drain() {
            active.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
}
impl Owner {
    fn close_sync(&self, reason: ConnectionCloseReason) {
        if reason == ConnectionCloseReason::WindowDetachment {
            return;
        }
        let mut state = self.0.lock().unwrap();
        for (_, active) in self.1.lock().unwrap().drain() {
            active.store(false, std::sync::atomic::Ordering::SeqCst);
        }
        state.state = ConnectionState::Disconnected;
        state.subscribers.retain(|weak| {
            if let Some(s) = weak.upgrade() {
                let mut s = s.lock().unwrap();
                s.pending = Some(ConnectionState::Disconnected);
                s.closed = true;
                if let Some(w) = s.waker.take() {
                    w.wake();
                }
                true
            } else {
                false
            }
        });
    }
}
impl ConnectionOwner for Owner {
    fn states(&self) -> EventStream<ConnectionState> {
        let mut state = self.0.lock().unwrap();
        let s = Arc::new(Mutex::new(Subscription {
            pending: Some(state.state.clone()),
            closed: state.state == ConnectionState::Disconnected,
            waker: None,
        }));
        state.subscribers.retain(|w| w.strong_count() > 0);
        state.subscribers.push(Arc::downgrade(&s));
        Box::pin(States(s))
    }
    fn close(&self, reason: ConnectionCloseReason) -> ServiceFuture<'_, Result<(), CoreError>> {
        Box::pin(async move {
            self.close_sync(reason);
            Ok(())
        })
    }
}
struct Leases {
    client: ClientID,
    runtime: RuntimeGeneration,
    values: crate::terminal::RegisteredLeases,
    terminal: Arc<crate::terminal::LocalTerminalService>,
    observation_markers: ObservationMarkers,
    owner: Arc<Owner>,
}
impl Leases {
    fn register_sync(&self, lease: WorkspaceLease) -> Result<(), CoreError> {
        let state = self.owner.0.lock().unwrap();
        if state.state != ConnectionState::Ready {
            return Err(CoreError::new(ErrorCode::Closed, "local connection closed"));
        }
        if lease.client != self.client || lease.runtime != self.runtime {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "workspace registration owner/runtime mismatch",
            ));
        }
        let mut values = self.values.lock().unwrap();
        if values.get(&lease.lease).is_some_and(|old| old != &lease) {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "lease already belongs to another workspace",
            ));
        }
        self.observation_markers
            .lock()
            .unwrap()
            .entry(lease.lease)
            .or_insert_with(|| Arc::new(std::sync::atomic::AtomicBool::new(true)));
        values.insert(lease.lease, lease);
        Ok(())
    }
}
impl WorkspaceLeaseService for Leases {
    fn register(&self, lease: WorkspaceLease) -> ServiceFuture<'_, Result<(), CoreError>> {
        Box::pin(async move { self.register_sync(lease) })
    }
    fn release(
        &self,
        id: WorkspaceLeaseID,
        intent: LeaseReleaseIntent,
    ) -> ServiceFuture<'_, Result<(), CoreError>> {
        Box::pin(async move {
            let mut values = self.values.lock().unwrap();
            revoke_marker(&self.observation_markers, id);
            if intent == LeaseReleaseIntent::ViewDetachment {
                return Ok(());
            }
            values.remove(&id);
            drop(values);
            self.terminal.end_owner(id);
            Ok(())
        })
    }
}
