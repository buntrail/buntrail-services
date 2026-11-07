use super::observation::{ObservationOwner, ObservationRecord};
use crate::files::{io_error, private_directory};
use buntrail_core::contracts::*;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{FileExt, OpenOptionsExt},
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

pub(super) const BYTE_LIMIT: u64 = 512 * 1024 * 1024;
const OWNER_LIMIT: usize = 256;
const CAPTURE_LIMIT: usize = 2;
const TTL: Duration = Duration::from_secs(600);
static STORES: OnceLock<Mutex<HashMap<PathBuf, Weak<Store>>>> = OnceLock::new();
#[cfg(test)]
thread_local! {
    static BEFORE_PIN_ADMISSION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static BEFORE_PIN_INSPECTION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static ON_SPOOL_DROP: std::cell::RefCell<Option<Box<dyn Fn()>>> = const { std::cell::RefCell::new(None) };
    static BEFORE_INPUT_ADOPTION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
fn unavailable(message: &str) -> CoreError {
    CoreError::new(ErrorCode::Unavailable, message)
}
fn busy(message: &str) -> CoreError {
    CoreError::new(ErrorCode::Busy, message)
}
fn key(worktree: &WorktreeIdentity) -> [u8; 32] {
    Sha256::digest(serde_json::to_vec(worktree).unwrap()).into()
}

pub(super) struct Store {
    directory: PathBuf,
    budget: Arc<Budget>,
    state: Mutex<State>,
    ttl: Duration,
}
struct Budget {
    bytes: AtomicU64,
    limit: u64,
}
#[derive(Default)]
struct State {
    owners: HashMap<WorkspaceLeaseID, Owner>,
    // Inspect metadata without temporarily owning a descriptor under this lock.
    pins: HashMap<[u8; 32], (ObservationOwner, Weak<Pin>)>,
    data: HashMap<[u8; 32], Weak<Data>>,
    captures: usize,
}
impl State {
    fn has_pin(&self, authority: &ObservationOwner) -> bool {
        self.pins
            .values()
            .any(|(owner, pin)| pin.strong_count() > 0 && owner.same(authority))
    }
    fn owner_slots(&self) -> usize {
        self.owners.len()
            + self
                .pins
                .values()
                .filter(|(authority, pin)| {
                    pin.strong_count() > 0
                        && !self
                            .owners
                            .get(&authority.lease.lease)
                            .is_some_and(|owner| owner.authority.same(authority))
                })
                .count()
    }
}
struct Owner {
    authority: ObservationOwner,
    touched: Instant,
    current: Option<([u8; 16], Arc<Data>)>,
    capturing: Option<[u8; 16]>,
    input: Weak<AtomicBool>,
    plan: Option<Arc<Plan>>,
}
pub(super) struct Plan {
    pub id: [u8; 16],
    pub request_digest: [u8; 32],
    pub operation: OperationID,
    pub alias_digest: [u8; 32],
    pub pin: Arc<Pin>,
    pub approvals: Arc<Spool>,
    // Retain the complete original request without an unbounded metadata clone.
    pub _original_request: Arc<Spool>,
}
pub(super) struct VerificationWork(Arc<Store>);
impl Drop for VerificationWork {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().captures -= 1;
    }
}
pub(super) struct Data {
    pub spool: Arc<Spool>,
    pub worktree: WorktreeIdentity,
    pub expected: GitExpectedState,
}
pub(super) struct Spool {
    file: Option<File>,
    bytes: u64,
    budget: Arc<Budget>,
}
struct RequestWriter<'a> {
    store: &'a Store,
    owner: &'a ObservationOwner,
    spool: &'a mut Spool,
    hash: Sha256,
}
impl Write for RequestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.owner
            .check()
            .map_err(|error| std::io::Error::other(error.message))?;
        self.store
            .write(self.spool, bytes)
            .map_err(|error| std::io::Error::other(error.message))?;
        self.hash.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Drop for Spool {
    fn drop(&mut self) {
        #[cfg(test)]
        ON_SPOOL_DROP.with(|hook| {
            if let Some(hook) = hook.borrow().as_ref() {
                hook();
            }
        });
        drop(self.file.take());
        self.budget.bytes.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}
pub(super) struct Capture {
    pub store: Arc<Store>,
    pub owner: ObservationOwner,
    pub id: [u8; 16],
    pub spool: Option<Spool>,
    hash: Sha256,
}
impl Drop for Capture {
    fn drop(&mut self) {
        let mut state = self.store.state.lock().unwrap();
        state.captures -= 1;
        if let Some(owner) = state.owners.get_mut(&self.owner.lease.lease)
            && owner.capturing == Some(self.id)
        {
            owner.capturing = None;
        }
    }
}
/// Immutable byte-accounted input for later bounded protocol framing. No executable authority.
pub struct ObservationInput {
    store: Arc<Store>,
    pub(super) owner: ObservationOwner,
    pub(super) spool: Arc<Spool>,
    token: Arc<AtomicBool>,
    pub digest: [u8; 32],
}
pub struct ObservationInputWriter {
    store: Arc<Store>,
    owner: ObservationOwner,
    spool: Option<Spool>,
    token: Arc<AtomicBool>,
    hash: Sha256,
    failed: bool,
}
impl Write for ObservationInputWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.append(bytes)
            .map_err(|error| std::io::Error::other(error.message))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl ObservationInputWriter {
    pub fn append(&mut self, bytes: &[u8]) -> Result<(), CoreError> {
        if self.failed {
            return Err(unavailable("proof input write already failed"));
        }
        self.failed = true;
        if let Err(error) = self
            .store
            .check_input(&self.owner, &self.token)
            .and_then(|()| self.store.write(self.spool.as_mut().unwrap(), bytes))
        {
            self.token.store(false, Ordering::SeqCst);
            return Err(error);
        }
        self.hash.update(bytes);
        self.failed = false;
        Ok(())
    }
    pub fn seal(mut self) -> Result<ObservationInput, CoreError> {
        if self.failed {
            return Err(unavailable("failed proof input cannot be sealed"));
        }
        self.store.check_input(&self.owner, &self.token)?;
        Ok(ObservationInput {
            store: self.store.clone(),
            owner: self.owner.clone(),
            spool: Arc::new(self.spool.take().unwrap()),
            token: self.token.clone(),
            digest: self.hash.clone().finalize().into(),
        })
    }
}
impl ObservationInput {
    fn verify_digest(&self) -> Result<(), CoreError> {
        let mut reader = self.reader()?;
        let mut hash = Sha256::new();
        let mut scratch = [0; 64 * 1024];
        loop {
            let count = reader.read(&mut scratch).map_err(io_error)?;
            if count == 0 {
                break;
            }
            hash.update(&scratch[..count]);
        }
        if <[u8; 32]>::from(hash.finalize()) != self.digest {
            return Err(unavailable("sealed proof input digest mismatch"));
        }
        Ok(())
    }
    pub fn reader(&self) -> Result<ObservationInputReader, CoreError> {
        self.store.check_input(&self.owner, &self.token)?;
        Ok(ObservationInputReader {
            store: self.store.clone(),
            token: self.token.clone(),
            owner: self.owner.clone(),
            reader: Cursor {
                spool: self.spool.clone(),
                offset: 0,
            },
        })
    }
    pub fn len(&self) -> u64 {
        self.spool.bytes
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
pub struct ObservationInputReader {
    store: Arc<Store>,
    token: Arc<AtomicBool>,
    owner: ObservationOwner,
    reader: Cursor,
}
impl Read for ObservationInputReader {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.store
            .check_input(&self.owner, &self.token)
            .map_err(|e| std::io::Error::other(e.message))?;
        self.reader.read(bytes)
    }
}
pub(super) struct Cursor {
    pub spool: Arc<Spool>,
    pub offset: u64,
}
impl Read for Cursor {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self
            .spool
            .bytes
            .saturating_sub(self.offset)
            .min(bytes.len() as u64) as usize;
        let n = self
            .spool
            .file
            .as_ref()
            .unwrap()
            .read_at(&mut bytes[..remaining], self.offset)?;
        self.offset += n as u64;
        Ok(n)
    }
}
pub struct ObservationReader {
    store: Arc<Store>,
    owner: ObservationOwner,
    id: [u8; 16],
    cursor: Cursor,
}
impl ObservationReader {
    pub fn next_record(&mut self) -> Result<Option<ObservationRecord>, CoreError> {
        self.store.lookup(&self.owner, self.id)?;
        ObservationRecord::read(&mut self.cursor)
    }
}
pub(super) struct Pin {
    pub data: Arc<Data>,
    owner: ObservationOwner,
    id: [u8; 16],
}
impl Plan {
    pub fn original(&self) -> Cursor {
        Cursor {
            spool: self.pin.data.spool.clone(),
            offset: 0,
        }
    }
    pub fn approvals(&self) -> Cursor {
        Cursor {
            spool: self.approvals.clone(),
            offset: 0,
        }
    }
}
pub struct ObservationPin {
    store: Arc<Store>,
    pin: Arc<Pin>,
}
impl ObservationPin {
    pub fn validate(&self) -> Result<(), CoreError> {
        self.store.lookup(&self.pin.owner, self.pin.id).map(|_| ())
    }
    pub fn reader(&self) -> Result<ObservationReader, CoreError> {
        self.store.reader(&self.pin.owner, self.pin.id)
    }
    pub fn bytes(&self) -> u64 {
        self.pin.data.spool.bytes
    }
    pub fn original_state(&self) -> Result<(&WorktreeIdentity, &GitExpectedState), CoreError> {
        self.validate()?;
        Ok((&self.pin.data.worktree, &self.pin.data.expected))
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct ObservationStorageStats {
    pub bytes: u64,
    pub owners: usize,
    pub captures: usize,
    pub pins: usize,
}

impl Store {
    pub fn input_pair(
        self: &Arc<Self>,
        authority: &ObservationOwner,
    ) -> Result<(ObservationInputWriter, ObservationInputWriter), CoreError> {
        let first = self.input(authority)?;
        let second = ObservationInputWriter {
            store: self.clone(),
            owner: authority.clone(),
            spool: Some(self.spool()?),
            token: first.token.clone(),
            hash: Sha256::new(),
            failed: false,
        };
        Ok((first, second))
    }
    pub fn open(directory: PathBuf) -> Result<Arc<Self>, CoreError> {
        private_directory(&directory)?;
        let directory = fs::canonicalize(directory).map_err(io_error)?;
        let mut stores = STORES
            .get_or_init(Default::default)
            .lock()
            .map_err(io_error)?;
        stores.retain(|_, value| value.strong_count() > 0);
        if let Some(store) = stores.get(&directory).and_then(Weak::upgrade) {
            return Ok(store);
        }
        drop(stores);
        let store = Arc::new(Self {
            directory: directory.clone(),
            budget: Arc::new(Budget {
                bytes: AtomicU64::new(0),
                limit: BYTE_LIMIT,
            }),
            state: Mutex::new(State::default()),
            ttl: TTL,
        });
        store.cleanup_orphans()?;
        let weak = Arc::downgrade(&store);
        std::thread::Builder::new()
            .name("buntrail-observation-reaper".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(100));
                    let Some(store) = weak.upgrade() else { break };
                    store.prune();
                }
            })
            .map_err(io_error)?;
        let mut stores = STORES.get().unwrap().lock().map_err(io_error)?;
        if let Some(existing) = stores.get(&directory).and_then(Weak::upgrade) {
            return Ok(existing);
        }
        stores.insert(directory, Arc::downgrade(&store));
        Ok(store)
    }
    fn disk_lock(&self) -> Result<File, CoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.directory.join("lock"))
            .map_err(io_error)?;
        file.lock().map_err(io_error)?;
        Ok(file)
    }
    fn cleanup_orphans(&self) -> Result<(), CoreError> {
        let _lock = self.disk_lock()?;
        for entry in fs::read_dir(&self.directory).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            if entry.file_name().as_encoded_bytes().starts_with(b".proof-") {
                fs::remove_file(entry.path()).map_err(io_error)?;
            }
        }
        Ok(())
    }
    fn spool(&self) -> Result<Spool, CoreError> {
        let _lock = self.disk_lock()?;
        let temporary = tempfile::Builder::new()
            .prefix(".proof-")
            .tempfile_in(&self.directory)
            .map_err(io_error)?;
        #[cfg(test)]
        if std::env::var("BUNTRAIL_PROOF_CRASH_STAGE").as_deref() == Ok("before_unlink") {
            fs::write(
                std::env::var("BUNTRAIL_PROOF_CRASH_SIGNAL").unwrap(),
                b"ready",
            )
            .unwrap();
            loop {
                std::thread::park();
            }
        }
        // The creation/unlink window is serialized with startup orphan cleanup.
        let (file, path) = temporary.into_parts();
        path.close().map_err(io_error)?;
        Ok(Spool {
            file: Some(file),
            bytes: 0,
            budget: self.budget.clone(),
        })
    }
    pub fn prune(&self) {
        let removed = {
            let mut state = self.state.lock().unwrap();
            state.pins.retain(|_, (_, pin)| pin.strong_count() > 0);
            state.data.retain(|_, data| data.strong_count() > 0);
            let ids: Vec<_> = state
                .owners
                .iter()
                .filter(|(_, value)| {
                    !value.authority.active.load(Ordering::SeqCst)
                        || value.touched.elapsed() >= self.ttl
                })
                .map(|(id, _)| *id)
                .collect();
            ids.into_iter()
                .filter_map(|id| state.owners.remove(&id))
                .collect::<Vec<_>>()
        };
        drop(removed);
    }
    fn owner<'a>(
        &self,
        state: &'a mut State,
        authority: &ObservationOwner,
    ) -> Result<&'a mut Owner, CoreError> {
        authority.check()?;
        if let Some(old) = state.owners.get(&authority.lease.lease)
            && !old.authority.same(authority)
        {
            return Err(busy("old registration is retiring"));
        }
        if !state.owners.contains_key(&authority.lease.lease)
            && !state.has_pin(authority)
            && state.owner_slots() >= OWNER_LIMIT
        {
            return Err(busy("retained observation owner capacity reached"));
        }
        Ok(state
            .owners
            .entry(authority.lease.lease)
            .or_insert_with(|| Owner {
                authority: authority.clone(),
                touched: Instant::now(),
                current: None,
                capturing: None,
                input: Weak::new(),
                plan: None,
            }))
    }
    pub fn input(
        self: &Arc<Self>,
        authority: &ObservationOwner,
    ) -> Result<ObservationInputWriter, CoreError> {
        self.prune();
        let token = Arc::new(AtomicBool::new(true));
        {
            let mut state = self.state.lock().map_err(io_error)?;
            let owner = self.owner(&mut state, authority)?;
            if owner.input.strong_count() != 0 {
                return Err(busy("owner already retains a proof input"));
            }
            owner.input = Arc::downgrade(&token);
            owner.touched = Instant::now();
        }
        Ok(ObservationInputWriter {
            store: self.clone(),
            owner: authority.clone(),
            spool: Some(self.spool()?),
            token,
            hash: Sha256::new(),
            failed: false,
        })
    }
    fn check_input(
        &self,
        authority: &ObservationOwner,
        token: &Arc<AtomicBool>,
    ) -> Result<(), CoreError> {
        authority.check()?;
        if !token.load(Ordering::SeqCst) {
            return Err(unavailable("proof input part failed"));
        }
        let state = self.state.lock().map_err(io_error)?;
        if state
            .owners
            .get(&authority.lease.lease)
            .is_some_and(|owner| {
                owner.authority.same(authority)
                    && owner.touched.elapsed() < self.ttl
                    && owner
                        .input
                        .upgrade()
                        .is_some_and(|known| Arc::ptr_eq(&known, token))
            })
        {
            Ok(())
        } else {
            Err(unavailable("proof input expired or registration changed"))
        }
    }
    pub fn begin(self: &Arc<Self>, authority: &ObservationOwner) -> Result<Capture, CoreError> {
        self.prune();
        let id = crate::connections::local::new_id()?;
        let old = {
            let mut state = self.state.lock().map_err(io_error)?;
            if state.captures >= CAPTURE_LIMIT {
                return Err(busy("two observation captures are already running"));
            }
            if state.pins.values().any(|(owner, pin)| {
                #[cfg(test)]
                BEFORE_PIN_INSPECTION.with(|hook| {
                    if let Some(hook) = hook.borrow_mut().take() {
                        hook();
                    }
                });
                pin.strong_count() > 0 && owner.same(authority)
            }) {
                return Err(busy("owner observation is pinned"));
            }
            let owner = self.owner(&mut state, authority)?;
            if owner.capturing.is_some() {
                return Err(busy("owner observation capture is running"));
            }
            owner.capturing = Some(id);
            owner.touched = Instant::now();
            let old = owner.current.take();
            state.captures += 1;
            old
        };
        drop(old);
        let mut capture = Capture {
            store: self.clone(),
            owner: authority.clone(),
            id,
            spool: None,
            hash: Sha256::new(),
        };
        capture.spool = Some(self.spool()?);
        Ok(capture)
    }
    fn reserve(&self, amount: u64) -> Result<(), CoreError> {
        loop {
            let current = self.budget.bytes.load(Ordering::SeqCst);
            if amount <= self.budget.limit.saturating_sub(current) {
                if self
                    .budget
                    .bytes
                    .compare_exchange(
                        current,
                        current + amount,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    )
                    .is_ok()
                {
                    return Ok(());
                }
                continue;
            }
            let removed = {
                let mut state = self.state.lock().map_err(io_error)?;
                let candidate = state
                    .owners
                    .iter()
                    .filter(|(_, owner)| {
                        owner.current.is_some()
                            && owner.capturing.is_none()
                            && !state.pins.values().any(|(authority, pin)| {
                                pin.strong_count() > 0 && authority.same(&owner.authority)
                            })
                    })
                    .min_by_key(|(_, owner)| owner.touched)
                    .map(|(id, _)| *id);
                candidate.and_then(|id| state.owners.get_mut(&id).unwrap().current.take())
            };
            if removed.is_none() {
                return Err(busy("retained proof byte capacity reached"));
            }
            drop(removed);
        }
    }
    fn write(&self, spool: &mut Spool, bytes: &[u8]) -> Result<(), CoreError> {
        self.reserve(bytes.len() as u64)?;
        spool.bytes += bytes.len() as u64;
        spool
            .file
            .as_mut()
            .unwrap()
            .write_all(bytes)
            .map_err(io_error)
    }
    pub fn lookup(
        &self,
        authority: &ObservationOwner,
        id: [u8; 16],
    ) -> Result<Arc<Data>, CoreError> {
        let state = self.state.lock().map_err(io_error)?;
        self.lookup_locked(&state, authority, id)
    }
    fn lookup_locked(
        &self,
        state: &State,
        authority: &ObservationOwner,
        id: [u8; 16],
    ) -> Result<Arc<Data>, CoreError> {
        authority.check()?;
        let owner = state
            .owners
            .get(&authority.lease.lease)
            .filter(|o| o.authority.same(authority) && o.touched.elapsed() < self.ttl)
            .ok_or_else(|| unavailable("original observation expired or registration changed"))?;
        owner
            .current
            .as_ref()
            .filter(|(known, _)| *known == id)
            .map(|(_, data)| data.clone())
            .ok_or_else(|| unavailable("original observation was released or evicted"))
    }
    pub fn reader(
        self: &Arc<Self>,
        authority: &ObservationOwner,
        id: [u8; 16],
    ) -> Result<ObservationReader, CoreError> {
        let data = self.lookup(authority, id)?;
        Ok(ObservationReader {
            store: self.clone(),
            owner: authority.clone(),
            id,
            cursor: Cursor {
                spool: data.spool.clone(),
                offset: 0,
            },
        })
    }
    pub fn pin(
        self: &Arc<Self>,
        authority: &ObservationOwner,
        id: [u8; 16],
    ) -> Result<ObservationPin, CoreError> {
        #[cfg(test)]
        BEFORE_PIN_ADMISSION.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
        let mut state = self.state.lock().map_err(io_error)?;
        let data = self.lookup_locked(&state, authority, id)?;
        let worktree = key(&data.worktree);
        if state
            .pins
            .get(&worktree)
            .is_some_and(|(_, pin)| pin.strong_count() > 0)
        {
            return Err(busy("worktree observation is already pinned"));
        }
        if state
            .pins
            .values()
            .any(|(owner, pin)| pin.strong_count() > 0 && owner.same(authority))
        {
            return Err(busy("owner already has a pinned observation"));
        }
        let pin = Arc::new(Pin {
            data,
            owner: authority.clone(),
            id,
        });
        state
            .pins
            .insert(worktree, (authority.clone(), Arc::downgrade(&pin)));
        Ok(ObservationPin {
            store: self.clone(),
            pin,
        })
    }
    pub fn release(&self, authority: &ObservationOwner, id: [u8; 16]) {
        let (old, removed, retired) = {
            let mut state = self.state.lock().unwrap();
            let mut retired = None;
            let old = state
                .owners
                .get_mut(&authority.lease.lease)
                .filter(|o| o.authority.same(authority))
                .and_then(|o| {
                    if o.current.as_ref().is_some_and(|(known, _)| *known == id) {
                        retired = o.plan.take();
                        o.input = Weak::new();
                        o.current.take()
                    } else {
                        None
                    }
                });
            let remove = old.is_some()
                && state
                    .owners
                    .get(&authority.lease.lease)
                    .is_some_and(|o| o.capturing.is_none() && o.input.strong_count() == 0);
            let removed = if remove {
                state.owners.remove(&authority.lease.lease)
            } else {
                None
            };
            (old, removed, retired)
        };
        drop(old);
        drop(removed);
        drop(retired);
    }
    pub fn stats(&self) -> ObservationStorageStats {
        let state = self.state.lock().unwrap();
        ObservationStorageStats {
            bytes: self.budget.bytes.load(Ordering::SeqCst),
            owners: state.owner_slots(),
            captures: state.captures,
            pins: state
                .pins
                .values()
                .filter(|(_, pin)| pin.strong_count() > 0)
                .count(),
        }
    }

    pub(super) fn adopt_plan(
        self: &Arc<Self>,
        authority: &ObservationOwner,
        pin: ObservationPin,
        original: &GitMutationRequest,
        alias_digest: [u8; 32],
        input: ObservationInput,
    ) -> Result<Arc<Plan>, CoreError> {
        if !input.owner.same(authority) {
            return Err(unavailable(
                "sealed plan input belongs to another registration",
            ));
        }
        if pin.pin.data.worktree != original.worktree || pin.pin.data.expected != original.expected
        {
            return Err(unavailable(
                "original request differs from retained observation",
            ));
        }
        input.verify_digest()?;
        let mut request = self.spool()?;
        let request_digest = {
            let mut writer = std::io::BufWriter::with_capacity(
                64 * 1024,
                RequestWriter {
                    store: self,
                    owner: authority,
                    spool: &mut request,
                    hash: Sha256::new(),
                },
            );
            serde_json::to_writer(&mut writer, original).map_err(io_error)?;
            writer.flush().map_err(io_error)?;
            <[u8; 32]>::from(writer.get_ref().hash.clone().finalize())
        };
        let plan = Arc::new(Plan {
            id: crate::connections::local::new_id()?,
            request_digest,
            operation: original.operation,
            alias_digest,
            pin: pin.pin.clone(),
            approvals: input.spool.clone(),
            _original_request: Arc::new(request),
        });
        #[cfg(test)]
        BEFORE_INPUT_ADOPTION.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
        let mut state = self.state.lock().map_err(io_error)?;
        self.lookup_locked(&state, authority, pin.pin.id)?;
        let owner = state.owners.get_mut(&authority.lease.lease).unwrap();
        if owner.plan.is_some()
            || !input.token.load(Ordering::SeqCst)
            || !input.owner.same(authority)
            || !owner
                .input
                .upgrade()
                .is_some_and(|token| Arc::ptr_eq(&token, &input.token))
        {
            return Err(unavailable(
                "plan input is not the current sealed owner input",
            ));
        }
        owner.input = Weak::new();
        owner.plan = Some(plan.clone());
        drop(state);
        Ok(plan)
    }
    pub(super) fn plan(
        &self,
        authority: &ObservationOwner,
        id: [u8; 16],
    ) -> Result<Arc<Plan>, CoreError> {
        authority.check()?;
        let state = self.state.lock().map_err(io_error)?;
        let plan = state
            .owners
            .get(&authority.lease.lease)
            .filter(|owner| owner.authority.same(authority) && owner.touched.elapsed() < self.ttl)
            .and_then(|owner| owner.plan.as_ref())
            .filter(|plan| plan.id == id)
            .ok_or_else(|| unavailable("prepared worktree plan expired or was released"))?;
        self.lookup_locked(&state, authority, plan.pin.id)?;
        Ok(plan.clone())
    }
    pub(super) fn adopt_execution_input(
        &self,
        authority: &ObservationOwner,
        input: ObservationInput,
    ) -> Result<Arc<Spool>, CoreError> {
        if !input.owner.same(authority) {
            return Err(unavailable(
                "sealed execution input belongs to another registration",
            ));
        }
        input.verify_digest()?;
        self.check_input(authority, &input.token)?;
        let mut state = self.state.lock().map_err(io_error)?;
        let owner = state
            .owners
            .get_mut(&authority.lease.lease)
            .ok_or_else(|| unavailable("input owner retired"))?;
        authority.check()?;
        if !owner.authority.same(authority)
            || owner.touched.elapsed() >= self.ttl
            || !input.token.load(Ordering::SeqCst)
            || !input.owner.same(authority)
            || !owner
                .input
                .upgrade()
                .is_some_and(|token| Arc::ptr_eq(&token, &input.token))
        {
            return Err(unavailable(
                "execution input is not the current sealed owner input",
            ));
        }
        owner.input = Weak::new();
        drop(state);
        Ok(input.spool.clone())
    }
    pub(super) fn verification(self: &Arc<Self>) -> Result<VerificationWork, CoreError> {
        let mut state = self.state.lock().map_err(io_error)?;
        if state.captures >= CAPTURE_LIMIT {
            return Err(busy("two proof observations are already running"));
        }
        state.captures += 1;
        Ok(VerificationWork(self.clone()))
    }
    pub(super) fn cancel_plan(&self, authority: &ObservationOwner, id: [u8; 16]) {
        let retired = {
            let mut state = self.state.lock().unwrap();
            state
                .owners
                .get_mut(&authority.lease.lease)
                .filter(|owner| owner.authority.same(authority))
                .and_then(|owner| {
                    if owner.plan.as_ref().is_some_and(|plan| plan.id == id) {
                        owner.input = Weak::new();
                        owner.plan.take()
                    } else {
                        None
                    }
                })
        };
        drop(retired);
    }
}
impl Capture {
    pub fn append(&mut self, record: &ObservationRecord) -> Result<(), CoreError> {
        self.owner.check()?;
        let bytes = record.encode()?;
        self.store.write(self.spool.as_mut().unwrap(), &bytes)?;
        self.hash.update(&bytes);
        Ok(())
    }
    pub fn cursor(&self) -> Result<CaptureCursor<'_>, CoreError> {
        let spool = self.spool.as_ref().unwrap();
        Ok(CaptureCursor {
            file: spool.file.as_ref().unwrap(),
            bytes: spool.bytes,
            offset: 0,
        })
    }
    pub fn publish(mut self, snapshot: &GitSnapshot) -> Result<u64, CoreError> {
        self.owner.check()?;
        self.hash
            .update(serde_json::to_vec(&(&snapshot.worktree, &snapshot.state)).map_err(io_error)?);
        let digest: [u8; 32] = self.hash.clone().finalize().into();
        let mut state = self.store.state.lock().map_err(io_error)?;
        let owner = state
            .owners
            .get(&self.owner.lease.lease)
            .filter(|owner| {
                owner.authority.same(&self.owner)
                    && owner.capturing == Some(self.id)
                    && owner.touched.elapsed() < self.store.ttl
            })
            .ok_or_else(|| unavailable("observation registration expired during capture"))?;
        owner.authority.check()?;
        let data = if let Some(data) = state.data.get(&digest).and_then(Weak::upgrade) {
            data
        } else {
            let data = Arc::new(Data {
                spool: Arc::new(self.spool.take().unwrap()),
                worktree: snapshot.worktree.clone(),
                expected: snapshot.state.clone(),
            });
            state.data.insert(digest, Arc::downgrade(&data));
            data
        };
        let bytes = data.spool.bytes;
        state
            .owners
            .get_mut(&self.owner.lease.lease)
            .unwrap()
            .current = Some((self.id, data));
        Ok(bytes)
    }
}

pub(super) struct CaptureCursor<'a> {
    file: &'a File,
    bytes: u64,
    offset: u64,
}
impl Read for CaptureCursor<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let length = self
            .bytes
            .saturating_sub(self.offset)
            .min(bytes.len() as u64) as usize;
        let n = self.file.read_at(&mut bytes[..length], self.offset)?;
        self.offset += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
pub(super) mod testing {
    use super::*;
    pub fn expire_owner(store: &Store, authority: &ObservationOwner) {
        {
            let mut state = store.state.lock().unwrap();
            let owner = state.owners.get_mut(&authority.lease.lease).unwrap();
            assert!(owner.authority.same(authority));
            owner.touched = Instant::now() - store.ttl;
        }
        store.prune();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::local::LocalConnection;
    #[test]
    fn paired_failure_between_seal_verification_and_adoption_cannot_publish_plan() {
        let (_dir, _local, store, owner) = fixture(8192, TTL);
        let id = capture(&store, &owner, 0);
        let (mut first, second) = store.input_pair(&owner).unwrap();
        let approvals = second.seal().unwrap();
        BEFORE_INPUT_ADOPTION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                assert!(first.append(&[0; 8192]).is_err());
            }))
        });
        assert!(
            store
                .adopt_plan(
                    &owner,
                    store.pin(&owner, id).unwrap(),
                    &original_request(&owner),
                    [3; 32],
                    approvals
                )
                .is_err(),
            "poisoned pair was adopted after its seal was checked"
        );
        store.release(&owner, id);
        assert_eq!(store.stats().bytes, 0);
    }
    #[test]
    fn paired_inputs_share_admission_and_poison_on_either_failed_write() {
        for failed_part in [0, 1] {
            let (_dir, _local, store, owner) = fixture(7, TTL);
            let (mut original, mut approvals) = store
                .input_pair(&owner)
                .expect("two charged parts must share one admission");
            original.append(b"orig").unwrap();
            approvals.append(b"yes").unwrap();
            assert_eq!(store.stats().bytes, 7);
            assert!(store.input(&owner).is_err());
            if failed_part == 0 {
                assert!(original.append(b"!").is_err());
            } else {
                assert!(approvals.append(b"!").is_err());
            }
            assert!(
                original.seal().is_err(),
                "failed pair retained original authority"
            );
            assert!(
                approvals.seal().is_err(),
                "failed pair retained approval authority"
            );
            assert_eq!(store.stats().bytes, 0);
            store.input(&owner).unwrap();
        }
    }
    #[test]
    fn paired_adoption_retires_both_readers_and_keeps_actual_descriptor_charge() {
        let (_dir, _local, store, owner) = fixture(8192, TTL);
        let id = capture(&store, &owner, 0);
        let (mut original, approvals) = store.input_pair(&owner).unwrap();
        original.append(b"original").unwrap();
        let original = original.seal().unwrap();
        let approvals = approvals.seal().unwrap();
        let mut old_original = original.reader().unwrap();
        let mut old_approvals = approvals.reader().unwrap();
        let plan = store
            .adopt_plan(
                &owner,
                store.pin(&owner, id).unwrap(),
                &original_request(&owner),
                [3; 32],
                approvals,
            )
            .unwrap();
        assert!(old_original.read(&mut [0; 1]).is_err());
        assert!(old_approvals.read(&mut [0; 1]).is_err());
        let later = store.input(&owner).unwrap().seal().unwrap();
        store.release(&owner, id);
        drop(plan);
        drop(later);
        drop(original);
        drop(old_approvals);
        assert_eq!(store.stats().bytes, 8, "old descriptor must retain charge");
        drop(old_original);
        assert_eq!(store.stats().bytes, 0);
    }
    #[test]
    fn paired_drop_order_expiry_and_revocation_do_not_create_a_second_slot() {
        for first in [true, false] {
            let (_dir, _local, store, owner) = fixture(8192, TTL);
            let (a, b) = store.input_pair(&owner).unwrap();
            let survivor = if first {
                drop(a);
                b
            } else {
                drop(b);
                a
            };
            assert!(store.input_pair(&owner).is_err());
            drop(survivor);
            let (mut a, mut b) = store.input_pair(&owner).unwrap();
            a.append(b"a").unwrap();
            b.append(b"b").unwrap();
            if first {
                testing::expire_owner(&store, &owner);
            } else {
                owner.active.store(false, Ordering::SeqCst);
                store.prune();
            }
            assert!(a.seal().is_err());
            assert!(b.seal().is_err());
            assert_eq!(store.stats().bytes, 0);
        }
    }
    #[test]
    fn plan_adoption_retires_upload_authority_but_preserves_readers_and_charge() {
        let (_dir, _local, store, owner) = fixture(8192, TTL);
        let id = capture(&store, &owner, 0);
        let mut input = store.input(&owner).unwrap();
        input.append(b"proof").unwrap();
        let input = input.seal().unwrap();
        let mut old_reader = input.reader().unwrap();
        let plan = store
            .adopt_plan(
                &owner,
                store.pin(&owner, id).unwrap(),
                &original_request(&owner),
                [3; 32],
                input,
            )
            .unwrap();
        assert_eq!(
            store.stats().bytes,
            49 + serde_json::to_vec(&original_request(&owner)).unwrap().len() as u64
        );
        assert!(old_reader.read(&mut [0; 1]).is_err());
        let later = store.input(&owner).unwrap().seal().unwrap();
        store.release(&owner, id);
        drop(plan);
        assert_eq!(
            store.stats().bytes,
            5,
            "release must retire plan despite a later live input"
        );
        assert!(later.reader().is_err());
        drop(later);
        drop(old_reader);
        assert_eq!(store.stats().bytes, 0);
    }
    #[test]
    fn cancel_plan_is_admission_free_and_retires_its_later_upload() {
        let (_dir, _local, mut store, owner) = fixture(8192, TTL);
        let request_bytes = serde_json::to_vec(&original_request(&owner)).unwrap().len() as u64;
        Arc::get_mut(&mut Arc::get_mut(&mut store).unwrap().budget)
            .unwrap()
            .limit = 45 + request_bytes;
        let id = capture(&store, &owner, 0);
        let mut input = store.input(&owner).unwrap();
        input.append(b"x").unwrap();
        let plan = store
            .adopt_plan(
                &owner,
                store.pin(&owner, id).unwrap(),
                &original_request(&owner),
                [3; 32],
                input.seal().unwrap(),
            )
            .unwrap();
        let later = store.input(&owner).unwrap().seal().unwrap();
        store.cancel_plan(&owner, plan.id);
        store.cancel_plan(&owner, plan.id);
        assert!(
            later.reader().is_err(),
            "cancel left a plan's later upload authoritative"
        );
        assert_eq!(
            store.stats().bytes,
            45 + request_bytes,
            "executing/retained data lost its charge"
        );
        store.release(&owner, id);
        drop(plan);
        drop(later);
        assert_eq!(store.stats().bytes, 0);
    }
    #[test]
    fn plan_expiry_does_not_renew_on_lookup_or_free_executing_descriptors() {
        let (_dir, _local, store, owner) = fixture(8192, TTL);
        let id = capture(&store, &owner, 0);
        let plan = store
            .adopt_plan(
                &owner,
                store.pin(&owner, id).unwrap(),
                &original_request(&owner),
                [3; 32],
                store.input(&owner).unwrap().seal().unwrap(),
            )
            .unwrap();
        let touched = store.state.lock().unwrap().owners[&owner.lease.lease].touched;
        store.plan(&owner, plan.id).unwrap();
        assert_eq!(
            store.state.lock().unwrap().owners[&owner.lease.lease].touched,
            touched
        );
        store
            .state
            .lock()
            .unwrap()
            .owners
            .get_mut(&owner.lease.lease)
            .unwrap()
            .touched = Instant::now() - TTL;
        assert!(store.plan(&owner, plan.id).is_err());
        store.prune();
        assert_eq!(
            store.stats().bytes,
            44 + serde_json::to_vec(&original_request(&owner)).unwrap().len() as u64
        );
        assert_eq!(store.stats().owners, 1);
        let mut executing = plan.original();
        drop(plan);
        assert!(ObservationRecord::read(&mut executing).unwrap().is_some());
        assert_eq!(store.stats().bytes, 44);
        drop(executing);
        store.prune();
        assert_eq!(store.stats().bytes, 0);
        assert_eq!(store.stats().owners, 0);
    }
    #[test]
    fn verification_work_uses_capture_slots_without_refreshing_the_pin() {
        let (_dir, _local, store, owner) = fixture(1024, TTL);
        let id = capture(&store, &owner, 0);
        let pin = store.pin(&owner, id).unwrap();
        let first = store.verification().unwrap();
        let second = store.verification().unwrap();
        assert!(store.verification().is_err());
        assert_eq!(store.stats().captures, 2);
        pin.validate().unwrap();
        drop(first);
        drop(second);
        assert_eq!(store.stats().captures, 0);
        pin.validate().unwrap();
    }
    #[test]
    fn sealed_input_digest_must_match_the_adopted_immutable_bytes() {
        let (_dir, _local, store, owner) = fixture(1024, TTL);
        let id = capture(&store, &owner, 0);
        let mut input = store.input(&owner).unwrap().seal().unwrap();
        input.digest[0] ^= 1;
        assert!(
            store
                .adopt_plan(
                    &owner,
                    store.pin(&owner, id).unwrap(),
                    &original_request(&owner),
                    [3; 32],
                    input
                )
                .is_err(),
            "plan accepted a mismatched sealed input digest"
        );
        assert_eq!(store.stats().bytes, 44);
        assert_eq!(store.stats().pins, 0);
    }
    #[test]
    fn last_pin_retirement_never_closes_a_spool_under_the_cache_lock() {
        let (_dir, local, store, owner) = fixture(1024, TTL);
        let id = capture(&store, &owner, 0);
        let pin = store.pin(&owner, id).unwrap();
        store.release(&owner, id);
        let sibling = WorkspaceLeaseID([2; 16]);
        local.register(WorkspaceID([2; 16]), sibling).unwrap();
        let sibling = local.observation_owner(sibling).unwrap();
        let (release, released) = std::sync::mpsc::channel();
        let (done, completed) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            released.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(pin);
            done.send(()).unwrap();
        });
        BEFORE_PIN_INSPECTION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                release.send(()).unwrap();
                completed.recv_timeout(Duration::from_secs(5)).unwrap();
            }))
        });
        let (observed, observations) = std::sync::mpsc::channel();
        let inspected = store.clone();
        ON_SPOOL_DROP.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                observed.send(inspected.state.try_lock().is_ok()).unwrap();
            }))
        });
        drop(store.begin(&sibling).unwrap());
        worker.join().unwrap();
        ON_SPOOL_DROP.with(|hook| {
            hook.borrow_mut().take();
        });
        assert!(
            observations.try_iter().all(|unlocked| unlocked),
            "last pin closed its descriptor under cache metadata lock"
        );
        assert_eq!(store.stats().bytes, 0);
    }
    #[test]
    fn failed_input_write_cannot_seal_partial_bytes_as_complete_input() {
        let (dir, _local, store, owner) = fixture(1024, TTL);
        let mut writer = store.input(&owner).unwrap();
        writer.append(b"accepted").unwrap();
        let read_only = dir.path().join("read-only");
        fs::write(&read_only, b"accepted").unwrap();
        writer.spool.as_mut().unwrap().file = Some(File::open(read_only).unwrap());
        assert!(writer.append(b"unwritten").is_err());
        assert!(
            writer.append(b"retry").is_err(),
            "failed input accepted a retry"
        );
        assert!(
            writer.seal().is_err(),
            "failed proof write sealed incomplete bytes"
        );
        assert_eq!(store.stats().bytes, 0);
    }
    #[test]
    fn sealed_inputs_share_capture_quota_and_keep_independent_reader_lifetimes() {
        let (_dir, local, store, owner) = fixture(50, TTL);
        let mut writer = store.input(&owner).unwrap();
        writer.append(b"abc").unwrap();
        writer.append(b"def").unwrap();
        let input = writer.seal().unwrap();
        assert_eq!(input.len(), 6);
        assert_eq!(input.digest, <[u8; 32]>::from(Sha256::digest(b"abcdef")));
        let id = capture(&store, &owner, 0);
        let pin = store.pin(&owner, id).unwrap();
        assert_eq!(store.stats().bytes, 50);
        let sibling = WorkspaceLeaseID([2; 16]);
        local.register(WorkspaceID([2; 16]), sibling).unwrap();
        let mut blocked = store
            .input(&local.observation_owner(sibling).unwrap())
            .unwrap();
        assert!(blocked.append(b"x").is_err());
        drop(blocked);
        let mut first = input.reader().unwrap();
        let mut second = input.reader().unwrap();
        let mut prefix = [0; 3];
        first.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"abc");
        let mut complete = Vec::new();
        second.read_to_end(&mut complete).unwrap();
        assert_eq!(&complete, b"abcdef");
        drop(input);
        assert!(store.input(&owner).is_err());
        first.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"def");
        drop(first);
        drop(second);
        assert_eq!(store.stats().bytes, 44);
        store.release(&owner, id);
        drop(pin);
        assert_eq!(store.stats().bytes, 0);
    }
    #[test]
    fn released_or_refreshed_observation_cannot_win_pin_admission() {
        for refresh in [false, true] {
            let (_dir, _local, store, owner) = fixture(1024, TTL);
            let original = capture(&store, &owner, 0);
            let raced_store = store.clone();
            let raced_owner = owner.clone();
            BEFORE_PIN_ADMISSION.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    if refresh {
                        capture(&raced_store, &raced_owner, 0);
                    } else {
                        raced_store.release(&raced_owner, original);
                    }
                }))
            });
            assert!(
                store.pin(&owner, original).is_err(),
                "stale lookup won pin admission"
            );
            assert_eq!(store.stats().pins, 0);
            assert_eq!(store.stats().captures, 0);
        }
    }
    fn fixture(
        limit: u64,
        ttl: Duration,
    ) -> (
        tempfile::TempDir,
        LocalConnection,
        Arc<Store>,
        ObservationOwner,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let local = LocalConnection::open(dir.path().join("state")).unwrap();
        let id = WorkspaceLeaseID([1; 16]);
        local.register(WorkspaceID([1; 16]), id).unwrap();
        let owner = local.observation_owner(id).unwrap();
        let directory = dir.path().join("bounded");
        private_directory(&directory).unwrap();
        let store = Arc::new(Store {
            directory,
            budget: Arc::new(Budget {
                bytes: AtomicU64::new(0),
                limit,
            }),
            state: Mutex::new(State::default()),
            ttl,
        });
        (dir, local, store, owner)
    }
    fn original_request(owner: &ObservationOwner) -> GitMutationRequest {
        let original = snapshot(owner, 0);
        GitMutationRequest {
            operation: OperationID([2; 16]),
            worktree: original.worktree,
            expected: original.state,
            command: GitMutation::Checkout {
                reference: b"main".to_vec(),
            },
        }
    }
    fn snapshot(owner: &ObservationOwner, n: u8) -> GitSnapshot {
        GitSnapshot {
            worktree: WorktreeIdentity {
                target: owner.target.clone(),
                canonical_path: TargetPath::posix(vec![b'/', b'a' + n]).unwrap(),
                common_git_directory_identity: vec![1],
            },
            state: GitExpectedState {
                head: GitHead::Unborn(b"main".to_vec()),
                index_fingerprint: [1; 32],
                worktree_fingerprint: [n; 32],
            },
            staged: vec![],
            unstaged: vec![],
            untracked: vec![],
            conflicts: vec![],
        }
    }
    fn record() -> ObservationRecord {
        ObservationRecord {
            path: TargetPath::posix(b"/a".to_vec()).unwrap(),
            structural_token: [1; 32],
            resolved: None,
            regular: None,
            membership: None,
            file_reference: None,
        }
    }
    fn capture(store: &Arc<Store>, owner: &ObservationOwner, n: u8) -> [u8; 16] {
        let mut capture = store.begin(owner).unwrap();
        capture.append(&record()).unwrap();
        let id = capture.id;
        capture.publish(&snapshot(owner, n)).unwrap();
        id
    }
    #[test]
    fn expired_input_cannot_be_read_or_extended_after_owner_cleanup() {
        let (_dir, _local, store, owner) = fixture(1024, TTL);
        let mut input = store.input(&owner).unwrap();
        input.append(b"original").unwrap();
        let input = input.seal().unwrap();
        store
            .state
            .lock()
            .unwrap()
            .owners
            .get_mut(&owner.lease.lease)
            .unwrap()
            .touched = Instant::now() - TTL;
        store.prune();
        assert!(
            input.reader().is_err(),
            "expired proof input retained authority"
        );
        assert_eq!(
            store.stats().bytes,
            8,
            "live descriptor lost byte accounting"
        );
        drop(input);
        assert_eq!(store.stats().bytes, 0);
    }
    #[test]
    fn explicit_release_frees_owner_slot_without_lifetime_tombstones() {
        let (_dir, local, store, _owner) = fixture(1024, TTL);
        for n in 0..257u16 {
            let mut bytes = [0; 16];
            bytes[..2].copy_from_slice(&n.to_be_bytes());
            let id = WorkspaceLeaseID(bytes);
            local.register(WorkspaceID(bytes), id).unwrap();
            let owner = local.observation_owner(id).unwrap();
            let observed = capture(&store, &owner, 0);
            store.release(&owner, observed);
        }
        assert_eq!(store.stats().owners, 0);
    }
    #[test]
    fn released_live_pins_cannot_escape_the_owner_metadata_limit() {
        let (_dir, local, store, _) = fixture(0, TTL);
        let mut pins = Vec::new();
        for n in 0..OWNER_LIMIT {
            let mut bytes = [0; 16];
            bytes[..2].copy_from_slice(&(n as u16).to_be_bytes());
            let id = WorkspaceLeaseID(bytes);
            local.register(WorkspaceID(bytes), id).unwrap();
            let owner = local.observation_owner(id).unwrap();
            let captured = store.begin(&owner).unwrap();
            let id = captured.id;
            let mut observed = snapshot(&owner, 0);
            observed.worktree.canonical_path =
                TargetPath::posix(format!("/worktree-{n}").into_bytes()).unwrap();
            captured.publish(&observed).unwrap();
            pins.push(store.pin(&owner, id).unwrap());
            store.release(&owner, id);
            if n + 1 == OWNER_LIMIT {
                assert!(
                    store.begin(&owner).is_err(),
                    "release bypassed live owner pin"
                );
                drop(store.input(&owner).unwrap());
                assert_eq!(
                    store.stats().owners,
                    OWNER_LIMIT,
                    "same owner counted twice"
                );
            }
            local.release(owner.registration().lease);
            store.prune();
        }
        assert_eq!(store.stats().bytes, 0);
        let old_id = WorkspaceLeaseID([0; 16]);
        local.register(WorkspaceID([0; 16]), old_id).unwrap();
        let renewed = local.observation_owner(old_id).unwrap();
        assert!(
            store.input(&renewed).is_err(),
            "new registration merged old pin metadata"
        );
        assert!(store.begin(&renewed).is_err());
        let id = WorkspaceLeaseID([255; 16]);
        local.register(WorkspaceID([255; 16]), id).unwrap();
        let owner = local.observation_owner(id).unwrap();
        assert!(
            store.begin(&owner).is_err(),
            "live pin metadata escaped owner limit"
        );
        assert_eq!(store.stats().owners, OWNER_LIMIT);
        drop(pins);
        store.prune();
        assert_eq!(store.stats().owners, 0);
        drop(store.begin(&owner).unwrap());
    }
    #[test]
    fn capacity_refresh_drops_old_data_and_failure_does_not_restore_it() {
        let (_dir, _local, store, owner) = fixture(44, TTL);
        let first = capture(&store, &owner, 0);
        assert_eq!(store.stats().bytes, 44);
        let mut refreshed = store.begin(&owner).unwrap();
        assert!(store.lookup(&owner, first).is_err());
        refreshed.append(&record()).unwrap();
        assert!(refreshed.append(&record()).is_err());
        drop(refreshed);
        assert!(store.lookup(&owner, first).is_err());
        assert_eq!(store.stats().bytes, 0);
        assert_eq!(store.stats().captures, 0);
    }
    #[test]
    fn pinned_reader_retains_actual_bytes_and_uses_independent_offsets() {
        let (_dir, local, store, owner) = fixture(88, TTL);
        let id = capture(&store, &owner, 0);
        let pin = store.pin(&owner, id).unwrap();
        let mut a = pin.reader().unwrap();
        let mut b = pin.reader().unwrap();
        assert_eq!(a.next_record().unwrap(), Some(record()));
        assert_eq!(b.next_record().unwrap(), Some(record()));
        assert_eq!(a.next_record().unwrap(), None);
        assert!(store.begin(&owner).is_err());
        local.release(owner.lease.lease);
        store.prune();
        assert!(pin.validate().is_err());
        assert!(b.next_record().is_err());
        assert_eq!(store.stats().bytes, 44);
        drop(pin);
        drop(a);
        assert_eq!(store.stats().bytes, 44);
        drop(b);
        assert_eq!(store.stats().bytes, 0);
    }
    #[test]
    fn captures_and_owner_metadata_are_bounded_without_byte_admission_for_cleanup() {
        let (_dir, local, store, owner) = fixture(0, TTL);
        let first = store.begin(&owner).unwrap();
        let id = WorkspaceLeaseID([2; 16]);
        local.register(WorkspaceID([2; 16]), id).unwrap();
        let other = local.observation_owner(id).unwrap();
        let second = store.begin(&other).unwrap();
        assert_eq!(store.begin(&owner).err().unwrap().code, ErrorCode::Busy);
        drop(first);
        drop(second);
        for n in 0..254u16 {
            let mut bytes = [3; 16];
            bytes[..2].copy_from_slice(&n.to_be_bytes());
            let id = WorkspaceLeaseID(bytes);
            local.register(WorkspaceID(bytes), id).unwrap();
            let owner = local.observation_owner(id).unwrap();
            drop(store.begin(&owner).unwrap());
        }
        let id = WorkspaceLeaseID([4; 16]);
        local.register(WorkspaceID([4; 16]), id).unwrap();
        assert!(store.begin(&local.observation_owner(id).unwrap()).is_err());
        local.close_connection(ConnectionCloseReason::ApplicationShutdown);
        store.prune();
        assert_eq!(store.stats().owners, 0);
    }
    #[test]
    fn eviction_is_unpinned_lru_and_lookup_does_not_renew_ttl() {
        let (_dir, local, store, a) = fixture(88, TTL);
        let aid = capture(&store, &a, 0);
        let bid = WorkspaceLeaseID([2; 16]);
        local.register(WorkspaceID([2; 16]), bid).unwrap();
        let b = local.observation_owner(bid).unwrap();
        let bid = capture(&store, &b, 1);
        store
            .state
            .lock()
            .unwrap()
            .owners
            .get_mut(&a.lease.lease)
            .unwrap()
            .touched = Instant::now() - Duration::from_secs(10);
        store.lookup(&a, aid).unwrap();
        let pin = store.pin(&b, bid).unwrap();
        let cid = WorkspaceLeaseID([3; 16]);
        local.register(WorkspaceID([3; 16]), cid).unwrap();
        let c = local.observation_owner(cid).unwrap();
        capture(&store, &c, 2);
        assert!(store.lookup(&a, aid).is_err());
        assert!(pin.validate().is_ok());
        store
            .state
            .lock()
            .unwrap()
            .owners
            .get_mut(&b.lease.lease)
            .unwrap()
            .touched = Instant::now() - TTL;
        assert!(store.lookup(&b, bid).is_err());
        store.prune();
        assert!(pin.validate().is_err());
        assert_eq!(pin.bytes(), 44);
    }
    #[test]
    #[ignore = "owned subprocess crash fixture"]
    fn observation_crash_child() {
        let root = PathBuf::from(std::env::var("BUNTRAIL_PROOF_CRASH_ROOT").unwrap());
        let local = LocalConnection::open(root.join("state")).unwrap();
        let id = WorkspaceLeaseID([1; 16]);
        local.register(WorkspaceID([1; 16]), id).unwrap();
        let owner = local.observation_owner(id).unwrap();
        let store = Store::open(root.join("proofs")).unwrap();
        let mut input = store.input(&owner).unwrap();
        input.append(b"retained crash fixture").unwrap();
        let _input = input.seal().unwrap();
        fs::write(
            std::env::var("BUNTRAIL_PROOF_CRASH_SIGNAL").unwrap(),
            b"ready",
        )
        .unwrap();
        loop {
            std::thread::park();
        }
    }
    #[test]
    fn actual_process_exit_reclaims_anonymous_spools_and_startup_cleans_creation_window() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        for stage in ["before_unlink", "after_unlink"] {
            let dir = tempfile::tempdir().unwrap();
            let signal = dir.path().join("ready");
            let proofs = dir.path().join("proofs");
            private_directory(&proofs).unwrap();
            let sentinel = dir.path().join("accepted-operation.json");
            fs::write(&sentinel, b"durable Git operation survives").unwrap();
            let mut child = Child(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "git::observation_store::tests::observation_crash_child",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env("BUNTRAIL_PROOF_CRASH_STAGE", stage)
                    .env("BUNTRAIL_PROOF_CRASH_ROOT", dir.path())
                    .env("BUNTRAIL_PROOF_CRASH_SIGNAL", &signal)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let deadline = Instant::now() + Duration::from_secs(10);
            while !signal.exists() {
                assert!(
                    Instant::now() < deadline,
                    "child failed to reach owned crash window"
                );
                assert!(child.0.try_wait().unwrap().is_none());
                std::thread::sleep(Duration::from_millis(10));
            }
            let named = fs::read_dir(&proofs)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().as_encoded_bytes().starts_with(b".proof-"))
                .count();
            assert_eq!(named, usize::from(stage == "before_unlink"));
            child.0.kill().unwrap();
            child.0.wait().unwrap();
            let reopened = Store::open(proofs.clone()).unwrap();
            assert_eq!(reopened.stats().bytes, 0);
            assert_eq!(fs::read_dir(&proofs).unwrap().count(), 1);
            assert_eq!(
                fs::read(&sentinel).unwrap(),
                b"durable Git operation survives"
            );
            println!(
                "crash stage={stage} owned_child_waited=true named_before_exit={named} named_after_startup=0 authority_reused=false"
            );
        }
    }
}
