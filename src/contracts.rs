use buntrail_core::contracts::async_types::{EventStream, ServiceFuture};
use buntrail_core::contracts::*;
use std::sync::Arc;

pub trait EnvironmentService: Send + Sync {
    fn connect(
        &self,
        locator: EnvironmentLocator,
        expected: Option<TargetIdentity>,
    ) -> ServiceFuture<'_, Result<ConnectedEnvironment, CoreError>>;
}
pub trait FileService: Send + Sync {
    fn resolve(
        &self,
        root: FileRef,
        purpose: FileResolvePurpose,
    ) -> ServiceFuture<'_, Result<FileResolution, CoreError>>;
    fn list(&self, directory: FileRef) -> ServiceFuture<'_, Result<Vec<FileEntry>, CoreError>>;
    fn read(&self, file: FileRef) -> ServiceFuture<'_, Result<FileSnapshot, CoreError>>;
    fn watch(&self, root: FileRef) -> ServiceFuture<'_, Result<EventStream<FileEvent>, CoreError>>;
    fn save(&self, request: SaveRequest) -> ServiceFuture<'_, OperationReceipt>;
    fn mutate(&self, request: FileMutationRequest) -> ServiceFuture<'_, OperationReceipt>;
}
pub trait SearchService: Send + Sync {
    fn search(
        &self,
        request: SearchRequest,
    ) -> ServiceFuture<'_, Result<EventStream<SearchEvent>, CoreError>>;
}
pub trait GitService: Send + Sync {
    fn read_query(
        &self,
        _worktree: WorktreeIdentity,
        _query: GitRead,
    ) -> ServiceFuture<'_, Result<GitReadOutput, CoreError>> {
        Box::pin(async {
            Err(CoreError::new(
                ErrorCode::Unavailable,
                "Git read capability unavailable",
            ))
        })
    }

    /// Read-only original-request lookup, before filesystem or expected-state validation.
    fn existing_receipt(
        &self,
        request: GitMutationRequest,
    ) -> ServiceFuture<'_, Result<Option<OperationReceipt>, CoreError>>;
    fn discover(
        &self,
        root: FileRef,
    ) -> ServiceFuture<'_, Result<Option<WorktreeIdentity>, CoreError>>;
    fn status(
        &self,
        worktree: WorktreeIdentity,
    ) -> ServiceFuture<'_, Result<GitSnapshot, CoreError>>;
    fn diff(&self, request: DiffRequest) -> ServiceFuture<'_, Result<DiffSnapshot, CoreError>>;
    fn history(&self, query: HistoryQuery) -> ServiceFuture<'_, Result<GraphPage, CoreError>>;
    fn mutate(&self, request: GitMutationRequest) -> ServiceFuture<'_, OperationReceipt>;
}
pub trait TerminalService: Send + Sync {
    fn open(&self, request: TerminalOpenRequest) -> ServiceFuture<'_, OperationReceipt>;
    fn attach(
        &self,
        request: TerminalAttachRequest,
    ) -> ServiceFuture<'_, Result<EventStream<TerminalEvent>, CoreError>>;
    fn input(
        &self,
        session: TerminalSessionID,
        bytes: Vec<u8>,
    ) -> ServiceFuture<'_, Result<(), CoreError>>;
    fn resize(
        &self,
        session: TerminalSessionID,
        size: TerminalSize,
    ) -> ServiceFuture<'_, Result<(), CoreError>>;
    fn end(
        &self,
        session: TerminalSessionID,
        intent: TerminalEndIntent,
    ) -> ServiceFuture<'_, Result<(), CoreError>>;
}
pub trait OperationService: Send + Sync {
    fn inspect(
        &self,
        id: OperationID,
        target: TargetIdentity,
    ) -> ServiceFuture<'_, Result<OperationReceipt, CoreError>>;
}
pub trait WorkspaceLeaseService: Send + Sync {
    fn register(&self, lease: WorkspaceLease) -> ServiceFuture<'_, Result<(), CoreError>>;
    fn release(
        &self,
        id: WorkspaceLeaseID,
        intent: LeaseReleaseIntent,
    ) -> ServiceFuture<'_, Result<(), CoreError>>;
}

pub enum ServiceAvailability<T: ?Sized> {
    Available(Arc<T>),
    Unavailable(CoreError),
}
pub struct ConnectedEnvironment {
    pub identity: TargetIdentity,
    pub runtime: RuntimeGeneration,
    pub capabilities: Capabilities,
    pub owner: Arc<dyn ConnectionOwner>,
    pub leases: ServiceAvailability<dyn WorkspaceLeaseService>,
    pub files: ServiceAvailability<dyn FileService>,
    pub search: ServiceAvailability<dyn SearchService>,
    pub git: ServiceAvailability<dyn GitService>,
    pub terminal: ServiceAvailability<dyn TerminalService>,
    pub operations: ServiceAvailability<dyn OperationService>,
}
pub trait ConnectionOwner: Send + Sync {
    fn states(&self) -> EventStream<ConnectionState>;
    fn close(&self, reason: ConnectionCloseReason) -> ServiceFuture<'_, Result<(), CoreError>>;
}
