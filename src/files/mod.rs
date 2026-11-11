#[cfg(unix)]
mod local;
#[cfg(unix)]
pub use local::*;

#[cfg(unix)]
mod mutations;
#[cfg(unix)]
pub(crate) use mutations::rename_exclusive;
#[cfg(unix)]
pub mod watcher;

mod resolve;

pub mod document_io;
mod owned;
pub use owned::{OwnedLocalFiles, OwnedSave, save_request_digest};

#[cfg(unix)]
mod trash;
