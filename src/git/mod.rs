mod adapter;
mod history;
mod mutations;
mod network;
mod output_parser;
pub(crate) mod process;
mod read;
pub use adapter::LocalGitService;
pub mod observation;
mod observation_store;
pub mod proof_codec;
pub mod worktree_proof;

pub mod authentication;
