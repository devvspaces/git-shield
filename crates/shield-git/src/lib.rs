//! Git access for git-shield.
//!
//! **Safety rule:** everything here reads the object database and refs
//! in-process via gitoxide. Nothing in this module runs hooks, filters,
//! fsmonitor, pagers or any other repository-controlled program. The only
//! `git` subprocesses live in [`hardened`] and are used for network/worktree
//! operations (fetch, fast-forward).

pub mod disk;
pub mod hardened;
mod local;
mod provenance;
mod repo;
pub mod signing;
pub mod trust;

pub use gix::hash::ObjectId;
pub use local::read_local_state;
pub use provenance::{HABIT_WALK, LOST_CAP, ProvenanceInput, REFLOG_WINDOW_SECS};
pub use repo::{GitRepo, Upstream};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a git repository (or any parent): {0}")]
    NotARepo(String),
    #[error("could not resolve revision `{spec}`: {reason}")]
    Resolve { spec: String, reason: String },
    #[error("current branch has no upstream configured; pass an explicit range or remote/branch")]
    NoUpstream,
    #[error("git operation failed: {0}")]
    Git(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn git_err(e: impl std::fmt::Display) -> Error {
    Error::Git(e.to_string())
}
