//! Core data model and scan engine for git-shield.
//!
//! The engine is deliberately ignorant of git: `shield-git` turns a repository
//! delta into a [`ScanContext`], detectors in `shield-rules` turn that into
//! [`Finding`]s, and `shield-report` renders them.

mod context;
mod engine;
mod finding;

pub use context::{BlobData, CommitInfo, ConfigEntry, FileChange, FileStatus, HookFile, LocalRepoState, ScanContext};
pub use engine::{Detector, Report, run};
pub use finding::{Finding, FindingId, Severity, Threat};
