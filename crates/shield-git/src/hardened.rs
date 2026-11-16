//! The only place git-shield spawns `git`.
//!
//! Every invocation neutralises the repository-controlled execution points we
//! know about, so a poisoned `.git/config` or hooks directory cannot run code
//! while we fetch. Callers must still run the T7 local-config audit first and
//! refuse to continue on Critical findings: `-c` overrides cover the known
//! keys, but the audit is what catches the unknown ones.

use crate::{Error, Result};
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// Config overrides applied to every git invocation.
fn hardening_args(empty_hooks: &Path) -> Vec<String> {
    vec![
        "-c".into(),
        "core.fsmonitor=false".into(),
        "-c".into(),
        format!("core.hooksPath={}", empty_hooks.display()),
        "-c".into(),
        "core.pager=cat".into(),
        "-c".into(),
        "pager.fetch=false".into(),
        "-c".into(),
        "diff.external=".into(),
        "-c".into(),
        "protocol.ext.allow=never".into(),
        "-c".into(),
        "submodule.recurse=false".into(),
        "-c".into(),
        "fetch.recurseSubmodules=false".into(),
        "-c".into(),
        "core.untrackedCache=false".into(),
    ]
}

/// A `git` command for `repo_dir` with hardening applied.
pub struct HardenedGit {
    repo_dir: std::path::PathBuf,
    empty_hooks: tempfile::TempDir,
}

impl HardenedGit {
    pub fn new(repo_dir: &Path) -> Result<Self> {
        Ok(HardenedGit { repo_dir: repo_dir.to_path_buf(), empty_hooks: tempfile::tempdir()? })
    }

    pub fn command(&self) -> Command {
        let mut cmd = Command::new("git");
        cmd.current_dir(&self.repo_dir)
            .args(hardening_args(self.empty_hooks.path()))
            // Ignore any repo-local overrides passed down through the environment.
            .env_remove("GIT_CONFIG_PARAMETERS")
            .env_remove("GIT_CONFIG_COUNT")
            .env_remove("GIT_EXTERNAL_DIFF")
            .env_remove("GIT_PAGER")
            // Never open an editor (merge/rebase run non-interactively).
            .env("GIT_EDITOR", ":")
            .env("GIT_SEQUENCE_EDITOR", ":")
            .env("GIT_OPTIONAL_LOCKS", "0");
        cmd
    }

    fn run(&self, args: &[&str], inherit_stderr: bool) -> Result<Output> {
        let mut cmd = self.command();
        cmd.args(args).stdin(Stdio::inherit()).stdout(Stdio::piped());
        cmd.stderr(if inherit_stderr { Stdio::inherit() } else { Stdio::piped() });
        let out = cmd.output()?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(Error::Git(format!("git {} failed: {}", args.join(" "), err)));
        }
        Ok(out)
    }

    /// `git fetch --no-recurse-submodules <remote> <branch>`. Objects and
    /// remote-tracking refs only; the working tree is never touched.
    pub fn fetch(&self, remote: &str, branch: Option<&str>) -> Result<()> {
        let mut args = vec!["fetch", "--no-recurse-submodules", "--no-write-fetch-head", remote];
        if let Some(b) = branch {
            args.push(b);
        }
        self.run(&args, true).map(|_| ())
    }

    /// Fast-forward the current branch to `target`. Refuses anything else.
    /// Callers pass the scanned commit id, never a ref name, so a ref that
    /// moves after the scan cannot slip unscanned commits in.
    pub fn merge_ff_only(&self, target: &str) -> Result<()> {
        self.run(&["merge", "--ff-only", "--no-edit", target], true).map(|_| ())
    }

    /// Merge `target` (a scanned commit id) with a merge commit if needed.
    pub fn merge(&self, target: &str) -> Result<()> {
        self.run(&["merge", "--no-edit", target], true).map(|_| ())
    }

    /// Rebase the current branch onto `target` (a scanned commit id).
    pub fn rebase(&self, target: &str) -> Result<()> {
        self.run(&["rebase", "--no-autosquash", target], true).map(|_| ())
    }
}
