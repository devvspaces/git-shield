//! Per-repository cache of GitHub facts that cannot change: a commit's
//! verification once it is final, and the merge commit of a merged PR.
//!
//! Location: `$XDG_CACHE_HOME/git-shield/github/OWNER__NAME.json`, else
//! `~/.cache/git-shield/github/…`. A missing or unreadable cache is treated as
//! empty; saving is best-effort (write to a temp file, then rename).

use crate::{PullState, RemoteCommit};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Cache {
    #[serde(default)]
    commits: BTreeMap<String, RemoteCommit>,
    /// PR number → merge commit sha (merged PRs only).
    #[serde(default)]
    pulls: BTreeMap<u64, String>,
    /// `base...head` ranges already compared (commit ids never change meaning).
    #[serde(default)]
    ranges: std::collections::BTreeSet<String>,
    /// Local verdicts against the bundled web-flow keyring, valid for `webflow_keyring`.
    #[serde(default)]
    webflow: BTreeMap<String, WebFlowVerdict>,
    #[serde(default)]
    webflow_keyring: String,
    #[serde(skip)]
    path: Option<PathBuf>,
    #[serde(skip)]
    dirty: bool,
}

/// A local check of a commit against GitHub's bundled web-flow keyring. The
/// keyring is fixed per git-shield build, so the verdict cannot change while
/// the keyring stays the same.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebFlowVerdict {
    pub good: bool,
    /// Signer when good, reason when bad.
    pub detail: String,
    /// For verdicts that are neither good nor bad: `nokey`, `expired` or
    /// `revoked`. Empty otherwise (and in caches written before this field).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
}

/// Verification results that a later key upload or email change cannot flip.
fn is_final(c: &RemoteCommit) -> bool {
    c.verified || matches!(c.reason.as_str(), "unsigned" | "invalid" | "malformed_signature" | "malformed_sig")
}

pub fn dir() -> Option<PathBuf> {
    let non_empty = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    non_empty("XDG_CACHE_HOME")
        .map(|p| p.join("git-shield"))
        .or_else(|| non_empty("HOME").map(|h| h.join(".cache/git-shield")))
        .map(|p| p.join("github"))
}

impl Cache {
    /// Load the cache for `owner/name`; empty if absent or corrupt.
    pub fn load(owner: &str, name: &str) -> Self {
        Self::load_at(dir().map(|d| d.join(format!("{owner}__{name}.json"))))
    }

    /// Cache for a repository without a GitHub session, identified by `id`
    /// (a hash of its git directory): `…/git-shield/local/ID.json`. Only the
    /// web-flow verdicts are used there.
    pub fn load_local(id: &str) -> Self {
        Self::load_at(dir().and_then(|d| d.parent().map(|p| p.join("local").join(format!("{id}.json")))))
    }

    fn load_at(path: Option<PathBuf>) -> Self {
        let mut c: Cache = path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        c.path = path;
        c
    }

    pub fn commit(&self, sha: &str) -> Option<&RemoteCommit> {
        self.commits.get(sha)
    }

    pub fn put_commit(&mut self, c: &RemoteCommit) {
        if is_final(c) && self.commits.get(&c.sha) != Some(c) {
            self.commits.insert(c.sha.clone(), c.clone());
            self.dirty = true;
        }
    }

    pub fn pull(&self, number: u64) -> Option<PullState> {
        self.pulls.get(&number).map(|sha| PullState::Merged { merge_commit_sha: sha.clone() })
    }

    pub fn put_pull(&mut self, number: u64, state: &PullState) {
        if let PullState::Merged { merge_commit_sha } = state
            && self.pulls.get(&number) != Some(merge_commit_sha)
        {
            self.pulls.insert(number, merge_commit_sha.clone());
            self.dirty = true;
        }
    }

    pub fn compared(&self, base: &str, head: &str) -> bool {
        self.ranges.contains(&format!("{base}...{head}"))
    }

    pub fn put_compared(&mut self, base: &str, head: &str) {
        if self.ranges.insert(format!("{base}...{head}")) {
            self.dirty = true;
        }
    }

    /// Use web-flow verdicts made with `keyring` (a hash); older ones are dropped.
    pub fn set_keyring(&mut self, keyring: &str) {
        if self.webflow_keyring != keyring {
            self.webflow.clear();
            self.webflow_keyring = keyring.to_string();
            self.dirty = true;
        }
    }

    pub fn webflow(&self, sha: &str) -> Option<&WebFlowVerdict> {
        self.webflow.get(sha)
    }

    pub fn put_webflow(&mut self, sha: &str, v: WebFlowVerdict) {
        if self.webflow.get(sha) != Some(&v) {
            self.webflow.insert(sha.to_string(), v);
            self.dirty = true;
        }
    }

    /// Write back if anything changed. Errors are ignored: the cache is an optimisation.
    pub fn save(&mut self) {
        let Some(path) = &self.path else { return };
        if !self.dirty {
            return;
        }
        let Some(parent) = path.parent() else { return };
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
        let Ok(body) = serde_json::to_vec(self) else { return };
        if let Ok(mut tmp) = tempfile::NamedTempFile::new_in(parent) {
            use std::io::Write as _;
            if tmp.write_all(&body).is_ok() && tmp.persist(path).is_ok() {
                self.dirty = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rc(sha: &str, verified: bool, reason: &str) -> RemoteCommit {
        RemoteCommit { sha: sha.into(), verified, reason: reason.into(), author_login: None, committer_login: None }
    }

    #[test]
    fn round_trip_and_corruption() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("o__r.json");
        let mut c = Cache { path: Some(path.clone()), ..Default::default() };
        c.put_commit(&rc("a", true, "valid"));
        c.put_commit(&rc("b", false, "unknown_key")); // may change later: not cached
        c.put_pull(7, &PullState::Merged { merge_commit_sha: "m".into() });
        c.put_pull(8, &PullState::Open);
        c.put_compared("a", "b");
        c.save();

        let back: Cache = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(back.commit("a").is_some() && back.commit("b").is_none());
        assert_eq!(back.pull(7), Some(PullState::Merged { merge_commit_sha: "m".into() }));
        assert_eq!(back.pull(8), None);
        assert!(back.compared("a", "b") && !back.compared("b", "a"));

        let mut back = back;
        back.set_keyring("k1");
        back.put_webflow("a", WebFlowVerdict { good: true, detail: "GitHub".into(), kind: String::new() });
        assert!(back.webflow("a").is_some());
        back.set_keyring("k1");
        assert!(back.webflow("a").is_some());
        back.set_keyring("k2");
        assert!(back.webflow("a").is_none());

        std::fs::write(&path, b"{not json").unwrap();
        let broken: Option<Cache> = serde_json::from_slice(&std::fs::read(&path).unwrap()).ok();
        assert!(broken.is_none());
    }
}
