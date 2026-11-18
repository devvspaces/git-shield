//! Per-repository trust store: the last tip pulled through git-shield for each
//! ref, and findings the user accepted (with a reason).
//!
//! It lives in the **user data directory**, never inside `.git/`: a `.git`
//! directory that arrives as files (zip, rsync, a shared drive) must not be
//! able to ship its own pre-accepted findings. See ADR 0003.
//!
//! Location: `$GIT_SHIELD_HOME`, else `$XDG_DATA_HOME/git-shield`, else
//! `~/.local/share/git-shield`; then `repos/<hash of the repo's git dir>.json`.

use crate::{Error, GitRepo, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedTip {
    pub tip: String,
    /// Unix seconds.
    pub at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Accepted {
    pub id: String,
    pub reason: String,
    pub at: i64,
    /// Incoming tip the finding was accepted for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustData {
    pub version: u32,
    pub repo_path: String,
    #[serde(default)]
    pub refs: BTreeMap<String, TrustedTip>,
    #[serde(default)]
    pub accepted: Vec<Accepted>,
}

pub struct TrustStore {
    path: PathBuf,
    pub data: TrustData,
}

/// Root of git-shield's per-user data.
pub fn data_dir() -> Option<PathBuf> {
    let non_empty = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    if let Some(p) = non_empty("GIT_SHIELD_HOME") {
        return Some(p);
    }
    if let Some(p) = non_empty("XDG_DATA_HOME") {
        return Some(p.join("git-shield"));
    }
    non_empty("HOME").map(|h| h.join(".local/share/git-shield"))
}

impl TrustStore {
    /// Load (or start empty) the store for `repo`.
    pub fn open(repo: &GitRepo) -> Result<Self> {
        let root = data_dir().ok_or_else(|| Error::Git("cannot locate a data directory (HOME is unset)".into()))?;
        let common = repo.common_dir().canonicalize()?;
        Self::open_at(&root, &common)
    }

    pub fn open_at(root: &Path, common_dir: &Path) -> Result<Self> {
        let key = hex::encode(Sha256::digest(common_dir.to_string_lossy().as_bytes()));
        let path = root.join("repos").join(format!("{}.json", &key[..16]));
        let repo_path = common_dir.to_string_lossy().into_owned();
        let data = match std::fs::read(&path) {
            Ok(bytes) => {
                let d: TrustData = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Git(format!("corrupt trust store {}: {e}", path.display())))?;
                if d.repo_path != repo_path {
                    // Hash collision or a moved file: never reuse another repo's trust.
                    TrustData { version: 1, repo_path, refs: BTreeMap::new(), accepted: Vec::new() }
                } else {
                    d
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                TrustData { version: 1, repo_path, refs: BTreeMap::new(), accepted: Vec::new() }
            }
            Err(e) => return Err(e.into()),
        };
        Ok(TrustStore { path, data })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn accepted_ids(&self) -> impl Iterator<Item = &str> {
        self.data.accepted.iter().map(|a| a.id.as_str())
    }

    pub fn trusted_tip(&self, ref_name: &str) -> Option<&TrustedTip> {
        self.data.refs.get(ref_name)
    }

    pub fn accept(&mut self, id: &str, reason: &str, tip: Option<&str>, now: i64) {
        self.data.accepted.retain(|a| a.id != id);
        self.data.accepted.push(Accepted {
            id: id.to_string(),
            reason: reason.to_string(),
            at: now,
            tip: tip.map(str::to_string),
        });
    }

    pub fn set_tip(&mut self, ref_name: &str, tip: &str, now: i64) {
        self.data.refs.insert(ref_name.to_string(), TrustedTip { tip: tip.to_string(), at: now });
    }

    /// Remove one accepted id. Returns whether it was present.
    pub fn forget(&mut self, id: &str) -> bool {
        let n = self.data.accepted.len();
        self.data.accepted.retain(|a| a.id != id);
        self.data.accepted.len() != n
    }

    /// Remove every accepted id. Returns how many there were.
    pub fn forget_all(&mut self) -> usize {
        std::mem::take(&mut self.data.accepted).len()
    }

    /// Drop the trusted tip of a ref. Returns whether it was present.
    pub fn forget_ref(&mut self, ref_name: &str) -> bool {
        self.data.refs.remove(ref_name).is_some()
    }

    /// Atomic write: temp file in the same directory, then rename.
    pub fn save(&self) -> Result<()> {
        let dir = self.path.parent().expect("store path has a parent");
        std::fs::create_dir_all(dir)?;
        let json = serde_json::to_vec_pretty(&self.data).map_err(|e| Error::Git(e.to_string()))?;
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        std::io::Write::write_all(&mut tmp, &json)?;
        tmp.persist(&self.path).map_err(|e| Error::Io(e.error))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_repo_binding() {
        let root = tempfile::tempdir().unwrap();
        let a = Path::new("/repos/a/.git");
        let mut s = TrustStore::open_at(root.path(), a).unwrap();
        s.accept("GS-T10-deadbeef", "reviewed with team", Some("abc"), 10);
        s.accept("GS-T10-deadbeef", "again", None, 11);
        s.set_tip("refs/remotes/origin/dev", "abc", 12);
        s.save().unwrap();

        let s2 = TrustStore::open_at(root.path(), a).unwrap();
        assert_eq!(s2.data.accepted.len(), 1);
        assert_eq!(s2.data.accepted[0].reason, "again");
        assert_eq!(s2.trusted_tip("refs/remotes/origin/dev").unwrap().tip, "abc");

        let other = TrustStore::open_at(root.path(), Path::new("/repos/b/.git")).unwrap();
        assert!(other.data.accepted.is_empty());
    }

    #[test]
    fn forget() {
        let root = tempfile::tempdir().unwrap();
        let mut s = TrustStore::open_at(root.path(), Path::new("/repos/a/.git")).unwrap();
        s.accept("GS-A", "r", None, 1);
        s.accept("GS-B", "r", None, 1);
        s.accept("GS-C", "r", None, 1);
        s.set_tip("refs/remotes/origin/dev", "abc", 1);
        assert!(s.forget("GS-A"));
        assert!(!s.forget("GS-A"));
        assert_eq!(s.accepted_ids().collect::<Vec<_>>(), ["GS-B", "GS-C"]);
        assert_eq!(s.forget_all(), 2);
        assert!(s.forget_ref("refs/remotes/origin/dev"));
        assert!(!s.forget_ref("refs/remotes/origin/dev"));
        assert!(s.trusted_tip("refs/remotes/origin/dev").is_none());
    }
}
