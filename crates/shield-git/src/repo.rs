use crate::{Error, Result, git_err, local};
use gix::bstr::ByteSlice;
use gix::hash::ObjectId;
use gix::objs::tree::EntryKind;
use shield_core::{BlobData, CommitInfo, FileChange, FileStatus, ScanContext};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Blobs larger than this are truncated for content detectors.
pub const BLOB_SCAN_CAP: u64 = 4 * 1024 * 1024;
/// Blobs larger than this are not read at all (only size/magic via first bytes is lost).
pub const BLOB_READ_LIMIT: u64 = 64 * 1024 * 1024;

/// The upstream a local branch tracks.
#[derive(Debug, Clone)]
pub struct Upstream {
    pub remote: String,
    /// Branch name on the remote, e.g. `dev`.
    pub branch: String,
    /// Local remote-tracking ref, e.g. `refs/remotes/origin/dev`.
    pub tracking_ref: String,
}

pub struct GitRepo {
    repo: gix::Repository,
}

impl GitRepo {
    /// Discover the repository containing `path`.
    ///
    /// Opened *isolated*: no global/system config, no environment overrides.
    /// We only need objects, refs and the local config, and isolation keeps
    /// gitoxide from even looking at anything that could alter behaviour.
    pub fn discover(path: &Path) -> Result<Self> {
        let repo = gix::discover_opts(path, Default::default(), gix::open::Options::isolated())
            .map_err(|e| Error::NotARepo(format!("{}: {e}", path.display())))?;
        let mut repo = repo;
        repo.object_cache_size_if_unset(32 * 1024 * 1024);
        Ok(GitRepo { repo })
    }

    pub(crate) fn repo(&self) -> &gix::Repository {
        &self.repo
    }

    pub fn git_dir(&self) -> &Path {
        self.repo.git_dir()
    }

    pub fn common_dir(&self) -> &Path {
        self.repo.common_dir()
    }

    pub fn workdir(&self) -> Option<PathBuf> {
        self.repo.workdir().map(Path::to_path_buf)
    }

    /// Resolve a revision spec to a commit id.
    pub fn resolve(&self, spec: &str) -> Result<ObjectId> {
        let id = self
            .repo
            .rev_parse_single(spec)
            .map_err(|e| Error::Resolve { spec: spec.into(), reason: e.to_string() })?;
        let obj = id.object().map_err(|e| Error::Resolve { spec: spec.into(), reason: e.to_string() })?;
        let commit = obj.peel_to_commit().map_err(|e| Error::Resolve { spec: spec.into(), reason: e.to_string() })?;
        Ok(commit.id)
    }

    /// Short name of the checked-out branch, if any.
    pub fn current_branch(&self) -> Option<String> {
        let name = self.repo.head_name().ok().flatten()?;
        Some(name.shorten().to_str_lossy().into_owned())
    }

    /// Upstream of the current branch from `branch.<name>.remote` / `.merge`.
    pub fn upstream(&self) -> Result<Upstream> {
        let branch = self.current_branch().ok_or(Error::NoUpstream)?;
        let cfg = self.repo.config_snapshot();
        let remote = cfg
            .string(format!("branch.{branch}.remote").as_str())
            .map(|s| s.to_str_lossy().into_owned())
            .ok_or(Error::NoUpstream)?;
        let merge = cfg
            .string(format!("branch.{branch}.merge").as_str())
            .map(|s| s.to_str_lossy().into_owned())
            .ok_or(Error::NoUpstream)?;
        let remote_branch = merge.strip_prefix("refs/heads/").unwrap_or(&merge).to_string();
        Ok(Upstream { tracking_ref: format!("refs/remotes/{remote}/{remote_branch}"), remote, branch: remote_branch })
    }

    pub fn merge_base(&self, a: ObjectId, b: ObjectId) -> Result<Option<ObjectId>> {
        Ok(self.repo.merge_base(a, b).map_err(git_err)?.map(|id| id.detach()))
    }

    pub fn is_ancestor(&self, ancestor: ObjectId, descendant: ObjectId) -> Result<bool> {
        Ok(self.merge_base(ancestor, descendant)? == Some(ancestor))
    }

    /// Build the scan context for "what `from` would receive from `to`".
    ///
    /// * net changes: tree of `merge-base(from, to)` → tree of `to`
    /// * commits: reachable from `to` but not from `from`, newest first
    /// * transited: blob versions added by an incoming commit that are not in `to`'s tree
    pub fn incoming(&self, from: ObjectId, to: ObjectId, label: impl Into<String>) -> Result<ScanContext> {
        let base = self.merge_base(from, to)?;
        let base_tree = match base {
            Some(b) => Some(self.commit_tree(b)?),
            None => None,
        };
        let tip_tree = self.commit_tree(to)?;

        let net = self.diff_trees(base_tree, Some(tip_tree))?;
        let tip_paths: HashMap<String, ObjectId> =
            net.iter().filter_map(|c| c.new.map(|n| (c.path.clone(), n.0))).collect();
        let commits = self.commit_range(from, to)?;

        // Per-commit diffs to find content that came and went.
        let mut transited = Vec::new();
        let mut seen: HashSet<(String, ObjectId)> = HashSet::new();
        for info in &commits {
            let cid = ObjectId::from_hex(info.id.as_bytes()).map_err(git_err)?;
            let parent_tree = match info.parents.first() {
                Some(p) => Some(self.commit_tree(ObjectId::from_hex(p.as_bytes()).map_err(git_err)?)?),
                None => None,
            };
            let changes = self.diff_trees(parent_tree, Some(self.commit_tree(cid)?))?;
            for ch in changes {
                let Some((new_oid, _)) = ch.new else { continue };
                if tip_paths.get(&ch.path) == Some(&new_oid) {
                    continue; // survives into the tip; covered by the net diff
                }
                if !seen.insert((ch.path.clone(), new_oid)) {
                    continue;
                }
                // Only report it if the tip doesn't contain this exact blob at this path
                // (i.e. it was later changed or removed).
                if self.tree_entry_oid(tip_tree, &ch.path)? == Some(new_oid) {
                    continue;
                }
                transited.push(self.materialize(ch, Some(info.id.clone()), true)?);
            }
        }
        let changes = net.into_iter().map(|ch| self.materialize(ch, None, false)).collect::<Result<Vec<_>>>()?;
        Ok(ScanContext {
            label: label.into(),
            base: base.map(|b| b.to_string()),
            tip: Some(to.to_string()),
            changes,
            transited,
            commits,
            local: Some(local::read_local_state(self)?),
            provenance: None,
        })
    }

    /// Every file in `commit`'s tree, as additions: what a fresh checkout writes.
    pub fn tree_scan(&self, commit: ObjectId, label: impl Into<String>) -> Result<ScanContext> {
        let tree = self.commit_tree(commit)?;
        let changes = self
            .diff_trees(None, Some(tree))?
            .into_iter()
            .map(|ch| self.materialize(ch, None, false))
            .collect::<Result<Vec<_>>>()?;
        Ok(ScanContext {
            label: label.into(),
            tip: Some(commit.to_string()),
            changes,
            local: Some(local::read_local_state(self)?),
            ..Default::default()
        })
    }

    /// The working-tree change of switching from `from` to `to` (plain tree
    /// diff, no merge base): what `git checkout` would write.
    pub fn tree_delta(&self, from: ObjectId, to: ObjectId, label: impl Into<String>) -> Result<ScanContext> {
        let changes = self
            .diff_trees(Some(self.commit_tree(from)?), Some(self.commit_tree(to)?))?
            .into_iter()
            .map(|ch| self.materialize(ch, None, false))
            .collect::<Result<Vec<_>>>()?;
        Ok(ScanContext {
            label: label.into(),
            base: Some(from.to_string()),
            tip: Some(to.to_string()),
            changes,
            local: Some(local::read_local_state(self)?),
            ..Default::default()
        })
    }

    /// Commits reachable from `to` and not from `from`, newest first.
    pub fn commit_range(&self, from: ObjectId, to: ObjectId) -> Result<Vec<CommitInfo>> {
        let walk = self.repo.rev_walk([to]).with_hidden([from]).all().map_err(git_err)?;
        let mut out = Vec::new();
        for info in walk {
            let info = info.map_err(git_err)?;
            out.push(self.commit_info(info.id)?);
        }
        Ok(out)
    }

    pub fn commit_info(&self, id: ObjectId) -> Result<CommitInfo> {
        let commit = self.repo.find_commit(id).map_err(git_err)?;
        let decoded = commit.decode().map_err(git_err)?;
        let author = decoded.author().map_err(git_err)?;
        let committer = decoded.committer().map_err(git_err)?;
        let at = author.time().map_err(git_err)?;
        let ct = committer.time().map_err(git_err)?;
        let message = decoded.message.to_str_lossy().into_owned();
        let summary = message.lines().next().unwrap_or("").trim().to_string();
        let signed =
            decoded.extra_headers.iter().any(|(k, _)| k.as_bytes() == b"gpgsig" || k.as_bytes() == b"gpgsig-sha256");
        Ok(CommitInfo {
            id: id.to_string(),
            parents: decoded.parents().map(|p| p.to_string()).collect(),
            tree: decoded.tree().to_string(),
            author_name: author.name.to_str_lossy().trim().to_string(),
            author_email: author.email.to_str_lossy().trim().to_string(),
            author_time: at.seconds,
            author_offset: at.offset,
            committer_name: committer.name.to_str_lossy().trim().to_string(),
            committer_email: committer.email.to_str_lossy().trim().to_string(),
            committer_time: ct.seconds,
            committer_offset: ct.offset,
            summary,
            message,
            signed,
        })
    }

    fn commit_tree(&self, id: ObjectId) -> Result<ObjectId> {
        let commit = self.repo.find_commit(id).map_err(git_err)?;
        Ok(commit.tree_id().map_err(git_err)?.detach())
    }

    fn tree_entry_oid(&self, tree: ObjectId, path: &str) -> Result<Option<ObjectId>> {
        let tree = self.repo.find_tree(tree).map_err(git_err)?;
        let entry = tree.lookup_entry_by_path(path).map_err(git_err)?;
        Ok(entry.map(|e| e.object_id()))
    }

    /// Plain tree diff: no rename tracking, no blob pipeline, no attributes,
    /// no drivers. Only blob and symlink entries are returned.
    fn diff_trees(&self, old: Option<ObjectId>, new: Option<ObjectId>) -> Result<Vec<RawChange>> {
        use gix::diff::tree::recorder::{Change, Location};
        let empty = self.repo.empty_tree();
        let old_tree = match old {
            Some(id) => self.repo.find_tree(id).map_err(git_err)?,
            None => empty.clone(),
        };
        let new_tree = match new {
            Some(id) => self.repo.find_tree(id).map_err(git_err)?,
            None => empty,
        };
        let mut recorder = gix::diff::tree::Recorder::default().track_location(Some(Location::Path));
        let mut state = gix::diff::tree::State::default();
        gix::diff::tree(
            gix::objs::TreeRefIter::from_bytes(&old_tree.data, old_tree.id.kind()),
            gix::objs::TreeRefIter::from_bytes(&new_tree.data, new_tree.id.kind()),
            &mut state,
            &self.repo.objects,
            &mut recorder,
        )
        .map_err(git_err)?;

        let is_file = |k: EntryKind| matches!(k, EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link);
        let mut out = Vec::new();
        for rec in recorder.records {
            match rec {
                Change::Addition { entry_mode, oid, path, .. } if is_file(entry_mode.kind()) => out.push(RawChange {
                    path: path.to_str_lossy().into_owned(),
                    status: FileStatus::Added,
                    old: None,
                    new: Some((oid, entry_mode.kind())),
                }),
                Change::Deletion { entry_mode, oid, path, .. } if is_file(entry_mode.kind()) => out.push(RawChange {
                    path: path.to_str_lossy().into_owned(),
                    status: FileStatus::Deleted,
                    old: Some((oid, entry_mode.kind())),
                    new: None,
                }),
                Change::Modification { previous_entry_mode, previous_oid, entry_mode, oid, path } => {
                    let (pk, nk) = (previous_entry_mode.kind(), entry_mode.kind());
                    let path = path.to_str_lossy().into_owned();
                    match (is_file(pk), is_file(nk)) {
                        (true, true) => out.push(RawChange {
                            path,
                            status: FileStatus::Modified,
                            old: Some((previous_oid, pk)),
                            new: Some((oid, nk)),
                        }),
                        (false, true) => {
                            out.push(RawChange { path, status: FileStatus::Added, old: None, new: Some((oid, nk)) })
                        }
                        (true, false) => out.push(RawChange {
                            path,
                            status: FileStatus::Deleted,
                            old: Some((previous_oid, pk)),
                            new: None,
                        }),
                        (false, false) => {}
                    }
                }
                _ => {}
            }
        }
        Ok(out)
    }

    fn materialize(&self, ch: RawChange, commit: Option<String>, transited: bool) -> Result<FileChange> {
        Ok(FileChange {
            old: ch.old.map(|(oid, k)| self.read_blob(oid, k)).transpose()?,
            new: ch.new.map(|(oid, k)| self.read_blob(oid, k)).transpose()?,
            path: ch.path,
            status: ch.status,
            commit,
            transited,
        })
    }

    fn read_blob(&self, oid: ObjectId, kind: EntryKind) -> Result<BlobData> {
        let header = self.repo.find_header(oid).map_err(git_err)?;
        let size = header.size();
        let (bytes, truncated): (Arc<[u8]>, bool) = if size > BLOB_READ_LIMIT {
            (Arc::from(&[][..]), true)
        } else {
            let blob = self.repo.find_blob(oid).map_err(git_err)?;
            let data = &blob.data;
            if size > BLOB_SCAN_CAP {
                (Arc::from(&data[..BLOB_SCAN_CAP as usize]), true)
            } else {
                (Arc::from(&data[..]), false)
            }
        };
        Ok(BlobData {
            oid: oid.to_string(),
            bytes,
            truncated,
            size,
            executable: kind == EntryKind::BlobExecutable,
            symlink: kind == EntryKind::Link,
        })
    }
}

struct RawChange {
    path: String,
    status: FileStatus,
    old: Option<(ObjectId, EntryKind)>,
    new: Option<(ObjectId, EntryKind)>,
}
