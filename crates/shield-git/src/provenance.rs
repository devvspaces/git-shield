//! History facts for the T10 (rewrite) and T11 (impersonation) detectors.
//!
//! Everything here reads refs, reflogs and commit objects in-process.

use crate::{GitRepo, Result, git_err};
use gix::hash::ObjectId;
use shield_core::{CommitInfo, ForcePushInfo, Provenance, Rewrite, TipSource};
use std::collections::HashMap;

/// At most this many commits are listed as dropped by one rewrite.
pub const LOST_CAP: usize = 500;
/// History walked behind the merge base to learn committer habits.
pub const HABIT_WALK: usize = 2000;
/// Reflog entries older than this are ignored when there is no trust-store record.
pub const REFLOG_WINDOW_SECS: i64 = 30 * 24 * 3600;
/// Upper bound on previous tips considered (most recent first).
const MAX_CANDIDATES: usize = 64;

/// Inputs for [`GitRepo::provenance`].
pub struct ProvenanceInput<'a> {
    /// Full ref name whose history is checked, e.g. `refs/remotes/origin/dev`.
    pub ref_name: &'a str,
    pub new_tip: ObjectId,
    /// Merge base of HEAD and the new tip (habits are learned behind it).
    pub base: Option<ObjectId>,
    /// Incoming commits (from the scan context).
    pub commits: &'a [CommitInfo],
    /// Known previous tips from outside the reflog (pre-fetch value, trust store).
    pub extra: &'a [(ObjectId, TipSource)],
    /// Who force-pushed over a tip, and when (from GitHub's activity log).
    pub pushers: &'a HashMap<ObjectId, ForcePushInfo>,
    /// Only reflog entries strictly after this time are considered (the
    /// trust-store record is written right after the fetch it covers).
    pub reflog_since: i64,
    pub now: i64,
}

impl GitRepo {
    /// Full name of a ref if `spec` names one (`origin/dev` → `refs/remotes/origin/dev`).
    pub fn full_ref_name(&self, spec: &str) -> Option<String> {
        let r = self.repo().find_reference(spec).ok()?;
        Some(r.name().as_bstr().to_string())
    }

    pub fn has_object(&self, id: ObjectId) -> bool {
        self.repo().has_object(id)
    }

    /// Names of configured remotes.
    pub fn remote_names(&self) -> Vec<String> {
        self.repo().remote_names().iter().map(|n| n.to_string()).collect()
    }

    /// `remote.<name>.url` from the repository config.
    pub fn remote_url(&self, remote: &str) -> Option<String> {
        let cfg = self.repo().config_snapshot();
        cfg.string(format!("remote.{remote}.url").as_str()).map(|s| s.to_string())
    }

    /// Current target of a ref, peeled to a commit, if it exists.
    pub fn ref_tip(&self, name: &str) -> Option<ObjectId> {
        let mut r = self.repo().find_reference(name).ok()?;
        let id = r.peel_to_id().ok()?;
        Some(id.detach())
    }

    pub fn provenance(&self, input: &ProvenanceInput<'_>) -> Result<Provenance> {
        let candidates = self.previous_tips(input)?;

        // Previous tips the new tip no longer contains. Tips known only from
        // GitHub whose objects could not be fetched are reported as-is.
        let mut rewritten: Vec<(ObjectId, TipSource)> = Vec::new();
        let mut missing: Vec<(ObjectId, TipSource)> = Vec::new();
        for (oid, src) in candidates {
            if !self.repo().has_object(oid) {
                missing.push((oid, src));
            } else if !self.is_ancestor(oid, input.new_tip)? {
                rewritten.push((oid, src));
            }
        }
        // Keep only maximal ones so one force-push yields one finding.
        let mut maximal = Vec::new();
        for (i, (oid, src)) in rewritten.iter().enumerate() {
            let mut dominated = false;
            for (j, (other, _)) in rewritten.iter().enumerate() {
                if i != j && oid != other && self.is_ancestor(*oid, *other)? {
                    dominated = true;
                    break;
                }
            }
            if !dominated {
                maximal.push((*oid, *src));
            }
        }

        let pusher = |oid: &ObjectId| input.pushers.get(oid).cloned();
        let mut rewrites = Vec::new();
        for (old, source) in missing {
            rewrites.push(Rewrite {
                old_tip: old.to_string(),
                source,
                lost: Vec::new(),
                lost_truncated: false,
                missing: true,
                push: pusher(&old),
            });
        }
        for (old, source) in maximal {
            let walk = self.repo().rev_walk([old]).with_hidden([input.new_tip]).all().map_err(git_err)?;
            let mut lost = Vec::new();
            let mut lost_truncated = false;
            for info in walk {
                if lost.len() == LOST_CAP {
                    lost_truncated = true;
                    break;
                }
                lost.push(self.commit_info(info.map_err(git_err)?.id)?);
            }
            rewrites.push(Rewrite {
                old_tip: old.to_string(),
                source,
                lost,
                lost_truncated,
                missing: false,
                push: pusher(&old),
            });
        }

        Ok(Provenance {
            ref_name: input.ref_name.to_string(),
            rewrites,
            committer_offsets: self.committer_offsets(input.base)?,
            parent_times: self.parent_times(input.commits)?,
            now: input.now,
        })
    }

    /// Distinct previous tips: extras first (they carry the strongest source), then reflog.
    fn previous_tips(&self, input: &ProvenanceInput<'_>) -> Result<Vec<(ObjectId, TipSource)>> {
        // Reflog transitions within the window, oldest first.
        let mut entries = Vec::new();
        // Tips the user replaced with their own `git push` (e.g. restoring a branch
        // after a malicious force-push, or force-pushing their own rebase). Those
        // were dropped on purpose and must not be reported as rewrites.
        let mut replaced_by_user: Vec<ObjectId> = Vec::new();
        // Only remote-tracking refs: a local branch's reflog is the user's own
        // amends and rebases, which are not attacks.
        let remote_tracking = input.ref_name.starts_with("refs/remotes/");
        if remote_tracking && let Ok(r) = self.repo().find_reference(input.ref_name) {
            let mut platform = r.log_iter();
            if let Some(lines) = platform.all().map_err(git_err)? {
                for line in lines {
                    let Ok(line) = line else { continue };
                    if line.signature.seconds() <= input.reflog_since {
                        continue;
                    }
                    if line.message.starts_with(b"update by push") {
                        replaced_by_user.push(line.previous_oid());
                    }
                    entries.push((line.previous_oid(), line.new_oid()));
                }
            }
        }

        let mut out: Vec<(ObjectId, TipSource)> = Vec::new();
        let mut push = |oid: ObjectId, src: TipSource| {
            if out.len() < MAX_CANDIDATES
                && !oid.is_null()
                && oid != input.new_tip
                && !replaced_by_user.contains(&oid)
                && !out.iter().any(|(o, _)| *o == oid)
                // The reflog may point at objects that were since garbage-collected.
                // GitHub tips are kept even when missing (reported without details).
                && (src == TipSource::GitHub || self.repo().has_object(oid))
            {
                out.push((oid, src));
            }
        };
        for (oid, src) in input.extra {
            push(*oid, *src);
        }
        // Most recent first.
        for (prev, new) in entries.into_iter().rev() {
            push(new, TipSource::Reflog);
            push(prev, TipSource::Reflog);
        }
        Ok(out)
    }

    /// Committer email → timezone offset → count, over history behind `base`.
    fn committer_offsets(&self, base: Option<ObjectId>) -> Result<HashMap<String, HashMap<i32, u32>>> {
        let mut map: HashMap<String, HashMap<i32, u32>> = HashMap::new();
        let Some(base) = base else { return Ok(map) };
        let walk = self.repo().rev_walk([base]).all().map_err(git_err)?;
        for info in walk.take(HABIT_WALK) {
            let id = info.map_err(git_err)?.id;
            let commit = self.repo().find_commit(id).map_err(git_err)?;
            let decoded = commit.decode().map_err(git_err)?;
            let committer = decoded.committer().map_err(git_err)?;
            let Ok(t) = committer.time() else { continue };
            let email = String::from_utf8_lossy(committer.email).trim().to_ascii_lowercase();
            *map.entry(email).or_default().entry(t.offset).or_default() += 1;
        }
        Ok(map)
    }

    /// Committer time of every parent of the incoming commits.
    fn parent_times(&self, commits: &[CommitInfo]) -> Result<HashMap<String, i64>> {
        let known: HashMap<&str, i64> = commits.iter().map(|c| (c.id.as_str(), c.committer_time)).collect();
        let mut out = HashMap::new();
        for c in commits {
            for p in &c.parents {
                if out.contains_key(p) {
                    continue;
                }
                let t = match known.get(p.as_str()) {
                    Some(t) => *t,
                    None => {
                        let oid = ObjectId::from_hex(p.as_bytes()).map_err(git_err)?;
                        self.commit_info(oid)?.committer_time
                    }
                };
                out.insert(p.clone(), t);
            }
        }
        Ok(out)
    }
}
