//! `git shield clone` and `git shield checkout`: scan what would be written to
//! the working tree before anything is written.

use crate::{Common, accepted, emit, gate, note, now, preflight, scan, short};
use anyhow::{Context, Result, bail};
use shield_git::hardened::HardenedGit;
use shield_git::trust::TrustStore;
use shield_git::{GitRepo, ObjectId};
use std::path::{Path, PathBuf};

/// Directory name git would pick for `url`.
fn default_dir(url: &str) -> String {
    let tail = url.trim_end_matches('/').rsplit(['/', ':']).next().unwrap_or("repo");
    let name = tail.strip_suffix(".git").unwrap_or(tail);
    if name.is_empty() { "repo".into() } else { name.into() }
}

pub fn clone(
    url: &str,
    dir: Option<PathBuf>,
    branch: Option<&str>,
    reason: Option<String>,
    common: &Common,
) -> Result<u8> {
    let dir = dir.unwrap_or_else(|| PathBuf::from(default_dir(url)));
    let dir = if dir.is_absolute() { dir } else { std::env::current_dir()?.join(dir) };
    if dir.exists() && std::fs::read_dir(&dir)?.next().is_some() {
        bail!("{} already exists and is not empty", dir.display());
    }
    let parent = dir.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&parent)?;
    if !common.json {
        eprintln!("git-shield: cloning {url} (hardened, no checkout)…");
    }
    HardenedGit::new(&parent)?.clone_no_checkout(url, &dir, branch)?;

    let repo = GitRepo::discover(&dir)?;
    let Ok(head) = repo.resolve("HEAD") else {
        if !common.json {
            eprintln!("git-shield: the repository is empty; nothing to check out.");
        }
        return Ok(0);
    };
    let mut store = TrustStore::open(&repo)?;
    let label = format!("clone {url} ({})", repo.current_branch().unwrap_or_else(|| short(&head)));
    let report = scan(&repo.tree_scan(head, label)?);
    let mut ok = accepted(common, Some(&store), &report, Some(&repo))?;
    emit(&report, &ok, common);

    let unchanged = format!(
        "the repository is in {} without a checkout (no files written). Inspect it with \
         `git shield audit --rev HEAD -C {}`, or delete the directory",
        dir.display(),
        dir.display()
    );
    let Some(decision) = gate(&report, &mut ok, common, reason, "checkout", &unchanged)? else {
        return Ok(2);
    };
    HardenedGit::new(&dir)?.reset_hard(&head.to_string())?;
    if !common.json {
        eprintln!("git-shield: checked out {} into {}", short(&head), dir.display());
    }
    if report.findings.iter().any(|f| f.path.as_deref() == Some(".gitmodules")) || dir.join(".gitmodules").exists() {
        note("submodules were not fetched; inspect .gitmodules, then clone each with `git shield clone`");
    }

    let t = now();
    let tip = head.to_string();
    decision.record(&mut store, &tip, t);
    if let Ok(up) = repo.upstream() {
        store.set_tip(&up.tracking_ref, &tip, t);
    }
    store.save().with_context(|| format!("writing trust store {}", store.path().display()))?;
    Ok(report.exit_code(&ok) as u8)
}

/// Resolve a checkout target the way `git checkout <name>` would: a local
/// ref/rev, else a unique remote branch of that name.
fn resolve_target(repo: &GitRepo, target: &str) -> Result<ObjectId> {
    if let Ok(id) = repo.resolve(target) {
        return Ok(id);
    }
    let matches: Vec<ObjectId> =
        repo.remote_names().iter().filter_map(|r| repo.ref_tip(&format!("refs/remotes/{r}/{target}"))).collect();
    match matches.as_slice() {
        [one] => Ok(*one),
        [] => bail!("`{target}` is not a branch, tag or commit here"),
        _ => bail!("`{target}` exists on several remotes; use <remote>/{target}"),
    }
}

pub fn checkout(target: &str, reason: Option<String>, allow_unsafe_config: bool, common: &Common) -> Result<u8> {
    let repo = GitRepo::discover(&common.repo)?;
    preflight(&repo, allow_unsafe_config, true, common)?;
    let mut store = TrustStore::open(&repo)?;
    let head = repo.resolve("HEAD")?;
    let to = resolve_target(&repo, target)?;
    let report = scan(&repo.tree_delta(head, to, format!("checkout {target} (HEAD → {})", short(&to)))?);
    let mut ok = accepted(common, Some(&store), &report, Some(&repo))?;
    emit(&report, &ok, common);
    let Some(decision) = gate(&report, &mut ok, common, reason, "checkout", "HEAD and the working tree are unchanged")?
    else {
        return Ok(2);
    };
    let workdir = repo.workdir().context("checkout needs a working tree")?;
    HardenedGit::new(&workdir)?.checkout(target)?;
    let after = GitRepo::discover(&common.repo)?.resolve("HEAD")?;
    if after != to {
        // The branch moved between scan and checkout (another process): say so.
        eprintln!(
            "git-shield: warning: HEAD is {} but {} was scanned; run `git shield checkout` again",
            short(&after),
            short(&to)
        );
    } else if !common.json {
        eprintln!("git-shield: switched to {target} ({})", short(&to));
    }
    let t = now();
    decision.record(&mut store, &to.to_string(), t);
    store.save().with_context(|| format!("writing trust store {}", store.path().display()))?;
    Ok(report.exit_code(&ok) as u8)
}

#[cfg(test)]
mod tests {
    #[test]
    fn default_dirs() {
        assert_eq!(super::default_dir("git@github.com:o/r.git"), "r");
        assert_eq!(super::default_dir("https://github.com/o/r/"), "r");
        assert_eq!(super::default_dir("/tmp/origin.git"), "origin");
    }
}
