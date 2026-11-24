//! `git shield clone` and `git shield checkout`: scan what would be written to
//! the working tree before anything is written.

use crate::{Budget, Common, KnownTips, accepted, attest, emit, gate, gh_session, note, now, preflight, scan, short};
use anyhow::{Context, Result, bail};
use shield_core::{Report, ScanContext};
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

/// Commits read at most for the signature pass (newest first).
const HISTORY_LIMIT: usize = 50_000;

/// Signature and pull-request checks over the commits `to` brings on top of
/// `from` (all of its history when `from` is `None`). GitHub is asked by
/// commit id, not by range: `from` may not exist on GitHub.
fn signature_pass(
    repo: &GitRepo,
    from: Option<ObjectId>,
    to: ObjectId,
    label: &str,
    no_github: bool,
    require: bool,
    common: &Common,
) -> Result<Option<Report>> {
    if common.no_verify_signatures && no_github {
        return Ok(None);
    }
    let commits = repo.commits_since(from, to, HISTORY_LIMIT)?;
    if commits.is_empty() {
        return Ok(None);
    }
    if commits.len() == HISTORY_LIMIT {
        note(&format!("checked the signatures and pull requests of the newest {HISTORY_LIMIT} commits only"));
    }
    let known = KnownTips {
        session: if no_github { None } else { gh_session(repo, None, common) },
        // A clone or checkout happens once; look at all of it.
        budget: Budget::DEEP,
        ..Default::default()
    };
    let attest = attest(repo, &commits, None, &known, common, require)?;
    let ctx =
        ScanContext { label: label.to_string(), tip: Some(to.to_string()), commits, attest, ..Default::default() };
    Ok(Some(shield_core::run(&shield_rules::signing_only(), &ctx)))
}

/// Nested submodules are followed this deep, and at most this many in total.
const SUBMODULE_DEPTH: usize = 3;
const SUBMODULE_MAX: usize = 50;

/// A submodule cloned (no checkout) and scanned, waiting for the verdict.
struct PendingSubmodule {
    name: String,
    url: String,
    commit: ObjectId,
    git_dir: PathBuf,
    worktree: PathBuf,
    parent_worktree: PathBuf,
}

/// Resolve a `.gitmodules` URL against the superproject's URL, refusing
/// anything that can run a command or read local files unexpectedly.
fn resolve_submodule_url(base: &str, url: &str) -> std::result::Result<String, String> {
    let u = url.trim();
    if u.starts_with('-') {
        return Err(format!("`{u}` starts with `-` (option injection)"));
    }
    if u.contains("::") {
        return Err(format!("`{u}` uses a transport helper (`ext::`, `fd::`), which can run commands"));
    }
    if u.starts_with("./") || u.starts_with("../") {
        // Like git: each `../` drops one component of the superproject URL.
        let mut b = base.trim_end_matches('/').to_string();
        let mut rest = u;
        loop {
            if let Some(r) = rest.strip_prefix("./") {
                rest = r;
            } else if let Some(r) = rest.strip_prefix("../") {
                if b.ends_with(':') {
                    return Err(format!("`{u}` climbs above `{base}`"));
                }
                let cut = b.rfind(['/', ':']).ok_or_else(|| format!("`{u}` climbs above `{base}`"))?;
                // Never climb into `scheme://` or past an scp-style `host:`.
                if cut == 0 || b.as_bytes()[cut - 1] == b'/' || b[..cut].ends_with(':') {
                    return Err(format!("`{u}` climbs above `{base}`"));
                }
                b.truncate(if b.as_bytes()[cut] == b':' { cut + 1 } else { cut });
                rest = r;
            } else {
                break;
            }
        }
        let sep = if b.ends_with(':') { "" } else { "/" };
        return Ok(format!("{b}{sep}{rest}"));
    }
    let lower = u.to_ascii_lowercase();
    if ["https://", "http://", "ssh://", "git://"].iter().any(|p| lower.starts_with(p)) {
        return Ok(u.to_string());
    }
    let scp = regex_lite_scp(u);
    if scp {
        return Ok(u.to_string());
    }
    let local = |s: &str| s.starts_with('/') || s.to_ascii_lowercase().starts_with("file://") || dos_drive_path(s);
    if local(u) {
        // A local path only makes sense when the superproject is local too.
        return if local(base) {
            Ok(u.to_string())
        } else {
            Err(format!("`{u}` is a local path in a remote repository"))
        };
    }
    Err(format!("`{u}` is not an https, ssh, git or relative URL"))
}

/// `C:\\dir` or `C:/dir`. git treats these as local paths on Windows only
/// (elsewhere `C:` would be an scp-style host).
fn dos_drive_path(s: &str) -> bool {
    let b = s.as_bytes();
    cfg!(windows) && b.len() > 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'/' | b'\\')
}

/// `user@host:path` (scp-like ssh), without spaces or a leading `-`.
fn regex_lite_scp(u: &str) -> bool {
    let Some((user_host, path)) = u.split_once(':') else { return false };
    let Some((user, host)) = user_host.split_once('@') else { return false };
    let word = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
    word(user) && word(host) && !path.is_empty() && !path.starts_with('/') && !u.contains(char::is_whitespace)
}

/// A submodule name or path that cannot escape its directory (CVE-2018-11235 class).
fn safe_relative(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.contains('\\')
        && p.split('/').all(|c| !c.is_empty() && c != "." && c != ".." && !c.eq_ignore_ascii_case(".git"))
}

/// `to` relative to the directory `from` (both absolute).
fn relative(from: &Path, to: &Path) -> PathBuf {
    let f: Vec<_> = from.components().collect();
    let t: Vec<_> = to.components().collect();
    let common = f.iter().zip(&t).take_while(|(a, b)| a == b).count();
    let mut out = PathBuf::new();
    for _ in common..f.len() {
        out.push("..");
    }
    for c in &t[common..] {
        out.push(c);
    }
    out
}

/// Clone (no checkout) and scan every submodule of `commit`, recursively.
/// Findings are merged into `report` with paths prefixed by the submodule path.
#[allow(clippy::too_many_arguments)]
fn fetch_submodules(
    repo: &GitRepo,
    commit: ObjectId,
    url: &str,
    worktree: &Path,
    git_dir: &Path,
    depth: usize,
    no_github: bool,
    common: &Common,
    report: &mut Report,
    pending: &mut Vec<PendingSubmodule>,
) -> Result<()> {
    for sub in repo.submodules(commit)? {
        let shown = worktree.join(&sub.path).display().to_string();
        if pending.len() >= SUBMODULE_MAX {
            note(&format!("more than {SUBMODULE_MAX} submodules; {shown} and later ones were not fetched"));
            return Ok(());
        }
        if !safe_relative(&sub.name) || !safe_relative(&sub.path) {
            note(&format!("submodule `{}` has an unsafe name or path; not fetched", sub.name));
            continue;
        }
        let sub_url = match resolve_submodule_url(url, &sub.url) {
            Ok(u) => u,
            Err(e) => {
                note(&format!("submodule {}: {e}; not fetched", sub.path));
                continue;
            }
        };
        let sub_git = git_dir.join("modules").join(&sub.name);
        let sub_work = worktree.join(&sub.path);
        if !common.json {
            eprintln!("git-shield: cloning submodule {} from {sub_url} (hardened, no checkout)…", sub.path);
        }
        if let Some(parent) = sub_git.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = tempfile::tempdir()?;
        let work = tmp.path().join("work");
        if let Err(e) = HardenedGit::new(tmp.path())?.clone_separate(&sub_url, &sub_git, &work) {
            note(&format!("submodule {}: clone failed ({e}); left uninitialized", sub.path));
            continue;
        }
        let mut sub_repo = GitRepo::discover(&sub_git)?;
        if !sub_repo.has_object(sub.commit) {
            let _ = HardenedGit::new(&sub_git)?.fetch("origin", Some(&sub.commit.to_string()));
            sub_repo = GitRepo::discover(&sub_git)?;
            if !sub_repo.has_object(sub.commit) {
                note(&format!(
                    "submodule {}: pinned commit {} not found; left uninitialized",
                    sub.path,
                    short(&sub.commit)
                ));
                continue;
            }
        }
        let label = format!("submodule {} ({})", sub.path, short(&sub.commit));
        let mut sub_report = scan(&sub_repo.tree_scan(sub.commit, label.clone())?);
        if let Some(sigs) = signature_pass(&sub_repo, None, sub.commit, &label, no_github, false, common)? {
            sub_report.merge(sigs);
        }
        for f in &mut sub_report.findings {
            if let Some(p) = &mut f.path {
                *p = format!("{}/{p}", sub.path);
            }
        }
        report.merge(sub_report);
        pending.push(PendingSubmodule {
            name: sub.name.clone(),
            url: sub_url.clone(),
            commit: sub.commit,
            git_dir: sub_git.clone(),
            worktree: sub_work.clone(),
            parent_worktree: worktree.to_path_buf(),
        });
        if depth + 1 < SUBMODULE_DEPTH {
            fetch_submodules(
                &sub_repo,
                sub.commit,
                &sub_url,
                &sub_work,
                &sub_git,
                depth + 1,
                no_github,
                common,
                report,
                pending,
            )?;
        } else if !sub_repo.submodules(sub.commit)?.is_empty() {
            note(&format!(
                "submodule {} has nested submodules deeper than {SUBMODULE_DEPTH} levels; not fetched",
                sub.path
            ));
        }
    }
    Ok(())
}

/// Check out scanned submodules the way `git submodule update` lays them
/// out: `.git` file → `.git/modules/<name>`, detached at the pinned commit.
fn check_out_submodules(pending: &[PendingSubmodule]) -> Result<()> {
    for p in pending {
        std::fs::create_dir_all(&p.worktree)?;
        std::fs::write(p.worktree.join(".git"), format!("gitdir: {}\n", relative(&p.worktree, &p.git_dir).display()))?;
        let git = HardenedGit::new(&p.worktree)?;
        git.config_set("core.worktree", &relative(&p.git_dir, &p.worktree).to_string_lossy())?;
        git.checkout(&p.commit.to_string())?;
        let parent = HardenedGit::new(&p.parent_worktree)?;
        parent.config_set(&format!("submodule.{}.url", p.name), &p.url)?;
        parent.config_set(&format!("submodule.{}.active", p.name), "true")?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn clone(
    url: &str,
    dir: Option<PathBuf>,
    branch: Option<&str>,
    reason: Option<String>,
    no_github: bool,
    recurse_submodules: bool,
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
    let mut report = scan(&repo.tree_scan(head, label.clone())?);
    if let Some(sigs) = signature_pass(&repo, None, head, &label, no_github, false, common)? {
        report.merge(sigs);
    }
    let mut pending = Vec::new();
    if recurse_submodules {
        let git_dir = repo.git_dir().to_path_buf();
        // The superproject URL as git resolves relative submodule URLs against it.
        let url = if Path::new(url).exists() {
            std::fs::canonicalize(url).map(|p| p.display().to_string()).unwrap_or_else(|_| url.to_string())
        } else {
            url.to_string()
        };
        let url = url.as_str();
        fetch_submodules(&repo, head, url, &dir, &git_dir, 0, no_github, common, &mut report, &mut pending)?;
    }
    if !recurse_submodules && !repo.submodules(head)?.is_empty() {
        note("submodules are not fetched; use `git shield clone --recurse-submodules` to scan and check them out too");
    }
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
    check_out_submodules(&pending)?;
    if !common.json {
        eprintln!("git-shield: checked out {} into {}", short(&head), dir.display());
        if !pending.is_empty() {
            eprintln!("git-shield: checked out {} submodule(s)", pending.len());
        }
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

pub fn checkout(
    target: &str,
    reason: Option<String>,
    allow_unsafe_config: bool,
    no_github: bool,
    common: &Common,
) -> Result<u8> {
    let repo = GitRepo::discover(&common.repo)?;
    preflight(&repo, allow_unsafe_config, true, common)?;
    let mut store = TrustStore::open(&repo)?;
    let head = repo.resolve("HEAD")?;
    let to = resolve_target(&repo, target)?;
    let label = format!("checkout {target} (HEAD → {})", short(&to));
    let mut report = scan(&repo.tree_delta(head, to, label.clone())?);
    if let Some(sigs) = signature_pass(&repo, Some(head), to, &label, no_github, true, common)? {
        report.merge(sigs);
    }
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
mod dir_tests {
    #[test]
    fn default_dirs() {
        assert_eq!(super::default_dir("git@github.com:o/r.git"), "r");
        assert_eq!(super::default_dir("https://github.com/o/r/"), "r");
        assert_eq!(super::default_dir("/tmp/origin.git"), "origin");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submodule_urls() {
        let gh = "https://github.com/acme/app.git";
        assert_eq!(resolve_submodule_url(gh, "../lib.git").unwrap(), "https://github.com/acme/lib.git");
        assert_eq!(resolve_submodule_url(gh, "../../other/lib").unwrap(), "https://github.com/other/lib");
        assert_eq!(
            resolve_submodule_url("git@github.com:acme/app.git", "../lib.git").unwrap(),
            "git@github.com:acme/lib.git"
        );
        assert_eq!(resolve_submodule_url(gh, "https://example.com/x.git").unwrap(), "https://example.com/x.git");
        assert_eq!(resolve_submodule_url(gh, "git@github.com:acme/x.git").unwrap(), "git@github.com:acme/x.git");
        assert_eq!(resolve_submodule_url("/srv/app.git", "/srv/lib.git").unwrap(), "/srv/lib.git");
        for bad in [
            "--upload-pack=touch /tmp/x",
            "ext::sh -c touch% /tmp/x",
            "fd::3",
            "/etc/passwd",
            "file:///srv/x",
            "ftp://x/y",
        ] {
            assert!(resolve_submodule_url(gh, bad).is_err(), "{bad}");
        }
        assert!(resolve_submodule_url(gh, "../../../../x").is_err());
        assert_eq!(resolve_submodule_url(gh, "./sub").unwrap(), "https://github.com/acme/app.git/sub");
        assert_eq!(resolve_submodule_url("git@host:acme/app.git", "../../x.git").unwrap(), "git@host:x.git");
        assert!(resolve_submodule_url("git@host:acme/app.git", "../../../x.git").is_err());
    }

    #[test]
    fn submodule_names_and_paths() {
        assert!(safe_relative("libs/ui"));
        for bad in ["", "/abs", "../x", "a/../b", ".git/hooks", "a/.GIT/b", "a//b", "a\\b"] {
            assert!(!safe_relative(bad), "{bad}");
        }
    }

    #[test]
    fn relative_paths() {
        assert_eq!(
            relative(Path::new("/r/libs/ui"), Path::new("/r/.git/modules/ui")),
            PathBuf::from("../../.git/modules/ui")
        );
        assert_eq!(
            relative(Path::new("/r/.git/modules/ui"), Path::new("/r/libs/ui")),
            PathBuf::from("../../../libs/ui")
        );
    }
}
