//! `git shield audit`: scan a repository or folder as it is, without git.

use crate::{Common, accepted, emit, note, scan};
use anyhow::{Context, Result};
use shield_git::GitRepo;
use shield_git::trust::TrustStore;

pub fn run(path: Option<std::path::PathBuf>, rev: Option<String>, common: &Common) -> Result<u8> {
    let root = path.unwrap_or_else(|| common.repo.clone());
    let root = root.canonicalize().with_context(|| format!("cannot open {}", root.display()))?;
    let repo = GitRepo::discover(&root).ok();
    let store = repo.as_ref().and_then(|r| TrustStore::open(r).ok());

    let ctx = match &rev {
        Some(rev) => {
            let repo = repo.as_ref().context("--rev needs a git repository")?;
            let id = repo.resolve(rev)?;
            repo.tree_scan(id, format!("audit {rev} (committed tree)"))?
        }
        None => {
            let d = shield_git::disk::scan_dir(&root, format!("audit {}", root.display()))?;
            if !common.json {
                if !d.skipped.is_empty() {
                    note(&format!("not scanned (dependencies / build output): {}", d.skipped.join(", ")));
                }
                if d.truncated {
                    note(&format!("stopped after {} files", shield_git::disk::MAX_FILES));
                }
            }
            d.ctx
        }
    };
    let report = scan(&ctx);
    let ok = accepted(common, store.as_ref(), &report, repo.as_ref())?;
    let code = emit(&report, &ok, common);
    if code == 2 && !common.json {
        eprintln!(
            "git-shield: do not run git, open an editor, or start an AI agent in this folder until the \
             blocking findings are resolved."
        );
    }
    Ok(code)
}
