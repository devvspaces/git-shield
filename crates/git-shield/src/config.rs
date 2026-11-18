//! User configuration (`config.toml`): never read from the repository.
//!
//! Location: `$GIT_SHIELD_CONFIG`, else `$XDG_CONFIG_HOME/git-shield/config.toml`,
//! else `~/.config/git-shield/config.toml`. See ADR 0005.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use shield_core::{Finding, Severity};
use shield_rules::glob_match;
use std::path::PathBuf;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub allow: Vec<Allow>,
}

/// One allowlist entry. Every given field must match.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allow {
    /// Rule name or glob, e.g. `t4.mcp.server` or `t9.*`.
    pub rule: String,
    /// Path glob (`**` crosses directories).
    pub path: Option<String>,
    /// Content id: prefix of the blob/commit the finding is anchored on (see `--json` `anchor`).
    pub blob: Option<String>,
    /// Repository glob, e.g. `github.com/acme/*` or a remote URL.
    pub repo: Option<String>,
    pub reason: String,
}

pub fn path() -> Option<PathBuf> {
    let non_empty = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    non_empty("GIT_SHIELD_CONFIG")
        .or_else(|| non_empty("XDG_CONFIG_HOME").map(|p| p.join("git-shield/config.toml")))
        .or_else(|| non_empty("HOME").map(|h| h.join(".config/git-shield/config.toml")))
}

pub fn load() -> Result<Config> {
    let Some(p) = path() else { return Ok(Config::default()) };
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", p.display())),
    };
    let cfg: Config = toml::from_str(&text).with_context(|| format!("invalid config {}", p.display()))?;
    for (i, a) in cfg.allow.iter().enumerate() {
        if a.reason.trim().is_empty() {
            bail!("{}: allow entry #{} needs a non-empty reason", p.display(), i + 1);
        }
        if a.path.is_none() && a.blob.is_none() && a.repo.is_none() && !a.rule.contains('.') {
            bail!("{}: allow entry #{} (`{}`) is too broad; add a path, blob or repo", p.display(), i + 1, a.rule);
        }
    }
    Ok(cfg)
}

impl Allow {
    /// Does this entry cover `f` in a repository known by `repo_ids`?
    /// Critical findings are only covered when the entry pins the content (`blob`).
    pub fn covers(&self, f: &Finding, repo_ids: &[String]) -> bool {
        if f.severity == Severity::Critical && self.blob.is_none() {
            return false;
        }
        glob_match(&self.rule, f.rule)
            && self.path.as_ref().is_none_or(|p| f.path.as_deref().is_some_and(|fp| glob_match(p, fp)))
            && self.blob.as_ref().is_none_or(|b| {
                b.len() >= 7 && f.anchor.as_deref().is_some_and(|a| a.starts_with(b.as_str()))
                    || f.commit.as_deref().is_some_and(|c| b.len() >= 7 && c.starts_with(b.as_str()))
            })
            && self.repo.as_ref().is_none_or(|r| repo_ids.iter().any(|id| glob_match(r, id)))
    }
}

impl Config {
    /// Ids of findings the allowlist accepts, plus a warning per Critical
    /// finding that an unpinned entry would otherwise have matched.
    pub fn accepted<'a>(&self, findings: &'a [Finding], repo_ids: &[String]) -> (Vec<&'a str>, Vec<String>) {
        let mut ids = Vec::new();
        let mut warnings = Vec::new();
        for f in findings {
            if self.allow.iter().any(|a| a.covers(f, repo_ids)) {
                ids.push(f.id.0.as_str());
            } else if f.severity == Severity::Critical
                && let Some(a) = self.allow.iter().find(|a| {
                    a.blob.is_none() && {
                        let mut pinned = Finding::clone(f);
                        pinned.severity = Severity::High;
                        a.covers(&pinned, repo_ids)
                    }
                })
            {
                warnings.push(format!(
                    "allowlist entry `{}` matches Critical finding {} but does not pin `blob`; not applied",
                    a.rule, f.id
                ));
            }
        }
        (ids, warnings)
    }
}
