//! Changes to paths that tools execute or trust. Reported at Info/Low when no
//! specific detector says more, so a human still sees that they changed.

use shield_core::{Detector, FileChange, FileStatus, Finding, Severity, Threat};

/// (matcher, severity, why)
enum M {
    Dir(&'static str),
    File(&'static str),
    Suffix(&'static str),
}

const SENSITIVE: &[(M, Severity, &str)] = &[
    (M::Dir(".vscode/"), Severity::Low, "VS Code workspace config (tasks/settings/launch can run code)"),
    (M::Dir(".idea/"), Severity::Low, "JetBrains workspace config (run configurations, startup tasks)"),
    (M::Dir(".claude/"), Severity::Low, "Claude Code project config (hooks run shell commands)"),
    (M::Dir(".cursor/"), Severity::Low, "Cursor config (rules can instruct the agent to run commands)"),
    (M::Dir(".gemini/"), Severity::Low, "Gemini CLI config"),
    (M::Dir(".codex/"), Severity::Low, "Codex config"),
    (M::File(".mcp.json"), Severity::Low, "MCP servers (agents start these programs)"),
    (M::Dir(".devcontainer/"), Severity::Low, "devcontainer lifecycle commands"),
    (M::Dir(".github/workflows/"), Severity::Low, "CI workflows"),
    (M::Dir(".husky/"), Severity::Low, "git hooks tracked in the repo"),
    (M::Dir(".githooks/"), Severity::Low, "git hooks tracked in the repo"),
    (M::File(".envrc"), Severity::Low, "direnv runs this on cd"),
    (M::File(".gitattributes"), Severity::Info, "git attribute drivers"),
    (M::File(".gitmodules"), Severity::Info, "submodule sources"),
    (M::File(".gitignore"), Severity::Info, "ignore rules (attackers un-ignore .env or hide payload dirs)"),
    (M::File("package.json"), Severity::Info, "npm lifecycle scripts"),
    (M::File(".npmrc"), Severity::Low, "npm config (registries, scripts)"),
    (M::File(".yarnrc.yml"), Severity::Low, "yarn config (plugins, paths)"),
    (M::File("setup.py"), Severity::Info, "runs on pip install"),
    (M::File("pyproject.toml"), Severity::Info, "Python build backend"),
    (M::File("conftest.py"), Severity::Info, "pytest auto-imports this"),
    (M::Suffix(".pth"), Severity::Medium, "Python runs lines starting with `import` on interpreter start"),
    (M::File("makefile"), Severity::Info, "build commands"),
    (M::File(".pre-commit-config.yaml"), Severity::Info, "hook definitions"),
    (M::Suffix(".code-workspace"), Severity::Low, "VS Code multi-root workspace (tasks/settings)"),
    (M::File("agents.md"), Severity::Info, "instructions AI agents follow"),
    (M::File("claude.md"), Severity::Info, "instructions AI agents follow"),
    (M::File(".tool-versions"), Severity::Info, "asdf/mise tool versions"),
    (M::File("mise.toml"), Severity::Low, "mise tasks/hooks"),
    (M::File(".mise.toml"), Severity::Low, "mise tasks/hooks"),
];

fn classify(path: &str) -> Option<(Severity, &'static str)> {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    SENSITIVE.iter().find_map(|(m, sev, why)| {
        let hit = match m {
            M::Dir(d) => lower.starts_with(d) || lower.contains(&format!("/{d}")),
            M::File(f) => name == *f,
            M::Suffix(s) => name.ends_with(s),
        };
        hit.then_some((*sev, *why))
    })
}

pub struct SensitivePaths;

impl Detector for SensitivePaths {
    fn name(&self) -> &'static str {
        "sensitive-paths"
    }

    fn interested(&self, c: &FileChange) -> bool {
        classify(&c.path).is_some()
    }

    fn scan_file(&self, c: &FileChange, out: &mut Vec<Finding>) {
        let Some((sev, why)) = classify(&c.path) else { return };
        let verb = match c.status {
            FileStatus::Added => "added",
            FileStatus::Modified => "modified",
            FileStatus::Deleted => "deleted",
        };
        let anchor = c.new.as_ref().or(c.old.as_ref()).map(|b| b.oid.clone()).unwrap_or_default();
        out.push(
            Finding::new(Threat::Path, "path.sensitive", sev, format!("Sensitive file {verb}"))
                .anchor(format!("{verb}:{anchor}"))
                .detail(why),
        );
    }
}

/// New symlinks and newly executable files.
pub struct ModeChanges;

impl Detector for ModeChanges {
    fn name(&self) -> &'static str {
        "mode-changes"
    }

    fn interested(&self, c: &FileChange) -> bool {
        c.new.as_ref().is_some_and(|n| n.symlink || n.executable)
    }

    fn scan_file(&self, c: &FileChange, out: &mut Vec<Finding>) {
        let Some(new) = &c.new else { return };
        let was = c.old.as_ref();
        if new.symlink && !was.is_some_and(|o| o.symlink && o.oid == new.oid) {
            let target = new.text().to_string();
            let escapes = target.starts_with('/') || target.starts_with('~') || escapes_repo(&c.path, &target);
            let sev = if escapes { Severity::High } else { Severity::Low };
            out.push(
                Finding::new(
                    Threat::Path,
                    "path.symlink",
                    sev,
                    if escapes { "Symlink points outside the repository" } else { "Symlink added or changed" },
                )
                .anchor(new.oid.clone())
                .detail(format!("target: {}", crate::util::clip(&target, 200))),
            );
        } else if new.executable && !was.is_some_and(|o| o.executable) {
            out.push(
                Finding::new(Threat::Path, "path.executable", Severity::Low, "File became executable")
                    .anchor(new.oid.clone()),
            );
        }
    }
}

/// Does `target`, relative to the directory of `link`, climb above the repo root?
fn escapes_repo(link: &str, target: &str) -> bool {
    let mut depth: isize = link.matches('/').count() as isize;
    for part in target.split('/') {
        match part {
            ".." => depth -= 1,
            "." | "" => {}
            _ => depth += 1,
        }
        if depth < 0 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification() {
        assert!(classify(".vscode/tasks.json").is_some());
        assert!(classify("sub/.claude/settings.json").is_some());
        assert!(classify("lib/site.pth").is_some());
        assert!(classify("src/main.rs").is_none());
    }

    #[test]
    fn symlink_escape() {
        assert!(escapes_repo("a/link", "../../etc/passwd"));
        assert!(!escapes_repo("a/link", "../b/file"));
    }
}
