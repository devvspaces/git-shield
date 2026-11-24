//! `git shield install` / `uninstall`: route a plain `git pull` through
//! `git shield pull` with a shell function (see ADR 0006 for why this is not a
//! git hook). Prints by default; edits a shell rc file only with `--write`,
//! between markers that `uninstall` removes.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

const BEGIN: &str = "# >>> git-shield >>>";
const END: &str = "# <<< git-shield <<<";

#[derive(Clone, Copy, PartialEq, Debug)]
enum Shell {
    Posix,
    Fish,
}

fn detect(shell: Option<&str>) -> (Shell, &'static str) {
    let s = shell.map(str::to_string).or_else(|| std::env::var("SHELL").ok()).unwrap_or_default();
    let name = s.rsplit('/').next().unwrap_or("");
    match name {
        "fish" => (Shell::Fish, "fish"),
        "bash" => (Shell::Posix, "bash"),
        _ => (Shell::Posix, "zsh"),
    }
}

fn snippet(shell: Shell) -> String {
    match shell {
        Shell::Posix => format!(
            "{BEGIN}\n# `git pull` goes through `git shield pull` (scan before merge).\n\
             # Bypass once: GIT_SHIELD_BYPASS=1 git pull ...\n\
             git() {{\n  if [ \"$1\" = pull ] && [ -z \"$GIT_SHIELD_BYPASS\" ]; then\n    shift\n    command git-shield pull \"$@\"\n  else\n    command git \"$@\"\n  fi\n}}\n{END}\n"
        ),
        Shell::Fish => format!(
            "{BEGIN}\n# `git pull` goes through `git shield pull` (scan before merge).\n\
             function git --wraps git\n    if test \"$argv[1]\" = pull; and not set -q GIT_SHIELD_BYPASS\n        command git-shield pull $argv[2..-1]\n    else\n        command git $argv\n    end\nend\n{END}\n"
        ),
    }
}

fn rc_file(home: &Path, name: &str) -> PathBuf {
    match name {
        "fish" => home.join(".config/fish/conf.d/git-shield.fish"),
        "bash" => home.join(".bashrc"),
        _ => home.join(".zshrc"),
    }
}

/// Text with any git-shield block removed.
fn strip_block(text: &str) -> (String, bool) {
    let (Some(a), Some(b)) = (text.find(BEGIN), text.find(END)) else { return (text.to_string(), false) };
    if b < a {
        return (text.to_string(), false);
    }
    let end = b + END.len();
    let end = if text[end..].starts_with('\n') { end + 1 } else { end };
    (format!("{}{}", &text[..a], &text[end..]), true)
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).context("HOME is not set")
}

pub fn install(shell: Option<&str>, rc: Option<PathBuf>, write: bool) -> Result<u8> {
    // Native Windows shells (cmd, PowerShell) have no SHELL; guessing zsh
    // there would write an rc file nothing reads.
    if cfg!(windows) && shell.is_none() && std::env::var_os("SHELL").is_none() {
        bail!(
            "`install` adds a bash/zsh/fish function; run it from Git Bash or WSL, or pass --shell bash|zsh|fish. \
             Use `git shield pull` directly in PowerShell or cmd."
        );
    }
    let (kind, name) = detect(shell);
    let block = snippet(kind);
    let target = rc.unwrap_or(rc_file(&home()?, name));
    if !write {
        println!("Add this to {} (or re-run with --write to do it for you):\n", target.display());
        print!("{block}");
        println!("\nThen open a new shell. Undo with `git shield uninstall`.");
        return Ok(0);
    }
    let old = std::fs::read_to_string(&target).unwrap_or_default();
    let (rest, had) = strip_block(&old);
    let sep = if rest.is_empty() || rest.ends_with('\n') { "" } else { "\n" };
    if let Some(dir) = target.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&target, format!("{rest}{sep}{block}")).with_context(|| format!("writing {}", target.display()))?;
    println!(
        "{} the git-shield block in {}. Open a new shell for it to take effect.",
        if had { "Updated" } else { "Added" },
        target.display()
    );
    Ok(0)
}

pub fn uninstall(shell: Option<&str>, rc: Option<PathBuf>) -> Result<u8> {
    let (_, name) = detect(shell);
    let target = rc.unwrap_or(rc_file(&home()?, name));
    let Ok(old) = std::fs::read_to_string(&target) else {
        bail!("{} does not exist", target.display());
    };
    let (rest, had) = strip_block(&old);
    if !had {
        println!("No git-shield block in {}.", target.display());
        return Ok(1);
    }
    if name == "fish" && rest.trim().is_empty() {
        std::fs::remove_file(&target)?;
    } else {
        std::fs::write(&target, rest)?;
    }
    println!("Removed the git-shield block from {}.", target.display());
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_roundtrip() {
        let rc = "export A=1\n";
        let with = format!("{rc}{}", snippet(Shell::Posix));
        let (back, had) = strip_block(&with);
        assert!(had);
        assert_eq!(back, rc);
        assert!(!strip_block(rc).1);
        assert_eq!(detect(Some("/usr/local/bin/fish")).0, Shell::Fish);
    }
}
