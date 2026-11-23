use crate::{GitRepo, Result, git_err};
use gix::bstr::ByteSlice;
use shield_core::{ConfigEntry, HookFile, LocalRepoState};
use std::path::{Path, PathBuf};

/// Includes are followed at most this deep.
const INCLUDE_DEPTH: usize = 3;
/// Included files larger than this are not read.
const INCLUDE_MAX_BYTES: u64 = 1024 * 1024;

/// Read the repository-local git config and hooks directory without running git.
///
/// `include.path` and every `includeIf.*.path` are followed (all conditions
/// are assumed true), because git follows them and a setting in an included
/// file runs just like one in `.git/config`. Included files are only read:
/// regular files only (no FIFOs or devices), at most 1 MiB, 3 levels deep,
/// each file once. Entries from them carry `source`.
pub fn read_local_state(repo: &GitRepo) -> Result<LocalRepoState> {
    let mut state = LocalRepoState::default();
    let mut seen = std::collections::HashSet::new();
    for dir in unique_dirs(repo.git_dir(), repo.common_dir()) {
        for name in ["config", "config.worktree"] {
            let path = dir.join(name);
            if !path.is_file() {
                continue;
            }
            if let Ok(c) = path.canonicalize() {
                seen.insert(c);
            }
            read_config_file(&path, None, 0, &mut seen, &mut state)?;
            if state.config_path.is_none() {
                state.config_path = Some(path.display().to_string());
            }
        }
    }

    let hooks_dir = repo.common_dir().join("hooks");
    if let Ok(entries) = std::fs::read_dir(&hooks_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".sample") {
                continue;
            }
            // symlink_metadata: never follow a hook symlink.
            let Ok(meta) = entry.path().symlink_metadata() else { continue };
            if meta.is_dir() {
                continue;
            }
            state.hooks.push(HookFile { name, executable: is_executable(&meta), size: meta.len() });
        }
    }
    state.hooks.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(state)
}

/// Entries of one config file, then of the files it includes.
fn read_config_file(
    path: &Path,
    source: Option<String>,
    depth: usize,
    seen: &mut std::collections::HashSet<PathBuf>,
    state: &mut LocalRepoState,
) -> Result<()> {
    let file =
        gix::config::File::from_path_no_includes(path.to_path_buf(), gix::config::Source::Local).map_err(git_err)?;
    let mut includes = Vec::new();
    for section in file.sections() {
        let header = section.header();
        let sec = header.name().to_str_lossy().to_ascii_lowercase();
        let sub = header.subsection_name().map(|s| s.to_str_lossy().into_owned());
        // value_names() repeats a name once per occurrence; dedupe so
        // multi-valued keys are not read quadratically.
        let mut names: Vec<String> = Vec::new();
        for n in section.value_names() {
            if !names.contains(&n) {
                names.push(n);
            }
        }
        for value_name in names {
            let name = value_name.to_ascii_lowercase();
            let key = match &sub {
                Some(sub) => format!("{sec}.{sub}.{name}"),
                None => format!("{sec}.{name}"),
            };
            let is_include = name == "path" && (sec == "include" || (sec == "includeif" && sub.is_some()));
            for value in section.values(&value_name) {
                let value = value.to_str_lossy().into_owned();
                if is_include {
                    includes.push(value.clone());
                }
                state.config.push(ConfigEntry { key: key.clone(), value, source: source.clone() });
            }
        }
    }
    if depth >= INCLUDE_DEPTH {
        return Ok(());
    }
    let base = path.parent().unwrap_or(Path::new("."));
    for inc in includes {
        let Some(target) = resolve_include(base, &inc) else { continue };
        // Never follow a symlink to a FIFO or device; only plain files.
        let Ok(meta) = std::fs::metadata(&target) else { continue };
        if !meta.is_file() || meta.len() > INCLUDE_MAX_BYTES {
            continue;
        }
        let Ok(canonical) = target.canonicalize() else { continue };
        if !seen.insert(canonical) {
            continue;
        }
        // An unparsable included file is skipped: git would refuse it too.
        let _ = read_config_file(&target, Some(target.display().to_string()), depth + 1, seen, state);
    }
    Ok(())
}

/// Resolve an include path as git does: `~/` is the home directory, a
/// relative path is relative to the including file's directory.
fn resolve_include(base: &Path, value: &str) -> Option<PathBuf> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    if let Some(rest) = v.strip_prefix("~/") {
        return std::env::var_os("HOME").map(|h| PathBuf::from(h).join(rest));
    }
    let p = PathBuf::from(v);
    Some(if p.is_absolute() { p } else { base.join(p) })
}

fn unique_dirs<'a>(a: &'a Path, b: &'a Path) -> Vec<&'a Path> {
    if a == b { vec![a] } else { vec![a, b] }
}

#[cfg(unix)]
fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.file_type().is_symlink() || meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_meta: &std::fs::Metadata) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// VS Code's GitHub extension writes thousands of `github-pr-owner-number`
    /// values into `.git/config`; reading them was once quadratic.
    #[test]
    fn thousands_of_config_values_read_fast() {
        let dir = tempfile::tempdir().unwrap();
        let ok = std::process::Command::new("git")
            .args(["init", "-q"])
            .arg(dir.path())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap()
            .success();
        assert!(ok);
        let cfg = dir.path().join(".git/config");
        let mut text = std::fs::read_to_string(&cfg).unwrap();
        for i in 0..5000 {
            text.push_str(&format!("[branch \"pr-{i}\"]\n\tgithub-pr-owner-number = \"acme#app#{i}\"\n"));
        }
        text.push_str("[vscode]\n");
        for i in 0..5000 {
            text.push_str(&format!("\tgithub-pr-owner-number = \"acme#app#{i}\"\n"));
        }
        std::fs::write(&cfg, text).unwrap();
        let repo = GitRepo::discover(dir.path()).unwrap();
        let start = std::time::Instant::now();
        let state = read_local_state(&repo).unwrap();
        let took = start.elapsed();
        assert!(state.config.len() >= 10_000, "{}", state.config.len());
        assert!(took < std::time::Duration::from_secs(2), "took {took:?}");
    }
}
