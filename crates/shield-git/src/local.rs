use crate::{GitRepo, Result, git_err};
use gix::bstr::ByteSlice;
use shield_core::{ConfigEntry, HookFile, LocalRepoState};
use std::path::Path;

/// Read the repository-local git config and hooks directory without running git.
///
/// Includes are *not* followed: an `include.path` is itself reported by the
/// T7 detector, and following it could mean reading attacker-chosen files.
pub fn read_local_state(repo: &GitRepo) -> Result<LocalRepoState> {
    let mut state = LocalRepoState::default();
    for dir in unique_dirs(repo.git_dir(), repo.common_dir()) {
        for name in ["config", "config.worktree"] {
            let path = dir.join(name);
            if !path.is_file() {
                continue;
            }
            let file =
                gix::config::File::from_path_no_includes(path.clone(), gix::config::Source::Local).map_err(git_err)?;
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
                    let key = match &sub {
                        Some(sub) => format!("{sec}.{sub}.{}", value_name.to_ascii_lowercase()),
                        None => format!("{sec}.{}", value_name.to_ascii_lowercase()),
                    };
                    for value in section.values(&value_name) {
                        state.config.push(ConfigEntry { key: key.clone(), value: value.to_str_lossy().into_owned() });
                    }
                }
            }
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
