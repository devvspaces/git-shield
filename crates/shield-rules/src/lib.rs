//! Built-in detectors. One module per threat family; see `docs/THREATS.md`.

use std::path::{Path, PathBuf};

mod agents;
mod assets;
mod ci;
mod gitconfig;
mod gitmeta;
mod lifecycle;
mod noise;
mod obfuscation;
mod paths;
mod provenance;
mod shellenv;
mod signatures;
mod signing;
pub(crate) mod util;
pub use signing::claimed_pr;
mod vscode;
#[cfg(feature = "yara")]
pub mod yara;

use shield_core::Detector;
pub use util::{glob_match, parse_jsonc};

/// All built-in detectors. Context detectors run in this order; the
/// correlation step (`TamperedPayload`) must stay last.
/// Only the commit-signature checks, for history that is checked out rather
/// than pulled (`clone`, `checkout`): the other context rules compare a pull
/// against what you had before, which does not apply there.
pub fn signing_only() -> Vec<Box<dyn Detector>> {
    vec![Box::new(signing::Signatures), Box::new(signing::PushAttribution)]
}

/// Whether this build can run user YARA rules (cargo feature `yara`).
pub const YARA: bool = cfg!(feature = "yara");

/// `$GIT_SHIELD_RULES`, else `rules/` next to the user config
/// (`$XDG_CONFIG_HOME/git-shield/rules`, else `~/.config/git-shield/rules`).
pub fn rules_dir() -> Option<PathBuf> {
    let non_empty = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    non_empty("GIT_SHIELD_RULES")
        .or_else(|| non_empty("XDG_CONFIG_HOME").map(|p| p.join("git-shield/rules")))
        .or_else(|| non_empty("HOME").map(|h| h.join(".config/git-shield/rules")))
}

/// `*.yar` / `*.yara` files directly in `dir`, sorted. Empty when `dir` is missing.
pub fn rule_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("reading {}: {e}", dir.display())),
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "yar" || x == "yara"))
        .collect();
    files.sort();
    Ok(files)
}

/// The built-in detectors plus `extra` (e.g. compiled user YARA rules).
/// Order does not matter for file rules: every file rule runs before the
/// context steps.
pub fn builtin_with(extra: Vec<Box<dyn Detector>>) -> Vec<Box<dyn Detector>> {
    let mut all = builtin();
    all.extend(extra);
    all
}

pub fn builtin() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(vscode::Tasks),
        Box::new(vscode::Settings),
        Box::new(assets::DisguisedAsset),
        Box::new(gitconfig::LocalConfig),
        Box::new(gitmeta::Attributes),
        Box::new(gitmeta::Submodules),
        Box::new(noise::NoiseMasking),
        Box::new(paths::SensitivePaths),
        Box::new(paths::ModeChanges),
        Box::new(agents::AgentConfig),
        Box::new(agents::AgentInstructions),
        Box::new(lifecycle::Lifecycle),
        Box::new(shellenv::ShellEnv),
        Box::new(ci::Ci),
        Box::new(obfuscation::Obfuscation),
        Box::new(signatures::KnownIoc),
        // Context steps: correlation over the file findings above.
        Box::new(obfuscation::PayloadWired),
        Box::new(provenance::RefRewritten),
        Box::new(signing::Signatures),
        Box::new(provenance::Impersonation),
        Box::new(signing::PushAttribution),
        Box::new(provenance::TamperedPayload),
    ]
}

#[cfg(test)]
pub(crate) mod testutil {
    use shield_core::{BlobData, FileChange, FileStatus, Finding};
    use std::sync::Arc;

    pub fn blob(bytes: &[u8]) -> BlobData {
        BlobData {
            oid: format!("{:040x}", bytes.len()),
            bytes: Arc::from(bytes),
            truncated: false,
            size: bytes.len() as u64,
            executable: false,
            symlink: false,
        }
    }

    pub fn added(path: &str, bytes: &[u8]) -> FileChange {
        FileChange {
            path: path.into(),
            status: FileStatus::Added,
            old: None,
            new: Some(blob(bytes)),
            commit: None,
            transited: false,
        }
    }

    pub fn modified(path: &str, old: &[u8], new: &[u8]) -> FileChange {
        FileChange {
            path: path.into(),
            status: FileStatus::Modified,
            old: Some(blob(old)),
            new: Some(blob(new)),
            commit: None,
            transited: false,
        }
    }

    pub fn scan(d: &dyn shield_core::Detector, c: &FileChange) -> Vec<Finding> {
        let mut out = Vec::new();
        if d.interested(c) {
            d.scan_file(c, &mut out);
        }
        out
    }
}
