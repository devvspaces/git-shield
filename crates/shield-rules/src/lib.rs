//! Built-in detectors. One module per threat family; see `docs/THREATS.md`.

mod assets;
mod gitconfig;
mod gitmeta;
mod noise;
mod paths;
pub(crate) mod util;
mod vscode;

use shield_core::Detector;

/// All built-in detectors, in no particular order.
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
