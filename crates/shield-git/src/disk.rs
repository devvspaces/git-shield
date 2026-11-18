//! Scan files as they are on disk (a repository or folder that arrived as
//! files: zip, tarball, rsync, shared drive). Nothing is executed and symlinks
//! are never followed.

use crate::repo::{BLOB_READ_LIMIT, BLOB_SCAN_CAP};
use crate::{GitRepo, Result, local};
use shield_core::{BlobData, FileChange, FileStatus, ScanContext};
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

/// Directories not descended into (dependency caches and build output).
pub const SKIP_DIRS: &[&str] = &[".git", "node_modules", ".venv", "venv", "target", "__pycache__", ".tox"];
/// Stop after this many files (a guard against pathological trees).
pub const MAX_FILES: usize = 200_000;

pub struct DiskScan {
    pub ctx: ScanContext,
    /// Skipped directories (relative paths), for the user's information.
    pub skipped: Vec<String>,
    pub truncated: bool,
}

/// Scan every regular file and symlink under `root`. If `root` is inside a git
/// repository, its local config and hooks are audited too (read-only).
pub fn scan_dir(root: &Path, label: impl Into<String>) -> Result<DiskScan> {
    let mut changes = Vec::new();
    let mut skipped = Vec::new();
    let mut truncated = false;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&dir)?.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let path = e.path();
            let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().replace('\\', "/");
            let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
            let ft = meta.file_type();
            if ft.is_dir() {
                if SKIP_DIRS.contains(&e.file_name().to_string_lossy().as_ref()) {
                    skipped.push(rel);
                } else {
                    stack.push(path);
                }
                continue;
            }
            if changes.len() >= MAX_FILES {
                truncated = true;
                break;
            }
            let blob = if ft.is_symlink() {
                let target = std::fs::read_link(&path)?.to_string_lossy().into_owned().into_bytes();
                blob_from(target, true, false)
            } else if ft.is_file() {
                read_file(&path, &meta)?
            } else {
                continue;
            };
            changes.push(FileChange {
                path: rel,
                status: FileStatus::Added,
                old: None,
                new: Some(blob),
                commit: None,
                transited: false,
            });
        }
    }
    let local = match GitRepo::discover(root) {
        Ok(repo) => Some(local::read_local_state(&repo)?),
        Err(_) => None,
    };
    let ctx = ScanContext { label: label.into(), changes, local, ..Default::default() };
    Ok(DiskScan { ctx, skipped, truncated })
}

fn read_file(path: &Path, meta: &std::fs::Metadata) -> Result<BlobData> {
    let size = meta.len();
    #[cfg(unix)]
    let exec = std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o111 != 0;
    #[cfg(not(unix))]
    let exec = false;
    if size > BLOB_READ_LIMIT {
        return Ok(BlobData {
            oid: format!("size:{size}"),
            bytes: Arc::from(&[][..]),
            truncated: true,
            size,
            executable: exec,
            symlink: false,
        });
    }
    let mut data = Vec::with_capacity(size as usize);
    std::fs::File::open(path)?.read_to_end(&mut data)?;
    Ok(blob_from(data, false, exec))
}

/// Blob with its git object id, so ids and allowlist pins match committed content.
fn blob_from(data: Vec<u8>, symlink: bool, executable: bool) -> BlobData {
    let oid = gix::objs::compute_hash(gix::hash::Kind::Sha1, gix::objs::Kind::Blob, &data)
        .map(|o| o.to_string())
        .unwrap_or_default();
    let size = data.len() as u64;
    let truncated = size > BLOB_SCAN_CAP;
    let bytes: Arc<[u8]> = if truncated { Arc::from(&data[..BLOB_SCAN_CAP as usize]) } else { Arc::from(data) };
    BlobData { oid, bytes, truncated, size, executable, symlink }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_without_following_links() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join(".vscode")).unwrap();
        std::fs::create_dir_all(d.path().join("node_modules/x")).unwrap();
        std::fs::write(d.path().join(".vscode/tasks.json"), "{}").unwrap();
        std::fs::write(d.path().join("node_modules/x/i.js"), "x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", d.path().join("link")).unwrap();
        let s = scan_dir(d.path(), "t").unwrap();
        let paths: Vec<_> = s.ctx.changes.iter().map(|c| c.path.as_str()).collect();
        assert!(paths.contains(&".vscode/tasks.json"), "{paths:?}");
        assert!(!paths.iter().any(|p| p.starts_with("node_modules")));
        assert_eq!(s.skipped, ["node_modules"]);
        #[cfg(unix)]
        assert!(s.ctx.changes.iter().any(|c| c.path == "link" && c.new.as_ref().unwrap().symlink));
        // `{}` hashes like git does.
        let t = s.ctx.changes.iter().find(|c| c.path == ".vscode/tasks.json").unwrap();
        assert_eq!(t.new.as_ref().unwrap().oid, "9e26dfeeb6e641a33dae4961196235bdb965b21b");
    }
}
