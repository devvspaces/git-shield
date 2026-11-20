use std::collections::HashMap;
use std::sync::Arc;

/// Content of a blob as read from the object database (never the worktree).
#[derive(Debug, Clone)]
pub struct BlobData {
    /// Hex object id.
    pub oid: String,
    /// Raw bytes, possibly truncated to the scan size cap.
    pub bytes: Arc<[u8]>,
    /// True when `bytes` was cut at the size cap.
    pub truncated: bool,
    /// Full size of the blob in bytes.
    pub size: u64,
    pub executable: bool,
    pub symlink: bool,
}

impl BlobData {
    /// Lossy UTF-8 view, with a leading BOM stripped.
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        let b: &[u8] = &self.bytes;
        let b = b.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(b);
        String::from_utf8_lossy(b)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    Added,
    Modified,
    Deleted,
}

/// A path that differs between the old and new side of the scanned delta.
#[derive(Debug, Clone)]
pub struct FileChange {
    /// Repository-relative path using `/` separators.
    pub path: String,
    pub status: FileStatus,
    pub old: Option<BlobData>,
    pub new: Option<BlobData>,
    /// Commit that introduced this version (set for per-commit / transited changes).
    pub commit: Option<String>,
    /// True if this version does not survive into the final incoming tree.
    pub transited: bool,
}

impl FileChange {
    /// Lower-cased file name.
    pub fn file_name_lower(&self) -> String {
        self.path.rsplit('/').next().unwrap_or(&self.path).to_ascii_lowercase()
    }

    /// Lower-cased extension without the dot, if any.
    pub fn extension_lower(&self) -> Option<String> {
        let name = self.path.rsplit('/').next()?;
        let (stem, ext) = name.rsplit_once('.')?;
        if stem.is_empty() {
            return None;
        }
        Some(ext.to_ascii_lowercase())
    }
}

/// Metadata of one incoming commit.
#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub id: String,
    pub parents: Vec<String>,
    pub tree: String,
    pub author_name: String,
    pub author_email: String,
    pub author_time: i64,
    /// UTC offset in seconds.
    pub author_offset: i32,
    pub committer_name: String,
    pub committer_email: String,
    pub committer_time: i64,
    pub committer_offset: i32,
    pub summary: String,
    pub message: String,
    /// `gpgsig` header present (GPG, SSH or X.509 signature). Presence only.
    pub signed: bool,
}

/// A key/value from the repository-local git config (`.git/config`).
#[derive(Debug, Clone)]
pub struct ConfigEntry {
    /// Fully qualified, lower-cased section/name, e.g. `core.fsmonitor`,
    /// `filter.lfs.smudge` (subsection keeps its case).
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct HookFile {
    pub name: String,
    pub executable: bool,
    pub size: u64,
}

/// State of the local repository that git itself would act on.
#[derive(Debug, Clone, Default)]
pub struct LocalRepoState {
    /// Path of the repository-local config file that was read.
    pub config_path: Option<String>,
    pub config: Vec<ConfigEntry>,
    /// Non-sample files in the hooks directory.
    pub hooks: Vec<HookFile>,
}

/// Everything detectors may look at.
#[derive(Debug, Clone, Default)]
pub struct ScanContext {
    /// Human description of what is scanned, e.g. `HEAD..origin/dev`.
    pub label: String,
    pub base: Option<String>,
    pub tip: Option<String>,
    /// Net changes between base tree and tip tree.
    pub changes: Vec<FileChange>,
    /// Versions introduced by intermediate commits that do not survive into the tip.
    pub transited: Vec<FileChange>,
    /// Incoming commits, newest first.
    pub commits: Vec<CommitInfo>,
    pub local: Option<LocalRepoState>,
    /// History facts about the ref being scanned (rewrites, committer habits).
    pub provenance: Option<Provenance>,
    /// What signatures and GitHub say about the incoming commits.
    pub attest: Option<Attestations>,
}

/// Where git-shield learned about a previous tip of the scanned ref.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TipSource {
    /// Value of the remote-tracking ref just before git-shield fetched.
    PreFetch,
    /// An earlier value recorded in the ref's reflog.
    Reflog,
    /// The last tip the user pulled through git-shield.
    TrustStore,
    /// Passed explicitly (`scan --previous-tip`).
    Given,
    /// The `before` of a force-push in GitHub's activity log.
    GitHub,
}

impl TipSource {
    pub fn describe(self) -> &'static str {
        match self {
            TipSource::PreFetch => "fetched before",
            TipSource::Reflog => "recorded in the reflog",
            TipSource::TrustStore => "last pulled through git-shield",
            TipSource::Given => "given with --previous-tip",
            TipSource::GitHub => "replaced by a force-push on GitHub",
        }
    }
}

/// A previous tip of the ref that is not contained in the new tip.
#[derive(Debug, Clone)]
pub struct Rewrite {
    pub old_tip: String,
    pub source: TipSource,
    /// Commits reachable from `old_tip` but not from the new tip, newest first (capped).
    pub lost: Vec<CommitInfo>,
    /// True if `lost` was cut at the cap.
    pub lost_truncated: bool,
    /// The old tip's objects are not available locally, so `lost` is unknown
    /// (only possible for tips learned from GitHub).
    pub missing: bool,
    /// The force-push that replaced `old_tip`, if GitHub reported it.
    pub push: Option<ForcePushInfo>,
}

/// A force-push as recorded by GitHub's activity log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForcePushInfo {
    /// GitHub login of the pusher.
    pub by: String,
    /// Unix seconds.
    pub at: i64,
    /// The pushed (rewritten) tip is already in the local branch: the user
    /// pulled it before git-shield was watching. Reported, but not blocking.
    pub already_in_head: bool,
}

/// History facts used by the T10/T11 detectors.
#[derive(Debug, Clone, Default)]
pub struct Provenance {
    /// Full ref name, e.g. `refs/remotes/origin/dev`.
    pub ref_name: String,
    pub rewrites: Vec<Rewrite>,
    /// Committer email (lower-cased) → UTC offset (seconds) → number of commits,
    /// from a bounded walk of history behind the merge base.
    pub committer_offsets: HashMap<String, HashMap<i32, u32>>,
    /// Committer time of each incoming commit's parents that are not themselves incoming
    /// (id → committer time), so date checks can compare against them.
    pub parent_times: HashMap<String, i64>,
    /// "Now" in unix seconds (injected so tests are deterministic).
    pub now: i64,
}

/// Format of a commit signature, from its armor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigFormat {
    Gpg,
    Ssh,
    X509,
    Unknown,
}

/// Outcome of verifying one commit signature locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigStatus {
    /// Valid, and made by a key the verifier trusts for this signer.
    Good {
        signer: String,
    },
    /// Cryptographically intact, but the key is not tied to anyone (SSH without allowed signers).
    Intact,
    /// The signature does not match the commit: altered or forged.
    Bad(String),
    /// Valid-looking, but the key is not in any keyring / allowed-signers file.
    NoKey,
    Expired,
    Revoked,
    /// Could not check (tool missing, timeout, unsupported format).
    Unchecked(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigCheck {
    pub format: SigFormat,
    pub status: SigStatus,
    /// Checked against GitHub's web-flow key (the commit claims GitHub as committer).
    pub web_flow: bool,
}

/// GitHub's verdict on a commit (`commit.verification` in the API).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteVerification {
    pub verified: bool,
    pub reason: String,
    pub author_login: Option<String>,
    pub committer_login: Option<String>,
}

/// A pull request's state on GitHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrState {
    Merged { merge_commit_sha: String },
    Open,
    ClosedUnmerged,
    NotFound,
}

/// The GitHub push that first brought an incoming commit onto the branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedBy {
    pub login: String,
    /// `push`, `force_push`, `pr_merge`, `merge_queue_merge`, ...
    pub kind: String,
    /// Unix seconds.
    pub at: i64,
}

/// Signature and GitHub facts about incoming commits (keyed by full commit id).
/// Every map may be partial: absent means "not checked", never "fine".
#[derive(Debug, Clone, Default)]
pub struct Attestations {
    pub local: HashMap<String, SigCheck>,
    pub github: HashMap<String, RemoteVerification>,
    pub prs: HashMap<u64, PrState>,
    pub pushes: HashMap<String, PushedBy>,
    /// The user's config requires signed commits for this repository.
    pub require_signed: bool,
}

impl Attestations {
    /// Did any trusted source confirm this commit's signature?
    pub fn confirmed(&self, id: &str) -> bool {
        self.github.get(id).is_some_and(|v| v.verified)
            || matches!(self.local.get(id), Some(SigCheck { status: SigStatus::Good { .. }, .. }))
    }
}
