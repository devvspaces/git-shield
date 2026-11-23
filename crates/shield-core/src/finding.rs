use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;

/// Severity of a finding. `High` and above block by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn blocks(self) -> bool {
        self >= Severity::High
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Threat category, matching `docs/THREATS.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Threat {
    /// Editor tasks that auto-run (`.vscode/tasks.json` folderOpen).
    T1,
    /// Payload disguised as a binary asset (fake fonts, images).
    T2,
    /// Editor settings that enable execution.
    T3,
    /// AI coding-agent configuration (hooks, MCP servers, rules).
    T4,
    /// Package lifecycle / build scripts.
    T5,
    /// Shell environment auto-loaders (.envrc …).
    T6,
    /// Local git config / hooks that execute commands.
    T7,
    /// `.gitattributes` drivers and `.gitmodules` changes.
    T8,
    /// CI workflows and devcontainers.
    T9,
    /// History rewrite / force-push.
    T10,
    /// Impersonated or duplicated commits.
    T11,
    /// Whitespace / line-ending noise masking real changes.
    T12,
    /// Obfuscated code.
    T13,
    /// Sensitive path touched (no specific detector fired).
    Path,
    /// A user-supplied content rule (YARA) without a `threat` meta.
    Custom,
}

impl Threat {
    pub fn code(self) -> &'static str {
        match self {
            Threat::T1 => "T1",
            Threat::T2 => "T2",
            Threat::T3 => "T3",
            Threat::T4 => "T4",
            Threat::T5 => "T5",
            Threat::T6 => "T6",
            Threat::T7 => "T7",
            Threat::T8 => "T8",
            Threat::T9 => "T9",
            Threat::T10 => "T10",
            Threat::T11 => "T11",
            Threat::T12 => "T12",
            Threat::T13 => "T13",
            Threat::Path => "PATH",
            Threat::Custom => "YR",
        }
    }

    /// One-line description, as in `docs/THREATS.md`.
    pub fn description(self) -> &'static str {
        match self {
            Threat::T1 => "Editor tasks that run automatically when a folder is opened",
            Threat::T2 => "Payload disguised as a binary asset",
            Threat::T3 => "Editor settings that enable code execution",
            Threat::T4 => "AI coding-agent configuration (hooks, MCP servers, rules)",
            Threat::T5 => "Package lifecycle and build scripts",
            Threat::T6 => "Shell environment auto-loaders",
            Threat::T7 => "Local git config or hooks that execute commands",
            Threat::T8 => "Git attribute drivers and submodule changes",
            Threat::T9 => "CI workflows and devcontainers",
            Threat::T10 => "History rewrite or force-push",
            Threat::T11 => "Impersonated, forged or duplicated commits",
            Threat::T12 => "Whitespace or line-ending noise masking real changes",
            Threat::T13 => "Obfuscated code",
            Threat::Path => "Sensitive path changed",
            Threat::Custom => "User content rule (YARA)",
        }
    }
}

/// Stable identifier for a finding, e.g. `GS-T1-3fa9c2a1`.
///
/// Derived from (rule, path, anchor) so it survives re-runs and can be used
/// with `--accept`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct FindingId(pub String);

impl FindingId {
    pub fn compute(threat: Threat, rule: &str, path: Option<&str>, anchor: Option<&str>) -> Self {
        let mut h = Sha256::new();
        h.update(rule.as_bytes());
        h.update([0]);
        h.update(path.unwrap_or("").as_bytes());
        h.update([0]);
        h.update(anchor.unwrap_or("").as_bytes());
        let digest = h.finalize();
        FindingId(format!("GS-{}-{}", threat.code(), &hex::encode(digest)[..8]))
    }
}

impl fmt::Display for FindingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One thing git-shield wants a human to look at.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: FindingId,
    pub threat: Threat,
    /// Machine-readable rule name, e.g. `vscode.tasks.folder-open`.
    pub rule: &'static str,
    pub severity: Severity,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Commit the finding is anchored to (introducing commit for transited findings).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Blob or other content anchor used for the stable id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    /// Supporting detail lines (evidence, explanation, remediation).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
    /// True when the content appeared in an intermediate commit but is not in
    /// the final incoming tree.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub transited: bool,
    /// Original severity when the engine lowered it (transited content).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capped_from: Option<Severity>,
    /// Repository paths this finding's command executes or loads (not part of the id).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<String>,
}

impl Finding {
    pub fn new(threat: Threat, rule: &'static str, severity: Severity, title: impl Into<String>) -> Self {
        Finding {
            id: FindingId(String::new()),
            threat,
            rule,
            severity,
            title: title.into(),
            path: None,
            commit: None,
            anchor: None,
            details: Vec::new(),
            transited: false,
            capped_from: None,
            refs: Vec::new(),
        }
    }

    /// Record repository paths the finding's command references.
    pub fn refs(mut self, refs: impl IntoIterator<Item = String>) -> Self {
        self.refs.extend(refs);
        self
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn commit(mut self, commit: impl Into<String>) -> Self {
        self.commit = Some(commit.into());
        self
    }

    pub fn anchor(mut self, anchor: impl Into<String>) -> Self {
        self.anchor = Some(anchor.into());
        self
    }

    pub fn detail(mut self, line: impl Into<String>) -> Self {
        self.details.push(line.into());
        self
    }

    /// Compute the stable id. Called by the engine after detectors run.
    pub(crate) fn seal(&mut self) {
        self.id = FindingId::compute(self.threat, self.rule, self.path.as_deref(), self.anchor.as_deref());
    }
}
