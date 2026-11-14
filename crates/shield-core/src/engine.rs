use crate::{FileChange, Finding, ScanContext, Severity, Threat};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::{BTreeSet, HashSet};

/// A detector inspects either individual file changes, the whole context, or both.
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;

    /// Cheap path prefilter; `scan_file` is only called when this returns true.
    fn interested(&self, _change: &FileChange) -> bool {
        false
    }

    fn scan_file(&self, _change: &FileChange, _out: &mut Vec<Finding>) {}

    fn scan_context(&self, _ctx: &ScanContext, _out: &mut Vec<Finding>) {}
}

/// Result of a scan.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tip: Option<String>,
    pub commits_scanned: usize,
    pub files_scanned: usize,
    /// Sorted: most severe first.
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Findings that block and have not been accepted.
    pub fn blocking<'a>(&'a self, accepted: &'a HashSet<String>) -> impl Iterator<Item = &'a Finding> + 'a {
        self.findings.iter().filter(move |f| f.severity.blocks() && !accepted.contains(&f.id.0))
    }

    /// 0 = clean, 1 = warnings only, 2 = blocked.
    pub fn exit_code(&self, accepted: &HashSet<String>) -> i32 {
        if self.blocking(accepted).next().is_some() {
            2
        } else if self.findings.iter().any(|f| f.severity > Severity::Info) {
            1
        } else {
            0
        }
    }
}

/// Run all detectors over the context.
pub fn run(detectors: &[Box<dyn Detector>], ctx: &ScanContext) -> Report {
    let file_findings: Vec<Finding> = ctx
        .changes
        .par_iter()
        .chain(ctx.transited.par_iter())
        .flat_map_iter(|change| {
            let mut out = Vec::new();
            for d in detectors {
                if d.interested(change) {
                    d.scan_file(change, &mut out);
                }
            }
            for f in &mut out {
                if f.path.is_none() {
                    f.path = Some(change.path.clone());
                }
                if f.commit.is_none() {
                    f.commit.clone_from(&change.commit);
                }
                if change.transited {
                    mark_transited(f);
                }
            }
            out
        })
        .collect();

    let mut findings = file_findings;
    for d in detectors {
        d.scan_context(ctx, &mut findings);
    }

    for f in &mut findings {
        f.seal();
    }
    let findings = finalize(findings);

    Report {
        label: ctx.label.clone(),
        base: ctx.base.clone(),
        tip: ctx.tip.clone(),
        commits_scanned: ctx.commits.len(),
        files_scanned: ctx.changes.len() + ctx.transited.len(),
        findings,
    }
}

/// Content that only existed in an intermediate commit is reported, but capped
/// at Medium: it never reaches your working tree on a fast-forward, though it
/// does on checkout of that commit and it is strong evidence of tampering.
fn mark_transited(f: &mut Finding) {
    f.transited = true;
    if f.severity > Severity::Medium {
        f.details.push(format!(
            "Severity lowered from {} because this content is not in the final incoming tree; \
             it was added by an intermediate commit and later removed.",
            f.severity
        ));
        f.severity = Severity::Medium;
    }
}

fn finalize(mut findings: Vec<Finding>) -> Vec<Finding> {
    // Drop generic "sensitive path" notes where a specific detector already reported.
    let specific: HashSet<(Option<String>, bool)> =
        findings.iter().filter(|f| f.threat != Threat::Path).map(|f| (f.path.clone(), f.transited)).collect();
    findings.retain(|f| f.threat != Threat::Path || !specific.contains(&(f.path.clone(), f.transited)));

    // Dedupe identical ids (same rule/path/anchor reported twice).
    let mut seen = BTreeSet::new();
    findings.retain(|f| seen.insert(f.id.0.clone()));

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.transited.cmp(&b.transited))
            .then(a.path.cmp(&b.path))
            .then(a.rule.cmp(b.rule))
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlobData, FileStatus};
    use std::sync::Arc;

    struct Always;
    impl Detector for Always {
        fn name(&self) -> &'static str {
            "always"
        }
        fn interested(&self, _c: &FileChange) -> bool {
            true
        }
        fn scan_file(&self, c: &FileChange, out: &mut Vec<Finding>) {
            out.push(Finding::new(Threat::T1, "test.always", Severity::Critical, "x").anchor(c.path.clone()));
        }
    }

    fn change(path: &str, transited: bool) -> FileChange {
        FileChange {
            path: path.into(),
            status: FileStatus::Added,
            old: None,
            new: Some(BlobData {
                oid: "0".repeat(40),
                bytes: Arc::from(&b"x"[..]),
                truncated: false,
                size: 1,
                executable: false,
                symlink: false,
            }),
            commit: None,
            transited,
        }
    }

    #[test]
    fn transited_is_capped_at_medium_and_ids_are_stable() {
        let ctx =
            ScanContext { changes: vec![change("a", false)], transited: vec![change("b", true)], ..Default::default() };
        let dets: Vec<Box<dyn Detector>> = vec![Box::new(Always)];
        let r1 = run(&dets, &ctx);
        let r2 = run(&dets, &ctx);
        assert_eq!(r1.findings.len(), 2);
        assert_eq!(r1.findings[0].severity, Severity::Critical);
        assert_eq!(r1.findings[1].severity, Severity::Medium);
        assert!(r1.findings[1].transited);
        assert_eq!(r1.findings[0].id, r2.findings[0].id);
        assert!(r1.findings[0].id.0.starts_with("GS-T1-"));
        assert_eq!(r1.exit_code(&HashSet::new()), 2);
        let accepted: HashSet<String> = [r1.findings[0].id.0.clone()].into();
        assert_eq!(r1.exit_code(&accepted), 1);
    }
}
