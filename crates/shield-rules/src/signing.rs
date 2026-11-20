//! T11 with evidence: what commit signatures and GitHub say about incoming
//! commits (`ScanContext.attest`). Absent data means "not checked": every
//! rule here stays silent rather than guessing.

use shield_core::{Attestations, CommitInfo, Detector, Finding, PrState, ScanContext, Severity, SigStatus, Threat};
use std::collections::HashSet;
use std::sync::LazyLock;

const GITHUB_EMAIL: &str = "noreply@github.com";
const LIST_LIMIT: usize = 10;

static MERGE_PR: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^Merge pull request #(\d+) from ").expect("valid regex"));

fn short(id: &str) -> &str {
    &id[..id.len().min(9)]
}

fn by_github(c: &CommitInfo) -> bool {
    c.committer_email.eq_ignore_ascii_case(GITHUB_EMAIL)
}

/// The PR number a "Merge pull request #N from ..." commit claims.
pub fn claimed_pr(summary: &str) -> Option<u64> {
    MERGE_PR.captures(summary)?.get(1)?.as_str().parse().ok()
}

/// Signed by GitHub itself (web-flow), per GitHub's API or our own gpgv check.
fn web_flow_signed(a: &Attestations, c: &CommitInfo) -> bool {
    if !by_github(c) {
        return false;
    }
    a.github.get(&c.id).is_some_and(|v| v.verified && v.committer_login.as_deref() == Some("web-flow"))
        || a.local.get(&c.id).is_some_and(|s| s.web_flow && matches!(s.status, SigStatus::Good { .. }))
}

pub struct Signatures;

impl Detector for Signatures {
    fn name(&self) -> &'static str {
        "signatures"
    }

    fn scan_context(&self, ctx: &ScanContext, out: &mut Vec<Finding>) {
        let Some(a) = &ctx.attest else { return };
        pr_merges(ctx, a, out);
        let bad = bad_signatures(ctx, a, out);
        github_unverified(ctx, a, &bad, out);
        identity_quirks(ctx, a, out);
        if a.require_signed {
            required(ctx, a, &bad, out);
        }
    }
}

/// "Merge pull request #N" must be the merge commit GitHub recorded for PR N.
fn pr_merges(ctx: &ScanContext, a: &Attestations, out: &mut Vec<Finding>) {
    for c in &ctx.commits {
        let Some(n) = claimed_pr(&c.summary) else { continue };
        let Some(state) = a.prs.get(&n) else { continue };
        let problem = match state {
            PrState::Merged { merge_commit_sha } if merge_commit_sha.eq_ignore_ascii_case(&c.id) => continue,
            PrState::Merged { merge_commit_sha } => {
                format!("GitHub's merge commit for PR #{n} is {}, not this commit", short(merge_commit_sha))
            }
            PrState::Open => format!("PR #{n} is still open: GitHub never merged it"),
            PrState::ClosedUnmerged => format!("PR #{n} was closed without being merged"),
            PrState::NotFound => format!("PR #{n} does not exist in this repository"),
        };
        let genuine = web_flow_signed(a, c);
        let (sev, title) = if genuine {
            (Severity::Low, format!("Merge commit {} names PR #{n} of another repository", short(&c.id)))
        } else {
            (Severity::Critical, format!("Commit {} claims to merge PR #{n}, but GitHub disagrees", short(&c.id)))
        };
        let mut f = Finding::new(Threat::T11, "t11.pr-merge-mismatch", sev, title)
            .commit(c.id.clone())
            .anchor(format!("pr-merge:{}", c.id))
            .detail(problem)
            .detail(format!("Summary: {}", c.summary))
            .detail(format!("Committer: {} <{}>", c.committer_name, c.committer_email));
        if genuine {
            f = f.detail(
                "It is signed by GitHub, so it is a real GitHub merge, most likely from an upstream or fork \
                 whose PR numbers differ.",
            );
        } else {
            f = f.detail(
                "Commits made by GitHub's merge button are exactly the PR's merge commit. A different commit \
                 with this summary was written elsewhere to look like one.",
            );
            if let Some(p) = a.pushes.get(&c.id)
                && matches!(p.kind.as_str(), "push" | "force_push")
            {
                f = f.detail(format!(
                    "It reached the branch in a direct {} by @{}, not through GitHub's merge.",
                    p.kind.replace('_', "-"),
                    p.login
                ));
            }
        }
        out.push(f);
    }
}

fn bad_signatures(ctx: &ScanContext, a: &Attestations, out: &mut Vec<Finding>) -> HashSet<String> {
    let mut bad = HashSet::new();
    for c in &ctx.commits {
        let local = match a.local.get(&c.id).map(|s| &s.status) {
            Some(SigStatus::Bad(why)) => Some(why.clone()),
            _ => None,
        };
        let remote = a.github.get(&c.id).filter(|v| {
            !v.verified && matches!(v.reason.as_str(), "invalid" | "malformed_signature" | "malformed_sig")
        });
        if local.is_none() && remote.is_none() {
            continue;
        }
        let gh = by_github(c);
        let (sev, title) = if gh {
            (Severity::Critical, format!("Commit {} carries a forged GitHub signature", short(&c.id)))
        } else {
            (Severity::High, format!("Commit {} has a signature that does not match its content", short(&c.id)))
        };
        let mut f = Finding::new(Threat::T11, "t11.signature-bad", sev, title)
            .commit(c.id.clone())
            .anchor(format!("sig-bad:{}", c.id))
            .detail(format!("Summary: {}", c.summary))
            .detail(format!("Committer: {} <{}>", c.committer_name, c.committer_email));
        if let Some(why) = local {
            f = f.detail(format!("Local check: {why}."));
        }
        if let Some(v) = remote {
            f = f.detail(format!("GitHub: not verified ({}).", v.reason));
        }
        f = f.detail(
            "A signature that does not verify means the commit was altered after signing, or the signature \
             was copied from another commit.",
        );
        bad.insert(c.id.clone());
        out.push(f);
    }
    bad
}

/// Signed, committed as GitHub, yet neither GitHub nor GitHub's key vouches for it.
fn github_unverified(ctx: &ScanContext, a: &Attestations, bad: &HashSet<String>, out: &mut Vec<Finding>) {
    for c in &ctx.commits {
        if !by_github(c) || !c.signed || bad.contains(&c.id) || web_flow_signed(a, c) {
            continue;
        }
        let local = a.local.get(&c.id).filter(|s| !matches!(s.status, SigStatus::Unchecked(_)));
        let remote = a.github.get(&c.id);
        if local.is_none() && remote.is_none() {
            continue;
        }
        let mut f = Finding::new(
            Threat::T11,
            "t11.github-unverified",
            Severity::Critical,
            format!("Commit {} claims GitHub as committer, but is not signed by GitHub", short(&c.id)),
        )
        .commit(c.id.clone())
        .anchor(format!("github-unverified:{}", c.id))
        .detail(format!("Summary: {}", c.summary));
        if let Some(s) = local {
            f = f.detail(format!("Checked against GitHub's published signing keys: {:?}.", s.status));
        }
        if let Some(v) = remote {
            f = f.detail(format!(
                "GitHub: {} ({}).",
                if v.verified { "verified, but not by web-flow" } else { "not verified" },
                v.reason
            ));
        }
        out.push(f.detail("Every commit GitHub writes (merges, web edits) is signed with its web-flow key."));
    }
}

/// GitHub could check the signature but not tie it to the committer. Common
/// (unverified secondary emails), so Low, grouped per committer.
fn identity_quirks(ctx: &ScanContext, a: &Attestations, out: &mut Vec<Finding>) {
    let mut groups: Vec<(String, Vec<(&CommitInfo, &str)>)> = Vec::new();
    for c in &ctx.commits {
        let Some(v) = a.github.get(&c.id) else { continue };
        if v.verified || !matches!(v.reason.as_str(), "bad_email" | "unverified_email" | "no_user") {
            continue;
        }
        let email = c.committer_email.to_ascii_lowercase();
        match groups.iter_mut().find(|(e, _)| *e == email) {
            Some((_, list)) => list.push((c, v.reason.as_str())),
            None => groups.push((email, vec![(c, v.reason.as_str())])),
        }
    }
    for (email, list) in groups {
        let first = list[0].0;
        let mut f = Finding::new(
            Threat::T11,
            "t11.signature-unverified",
            Severity::Low,
            format!(
                "{} signed commit(s) by {} that GitHub cannot tie to the committer",
                list.len(),
                first.committer_name
            ),
        )
        .commit(first.id.clone())
        .anchor(format!("sig-identity:{email}"));
        for (c, reason) in list.iter().take(LIST_LIMIT) {
            f = f.detail(format!("  {}  {}  ({reason})", short(&c.id), c.summary));
        }
        out.push(f);
    }
}

/// The user's config requires signatures for this repository.
fn required(ctx: &ScanContext, a: &Attestations, bad: &HashSet<String>, out: &mut Vec<Finding>) {
    // (committer email, signed?) → commits
    let mut groups: Vec<((String, bool), Vec<&CommitInfo>)> = Vec::new();
    for c in &ctx.commits {
        if bad.contains(&c.id) || a.confirmed(&c.id) {
            continue;
        }
        let key = (c.committer_email.to_ascii_lowercase(), c.signed);
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(c),
            None => groups.push((key, vec![c])),
        }
    }
    for ((email, signed), list) in groups {
        let first = list[0];
        let (sev, what, tag) = if signed {
            (Severity::Medium, "signed by a key that could not be tied to the committer", "unverified")
        } else {
            (Severity::High, "unsigned", "unsigned")
        };
        let mut f = Finding::new(
            Threat::T11,
            "t11.unsigned-required",
            sev,
            format!(
                "{} commit(s) by {} are {what} (your config requires signed commits)",
                list.len(),
                first.committer_name
            ),
        )
        .commit(first.id.clone())
        .anchor(format!("required-{tag}:{email}"));
        for c in list.iter().take(LIST_LIMIT) {
            f = f.detail(format!("  {}  {}", short(&c.id), c.summary));
        }
        if list.len() > LIST_LIMIT {
            f = f.detail(format!("  … and {} more", list.len() - LIST_LIMIT));
        }
        out.push(f);
    }
}

/// Adds "who pushed it" to every commit-level T10/T11 finding, from GitHub's
/// activity log. Evidence only: no findings of its own.
pub struct PushAttribution;

impl Detector for PushAttribution {
    fn name(&self) -> &'static str {
        "push-attribution"
    }

    fn scan_context(&self, ctx: &ScanContext, out: &mut Vec<Finding>) {
        let Some(a) = &ctx.attest else { return };
        if a.pushes.is_empty() {
            return;
        }
        for f in out.iter_mut() {
            if !matches!(f.threat, Threat::T10 | Threat::T11) || f.rule == "t10.ref-rewritten" {
                continue;
            }
            let Some(p) = f.commit.as_deref().and_then(|c| a.pushes.get(c)) else { continue };
            let line = format!(
                "Arrived in a {} by @{} on {} (GitHub activity log).",
                p.kind.replace('_', "-"),
                p.login,
                shield_core::utc_datetime(p.at)
            );
            if !f.details.contains(&line) {
                f.details.push(line);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shield_core::{PushedBy, RemoteVerification, SigCheck, SigFormat};

    fn commit(id: &str, summary: &str, github: bool, signed: bool) -> CommitInfo {
        let (n, e) = if github { ("GitHub", GITHUB_EMAIL) } else { ("Hycienth", "h@example.com") };
        CommitInfo {
            id: id.repeat(40 / id.len()),
            parents: vec![],
            tree: "t".into(),
            author_name: "A".into(),
            author_email: "a@example.com".into(),
            author_time: 0,
            author_offset: 0,
            committer_name: n.into(),
            committer_email: e.into(),
            committer_time: 0,
            committer_offset: 0,
            summary: summary.into(),
            message: summary.into(),
            signed,
        }
    }

    fn run(commits: Vec<CommitInfo>, a: Attestations) -> Vec<Finding> {
        let ctx = ScanContext { commits, attest: Some(a), ..Default::default() };
        let mut out = Vec::new();
        Signatures.scan_context(&ctx, &mut out);
        PushAttribution.scan_context(&ctx, &mut out);
        out
    }

    fn rv(verified: bool, reason: &str, committer: Option<&str>) -> RemoteVerification {
        RemoteVerification {
            verified,
            reason: reason.into(),
            author_login: None,
            committer_login: committer.map(str::to_string),
        }
    }

    const PR: &str = "Merge pull request #2921 from org/fix";

    #[test]
    fn forged_pr_merge_is_critical_with_pusher() {
        let c = commit("b", PR, false, false);
        let mut a = Attestations::default();
        a.prs.insert(2921, PrState::Merged { merge_commit_sha: "a".repeat(40) });
        a.pushes.insert(c.id.clone(), PushedBy { login: "mallory".into(), kind: "force_push".into(), at: 0 });
        let out = run(vec![c], a);
        let f = out.iter().find(|f| f.rule == "t11.pr-merge-mismatch").unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.details.iter().any(|d| d.contains("aaaaaaaaa, not this commit")));
        assert!(f.details.iter().any(|d| d.contains("direct force-push by @mallory")));
        assert!(f.details.iter().any(|d| d.starts_with("Arrived in a force-push by @mallory")));
    }

    #[test]
    fn real_merge_and_unknown_pr_are_silent() {
        let c = commit("a", PR, true, true);
        let mut a = Attestations::default();
        a.prs.insert(2921, PrState::Merged { merge_commit_sha: c.id.clone() });
        assert!(run(vec![c.clone()], a).is_empty());
        // Not looked up: no opinion.
        assert!(run(vec![c], Attestations::default()).is_empty());
    }

    #[test]
    fn web_flow_merge_with_other_number_is_low() {
        let c = commit("c", PR, true, true);
        let mut a = Attestations::default();
        a.prs.insert(2921, PrState::NotFound);
        a.github.insert(c.id.clone(), rv(true, "valid", Some("web-flow")));
        let out = run(vec![c], a);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Low);
        // Open / closed PRs are Critical without GitHub's signature.
        for st in [PrState::Open, PrState::ClosedUnmerged, PrState::NotFound] {
            let mut a = Attestations::default();
            a.prs.insert(2921, st);
            let out = run(vec![commit("d", PR, false, false)], a);
            assert_eq!(out[0].severity, Severity::Critical);
        }
    }

    #[test]
    fn bad_signatures() {
        let local_bad = |web_flow| SigCheck { format: SigFormat::Gpg, status: SigStatus::Bad("bad".into()), web_flow };
        let c = commit("e", "Fix", false, true);
        let mut a = Attestations::default();
        a.local.insert(c.id.clone(), local_bad(false));
        let out = run(vec![c], a);
        assert_eq!(out[0].rule, "t11.signature-bad");
        assert_eq!(out[0].severity, Severity::High);

        let g = commit("f", "Fix", true, true);
        let mut a = Attestations::default();
        a.local.insert(g.id.clone(), local_bad(true));
        let out = run(vec![g.clone()], a);
        assert_eq!((out.len(), out[0].severity), (1, Severity::Critical), "{out:#?}");

        let mut a = Attestations::default();
        a.github.insert(g.id.clone(), rv(false, "invalid", None));
        assert_eq!(run(vec![g], a)[0].rule, "t11.signature-bad");
    }

    #[test]
    fn github_committer_without_github_signature() {
        let g = commit("a1", "Update README.md", true, true);
        let mut a = Attestations::default();
        a.local.insert(g.id.clone(), SigCheck { format: SigFormat::Gpg, status: SigStatus::NoKey, web_flow: true });
        let out = run(vec![g.clone()], a);
        assert_eq!(out[0].rule, "t11.github-unverified");
        assert_eq!(out[0].severity, Severity::Critical);
        // Good web-flow signature, or nothing checked: silent.
        let mut a = Attestations::default();
        a.local.insert(
            g.id.clone(),
            SigCheck { format: SigFormat::Gpg, status: SigStatus::Good { signer: "GitHub".into() }, web_flow: true },
        );
        assert!(run(vec![g.clone()], a).is_empty());
        let mut a = Attestations::default();
        a.local.insert(
            g.id.clone(),
            SigCheck { format: SigFormat::Gpg, status: SigStatus::Unchecked("no gpgv".into()), web_flow: true },
        );
        assert!(run(vec![g], a).is_empty());
    }

    #[test]
    fn identity_and_required() {
        let c1 = commit("b1", "One", false, true);
        let c2 = commit("b2", "Two", false, false);
        let mut a = Attestations::default();
        a.github.insert(c1.id.clone(), rv(false, "unverified_email", None));
        a.github.insert(c2.id.clone(), rv(false, "unknown_key", None));
        let out = run(vec![c1.clone(), c2.clone()], a.clone());
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].rule, out[0].severity), ("t11.signature-unverified", Severity::Low));

        a.require_signed = true;
        let out = run(vec![c1, c2], a);
        let req: Vec<_> = out.iter().filter(|f| f.rule == "t11.unsigned-required").collect();
        assert_eq!(req.len(), 2);
        assert!(req.iter().any(|f| f.severity == Severity::High));
        assert!(req.iter().any(|f| f.severity == Severity::Medium));
    }

    #[test]
    fn claimed_pr_numbers() {
        assert_eq!(claimed_pr("Merge pull request #2921 from org/fix"), Some(2921));
        assert_eq!(claimed_pr("Merge branch 'dev'"), None);
        assert_eq!(claimed_pr("Revert \"Merge pull request #1 from x/y\""), None);
    }
}
