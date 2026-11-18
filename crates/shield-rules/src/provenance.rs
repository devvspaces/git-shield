//! T10 history rewrites and T11 impersonated / duplicated commits (offline).
//!
//! Signals come from the scanned ref's previous tips (pre-fetch value, reflog,
//! trust store) and from the incoming commit objects themselves. Signature
//! *presence* only; cryptographic verification is Phase 5.

use shield_core::{CommitInfo, Detector, Finding, ScanContext, Severity, Threat};
use std::collections::{HashMap, HashSet};

const GITHUB_EMAIL: &str = "noreply@github.com";
const DAY: i64 = 24 * 3600;
/// Committer must have at least this many commits before an unseen timezone is notable.
const TZ_MIN_HISTORY: u32 = 5;
const LIST_LIMIT: usize = 10;

fn short(id: &str) -> &str {
    &id[..id.len().min(9)]
}

fn fmt_offset(secs: i32) -> String {
    let sign = if secs < 0 { '-' } else { '+' };
    let a = secs.unsigned_abs();
    format!("{sign}{:02}{:02}", a / 3600, (a % 3600) / 60)
}

fn display_ref(name: &str) -> &str {
    name.strip_prefix("refs/remotes/").or_else(|| name.strip_prefix("refs/heads/")).unwrap_or(name)
}

fn who(name: &str, email: &str) -> String {
    format!("{name} <{email}>")
}

/// T10: the scanned ref no longer contains a tip we saw before.
pub struct RefRewritten;

impl Detector for RefRewritten {
    fn name(&self) -> &'static str {
        "ref-rewritten"
    }

    fn scan_context(&self, ctx: &ScanContext, out: &mut Vec<Finding>) {
        let Some(p) = &ctx.provenance else { return };
        let tip = ctx.tip.as_deref().unwrap_or("");
        for rw in &p.rewrites {
            let mut f = Finding::new(
                Threat::T10,
                "t10.ref-rewritten",
                Severity::High,
                format!(
                    "`{}` was rewritten (force-push): {} is no longer in its history",
                    display_ref(&p.ref_name),
                    short(&rw.old_tip)
                ),
            )
            .commit(tip)
            .anchor(format!("{}..{}", rw.old_tip, tip))
            .detail(format!("Previous tip {} ({}).", short(&rw.old_tip), rw.source.describe()));
            let more = if rw.lost_truncated { "+" } else { "" };
            f = f.detail(format!("{}{more} commit(s) dropped from the branch:", rw.lost.len()));
            for c in rw.lost.iter().take(LIST_LIMIT) {
                f = f.detail(format!("  {}  {}  ({})", short(&c.id), c.summary, c.author_name));
            }
            if rw.lost.len() > LIST_LIMIT {
                f = f.detail(format!("  … and {} more", rw.lost.len() - LIST_LIMIT));
            }
            out.push(f.detail(
                "Confirm with whoever owns the branch before pulling. On GitHub: repository → Activity → force pushes.",
            ));
        }
    }
}

/// T11: commits that pretend to be someone else's.
pub struct Impersonation;

impl Detector for Impersonation {
    fn name(&self) -> &'static str {
        "impersonation"
    }

    fn scan_context(&self, ctx: &ScanContext, out: &mut Vec<Finding>) {
        let mut copies = HashSet::new();
        if let Some(p) = &ctx.provenance {
            copies = rewritten_copies(ctx, p, out);
            unusual_timezones(ctx, p, out);
            date_anomalies(ctx, p, out);
        }
        github_merges(ctx, &copies, out);
    }
}

/// An incoming commit that duplicates a dropped one (same summary, author and
/// author date) under a new id: the classic "rewrite the tip, keep the
/// metadata" force-push. Returns the ids of the copies it reported.
fn rewritten_copies(ctx: &ScanContext, p: &shield_core::Provenance, out: &mut Vec<Finding>) -> HashSet<String> {
    let mut reported = HashSet::new();
    let mut lost: HashMap<(&str, String, i64), &CommitInfo> = HashMap::new();
    for rw in &p.rewrites {
        for c in &rw.lost {
            lost.entry((c.summary.as_str(), c.author_email.to_ascii_lowercase(), c.author_time)).or_insert(c);
        }
    }
    if lost.is_empty() {
        return reported;
    }
    for copy in &ctx.commits {
        let k = (copy.summary.as_str(), copy.author_email.to_ascii_lowercase(), copy.author_time);
        let Some(orig) = lost.get(&k) else { continue };
        if orig.id == copy.id {
            continue;
        }
        let dropped_sig = orig.signed && !copy.signed;
        let committer_changed = !orig.committer_email.eq_ignore_ascii_case(&copy.committer_email)
            || orig.committer_name != copy.committer_name;
        let sev = if dropped_sig || committer_changed { Severity::Critical } else { Severity::High };
        let mut f = Finding::new(
            Threat::T11,
            "t11.rewritten-copy",
            sev,
            format!("Commit {} is a rewritten copy of {} (\"{}\")", short(&copy.id), short(&orig.id), copy.summary),
        )
        .commit(copy.id.clone())
        .anchor(format!("{}<-{}", copy.id, orig.id))
        .detail(format!(
            "Same summary, author ({}) and author date as the dropped original.",
            who(&copy.author_name, &copy.author_email)
        ));
        if dropped_sig {
            f = f.detail("Signature: original was signed, the copy is not.");
        } else if orig.signed != copy.signed {
            f = f.detail("Signature: original was unsigned, the copy is signed.");
        }
        if committer_changed {
            f = f.detail(format!(
                "Committer: {} → {}",
                who(&orig.committer_name, &orig.committer_email),
                who(&copy.committer_name, &copy.committer_email)
            ));
        }
        if orig.committer_offset != copy.committer_offset {
            f = f.detail(format!(
                "Committer timezone: {} → {}",
                fmt_offset(orig.committer_offset),
                fmt_offset(copy.committer_offset)
            ));
        }
        if orig.tree != copy.tree {
            f = f.detail(format!(
                "Content differs from the original; compare: git diff {} {}",
                short(&orig.id),
                short(&copy.id)
            ));
        }
        if orig.parents != copy.parents {
            f = f.detail("Parents differ from the original.");
        }
        reported.insert(copy.id.clone());
        out.push(f);
    }
    reported
}

/// "Merge pull request #N" commits are created by GitHub, committed as
/// `GitHub <noreply@github.com>` and signed with GitHub's key.
///
/// One finding per (committer, problem), so a long range with many forged
/// merges stays readable and one `--accept` covers one impersonator. Commits
/// already reported as rewritten copies are skipped (that finding is stronger).
fn github_merges(ctx: &ScanContext, skip: &HashSet<String>, out: &mut Vec<Finding>) {
    // (committer email, unsigned-by-github?) → commits, newest first (ctx order).
    let mut groups: Vec<((String, bool), Vec<&CommitInfo>)> = Vec::new();
    for c in &ctx.commits {
        if !c.summary.starts_with("Merge pull request #") || skip.contains(&c.id) {
            continue;
        }
        let by_github = c.committer_email.eq_ignore_ascii_case(GITHUB_EMAIL);
        if by_github && c.signed {
            continue;
        }
        let key = (c.committer_email.to_ascii_lowercase(), by_github);
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(c),
            None => groups.push((key, vec![c])),
        }
    }
    for ((email, by_github), commits) in groups {
        let first = commits[0];
        let n = commits.len();
        let (title, detail, anchor) = if by_github {
            (
                if n == 1 {
                    "GitHub merge commit has no signature".to_string()
                } else {
                    format!("{n} GitHub merge commits have no signature")
                },
                "Merges made on GitHub are signed by GitHub's key.".to_string(),
                format!("merge-unsigned:{email}"),
            )
        } else {
            (
                if n == 1 {
                    format!("GitHub-style merge commit was not committed by GitHub (by {})", first.committer_name)
                } else {
                    format!("{n} GitHub-style merge commits were not committed by GitHub (by {})", first.committer_name)
                },
                format!(
                    "Committer is {}; merges made on GitHub are committed by GitHub <{GITHUB_EMAIL}>.",
                    who(&first.committer_name, &first.committer_email)
                ),
                format!("merge-not-github:{email}"),
            )
        };
        let mut f = Finding::new(Threat::T11, "t11.merge-not-by-github", Severity::Medium, title)
            .commit(first.id.clone())
            .anchor(anchor)
            .detail(detail);
        for c in commits.iter().take(LIST_LIMIT) {
            f = f.detail(format!("  {}  {}", short(&c.id), c.summary));
        }
        if n > LIST_LIMIT {
            f = f.detail(format!("  … and {} more", n - LIST_LIMIT));
        }
        out.push(f);
    }
}

fn unusual_timezones(ctx: &ScanContext, p: &shield_core::Provenance, out: &mut Vec<Finding>) {
    for c in &ctx.commits {
        let email = c.committer_email.to_ascii_lowercase();
        let Some(seen) = p.committer_offsets.get(&email) else { continue };
        let total: u32 = seen.values().sum();
        if total < TZ_MIN_HISTORY || seen.contains_key(&c.committer_offset) {
            continue;
        }
        let mut habits: Vec<_> = seen.iter().collect();
        habits.sort_by(|a, b| b.1.cmp(a.1));
        let habits: Vec<String> = habits.iter().take(3).map(|(o, n)| format!("{} ×{n}", fmt_offset(**o))).collect();
        out.push(
            Finding::new(
                Threat::T11,
                "t11.unusual-timezone",
                Severity::Low,
                format!(
                    "Committer timezone {} never used before by {}",
                    fmt_offset(c.committer_offset),
                    c.committer_name
                ),
            )
            .commit(c.id.clone())
            .anchor(c.id.clone())
            .detail(format!("Seen in {total} earlier commits: {}", habits.join(", "))),
        );
    }
}

fn date_anomalies(ctx: &ScanContext, p: &shield_core::Provenance, out: &mut Vec<Finding>) {
    for c in &ctx.commits {
        if c.committer_time > p.now + DAY {
            out.push(
                Finding::new(Threat::T11, "t11.date-anomaly", Severity::Medium, "Commit is dated in the future")
                    .commit(c.id.clone())
                    .anchor(format!("future:{}", c.id))
                    .detail(format!("Committer date is {} day(s) ahead of now.", (c.committer_time - p.now) / DAY)),
            );
        }
        let parent_max = c.parents.iter().filter_map(|id| p.parent_times.get(id)).max();
        if let Some(&pt) = parent_max
            && c.committer_time + DAY < pt
        {
            out.push(
                Finding::new(Threat::T11, "t11.date-anomaly", Severity::Low, "Commit is dated before its parent")
                    .commit(c.id.clone())
                    .anchor(format!("before-parent:{}", c.id))
                    .detail(format!("Committed {} day(s) before its parent.", (pt - c.committer_time) / DAY)),
            );
        }
    }
}

/// Runs last: rewritten history that carried (even briefly) a high-severity
/// payload is the signature of the force-push worm, so escalate it.
pub struct TamperedPayload;

impl Detector for TamperedPayload {
    fn name(&self) -> &'static str {
        "tampered-payload"
    }

    fn scan_context(&self, ctx: &ScanContext, out: &mut Vec<Finding>) {
        let forged: Vec<&Finding> = out
            .iter()
            .filter(|f| matches!(f.threat, Threat::T10 | Threat::T11) && f.severity >= Severity::High)
            .collect();
        let payloads: Vec<&Finding> =
            out.iter().filter(|f| f.transited && f.capped_from.is_some_and(|s| s >= Severity::High)).collect();
        if forged.is_empty() || payloads.is_empty() {
            return;
        }
        let mut f = Finding::new(
            Threat::T10,
            "t10.tampered-payload",
            Severity::Critical,
            "Rewritten history carried a payload that was later removed",
        )
        .anchor(ctx.tip.clone().unwrap_or_default())
        .detail("History was rewritten or impersonated, and an intermediate commit added content that runs code:");
        if let Some(t) = &ctx.tip {
            f = f.commit(t.clone());
        }
        for p in payloads.iter().take(LIST_LIMIT) {
            let at = p.commit.as_deref().map(short).unwrap_or("?");
            f = f.detail(format!("  {} ({} @ {at})", p.title, p.path.as_deref().unwrap_or("")));
        }
        for x in forged.iter().take(LIST_LIMIT) {
            f = f.detail(format!("  {}", x.title));
        }
        f = f.detail(
            "Anyone who checked out the intermediate commit, or whose editor/CI ran in it, may have executed it.",
        );
        out.push(f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shield_core::{Provenance, Rewrite, TipSource};

    fn commit(id: &str, summary: &str, committer: (&str, &str), offset: i32, signed: bool) -> CommitInfo {
        CommitInfo {
            id: id.repeat(40 / id.len()),
            parents: vec!["p".repeat(40)],
            tree: format!("{id}-tree"),
            author_name: "Hycienth".into(),
            author_email: "h@example.com".into(),
            author_time: 1000,
            author_offset: 3600,
            committer_name: committer.0.into(),
            committer_email: committer.1.into(),
            committer_time: 2000,
            committer_offset: offset,
            summary: summary.into(),
            message: summary.into(),
            signed,
        }
    }

    const GH: (&str, &str) = ("GitHub", "noreply@github.com");
    const HY: (&str, &str) = ("Hycienth", "h@example.com");

    fn ctx(incoming: Vec<CommitInfo>, lost: Vec<CommitInfo>) -> ScanContext {
        let mut p = Provenance { ref_name: "refs/remotes/origin/dev".into(), now: 10_000, ..Default::default() };
        if !lost.is_empty() {
            p.rewrites.push(Rewrite {
                old_tip: lost[0].id.clone(),
                source: TipSource::PreFetch,
                lost,
                lost_truncated: false,
            });
        }
        p.parent_times.insert("p".repeat(40), 1900);
        ScanContext { tip: Some(incoming[0].id.clone()), commits: incoming, provenance: Some(p), ..Default::default() }
    }

    fn run(ctx: &ScanContext) -> Vec<Finding> {
        let mut out = Vec::new();
        RefRewritten.scan_context(ctx, &mut out);
        Impersonation.scan_context(ctx, &mut out);
        TamperedPayload.scan_context(ctx, &mut out);
        out
    }

    fn get<'a>(v: &'a [Finding], rule: &str) -> Option<&'a Finding> {
        v.iter().find(|f| f.rule == rule)
    }

    #[test]
    fn signed_github_merge_rewritten_unsigned_is_critical() {
        let msg = "Merge pull request #2921 from org/fix";
        let orig = commit("a", msg, GH, 3600, true);
        let copy = commit("b", msg, HY, -8 * 3600, false);
        let out = run(&ctx(vec![copy], vec![orig]));
        assert_eq!(get(&out, "t10.ref-rewritten").unwrap().severity, Severity::High);
        let c = get(&out, "t11.rewritten-copy").unwrap();
        assert_eq!(c.severity, Severity::Critical);
        assert!(c.details.iter().any(|d| d.contains("original was signed")));
        assert!(c.details.iter().any(|d| d.contains("+0100 → -0800")));
        // Already covered by the Critical rewritten-copy finding.
        assert!(get(&out, "t11.merge-not-by-github").is_none());
    }

    #[test]
    fn same_signature_copy_is_high() {
        let orig = commit("a", "Fix bug", HY, 3600, false);
        let copy = commit("b", "Fix bug", HY, 3600, false);
        let out = run(&ctx(vec![copy], vec![orig]));
        assert_eq!(get(&out, "t11.rewritten-copy").unwrap().severity, Severity::High);
    }

    #[test]
    fn plain_fast_forward_is_silent() {
        let c = commit("b", "Fix bug", HY, 3600, false);
        let out = run(&ctx(vec![c], vec![]));
        assert!(out.is_empty(), "{out:#?}");
    }

    #[test]
    fn unsigned_github_commit_is_flagged() {
        let c = commit("b", "Merge pull request #1 from x/y", GH, 0, false);
        let out = run(&ctx(vec![c], vec![]));
        assert_eq!(get(&out, "t11.merge-not-by-github").unwrap().title, "GitHub merge commit has no signature");
        let signed = commit("b", "Merge pull request #1 from x/y", GH, 0, true);
        assert!(run(&ctx(vec![signed], vec![])).is_empty());
    }

    #[test]
    fn forged_merges_group_per_committer() {
        let mut v: Vec<CommitInfo> = (0..12)
            .map(|i| commit(&format!("{i:02x}"), &format!("Merge pull request #{i} from x/y"), HY, 0, false))
            .collect();
        v.push(commit("ee", "Merge pull request #99 from x/y", ("Eve", "eve@example.com"), 0, false));
        let out = run(&ctx(v, vec![]));
        let m: Vec<_> = out.iter().filter(|f| f.rule == "t11.merge-not-by-github").collect();
        assert_eq!(m.len(), 2, "{m:#?}");
        assert!(m[0].title.starts_with("12 GitHub-style merge commits"));
        assert!(m[0].details.iter().any(|d| d.contains("… and 2 more")));
        assert_eq!(m[1].title, "GitHub-style merge commit was not committed by GitHub (by Eve)");
        // The anchor is per committer, so the id is stable as the range grows.
        assert_eq!(m[0].anchor.as_deref(), Some("merge-not-github:h@example.com"));
    }

    #[test]
    fn unusual_timezone_needs_history() {
        let c = commit("b", "Fix", HY, -8 * 3600, false);
        let mut cx = ctx(vec![c], vec![]);
        let p = cx.provenance.as_mut().unwrap();
        p.committer_offsets.insert("h@example.com".into(), [(3600, 4)].into());
        assert!(get(&run(&cx), "t11.unusual-timezone").is_none());
        cx.provenance.as_mut().unwrap().committer_offsets.insert("h@example.com".into(), [(3600, 40)].into());
        let out = run(&cx);
        assert_eq!(get(&out, "t11.unusual-timezone").unwrap().severity, Severity::Low);
    }

    #[test]
    fn dates_in_future_or_before_parent() {
        let mut c = commit("b", "Fix", HY, 3600, false);
        c.committer_time = 10_000 + 3 * DAY;
        let out = run(&ctx(vec![c.clone()], vec![]));
        assert_eq!(get(&out, "t11.date-anomaly").unwrap().severity, Severity::Medium);
        c.committer_time = 1900 - 2 * DAY;
        let out = run(&ctx(vec![c], vec![]));
        assert_eq!(get(&out, "t11.date-anomaly").unwrap().severity, Severity::Low);
    }

    #[test]
    fn rewrite_with_transited_payload_escalates() {
        let orig = commit("a", "Merge pull request #2921 from org/fix", GH, 3600, true);
        let copy = commit("b", "Merge pull request #2921 from org/fix", HY, -8 * 3600, false);
        let cx = ctx(vec![copy], vec![orig]);
        let mut payload = Finding::new(Threat::T1, "vscode.tasks.folder-open", Severity::Medium, "task");
        payload.transited = true;
        payload.capped_from = Some(Severity::Critical);
        let mut out = vec![payload];
        RefRewritten.scan_context(&cx, &mut out);
        Impersonation.scan_context(&cx, &mut out);
        TamperedPayload.scan_context(&cx, &mut out);
        assert_eq!(get(&out, "t10.tampered-payload").unwrap().severity, Severity::Critical);

        // Without the rewrite, a transited payload alone does not escalate.
        let mut payload = Finding::new(Threat::T1, "vscode.tasks.folder-open", Severity::Medium, "task");
        payload.transited = true;
        payload.capped_from = Some(Severity::Critical);
        let mut out = vec![payload];
        TamperedPayload.scan_context(&ctx(vec![commit("c", "x", HY, 3600, false)], vec![]), &mut out);
        assert!(get(&out, "t10.tampered-payload").is_none());
    }
}
