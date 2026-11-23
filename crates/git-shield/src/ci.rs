//! `git shield ci`: scan what a GitHub push or pull request brings in, from
//! inside the workflow run (ADR 0008).
//!
//! The range comes from the event payload, never from the checked-out tree.
//! Accepted findings come only from the user's flags, the user config, or an
//! accept file read from the *trusted* side of the event (the PR base, or the
//! branch before the push), so a pushed commit cannot accept its own findings.

use crate::{
    Budget, Common, KnownTips, accepted, build_context, emit, gh_session, github_tips, history_branch, note, preflight,
    resolve_range, scan, short,
};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;
use shield_core::{Severity, TipSource};
use shield_git::hardened::HardenedGit;
use shield_git::trust::TrustStore;
use shield_git::{GitRepo, ObjectId};
use std::collections::HashSet;
use std::io::Write as _;
use std::path::PathBuf;

pub(crate) struct CiArgs {
    pub range: Option<String>,
    pub event: Option<PathBuf>,
    pub event_name: Option<String>,
    pub fail_on: Severity,
    pub accept_file: Option<PathBuf>,
    pub accepts_path: Option<String>,
    pub no_github: bool,
    pub deep: bool,
    pub common: Common,
}

pub(crate) fn parse_severity(s: &str) -> Result<Severity, String> {
    match s.to_ascii_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(format!("expected info, low, medium, high or critical, got `{s}`")),
    }
}

/// What the event says to scan.
#[derive(Debug, PartialEq)]
pub(crate) enum EventRange {
    PullRequest {
        base: String,
        head: String,
        /// The head branch, only when it lives in the same repository.
        head_ref: Option<String>,
    },
    Push {
        /// `None` when the push created the branch.
        before: Option<String>,
        after: String,
        /// `None` for tag pushes.
        branch: Option<String>,
        forced: bool,
    },
    /// The push deleted the ref: nothing comes in.
    Deleted,
    Other,
}

fn is_zero(sha: &str) -> bool {
    !sha.is_empty() && sha.bytes().all(|b| b == b'0')
}

fn sha(v: &Value) -> Option<String> {
    v.as_str().filter(|s| s.len() >= 40 && s.bytes().all(|b| b.is_ascii_hexdigit())).map(str::to_ascii_lowercase)
}

pub(crate) fn parse_event(name: &str, payload: &str) -> Result<EventRange> {
    let v: Value = serde_json::from_str(payload).context("event payload is not JSON")?;
    match name {
        "pull_request" | "pull_request_target" => {
            let pr = &v["pull_request"];
            let base = sha(&pr["base"]["sha"]).context("pull_request.base.sha missing")?;
            let head = sha(&pr["head"]["sha"]).context("pull_request.head.sha missing")?;
            let same = pr["head"]["repo"]["full_name"].as_str().is_some()
                && pr["head"]["repo"]["full_name"] == pr["base"]["repo"]["full_name"];
            let head_ref = same.then(|| pr["head"]["ref"].as_str().map(str::to_string)).flatten();
            Ok(EventRange::PullRequest { base, head, head_ref })
        }
        "push" => {
            if v["deleted"].as_bool() == Some(true) {
                return Ok(EventRange::Deleted);
            }
            let after = sha(&v["after"]).context("push.after missing")?;
            if is_zero(&after) {
                return Ok(EventRange::Deleted);
            }
            let before = sha(&v["before"]).filter(|b| !is_zero(b));
            let branch = v["ref"].as_str().and_then(|r| r.strip_prefix("refs/heads/")).map(str::to_string);
            let forced = v["forced"].as_bool() == Some(true);
            Ok(EventRange::Push { before, after, branch, forced })
        }
        _ => Ok(EventRange::Other),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptFile {
    #[serde(default)]
    accept: Vec<AcceptEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptEntry {
    id: String,
    reason: String,
}

fn parse_accepts(text: &str, origin: &str) -> Result<Vec<String>> {
    let f: AcceptFile = toml::from_str(text).with_context(|| format!("invalid accept file {origin}"))?;
    let mut ids = Vec::new();
    for (i, e) in f.accept.into_iter().enumerate() {
        if e.reason.trim().is_empty() {
            bail!("{origin}: accept entry #{} needs a non-empty reason", i + 1);
        }
        ids.push(e.id);
    }
    Ok(ids)
}

/// Make sure `id` is present, fetching it from origin by SHA when not.
fn ensure_object(repo: &GitRepo, id: &str, common: &Common) -> Option<ObjectId> {
    let oid = ObjectId::from_hex(id.as_bytes()).ok()?;
    if repo.has_object(oid) {
        return Some(oid);
    }
    let workdir = repo.workdir().unwrap_or_else(|| repo.git_dir().to_path_buf());
    if !common.json {
        eprintln!("git-shield: fetching {} from origin (not in the checkout)…", short(&oid));
    }
    match HardenedGit::new(&workdir).map_err(anyhow::Error::from).and_then(|g| Ok(g.fetch("origin", Some(id))?)) {
        Ok(()) => {
            let fresh = GitRepo::discover(&common.repo).ok()?;
            fresh.has_object(oid).then_some(oid)
        }
        Err(e) => {
            note(&format!("could not fetch {}: {e:#}", short(&oid)));
            None
        }
    }
}

/// What to scan, decided from the event.
struct Target {
    from: ObjectId,
    to: ObjectId,
    label: String,
    /// The branch on GitHub whose push history explains the range.
    branch: Option<String>,
    /// The tip the branch had before (a forced push).
    previous: Option<ObjectId>,
    /// Commit the accept file is read from: never the incoming side.
    trusted: Option<ObjectId>,
}

fn default_branch_tip(repo: &GitRepo) -> Option<(String, ObjectId)> {
    let def = repo.remote_default_branch("origin")?;
    let tip = repo.ref_tip(&format!("refs/remotes/origin/{def}"))?;
    Some((def, tip))
}

fn target(repo: &GitRepo, ev: &EventRange, common: &Common) -> Result<Option<Target>> {
    Ok(Some(match ev {
        EventRange::Deleted => return Ok(None),
        EventRange::PullRequest { base, head, head_ref } => {
            let from = ensure_object(repo, base, common).with_context(|| format!("PR base {base} not found"))?;
            let to = ensure_object(repo, head, common).with_context(|| format!("PR head {head} not found"))?;
            Target {
                from,
                to,
                label: format!("{}..{}", short(&from), short(&to)),
                branch: head_ref.clone(),
                previous: None,
                trusted: Some(from),
            }
        }
        EventRange::Push { before, after, branch, forced } => {
            let to = ensure_object(repo, after, common).with_context(|| format!("pushed commit {after} not found"))?;
            let before = before.as_deref().and_then(|b| ensure_object(repo, b, common));
            match before {
                Some(b) => {
                    let rewritten = *forced || !repo.is_ancestor(b, to).unwrap_or(false);
                    Target {
                        from: b,
                        to,
                        label: format!("{}..{}", short(&b), short(&to)),
                        branch: branch.clone(),
                        previous: rewritten.then_some(b),
                        trusted: Some(b),
                    }
                }
                None => {
                    // A new branch (or a `before` that is gone): compare with
                    // the default branch.
                    let (from, trusted, label) = match default_branch_tip(repo) {
                        Some((def, tip)) => (tip, Some(tip), format!("origin/{def}..{}", short(&to))),
                        None => {
                            note("no default branch known; scanning only the pushed commit");
                            let parent = repo.resolve(&format!("{to}~1")).context("pushed commit has no parent")?;
                            (parent, None, format!("{}~1..{}", short(&to), short(&to)))
                        }
                    };
                    Target { from, to, label, branch: branch.clone(), previous: None, trusted }
                }
            }
        }
        EventRange::Other => unreachable!("handled by the caller"),
    }))
}

pub(crate) fn run(mut a: CiArgs) -> Result<u8> {
    let common = &mut a.common;
    if common.github_repo.is_none() {
        common.github_repo = std::env::var("GITHUB_REPOSITORY").ok().filter(|s| s.contains('/'));
    }
    if let Ok(api) = std::env::var("GITHUB_API_URL") {
        shield_github::set_api_base(&api);
    }
    let common = &a.common;
    let repo = GitRepo::discover(&common.repo)?;
    preflight(&repo, false, false, common)?;

    let event_name = a.event_name.clone().or_else(|| std::env::var("GITHUB_EVENT_NAME").ok()).unwrap_or_default();
    let event_path = a.event.clone().or_else(|| std::env::var_os("GITHUB_EVENT_PATH").map(PathBuf::from));
    let ev = match (&a.range, &event_path) {
        (Some(_), _) | (None, None) => EventRange::Other,
        (None, Some(p)) => {
            let text = std::fs::read_to_string(p).with_context(|| format!("reading event {}", p.display()))?;
            parse_event(&event_name, &text)?
        }
    };
    let t = match ev {
        EventRange::Other => {
            let range = a.range.clone().unwrap_or_else(|| {
                note(&format!(
                    "no push or pull_request event{}; scanning HEAD~1..HEAD",
                    if event_name.is_empty() { String::new() } else { format!(" (got `{event_name}`)") }
                ));
                "HEAD~1..HEAD".into()
            });
            let (from, to, _, label) = resolve_range(&repo, Some(&range))?;
            Target { from, to, label, branch: None, previous: None, trusted: None }
        }
        ref ev => match target(&repo, ev, common)? {
            Some(t) => t,
            None => {
                if !common.json {
                    eprintln!("git-shield: the push deleted the ref; nothing to scan");
                }
                return Ok(0);
            }
        },
    };
    // Objects fetched above are only visible to a fresh handle.
    let repo = GitRepo::discover(&common.repo)?;
    if !common.json {
        eprintln!("git-shield: ci: scanning {}", t.label);
    }

    let store = TrustStore::open(&repo)?;
    let budget = if a.deep { Budget::DEEP } else { Budget::DEFAULT };
    let github = !a.no_github;
    let mut gh = KnownTips::default();
    let mut ref_name = None;
    if github {
        let branch = match &t.branch {
            Some(b) => Some(("origin".to_string(), b.clone())),
            None => history_branch(&repo, t.to, None, common),
        };
        match branch {
            Some((remote, branch)) => {
                let tracking = format!("refs/remotes/{remote}/{branch}");
                gh = github_tips(&repo, &store, &tracking, &remote, &branch, t.to, Some(t.from), true, budget, common);
                ref_name = Some(tracking);
            }
            None => gh.session = gh_session(&repo, None, common),
        }
    }
    gh.budget = budget;
    if let Some(p) = t.previous {
        gh.tips.insert(0, (p, TipSource::Given));
    }
    if ref_name.is_none() && !gh.tips.is_empty() {
        ref_name = Some(match &t.branch {
            Some(b) => format!("refs/remotes/origin/{b}"),
            None => t.to.to_string(),
        });
    }
    let repo = if gh.fetched { GitRepo::discover(&common.repo)? } else { repo };
    let ctx = build_context(&repo, &store, t.from, t.to, t.label.clone(), ref_name.as_deref(), &gh, common)?;
    let report = scan(&ctx);

    let mut ok: HashSet<String> = accepted(common, Some(&store), &report, Some(&repo))?;
    if let Some(p) = &a.accept_file {
        let text = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
        ok.extend(parse_accepts(&text, &p.display().to_string())?);
    }
    if let Some(path) = &a.accepts_path {
        match t.trusted {
            Some(c) => match repo.file_at(c, path)? {
                Some(bytes) => {
                    let origin = format!("{path} at {}", short(&c));
                    ok.extend(parse_accepts(&String::from_utf8_lossy(&bytes), &origin)?);
                }
                None => note(&format!("no {path} at {} (the trusted side of this event)", short(&c))),
            },
            None => note(&format!("no trusted commit for this event; {path} not read")),
        }
    }

    if emit(&report, &ok, common) == 3 {
        return Ok(3);
    }
    if !common.json {
        print!("{}", shield_report::github_annotations(&report, &ok, a.fail_on));
    }
    if let Some(p) = std::env::var_os("GITHUB_STEP_SUMMARY").filter(|p| !p.is_empty()) {
        let text = shield_report::step_summary(&report, &ok, a.fail_on, 50);
        let res = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)
            .and_then(|mut f| f.write_all(text.as_bytes()));
        if let Err(e) = res {
            note(&format!("could not write the job summary: {e}"));
        }
    }
    let failing = report.findings.iter().any(|f| f.severity >= a.fail_on && !ok.contains(&f.id.0));
    Ok(if failing { 2 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "1111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222";
    const Z: &str = "0000000000000000000000000000000000000000";

    #[test]
    fn pull_request_events() {
        let same = format!(
            r#"{{"pull_request":{{"base":{{"sha":"{A}","repo":{{"full_name":"o/r"}}}},"head":{{"sha":"{B}","ref":"feat","repo":{{"full_name":"o/r"}}}}}}}}"#
        );
        assert_eq!(
            parse_event("pull_request", &same).unwrap(),
            EventRange::PullRequest { base: A.into(), head: B.into(), head_ref: Some("feat".into()) }
        );
        let fork = same.replacen(
            r#""ref":"feat","repo":{"full_name":"o/r"}"#,
            r#""ref":"feat","repo":{"full_name":"x/r"}"#,
            1,
        );
        assert_eq!(
            parse_event("pull_request_target", &fork).unwrap(),
            EventRange::PullRequest { base: A.into(), head: B.into(), head_ref: None }
        );
    }

    #[test]
    fn push_events() {
        let push = |before: &str, forced: bool| {
            format!(r#"{{"ref":"refs/heads/dev","before":"{before}","after":"{B}","forced":{forced},"deleted":false}}"#)
        };
        assert_eq!(
            parse_event("push", &push(A, true)).unwrap(),
            EventRange::Push { before: Some(A.into()), after: B.into(), branch: Some("dev".into()), forced: true }
        );
        assert_eq!(
            parse_event("push", &push(Z, false)).unwrap(),
            EventRange::Push { before: None, after: B.into(), branch: Some("dev".into()), forced: false }
        );
        let deleted = format!(r#"{{"ref":"refs/heads/dev","before":"{A}","after":"{Z}","deleted":true}}"#);
        assert_eq!(parse_event("push", &deleted).unwrap(), EventRange::Deleted);
        let tag = format!(r#"{{"ref":"refs/tags/v1","before":"{Z}","after":"{B}"}}"#);
        assert!(matches!(parse_event("push", &tag).unwrap(), EventRange::Push { branch: None, .. }));
        assert_eq!(parse_event("workflow_dispatch", "{}").unwrap(), EventRange::Other);
        assert!(parse_event("push", r#"{"after":"not-a-sha"}"#).is_err());
    }

    #[test]
    fn accept_files_need_reasons() {
        let ok = parse_accepts("[[accept]]\nid = \"GS-T1-aaaaaaaa\"\nreason = \"reviewed\"\n", "x").unwrap();
        assert_eq!(ok, ["GS-T1-aaaaaaaa"]);
        assert!(parse_accepts("[[accept]]\nid = \"GS-T1-a\"\nreason = \" \"\n", "x").is_err());
        assert!(parse_accepts("[[accept]]\nid = \"GS-T1-a\"\nreason = \"r\"\nextra = 1\n", "x").is_err());
    }
}
