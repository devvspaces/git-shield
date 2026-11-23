//! Output for CI systems: SARIF 2.1.0, GitHub workflow annotations and the
//! job summary (ADR 0008).
//!
//! Everything here renders text that came from the scanned repository (paths,
//! commit summaries), so each format escapes it for its own syntax.

use serde_json::{Value, json};
use shield_core::{Finding, Report, Severity, Threat};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write;

const INFO_URI: &str = "https://github.com/devvspaces/git-shield";

/// Location for findings that are about a commit, not a file. Code scanning
/// rejects results without a location, so they point at this placeholder.
pub fn commit_placeholder(sha: &str) -> String {
    format!(".git-shield/commits/{sha}")
}

fn level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// GitHub code scanning's `security-severity` (0–10): ≥9 critical, ≥7 high, ≥4 medium.
fn security_severity(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
        Severity::Info => "1.0",
    }
}

fn message(f: &Finding) -> String {
    let mut m = f.title.clone();
    if let Some(c) = &f.commit {
        let _ = write!(m, " (commit {c})");
    }
    for d in &f.details {
        m.push('\n');
        m.push_str(d);
    }
    m
}

fn location(f: &Finding) -> Option<String> {
    f.path.clone().or_else(|| f.commit.as_deref().map(commit_placeholder))
}

/// The report as a SARIF 2.1.0 log. Accepted findings stay in the log as
/// suppressed results, so a reviewer can still see them.
pub fn sarif(report: &Report, accepted: &HashSet<String>, version: &str) -> String {
    // One rule entry per rule id, at the highest severity it was seen with.
    let mut rules: BTreeMap<&str, (Threat, Severity)> = BTreeMap::new();
    for f in &report.findings {
        let e = rules.entry(f.rule).or_insert((f.threat, f.severity));
        e.1 = e.1.max(f.severity);
    }
    let index: BTreeMap<&str, usize> = rules.keys().enumerate().map(|(i, r)| (*r, i)).collect();
    let rule_objs: Vec<Value> = rules
        .iter()
        .map(|(id, (threat, sev))| {
            json!({
                "id": id,
                "name": id,
                "shortDescription": {"text": threat.description()},
                "helpUri": format!("{INFO_URI}/blob/master/docs/THREATS.md"),
                "defaultConfiguration": {"level": level(*sev)},
                "properties": {
                    "tags": ["security", threat.code()],
                    "security-severity": security_severity(*sev),
                },
            })
        })
        .collect();

    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            let mut r = json!({
                "ruleId": f.rule,
                "ruleIndex": index[f.rule],
                "level": level(f.severity),
                "message": {"text": message(f)},
                "partialFingerprints": {"gitShieldId/v1": f.id.0},
                "properties": {
                    "id": f.id.0,
                    "severity": f.severity.as_str(),
                    "security-severity": security_severity(f.severity),
                },
            });
            if let Some(uri) = location(f) {
                r["locations"] = json!([{
                    "physicalLocation": {"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"}}
                }]);
            }
            if let Some(c) = &f.commit {
                r["properties"]["commit"] = json!(c);
            }
            if f.transited {
                r["properties"]["transited"] = json!(true);
            }
            if accepted.contains(&f.id.0) {
                r["suppressions"] = json!([{
                    "kind": "external",
                    "justification": "accepted in git-shield (--accept, accept file, trust store or allowlist)",
                }]);
            }
            r
        })
        .collect();

    let mut run = json!({
        "tool": {"driver": {
            "name": "git-shield",
            "version": version,
            "semanticVersion": version,
            "informationUri": INFO_URI,
            "rules": rule_objs,
        }},
        "results": results,
        "properties": {"label": report.label, "commitsScanned": report.commits_scanned},
    });
    if let Some(tip) = &report.tip {
        run["properties"]["tip"] = json!(tip);
    }
    let log = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    });
    serde_json::to_string_pretty(&log).expect("sarif serializes")
}

/// Escape the message part of a workflow command (`::cmd props::message`).
pub fn escape_data(s: &str) -> String {
    s.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A")
}

/// Escape a workflow command property value.
pub fn escape_property(s: &str) -> String {
    escape_data(s).replace(':', "%3A").replace(',', "%2C")
}

/// GitHub Actions workflow commands, one per finding at or above Low:
/// `error` for findings at or above `fail_on` that are not accepted,
/// `warning` for the rest above Low, `notice` for Low.
pub fn github_annotations(report: &Report, accepted: &HashSet<String>, fail_on: Severity) -> String {
    let mut out = String::new();
    for f in report.findings.iter().filter(|f| f.severity >= Severity::Low) {
        let ok = accepted.contains(&f.id.0);
        let cmd = if f.severity >= fail_on && !ok {
            "error"
        } else if f.severity >= Severity::Medium && !ok {
            "warning"
        } else {
            "notice"
        };
        let mut props = vec![format!("title={}", escape_property(&format!("{} {} ({})", f.id, f.rule, f.severity)))];
        if let Some(p) = &f.path {
            props.push(format!("file={}", escape_property(p)));
        }
        let mut msg = message(f);
        if ok {
            msg.push_str("\n[accepted]");
        }
        let _ = writeln!(out, "::{cmd} {}::{}", props.join(","), escape_data(&msg));
    }
    out
}

/// Escape text for a Markdown table cell: no links, images, HTML or cell breaks.
fn md(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '|' | '!' | '#' | '~' | '(' | ')' => {
                out.push('\\');
                out.push(c);
            }
            '\n' | '\r' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// Markdown for `$GITHUB_STEP_SUMMARY`.
pub fn step_summary(report: &Report, accepted: &HashSet<String>, fail_on: Severity, max_rows: usize) -> String {
    let failing = report.findings.iter().filter(|f| f.severity >= fail_on && !accepted.contains(&f.id.0)).count();
    let warnings = report.findings.iter().filter(|f| f.severity > Severity::Info).count() - failing;
    let verdict = if failing > 0 {
        format!("**Blocked**: {failing} finding(s) at or above {fail_on}")
    } else if warnings > 0 {
        format!("**Passed with warnings**: {warnings} finding(s) below {fail_on} or accepted")
    } else {
        "**Clean**".to_string()
    };
    let mut out = String::new();
    let _ = writeln!(out, "## git-shield\n");
    let _ = writeln!(out, "{verdict}\n");
    let _ = writeln!(out, "{} · {} commit(s) scanned\n", md(&report.label), report.commits_scanned);
    let shown: Vec<&Finding> = report.findings.iter().filter(|f| f.severity > Severity::Info).collect();
    if !shown.is_empty() {
        let _ = writeln!(out, "| Severity | Id | Rule | Where | Finding |");
        let _ = writeln!(out, "|---|---|---|---|---|");
        for f in shown.iter().take(max_rows) {
            let mut sev = f.severity.as_str().to_string();
            if accepted.contains(&f.id.0) {
                sev.push_str(" (accepted)");
            }
            let place = f.path.clone().or_else(|| f.commit.as_ref().map(|c| c[..c.len().min(9)].to_string()));
            let _ = writeln!(
                out,
                "| {sev} | {} | {} | {} | {} |",
                md(&f.id.0),
                md(f.rule),
                md(place.as_deref().unwrap_or("")),
                md(&f.title)
            );
        }
        if shown.len() > max_rows {
            let _ = writeln!(out, "\n…and {} more (see the job log or the SARIF results).", shown.len() - max_rows);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use shield_core::{Finding, Report, Severity, Threat};

    fn report() -> Report {
        let mut a = Finding::new(Threat::T1, "t1.tasks.folder-open", Severity::Critical, "Task runs on folder open")
            .path(".vscode/tasks.json")
            .detail("command: node x.js");
        a.id = shield_core::FindingId("GS-T1-aaaaaaaa".into());
        let mut b = Finding::new(Threat::T11, "t11.pr-merge-mismatch", Severity::Critical, "Forged merge of PR #7")
            .commit("0123456789abcdef0123456789abcdef01234567");
        b.id = shield_core::FindingId("GS-T11-bbbbbbbb".into());
        let mut c = Finding::new(Threat::T12, "t12.noise", Severity::Medium, "CRLF churn").path("a|b.py");
        c.id = shield_core::FindingId("GS-T12-cccccccc".into());
        Report {
            label: "base..tip".into(),
            base: None,
            tip: Some("0123".into()),
            commits_scanned: 3,
            files_scanned: 2,
            findings: vec![a, b, c],
        }
    }

    #[test]
    fn sarif_shape() {
        let accepted: HashSet<String> = ["GS-T12-cccccccc".to_string()].into();
        let v: Value = serde_json::from_str(&sarif(&report(), &accepted, "0.0.0-test")).unwrap();
        assert_eq!(v["version"], "2.1.0");
        let run = &v["runs"][0];
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 3);
        let results = run["results"].as_array().unwrap();
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], ".vscode/tasks.json");
        assert_eq!(results[0]["partialFingerprints"]["gitShieldId/v1"], "GS-T1-aaaaaaaa");
        // A commit-only finding gets the placeholder location.
        assert_eq!(
            results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            ".git-shield/commits/0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(results[2]["level"], "warning");
        assert_eq!(results[2]["suppressions"][0]["kind"], "external");
        assert!(results[0].get("suppressions").is_none());
        let idx = results[1]["ruleIndex"].as_u64().unwrap() as usize;
        assert_eq!(rules[idx]["id"], "t11.pr-merge-mismatch");
        assert_eq!(rules[idx]["properties"]["security-severity"], "9.5");
    }

    #[test]
    fn annotations_cannot_inject_commands() {
        let mut r = report();
        r.findings[0].title = "x\n::error::pwned".into();
        r.findings[0].path = Some("a,b:c.json".into());
        let out = github_annotations(&r, &HashSet::new(), Severity::High);
        // Each finding is exactly one line; nothing else starts a command.
        assert_eq!(out.lines().count(), 3);
        assert!(out.lines().all(|l| l.starts_with("::error ") || l.starts_with("::warning ")));
        assert!(out.contains("x%0A::error::pwned"));
        assert!(out.contains("file=a%2Cb%3Ac.json"));
    }

    #[test]
    fn annotation_levels_follow_fail_on() {
        let accepted: HashSet<String> = ["GS-T11-bbbbbbbb".to_string()].into();
        let out = github_annotations(&report(), &accepted, Severity::Medium);
        let cmds: Vec<&str> = out.lines().map(|l| l.split(' ').next().unwrap()).collect();
        assert_eq!(cmds, ["::error", "::notice", "::error"]);
    }

    #[test]
    fn summary_escapes_markdown() {
        let mut r = report();
        r.findings[0].title = "see [here](http://evil) <img>".into();
        let s = step_summary(&r, &HashSet::new(), Severity::High, 10);
        assert!(s.contains("**Blocked**: 2 finding(s)"));
        assert!(s.contains(r"\[here\]\(http://evil\) \<img\>"));
        assert!(s.contains(r"a\|b.py"));
        assert_eq!(step_summary(&r, &HashSet::new(), Severity::High, 1).matches("\n| ").count(), 2);
    }
}
