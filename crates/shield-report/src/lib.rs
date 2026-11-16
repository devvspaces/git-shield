//! Rendering of scan reports: human terminal output and JSON.

use owo_colors::{OwoColorize, Style};
use shield_core::{Finding, Report, Severity};
use std::collections::{HashMap, HashSet};
use std::fmt::Write;

pub fn json(report: &Report) -> String {
    serde_json::to_string_pretty(report).expect("report serializes")
}

fn sev_style(s: Severity) -> Style {
    match s {
        Severity::Critical => Style::new().white().on_red().bold(),
        Severity::High => Style::new().red().bold(),
        Severity::Medium => Style::new().yellow().bold(),
        Severity::Low => Style::new().cyan(),
        Severity::Info => Style::new().dimmed(),
    }
}

fn short(sha: &str) -> &str {
    &sha[..sha.len().min(9)]
}

fn plural<'a>(n: usize, one: &'a str, many: &'a str) -> &'a str {
    if n == 1 { one } else { many }
}

/// A rule with at least this many findings (all Medium or below) is shown as one block.
const GROUP_MIN: usize = 4;

fn location(f: &Finding) -> String {
    let mut loc = String::new();
    if let Some(p) = &f.path {
        loc.push_str(p);
    }
    if let Some(c) = &f.commit {
        let _ = write!(loc, "{}@ {}", if loc.is_empty() { "" } else { "  " }, short(c));
    }
    loc
}

fn render_group(
    out: &mut String,
    rule: &str,
    shown: &[&Finding],
    accepted: &HashSet<String>,
    paint: &dyn Fn(&str, Style) -> String,
) {
    let dim = Style::new().dimmed();
    let members: Vec<&&Finding> = shown.iter().filter(|f| f.rule == rule).collect();
    let max = members.iter().map(|f| f.severity).max().unwrap_or(Severity::Info);
    let first = members[0];
    let label = format!(" {:<8} ", max.as_str().to_uppercase());
    let _ = writeln!(
        out,
        "\n{} {}  {} in {} places",
        paint(&label, sev_style(max)),
        paint(first.threat.code(), dim),
        rule,
        members.len()
    );
    for f in members {
        let mut line = format!("{}  {}  {}", paint(&f.id.0, dim), location(f), paint(&format!("· {}", f.title), dim));
        if f.severity != max {
            let _ = write!(line, "  [{}]", f.severity);
        }
        if accepted.contains(&f.id.0) {
            line.push_str(&paint("  [accepted]", Style::new().green()));
        }
        if f.transited {
            line.push_str(&paint("  [in history only]", dim));
        }
        let _ = writeln!(out, "           {line}");
    }
    let _ = writeln!(out, "           {}", paint("(grouped; use --verbose for full details)", dim));
}

/// Human-readable report. `verbose` includes Info findings.
pub fn terminal(report: &Report, accepted: &HashSet<String>, color: bool, verbose: bool) -> String {
    let paint = |s: &str, st: Style| if color { s.style(st).to_string() } else { s.to_string() };
    let dim = Style::new().dimmed();
    let bold = Style::new().bold();
    let mut out = String::new();

    let _ = writeln!(
        out,
        "{} {} {}",
        paint("git-shield", bold),
        paint("·", dim),
        paint(
            &format!(
                "{} · {} {}, {} file {} scanned",
                report.label,
                report.commits_scanned,
                plural(report.commits_scanned, "commit", "commits"),
                report.files_scanned,
                plural(report.files_scanned, "version", "versions")
            ),
            dim
        )
    );

    let shown: Vec<_> = report.findings.iter().filter(|f| verbose || f.severity > Severity::Info).collect();
    let hidden_info = report.findings.len() - shown.len();

    // Collapse rules that fire many times at Medium or below (e.g. CRLF noise in
    // ten files) into one block. Display only: ids and JSON are unchanged.
    let mut per_rule: HashMap<&str, (usize, Severity)> = HashMap::new();
    for f in &shown {
        let e = per_rule.entry(f.rule).or_insert((0, Severity::Info));
        e.0 += 1;
        e.1 = e.1.max(f.severity);
    }
    let grouped = |f: &Finding| {
        !verbose && per_rule.get(f.rule).is_some_and(|&(n, max)| n >= GROUP_MIN && max <= Severity::Medium)
    };
    // A group is rendered where its last member would be, i.e. after the
    // individual findings of the same severity.
    let mut remaining: HashMap<&str, usize> = per_rule.iter().map(|(k, v)| (*k, v.0)).collect();

    for f in &shown {
        if grouped(f) {
            let left = remaining.get_mut(f.rule).expect("counted above");
            *left -= 1;
            if *left == 0 {
                render_group(&mut out, f.rule, &shown, accepted, &paint);
            }
            continue;
        }
        let label = format!(" {:<8} ", f.severity.as_str().to_uppercase());
        let mut line = format!("\n{} {}  {}", paint(&label, sev_style(f.severity)), paint(&f.id.0, dim), f.title);
        if accepted.contains(&f.id.0) {
            line.push_str(&paint("  [accepted]", Style::new().green()));
        }
        if f.transited {
            line.push_str(&paint("  [in history only]", dim));
        }
        let _ = writeln!(out, "{line}");
        let loc = location(f);
        if !loc.is_empty() {
            let _ = writeln!(out, "           {}", paint(&loc, Style::new().underline()));
        }
        for d in &f.details {
            let _ = writeln!(out, "           {} {}", paint("·", dim), d);
        }
    }

    let count = |s: Severity| report.findings.iter().filter(|f| f.severity == s).count();
    let mut parts = Vec::new();
    for s in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info] {
        let n = count(s);
        if n > 0 {
            parts.push(format!("{n} {s}"));
        }
    }
    let blocking: Vec<_> = report.blocking(accepted).collect();
    let _ = writeln!(out);
    let verdict = if !blocking.is_empty() {
        paint(&format!("BLOCKED: {} finding(s) at high or above", blocking.len()), Style::new().red().bold())
    } else if report.findings.iter().any(|f| f.severity > Severity::Info) {
        paint("PASSED with warnings", Style::new().yellow().bold())
    } else {
        paint("CLEAN", Style::new().green().bold())
    };
    let summary = if parts.is_empty() { "no findings".to_string() } else { parts.join(", ") };
    let _ = writeln!(out, "{verdict}  {}", paint(&format!("({summary})"), dim));
    if hidden_info > 0 && !verbose {
        let _ =
            writeln!(out, "{}", paint(&format!("{hidden_info} info finding(s) hidden; use --verbose to show"), dim));
    }
    if !blocking.is_empty() {
        let ids: Vec<_> = blocking.iter().map(|f| f.id.0.as_str()).collect();
        let _ = writeln!(
            out,
            "{}",
            paint(&format!("After reviewing, accept with: --accept {}", ids.join(" --accept ")), dim)
        );
    }
    out
}
