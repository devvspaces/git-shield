//! Rendering of scan reports: human terminal output and JSON.

use owo_colors::{OwoColorize, Style};
use shield_core::{Report, Severity};
use std::collections::HashSet;
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
                "{} · {} commits, {} file versions scanned",
                report.label, report.commits_scanned, report.files_scanned
            ),
            dim
        )
    );

    let shown: Vec<_> = report.findings.iter().filter(|f| verbose || f.severity > Severity::Info).collect();
    let hidden_info = report.findings.len() - shown.len();

    for f in &shown {
        let label = format!(" {:<8} ", f.severity.as_str().to_uppercase());
        let mut line = format!("\n{} {}  {}", paint(&label, sev_style(f.severity)), paint(&f.id.0, dim), f.title);
        if accepted.contains(&f.id.0) {
            line.push_str(&paint("  [accepted]", Style::new().green()));
        }
        if f.transited {
            line.push_str(&paint("  [in history only]", dim));
        }
        let _ = writeln!(out, "{line}");
        let mut loc = String::new();
        if let Some(p) = &f.path {
            loc.push_str(p);
        }
        if let Some(c) = &f.commit {
            let _ = write!(loc, "{}@ {}", if loc.is_empty() { "" } else { "  " }, short(c));
        }
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
