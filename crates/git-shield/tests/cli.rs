//! End-to-end tests: build hostile-but-inert repos, run the real binary, and
//! assert on exit codes, findings and — always — that nothing was executed.

use assert_cmd::Command;
use serde_json::Value;
use shield_fixtures::{self as fx, Fixture};

fn shield(f: &Fixture) -> Command {
    let mut cmd = Command::cargo_bin("git-shield").unwrap();
    cmd.current_dir(&f.local)
        .env("HOME", fx::home(f))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GS_MARKER", &f.marker)
        .env("NO_COLOR", "1");
    cmd
}

fn json_check(f: &Fixture, extra: &[&str]) -> (i32, Value) {
    let out = shield(f).args(["check", "--json"]).args(extra).output().unwrap();
    let code = out.status.code().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!("bad json ({e}): {}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    });
    (code, v)
}

fn rules(v: &Value) -> Vec<(String, String, bool)> {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["rule"].as_str().unwrap().to_string(),
                f["severity"].as_str().unwrap().to_string(),
                f["transited"].as_bool().unwrap_or(false),
            )
        })
        .collect()
}

fn has(v: &Value, rule: &str, sev: &str, transited: bool) -> bool {
    rules(v).iter().any(|(r, s, t)| r == rule && s == sev && *t == transited)
}

#[test]
fn matador_incident_is_blocked_and_nothing_runs() {
    let f = fx::matador_incident();
    let (code, v) = json_check(&f, &[]);
    assert_eq!(code, 2, "expected BLOCKED: {:#?}", rules(&v));

    // Disguised payload survives in the final tree → critical.
    assert!(has(&v, "asset.code-disguised", "critical", false), "{:#?}", rules(&v));
    // tasks.json / settings.json only existed in the forged commit → reported as transited.
    assert!(has(&v, "vscode.tasks.folder-open", "medium", true), "{:#?}", rules(&v));
    assert!(has(&v, "vscode.settings.allow-automatic-tasks", "medium", true), "{:#?}", rules(&v));
    // CRLF churn masking a real change.
    assert!(has(&v, "noise.whitespace-masking", "medium", false), "{:#?}", rules(&v));
    assert_eq!(v["commits_scanned"], 3); // feature, forged merge, cleanup

    assert!(!f.marker_exists(), "payload executed!");
    // Working tree untouched: the payload font must not be checked out.
    assert!(!f.local.join("public/fonts/fa-solid-600.ttf").exists());
}

#[test]
fn accepting_blocking_findings_unblocks() {
    let f = fx::matador_incident();
    let (_, v) = json_check(&f, &[]);
    let blocking: Vec<String> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| matches!(f["severity"].as_str(), Some("high" | "critical")))
        .map(|f| f["id"].as_str().unwrap().to_string())
        .collect();
    assert!(!blocking.is_empty());
    let mut args = vec!["--no-fetch".to_string()];
    for id in &blocking {
        args.push("--accept".into());
        args.push(id.clone());
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, _) = json_check(&f, &args);
    assert_eq!(code, 1, "accepted findings should leave only warnings");
    assert!(!f.marker_exists());
}

#[test]
fn finding_ids_are_stable_across_runs() {
    let f = fx::matador_incident();
    let (_, a) = json_check(&f, &[]);
    let (_, b) = json_check(&f, &["--no-fetch"]);
    let ids = |v: &Value| v["findings"].as_array().unwrap().iter().map(|f| f["id"].to_string()).collect::<Vec<_>>();
    assert_eq!(ids(&a), ids(&b));
}

#[test]
fn clean_fast_forward_passes() {
    let f = fx::clean_fast_forward();
    let (code, v) = json_check(&f, &[]);
    assert_eq!(code, 0, "{:#?}", rules(&v));
    assert_eq!(v["commits_scanned"], 1);
    assert!(!f.marker_exists());
}

#[test]
fn crlf_only_is_info_not_blocking() {
    let f = fx::crlf_only();
    let (code, v) = json_check(&f, &[]);
    assert_eq!(code, 0, "{:#?}", rules(&v));
    assert!(has(&v, "noise.whitespace-masking", "info", false));
}

#[test]
fn scan_works_offline_on_explicit_range() {
    let f = fx::matador_incident();
    fx::git(&f.local, &fx::home(&f), &["fetch", "-q", "origin"]);
    let out = shield(&f).args(["scan", "HEAD..origin/dev"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("BLOCKED"), "{text}");
    assert!(text.contains("is actually source code"), "{text}");
    assert!(text.contains("[in history only]"), "{text}");
}

#[test]
fn poisoned_local_config_refuses_to_run_git() {
    let f = fx::clean_fast_forward();
    // GitSpawn-style: fsmonitor pointing at a program that would create the marker.
    // (Written directly to the file: running `git config` here is fine, but we must
    // never run a git command that *reads* fsmonitor in this repo afterwards.)
    let cfg = f.local.join(".git/config");
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str(&format!("[core]\n\tfsmonitor = \"touch {}\"\n", f.marker.display()));
    std::fs::write(&cfg, text).unwrap();

    let out = shield(&f).args(["check"]).output().unwrap();
    assert_eq!(out.status.code(), Some(3));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("refusing to run git"), "{err}");
    assert!(!f.marker_exists(), "fsmonitor ran!");
}

#[test]
fn hardened_fetch_neutralises_fsmonitor_when_overridden() {
    let f = fx::clean_fast_forward();
    let cfg = f.local.join(".git/config");
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str(&format!("[core]\n\tfsmonitor = \"touch {}\"\n", f.marker.display()));
    std::fs::write(&cfg, text).unwrap();

    // Even when the user forces past the preflight, the hardened runner must not trigger it.
    let out = shield(&f).args(["check", "--allow-unsafe-config", "--json"]).output().unwrap();
    assert!(matches!(out.status.code(), Some(0..=2)), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!f.marker_exists(), "fsmonitor ran during hardened fetch!");
}
