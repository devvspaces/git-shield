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
        .env("GIT_SHIELD_HOME", shield_home(f))
        .env_remove("XDG_DATA_HOME")
        // Identity for commits git itself creates (rebase / merge).
        .env("GIT_AUTHOR_NAME", "Victim")
        .env("GIT_AUTHOR_EMAIL", "victim@example.com")
        .env("GIT_COMMITTER_NAME", "Victim")
        .env("GIT_COMMITTER_EMAIL", "victim@example.com")
        .env("NO_COLOR", "1");
    cmd
}

fn shield_home(f: &Fixture) -> std::path::PathBuf {
    f.dir.path().join("shield-home")
}

fn head(f: &Fixture) -> String {
    fx::git(&f.local, &fx::home(f), &["rev-parse", "HEAD"])
}

fn origin_dev(f: &Fixture) -> String {
    fx::git(&f.origin, &fx::home(f), &["rev-parse", "dev"])
}

fn json_pull(f: &Fixture, extra: &[&str]) -> (i32, Value, String) {
    let out = shield(f).args(["pull", "--json"]).args(extra).output().unwrap();
    let code = out.status.code().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!("bad json ({e}): {}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    });
    (code, v, String::from_utf8_lossy(&out.stderr).into_owned())
}

fn blocking_ids(v: &Value) -> Vec<String> {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| matches!(f["severity"].as_str(), Some("high" | "critical")))
        .map(|f| f["id"].as_str().unwrap().to_string())
        .collect()
}

fn accept_args(ids: &[String]) -> Vec<String> {
    ids.iter().flat_map(|id| ["--accept".to_string(), id.clone()]).collect()
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
    let blocking = blocking_ids(&v);
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

// ---------------------------------------------------------------- Phase 2: pull

#[test]
fn pull_fast_forwards_clean_changes() {
    let f = fx::clean_fast_forward();
    let before = head(&f);
    let (code, v, err) = json_pull(&f, &[]);
    assert_eq!(code, 0, "{err}\n{:#?}", rules(&v));
    assert_ne!(head(&f), before);
    assert_eq!(head(&f), origin_dev(&f));
    assert!(!f.marker_exists());
    // Trust store records the pulled tip, outside the repository.
    let store = std::fs::read_dir(shield_home(&f).join("repos")).unwrap().next().unwrap().unwrap().path();
    let text = std::fs::read_to_string(store).unwrap();
    assert!(text.contains(&origin_dev(&f)), "{text}");
    assert!(!f.local.join(".git/shield").exists());
}

#[test]
fn pull_blocks_matador_incident_and_changes_nothing() {
    let f = fx::matador_incident();
    let before = head(&f);
    let (code, v, err) = json_pull(&f, &[]);
    assert_eq!(code, 2, "{err}\n{:#?}", rules(&v));
    assert!(has(&v, "t10.ref-rewritten", "high", false), "{:#?}", rules(&v));
    assert!(has(&v, "t11.rewritten-copy", "critical", false), "{:#?}", rules(&v));
    assert!(has(&v, "t10.tampered-payload", "critical", false), "{:#?}", rules(&v));
    assert!(has(&v, "t11.merge-not-by-github", "medium", false), "{:#?}", rules(&v));
    assert!(err.contains("pull blocked"), "{err}");
    assert_eq!(head(&f), before, "HEAD moved on a blocked pull");
    assert!(!f.local.join("public/fonts/fa-solid-600.ttf").exists());
    assert!(!f.marker_exists());
}

#[test]
fn pull_after_accepting_fast_forwards_and_remembers() {
    let f = fx::matador_incident();
    let (_, v, _) = json_pull(&f, &[]);
    let ids = blocking_ids(&v);
    let mut args = accept_args(&ids);
    args.extend(["--reason".into(), "reviewed with the team".into()]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, v2, err) = json_pull(&f, &args);
    assert_eq!(code, 1, "{err}\n{:#?}", rules(&v2));
    assert_eq!(head(&f), origin_dev(&f));
    assert!(!f.marker_exists(), "payload executed after checkout!");

    let store = std::fs::read_dir(shield_home(&f).join("repos")).unwrap().next().unwrap().unwrap().path();
    let text = std::fs::read_to_string(store).unwrap();
    for id in &ids {
        assert!(text.contains(id.as_str()), "{id} not stored: {text}");
    }
    assert!(text.contains("reviewed with the team"));

    // Already up to date; stored acceptances keep `check` from blocking.
    let out = shield(&f).args(["pull"]).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}\n{}", String::from_utf8_lossy(&out.stdout));
    assert!(err.contains("already up to date"), "{err}");
    let out = shield(&f).args(["scan", "HEAD~1..HEAD"]).output().unwrap();
    assert_ne!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stdout));
}

#[test]
fn pull_blocks_incident_via_provenance_alone() {
    let f = fx::matador_incident_with(fx::IncidentOpts { font: false });
    let before = head(&f);
    let (code, v, err) = json_pull(&f, &[]);
    assert_eq!(code, 2, "{err}\n{:#?}", rules(&v));
    // Nothing in the final tree is high on its own...
    assert!(!rules(&v).iter().any(|(r, s, _)| s == "critical" && !r.starts_with("t1")), "{:#?}", rules(&v));
    // ...the rewrite is what blocks.
    assert!(has(&v, "t11.rewritten-copy", "critical", false), "{:#?}", rules(&v));
    assert_eq!(head(&f), before);
    assert!(!f.marker_exists());
}

#[test]
fn offline_scan_detects_rewrite_from_reflog() {
    let f = fx::matador_incident_with(fx::IncidentOpts { font: false });
    // The victim already fetched with plain git: pre-fetch tip is gone, the reflog remembers.
    fx::fetch_now(&f.local, &fx::home(&f));
    let out = shield(&f).args(["scan", "HEAD..origin/dev", "--json"]).output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(2), "{:#?}", rules(&v));
    assert!(has(&v, "t10.ref-rewritten", "high", false), "{:#?}", rules(&v));
    let rw = v["findings"].as_array().unwrap().iter().find(|f| f["rule"] == "t10.ref-rewritten").unwrap();
    assert!(rw["details"].to_string().contains("recorded in the reflog"), "{rw}");
}

#[test]
fn diverged_history_needs_rebase_or_merge() {
    let f = fx::diverged_local();
    let before = head(&f);
    let out = shield(&f).args(["pull"]).output().unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("diverged"));
    assert_eq!(head(&f), before);

    let (code, v, err) = json_pull(&f, &["--rebase"]);
    assert_eq!(code, 0, "{err}\n{:#?}", rules(&v));
    let base = fx::git(&f.local, &fx::home(&f), &["merge-base", "HEAD", "origin/dev"]);
    assert_eq!(base, origin_dev(&f), "local commit not rebased onto the scanned tip");
    assert!(!f.marker_exists());
}

#[test]
fn pull_refuses_checkout_time_config_drivers() {
    let f = fx::clean_fast_forward();
    let cfg = f.local.join(".git/config");
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str(&format!("[filter \"x\"]\n\tsmudge = \"touch {}\"\n", f.marker.display()));
    std::fs::write(&cfg, text).unwrap();
    // `check` only fetches, so a smudge filter is not a reason to refuse...
    let out = shield(&f).args(["check", "--json"]).output().unwrap();
    assert_ne!(out.status.code(), Some(3), "{}", String::from_utf8_lossy(&out.stderr));
    // ...but `pull` checks files out, so it must.
    let out = shield(&f).args(["pull"]).output().unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("refusing to run git"));
    assert!(!f.marker_exists());
}
