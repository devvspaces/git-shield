//! Snapshot tests of the human-readable report, so wording and layout changes
//! are deliberate. Commit SHAs and finding ids are redacted: fixtures are
//! deterministic, but the snapshots should not churn when hashing changes.
//!
//! Update with `INSTA_UPDATE=always cargo test -p git-shield --test snapshots`
//! (or `cargo insta review`), then inspect the diff before committing.

use assert_cmd::Command;
use shield_fixtures::{self as fx, Fixture};

fn run(f: &Fixture, args: &[&str]) -> String {
    let out = Command::cargo_bin("git-shield")
        .unwrap()
        .current_dir(&f.local)
        .env("HOME", fx::home(f))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_SHIELD_HOME", f.dir.path().join("shield-home"))
        .env_remove("XDG_DATA_HOME")
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .unwrap();
    assert!(!f.marker_exists());
    format!("exit: {}\n{}", out.status.code().unwrap(), String::from_utf8_lossy(&out.stdout))
}

macro_rules! snap {
    ($name:expr, $text:expr) => {
        insta::with_settings!({
            filters => vec![
                (r"GS-([A-Z0-9]+)-[0-9a-f]{8}", "GS-$1-[id]"),
                (r"\b[0-9a-f]{40}\b", "[sha]"),
                (r"\b[0-9a-f]{9}\b", "[sha]"),
            ],
        }, {
            insta::assert_snapshot!($name, $text);
        });
    };
}

#[test]
fn report_matador_check() {
    let f = fx::matador_incident();
    snap!("matador_check", run(&f, &["check"]));
}

#[test]
fn report_matador_pull_blocked() {
    let f = fx::matador_incident();
    snap!("matador_pull_blocked", run(&f, &["pull"]));
}

#[test]
fn report_clean_check() {
    let f = fx::clean_fast_forward();
    snap!("clean_check", run(&f, &["check"]));
}

#[test]
fn report_crlf_only_verbose() {
    let f = fx::crlf_only();
    snap!("crlf_only_verbose", run(&f, &["check", "--verbose"]));
}
