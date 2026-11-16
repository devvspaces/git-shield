//! Builders for hostile-but-harmless git repositories used by git-shield tests.
//!
//! **Every payload here is inert.** "Malicious" files only ever *describe*
//! touching a marker file (`PWNED`) inside the fixture's temp directory. Tests
//! assert that the marker never appears, which proves git-shield did not
//! execute anything from the repository.
//!
//! All git invocations run with an isolated environment (no global/system
//! config, fixed identities and dates) so fixtures are reproducible.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub struct Fixture {
    pub dir: tempfile::TempDir,
    /// Bare "server" repository.
    pub origin: PathBuf,
    /// The victim's clone (what git-shield runs in).
    pub local: PathBuf,
    /// Working clone used to push (legit teammate / attacker).
    pub pusher: PathBuf,
    /// If this file ever exists, something executed a payload.
    pub marker: PathBuf,
}

impl Fixture {
    pub fn marker_exists(&self) -> bool {
        self.marker.exists()
    }
}

/// Environment applied to every fixture git call.
pub fn isolated(cmd: &mut Command, home: &Path) {
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LANG", "C");
}

pub struct Identity<'a> {
    pub name: &'a str,
    pub email: &'a str,
    /// `<unix-seconds> <+hhmm>`
    pub date: &'a str,
}

pub const ALICE: Identity<'static> =
    Identity { name: "Alice Dev", email: "alice@example.com", date: "1762700000 +0100" };
pub const EMEKA: Identity<'static> = Identity { name: "Emeka", email: "emeka@example.com", date: "1762710000 +0100" };
pub const HYCIENTH: Identity<'static> =
    Identity { name: "Hycienth E.O", email: "1038+hycienth@users.noreply.github.com", date: "1762720607 +0100" };
pub const GITHUB: Identity<'static> =
    Identity { name: "GitHub", email: "noreply@github.com", date: "1762720607 +0100" };

pub fn git(dir: &Path, home: &Path, args: &[&str]) -> String {
    git_as(dir, home, args, &ALICE, &ALICE)
}

pub fn git_as(dir: &Path, home: &Path, args: &[&str], author: &Identity, committer: &Identity) -> String {
    let mut cmd = Command::new("git");
    isolated(&mut cmd, home);
    cmd.current_dir(dir)
        .args(["-c", "init.defaultBranch=dev", "-c", "core.autocrlf=false", "-c", "advice.detachedHead=false"])
        .args(args)
        .env("GIT_AUTHOR_NAME", author.name)
        .env("GIT_AUTHOR_EMAIL", author.email)
        .env("GIT_AUTHOR_DATE", author.date)
        .env("GIT_COMMITTER_NAME", committer.name)
        .env("GIT_COMMITTER_EMAIL", committer.email)
        .env("GIT_COMMITTER_DATE", committer.date);
    let out = cmd.output().expect("run git");
    assert!(
        out.status.success(),
        "git {args:?} in {} failed:\n{}{}",
        dir.display(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `git fetch -q origin` with the real clock, so reflog entries carry today's
/// date (fixture identities use fixed 2025 dates, which would fall outside
/// git-shield's reflog window).
pub fn fetch_now(dir: &Path, home: &Path) {
    let mut cmd = Command::new("git");
    isolated(&mut cmd, home);
    let out = cmd
        .current_dir(dir)
        .args(["-c", "user.name=Victim", "-c", "user.email=victim@example.com", "fetch", "-q", "origin"])
        .output()
        .expect("run git fetch");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

/// Write a raw commit object (lets tests forge signature headers, committers, dates).
pub fn write_raw_commit(dir: &Path, home: &Path, raw: &str) -> String {
    let mut cmd = Command::new("git");
    isolated(&mut cmd, home);
    let mut child = cmd
        .current_dir(dir)
        .args(["hash-object", "-t", "commit", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn git hash-object");
    child.stdin.take().unwrap().write_all(raw.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

pub fn write(dir: &Path, rel: &str, content: impl AsRef<[u8]>) {
    let p = dir.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, content).unwrap();
}

/// A ~300-line LF Python file.
pub fn python_module(seed: &str) -> String {
    let mut s = String::from("import json\n\n\n");
    for i in 0..60 {
        s.push_str(&format!(
            "def handler_{seed}_{i}(request):\n    data = json.loads(request.body)\n    total = data.get(\"amount\", 0) * {i}\n    return {{\"ok\": True, \"total\": total}}\n\n"
        ));
    }
    s
}

/// Inert stand-in for the fake-font JavaScript payload.
pub fn fake_font_payload() -> String {
    "// git-shield TEST FIXTURE: inert stand-in for a disguised payload. Never executed.\n\
     const fs = require('fs');\n\
     const marker = process.env.GS_MARKER || 'PWNED';\n\
     (function () { fs.writeFileSync(marker, 'pwned'); })();\n"
        .to_string()
}

pub fn tasks_json_payload() -> String {
    "\u{feff}{\n  \"version\": \"2.0.0\",\n  \"tasks\": [\n    {\n      \"label\": \"eslint-check\",\n      \"type\": \"shell\",\n      \"command\": \"node\",\n      \"args\": [\"./public/fonts/fa-solid-600.ttf\"],\n      \"problemMatcher\": [],\n      \"isBackground\": true,\n      \"hide\": true,\n      \"presentation\": {\"reveal\": \"never\", \"panel\": \"dedicated\", \"focus\": false, \"clear\": false, \"echo\": false, \"close\": true},\n      \"runOptions\": {\"runOn\": \"folderOpen\"}\n    }\n  ]\n}\n".to_string()
}

fn base(dir: &tempfile::TempDir) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let root = dir.path().to_path_buf();
    let home = root.join("home");
    fs::create_dir_all(&home).unwrap();
    let origin = root.join("origin.git");
    let pusher = root.join("pusher");
    let local = root.join("local");
    git(&root, &home, &["init", "-q", "--bare", origin.to_str().unwrap()]);
    git(&root, &home, &["clone", "-q", origin.to_str().unwrap(), pusher.to_str().unwrap()]);
    write(&pusher, "README.md", "# demo app\n");
    write(&pusher, ".gitignore", "node_modules\n\n.env\n.vscode\n");
    write(&pusher, "app/views.py", python_module("views"));
    write(&pusher, "app/models.py", python_module("models"));
    git(&pusher, &home, &["checkout", "-q", "-b", "dev"]);
    git(&pusher, &home, &["add", "-A"]);
    git(&pusher, &home, &["commit", "-q", "-m", "initial"]);
    git(&pusher, &home, &["push", "-q", "-u", "origin", "dev"]);
    git(&root, &home, &["clone", "-q", "-b", "dev", origin.to_str().unwrap(), local.to_str().unwrap()]);
    (root, home, origin, local)
}

fn finish(dir: tempfile::TempDir, origin: PathBuf, local: PathBuf) -> Fixture {
    let pusher = dir.path().join("pusher");
    let marker = dir.path().join("PWNED");
    Fixture { dir, origin, local, pusher, marker }
}

pub fn home(f: &Fixture) -> PathBuf {
    f.dir.path().join("home")
}

/// Teammate pushes an ordinary change; the victim's pull should be clean.
pub fn clean_fast_forward() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (root, home, origin, local) = base(&dir);
    let pusher = root.join("pusher");
    let views = python_module("views").replace("* 7\n", "* 7 + 1\n");
    write(&pusher, "app/views.py", views);
    git_as(&pusher, &home, &["commit", "-q", "-am", "Fix total for handler 7"], &EMEKA, &EMEKA);
    git(&pusher, &home, &["push", "-q", "origin", "dev"]);
    finish(dir, origin, local)
}

/// Only line endings change.
pub fn crlf_only() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (root, home, origin, local) = base(&dir);
    let pusher = root.join("pusher");
    write(&pusher, "app/views.py", python_module("views").replace('\n', "\r\n"));
    git_as(&pusher, &home, &["commit", "-q", "-am", "Normalize line endings"], &EMEKA, &EMEKA);
    git(&pusher, &home, &["push", "-q", "origin", "dev"]);
    finish(dir, origin, local)
}

/// The victim committed locally while a teammate pushed: histories diverge.
pub fn diverged_local() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (root, home, origin, local) = base(&dir);
    let pusher = root.join("pusher");
    write(&pusher, "app/views.py", python_module("views").replace("* 7\n", "* 7 + 1\n"));
    git_as(&pusher, &home, &["commit", "-q", "-am", "Fix total for handler 7"], &EMEKA, &EMEKA);
    git(&pusher, &home, &["push", "-q", "origin", "dev"]);
    write(&local, "README.md", "# demo app\n\nLocal notes.\n");
    git(&local, &home, &["commit", "-q", "-am", "Local README tweak"]);
    finish(dir, origin, local)
}

/// Knobs for [`matador_incident_with`].
#[derive(Debug, Clone, Copy)]
pub struct IncidentOpts {
    /// Include the fake-font payload in the forged commit (it survives cleanup).
    pub font: bool,
}

impl Default for IncidentOpts {
    fn default() -> Self {
        IncidentOpts { font: true }
    }
}

/// Faithful, inert reproduction of the 2026-11-10 matador-legacy incident:
///
/// 1. A real PR merge lands on `dev` (signed, committed by GitHub). The victim fetches it.
/// 2. A compromised account force-pushes an unsigned *copy* of that merge whose tree also
///    adds `.vscode/tasks.json` (folderOpen → `node ./public/fonts/fa-solid-600.ttf`),
///    `.vscode/settings.json` (allowAutomaticTasks), the fake-font JS payload, un-ignores
///    `.env`/`.vscode`, and rewrites Python files to CRLF to bury a small code change.
/// 3. A later commit removes `.vscode/` (the font and CRLF churn stay).
pub fn matador_incident() -> Fixture {
    matador_incident_with(IncidentOpts::default())
}

/// [`matador_incident`] with options (e.g. without the surviving font payload,
/// so only provenance can catch it).
pub fn matador_incident_with(opts: IncidentOpts) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (root, home, origin, local) = base(&dir);
    let pusher = root.join("pusher");

    // --- 1. legit feature + real GitHub merge commit (forged gpgsig header = "signed").
    git(&pusher, &home, &["checkout", "-q", "-b", "fix-transfer-ownership-bug"]);
    write(&pusher, "app/views.py", python_module("views").replace("* 3\n", "* 3 - fee\n"));
    git_as(&pusher, &home, &["commit", "-q", "-am", "Resolve full equity transfer chain"], &EMEKA, &EMEKA);
    let feature = git(&pusher, &home, &["rev-parse", "HEAD"]);
    let feature_tree = git(&pusher, &home, &["rev-parse", "HEAD^{tree}"]);
    git(&pusher, &home, &["checkout", "-q", "dev"]);
    let dev = git(&pusher, &home, &["rev-parse", "HEAD"]);
    let msg = "Merge pull request #2921 from org/fix-transfer-ownership-bug\n\nResolve full equity transfer chain\n";
    let real_merge = write_raw_commit(
        &pusher,
        &home,
        &format!(
            "tree {feature_tree}\nparent {dev}\nparent {feature}\nauthor {} <{}> {}\ncommitter {} <{}> {}\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n wsBcBAABCAAQBQJpEXAMPLEFIXTUREONLYnotarealsignature0000000000\n =AAAA\n -----END PGP SIGNATURE-----\n\n{msg}",
            HYCIENTH.name, HYCIENTH.email, HYCIENTH.date, GITHUB.name, GITHUB.email, GITHUB.date
        ),
    );
    git(&pusher, &home, &["push", "-q", "origin", &format!("{real_merge}:refs/heads/dev")]);
    // Victim fetches the real merge (so their reflog / trust state has seen it).
    git(&local, &home, &["fetch", "-q", "origin"]);

    // --- 2. forged copy with payload, force-pushed.
    git(&pusher, &home, &["fetch", "-q", "origin"]);
    git(&pusher, &home, &["checkout", "-q", "--detach", &real_merge]);
    write(&pusher, ".vscode/tasks.json", tasks_json_payload());
    write(&pusher, ".vscode/settings.json", "{\n  \"task.allowAutomaticTasks\": true\n}\n");
    write(&pusher, ".vscode/extensions.json", "{ \"recommendations\": [] }\n");
    if opts.font {
        write(&pusher, "public/fonts/fa-solid-600.ttf", fake_font_payload());
    }
    write(&pusher, ".gitignore", "node_modules\n");
    // CRLF churn hiding a small real change.
    let views = python_module("views").replace("* 3\n", "* 3 - fee\n").replace("* 9\n", "* 9 * rate\n");
    write(&pusher, "app/views.py", views.replace('\n', "\r\n"));
    write(&pusher, "app/models.py", python_module("models").replace('\n', "\r\n"));
    git(&pusher, &home, &["add", "-A"]);
    let forged_tree = git(&pusher, &home, &["write-tree"]);
    let forged = write_raw_commit(
        &pusher,
        &home,
        &format!(
            "tree {forged_tree}\nparent {dev}\nparent {feature}\nauthor {} <{}> {}\ncommitter {} <{}> 1762688207 -0800\n\n{msg}",
            HYCIENTH.name, HYCIENTH.email, HYCIENTH.date, HYCIENTH.name, HYCIENTH.email
        ),
    );
    git(&pusher, &home, &["push", "-q", "--force", "origin", &format!("{forged}:refs/heads/dev")]);

    // --- 3. cleanup commit removes .vscode only.
    git(&pusher, &home, &["checkout", "-q", "--detach", &forged]);
    git(&pusher, &home, &["rm", "-q", "-r", ".vscode"]);
    git_as(
        &pusher,
        &home,
        &["commit", "-q", "-m", "Remove .vscode config; include TRANSFERRED status"],
        &EMEKA,
        &EMEKA,
    );
    git(&pusher, &home, &["push", "-q", "origin", "HEAD:refs/heads/dev"]);

    finish(dir, origin, local)
}
