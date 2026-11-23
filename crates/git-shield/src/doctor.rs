//! `git shield doctor`: read-only checks of the user's own setup (git, editors,
//! agents). Suggests fixes; never changes anything.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use shield_rules::parse_jsonc;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Serialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum Status {
    Ok,
    Warn,
    Info,
}

#[derive(Serialize)]
struct Check {
    area: String,
    status: Status,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<String>,
}

fn check(area: &str, status: Status, message: impl Into<String>, fix: Option<&str>) -> Check {
    Check { area: area.into(), status, message: message.into(), fix: fix.map(str::to_string) }
}

/// `git config --global --get <key>`, run from an empty temp dir so no
/// repository's config (or fsmonitor) is involved.
pub(crate) fn git_global(key: &str) -> Option<String> {
    let dir = tempfile::tempdir().ok()?;
    let out = Command::new("git")
        .current_dir(dir.path())
        .env("GIT_CEILING_DIRECTORIES", dir.path())
        .args(["config", "--global", "--get", key])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn git_checks(out: &mut Vec<Check>) {
    match git_global("safe.bareRepository").as_deref() {
        Some("explicit") => out.push(check("git", Status::Ok, "safe.bareRepository = explicit", None)),
        _ => out.push(check(
            "git",
            Status::Warn,
            "safe.bareRepository is not `explicit`: a bare repo embedded in a project can run its own config/hooks",
            Some("git config --global safe.bareRepository explicit"),
        )),
    }
    match git_global("transfer.fsckObjects").as_deref() {
        Some("true") => out.push(check("git", Status::Ok, "transfer.fsckObjects = true", None)),
        _ => out.push(check(
            "git",
            Status::Info,
            "transfer.fsckObjects is off: malformed objects are not rejected on fetch",
            Some("git config --global transfer.fsckObjects true"),
        )),
    }
    if let Some(v) = git_global("core.fsmonitor").filter(|v| !matches!(v.as_str(), "false" | "true" | "")) {
        out.push(check(
            "git",
            Status::Info,
            format!("global core.fsmonitor runs `{v}` in every repository; make sure that is yours"),
            None,
        ));
    }
    if let Some(v) = git_global("core.hooksPath") {
        out.push(check(
            "git",
            Status::Info,
            format!("global core.hooksPath = {v} (hooks there run in every repo)"),
            None,
        ));
    }
}

/// User settings files of VS Code and its forks that exist on this machine.
fn editor_settings(home: &Path) -> Vec<(String, PathBuf)> {
    let apps = ["Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf", "Positron"];
    let mut out = Vec::new();
    for app in apps {
        for base in [home.join("Library/Application Support"), home.join(".config"), home.join("AppData/Roaming")] {
            let p = base.join(app).join("User/settings.json");
            if p.is_file() {
                out.push((app.to_string(), p));
            }
        }
    }
    out
}

fn read_json(p: &Path) -> Option<Value> {
    parse_jsonc(&std::fs::read_to_string(p).ok()?)
}

fn editor_checks(home: &Path, out: &mut Vec<Check>) {
    let found = editor_settings(home);
    if found.is_empty() {
        out.push(check("editor", Status::Info, "no VS Code-family user settings found", None));
    }
    for (app, path) in found {
        let area = format!("editor:{app}");
        let Some(v) = read_json(&path) else {
            out.push(check(&area, Status::Info, format!("could not parse {}", path.display()), None));
            continue;
        };
        match v.get("task.allowAutomaticTasks") {
            Some(x) if x == "on" || x == &Value::Bool(true) => out.push(check(
                &area,
                Status::Warn,
                "task.allowAutomaticTasks is on: folderOpen tasks in any repo run without asking",
                Some(r#"set "task.allowAutomaticTasks": "off" in user settings"#),
            )),
            Some(x) if x == "off" => out.push(check(&area, Status::Ok, "task.allowAutomaticTasks = off", None)),
            _ => out.push(check(
                &area,
                Status::Info,
                "task.allowAutomaticTasks not set explicitly (older versions prompt instead of blocking)",
                Some(r#"set "task.allowAutomaticTasks": "off" in user settings"#),
            )),
        }
        if v.get("security.workspace.trust.enabled") == Some(&Value::Bool(false)) {
            out.push(check(
                &area,
                Status::Warn,
                "Workspace Trust is disabled: every folder is trusted",
                Some(r#"remove "security.workspace.trust.enabled": false"#),
            ));
        }
        for k in ["chat.tools.autoApprove", "chat.tools.global.autoApprove", "github.copilot.chat.agent.autoApprove"] {
            if v.get(k).is_some_and(|x| x == &Value::Bool(true)) {
                out.push(check(&area, Status::Warn, format!("{k} is on: the agent runs tools without asking"), None));
            }
        }
    }
}

fn agent_checks(home: &Path, out: &mut Vec<Check>) {
    let p = home.join(".claude/settings.json");
    let Some(v) = read_json(&p) else { return };
    if v.get("enableAllProjectMcpServers") == Some(&Value::Bool(true)) {
        out.push(check(
            "claude-code",
            Status::Warn,
            "enableAllProjectMcpServers is on: every repo's .mcp.json servers start without asking",
            Some("remove enableAllProjectMcpServers from ~/.claude/settings.json"),
        ));
    } else {
        out.push(check("claude-code", Status::Ok, "project MCP servers need approval", None));
    }
    if v.pointer("/permissions/defaultMode").and_then(Value::as_str) == Some("bypassPermissions") {
        out.push(check(
            "claude-code",
            Status::Warn,
            "defaultMode is bypassPermissions: tools run without prompts in every project",
            None,
        ));
    }
}

/// The user's YARA rules directory: found, compiled, usable by this build.
fn rule_checks(out: &mut Vec<Check>) {
    let Some(dir) = shield_rules::rules_dir() else { return };
    let files = match shield_rules::rule_files(&dir) {
        Ok(f) => f,
        Err(e) => return out.push(check("yara rules", Status::Warn, e, None)),
    };
    if files.is_empty() {
        let what = if shield_rules::YARA { "none" } else { "none (this build has no YARA support)" };
        return out.push(check(
            "yara rules",
            Status::Info,
            format!("{what}; add *.yar files to {}", dir.display()),
            None,
        ));
    }
    #[cfg(not(feature = "yara"))]
    out.push(check(
        "yara rules",
        Status::Warn,
        format!("{} rule file(s) in {}, but this build has no YARA support", files.len(), dir.display()),
        Some("rebuild with the default features (`cargo install --path crates/git-shield`)"),
    ));
    #[cfg(feature = "yara")]
    match shield_rules::yara::compile_dir(&dir) {
        Ok(Some(d)) => out.push(check(
            "yara rules",
            Status::Ok,
            format!("{} rule(s) from {} file(s) in {}", d.rule_count(), d.files().len(), dir.display()),
            None,
        )),
        Ok(None) => {}
        Err(e) => {
            out.push(check("yara rules", Status::Warn, e, Some("fix the rule; scans refuse to run until it compiles")))
        }
    }
}

pub fn run(json: bool) -> Result<u8> {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    let mut checks = Vec::new();
    git_checks(&mut checks);
    editor_checks(&home, &mut checks);
    agent_checks(&home, &mut checks);
    rule_checks(&mut checks);
    let warn = checks.iter().any(|c| c.status == Status::Warn);
    if json {
        println!("{}", serde_json::to_string_pretty(&checks)?);
    } else {
        for c in &checks {
            let tag = match c.status {
                Status::Ok => "ok  ",
                Status::Warn => "WARN",
                Status::Info => "info",
            };
            println!("{tag}  {:<18} {}", c.area, c.message);
            if let Some(f) = &c.fix {
                println!("      {:<18} fix: {f}", "");
            }
        }
        println!("\nNothing was changed. {}", if warn { "Review the WARN lines." } else { "No warnings." });
    }
    Ok(u8::from(warn))
}
