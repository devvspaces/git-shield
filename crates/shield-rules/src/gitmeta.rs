//! T8: `.gitattributes` drivers and `.gitmodules` changes.

use shield_core::{Detector, FileChange, Finding, Severity, Threat};
use std::collections::{BTreeMap, BTreeSet};

/// Built-in userdiff drivers (no external program involved).
const BUILTIN_DIFF: &[&str] = &[
    "ada", "bash", "bibtex", "cpp", "csharp", "css", "dts", "elixir", "fortran", "fountain", "golang", "html", "java",
    "kotlin", "markdown", "matlab", "objc", "pascal", "perl", "php", "python", "r", "ruby", "rust", "scheme", "tex",
];
/// Common, well-known external drivers.
const KNOWN_FILTERS: &[&str] = &["lfs", "git-crypt"];
const BUILTIN_MERGE: &[&str] = &["text", "binary", "union"];

/// (attribute, driver) pairs that name a custom program.
fn drivers(text: &str) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for token in line.split_whitespace().skip(1) {
            let Some((attr, val)) = token.split_once('=') else { continue };
            let custom = match attr {
                "filter" => !KNOWN_FILTERS.contains(&val),
                "diff" => !BUILTIN_DIFF.contains(&val),
                "merge" => !BUILTIN_MERGE.contains(&val),
                _ => false,
            };
            if custom {
                out.insert((attr.to_string(), val.to_string()));
            }
        }
    }
    out
}

pub struct Attributes;

impl Detector for Attributes {
    fn name(&self) -> &'static str {
        "gitattributes"
    }

    fn interested(&self, c: &FileChange) -> bool {
        c.new.is_some() && c.file_name_lower() == ".gitattributes"
    }

    fn scan_file(&self, c: &FileChange, out: &mut Vec<Finding>) {
        let Some(new) = &c.new else { return };
        let before = c.old.as_ref().map(|o| drivers(&o.text())).unwrap_or_default();
        for (attr, driver) in drivers(&new.text()).difference(&before) {
            out.push(
                Finding::new(Threat::T8, "gitattributes.custom-driver", Severity::Medium,
                    format!("`.gitattributes` assigns custom {attr} driver `{driver}`"))
                    .anchor(format!("{attr}={driver}"))
                    .detail(format!("git runs `{attr}.{driver}.*` programs from your config for matching files. Harmless unless that driver is defined; a malicious config or setup script would define it."))
                    .detail("git-shield also reports local config that defines such drivers (T7)."),
            );
        }
    }
}

#[derive(Default, Debug, PartialEq)]
struct Submodule {
    path: Option<String>,
    url: Option<String>,
    update: Option<String>,
}

fn parse_gitmodules(text: &str) -> BTreeMap<String, Submodule> {
    let mut out: BTreeMap<String, Submodule> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            current = line
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .strip_prefix("submodule")
                .map(|r| r.trim().trim_matches('"').to_string());
            if let Some(name) = &current {
                out.entry(name.clone()).or_default();
            }
            continue;
        }
        let (Some(name), Some((k, v))) = (&current, line.split_once('=')) else { continue };
        let entry = out.entry(name.clone()).or_default();
        let v = v.trim().trim_matches('"').to_string();
        match k.trim().to_ascii_lowercase().as_str() {
            "path" => entry.path = Some(v),
            "url" => entry.url = Some(v),
            "update" => entry.update = Some(v),
            _ => {}
        }
    }
    out
}

pub struct Submodules;

impl Detector for Submodules {
    fn name(&self) -> &'static str {
        "gitmodules"
    }

    fn interested(&self, c: &FileChange) -> bool {
        c.new.is_some() && c.file_name_lower() == ".gitmodules"
    }

    fn scan_file(&self, c: &FileChange, out: &mut Vec<Finding>) {
        let Some(new) = &c.new else { return };
        let before = c.old.as_ref().map(|o| parse_gitmodules(&o.text())).unwrap_or_default();
        for (name, sm) in parse_gitmodules(&new.text()) {
            let old = before.get(&name);
            if old == Some(&sm) {
                continue;
            }
            let anchor = format!("{name}:{:?}:{:?}:{:?}", sm.path, sm.url, sm.update);
            if let Some(update) = sm.update.as_deref().filter(|u| u.starts_with('!')) {
                out.push(
                    Finding::new(
                        Threat::T8,
                        "gitmodules.update-command",
                        Severity::Critical,
                        format!("Submodule `{name}` runs a command on update"),
                    )
                    .anchor(anchor.clone())
                    .detail(format!("update = {update}")),
                );
            }
            let path = sm.path.clone().unwrap_or_default();
            if path.split('/').any(|p| p == ".." || p.eq_ignore_ascii_case(".git")) || path.starts_with('/') {
                out.push(
                    Finding::new(
                        Threat::T8,
                        "gitmodules.path-escape",
                        Severity::Critical,
                        format!("Submodule `{name}` path escapes the worktree or targets .git"),
                    )
                    .anchor(anchor.clone())
                    .detail(format!("path = {path}")),
                );
            }
            let url = sm.url.clone().unwrap_or_default();
            let changed_url = old.map(|o| o.url != sm.url).unwrap_or(true);
            if url.starts_with("ext::") {
                out.push(
                    Finding::new(
                        Threat::T8,
                        "gitmodules.ext-url",
                        Severity::Critical,
                        format!("Submodule `{name}` uses the ext:: transport"),
                    )
                    .anchor(anchor.clone())
                    .detail(format!("url = {url}"))
                    .detail("ext:: URLs execute an arbitrary command to connect."),
                );
            } else if changed_url {
                let local = url.starts_with("file://") || url.starts_with('/') || url.starts_with('-');
                let sev = if local { Severity::High } else { Severity::Medium };
                let what = if old.is_some() { "changed URL" } else { "added" };
                out.push(
                    Finding::new(Threat::T8, "gitmodules.url", sev, format!("Submodule `{name}` {what}"))
                        .anchor(anchor)
                        .detail(format!("url = {url}"))
                        .detail(match old.and_then(|o| o.url.clone()) {
                            Some(prev) => format!("previous url = {prev}"),
                            None => {
                                "new submodule: its contents will be fetched from this URL on `submodule update`".into()
                            }
                        }),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{added, modified, scan};

    #[test]
    fn attributes_only_reports_new_custom_drivers() {
        let old = b"*.png binary\n*.psd filter=lfs diff=lfs merge=lfs -text\n";
        let new = b"*.png binary\n*.psd filter=lfs diff=lfs merge=lfs -text\n*.py diff=python\n*.js filter=pretty\n";
        let f = scan(&Attributes, &modified(".gitattributes", old, new));
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].title.contains("pretty"));
    }

    #[test]
    fn submodule_url_swap_and_ext() {
        let old = b"[submodule \"lib\"]\n\tpath = lib\n\turl = https://github.com/a/lib.git\n";
        let new = b"[submodule \"lib\"]\n\tpath = lib\n\turl = https://github.com/evil/lib.git\n[submodule \"x\"]\n\tpath = x\n\turl = ext::sh -c touch% /tmp/pwned\n";
        let f = scan(&Submodules, &modified(".gitmodules", old, new));
        assert!(f.iter().any(|f| f.rule == "gitmodules.ext-url" && f.severity == Severity::Critical));
        assert!(f.iter().any(|f| f.rule == "gitmodules.url" && f.details.iter().any(|d| d.contains("previous"))));
    }

    #[test]
    fn submodule_path_escape() {
        let new = b"[submodule \"x\"]\n path = ../../.git/hooks\n url = https://e.com/x\n";
        let f = scan(&Submodules, &added(".gitmodules", new));
        assert!(f.iter().any(|f| f.rule == "gitmodules.path-escape"));
    }
}
