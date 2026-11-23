//! User YARA content rules (ADR 0009), compiled with yara-x.
//!
//! Rules come only from the user's own rules directory, never from the
//! scanned repository. Each matching rule becomes one finding per file
//! version, with its id anchored on the blob like the built-in content rules.
//!
//! Recognised metadata:
//! - `severity`: info, low, medium (default), high or critical.
//! - `threat`: T1–T13 (default: `YR`, a user rule).
//! - `description`: the finding title (default: the rule name).

use crate::rule_files;
use shield_core::{Detector, FileChange, Finding, Severity, Threat};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Per-blob scan limit. A timeout is a note, not a finding.
const SCAN_TIMEOUT: Duration = Duration::from_secs(2);
/// Matched patterns listed per finding.
const MAX_PATTERNS: usize = 5;

struct RuleMeta {
    rule: &'static str,
    threat: Threat,
    severity: Severity,
    title: String,
}

/// A compiled rule set, usable as a [`Detector`].
pub struct YaraDetector {
    rules: &'static yara_x::Rules,
    meta: HashMap<String, RuleMeta>,
    files: Vec<PathBuf>,
}

impl YaraDetector {
    pub fn rule_count(&self) -> usize {
        self.meta.len()
    }

    /// The rule files that were compiled.
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }
}

/// Compile every rule file in `dir`. `Ok(None)` when there are none.
pub fn compile_dir(dir: &Path) -> Result<Option<YaraDetector>, String> {
    let files = rule_files(dir)?;
    if files.is_empty() {
        return Ok(None);
    }
    let mut sources = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).map_err(|e| format!("reading {}: {e}", f.display()))?;
        sources.push((f.display().to_string(), text));
    }
    let mut d = compile(&sources)?;
    d.files = files;
    Ok(Some(d))
}

fn parse_severity(s: &str) -> Option<Severity> {
    Some(match s.to_ascii_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => return None,
    })
}

fn parse_threat(s: &str) -> Option<Threat> {
    Some(match s.to_ascii_uppercase().as_str() {
        "T1" => Threat::T1,
        "T2" => Threat::T2,
        "T3" => Threat::T3,
        "T4" => Threat::T4,
        "T5" => Threat::T5,
        "T6" => Threat::T6,
        "T7" => Threat::T7,
        "T8" => Threat::T8,
        "T9" => Threat::T9,
        "T10" => Threat::T10,
        "T11" => Threat::T11,
        "T12" => Threat::T12,
        "T13" => Threat::T13,
        "YR" => Threat::Custom,
        _ => return None,
    })
}

/// Compile `(origin, source)` pairs. Any error, including bad metadata, fails
/// the whole set: a rule that silently does nothing is worse than a stop.
pub fn compile(sources: &[(String, String)]) -> Result<YaraDetector, String> {
    let mut c = yara_x::Compiler::new();
    for (origin, text) in sources {
        c.add_source(yara_x::SourceCode::from(text.as_str()).with_origin(origin.as_str()))
            .map_err(|e| format!("YARA rule error:\n{e}"))?;
    }
    let rules: &'static yara_x::Rules = Box::leak(Box::new(c.build()));
    let mut meta = HashMap::new();
    for r in rules.iter() {
        let id = r.identifier();
        let mut m = RuleMeta {
            rule: Box::leak(format!("yara.{id}").into_boxed_str()),
            threat: Threat::Custom,
            severity: Severity::Medium,
            title: format!("YARA rule `{id}` matched"),
        };
        for (key, value) in r.metadata() {
            let yara_x::MetaValue::String(v) = value else { continue };
            match key {
                "severity" => {
                    m.severity = parse_severity(v).ok_or_else(|| {
                        format!("YARA rule `{id}`: severity must be info, low, medium, high or critical, got `{v}`")
                    })?;
                }
                "threat" => {
                    m.threat =
                        parse_threat(v).ok_or_else(|| format!("YARA rule `{id}`: threat must be T1–T13, got `{v}`"))?;
                }
                "description" => m.title = v.to_string(),
                _ => {}
            }
        }
        meta.insert(format!("{}:{id}", r.namespace()), m);
    }
    Ok(YaraDetector { rules, meta, files: Vec::new() })
}

thread_local! {
    /// One scanner per thread, rebuilt if a different rule set shows up.
    static SCANNER: RefCell<Option<(usize, yara_x::Scanner<'static>)>> = const { RefCell::new(None) };
}

impl Detector for YaraDetector {
    fn name(&self) -> &'static str {
        "yara"
    }

    fn interested(&self, change: &FileChange) -> bool {
        change.new.as_ref().is_some_and(|b| !b.symlink && !b.bytes.is_empty())
    }

    fn scan_file(&self, change: &FileChange, out: &mut Vec<Finding>) {
        let Some(blob) = &change.new else { return };
        let key = self.rules as *const yara_x::Rules as usize;
        SCANNER.with(|cell| {
            let mut slot = cell.borrow_mut();
            if slot.as_ref().is_none_or(|(k, _)| *k != key) {
                let mut s = yara_x::Scanner::new(self.rules);
                s.set_timeout(SCAN_TIMEOUT);
                *slot = Some((key, s));
            }
            let (_, scanner) = slot.as_mut().expect("set above");
            let results = match scanner.scan(&blob.bytes) {
                Ok(r) => r,
                Err(yara_x::ScanError::Timeout) => {
                    out.push(
                        Finding::new(
                            Threat::Custom,
                            "yara.timeout",
                            Severity::Info,
                            "YARA scan timed out on this file",
                        )
                        .anchor(blob.oid.clone())
                        .detail(format!(
                            "Stopped after {} s; the user rules were not fully applied.",
                            SCAN_TIMEOUT.as_secs()
                        )),
                    );
                    return;
                }
                Err(e) => {
                    out.push(
                        Finding::new(Threat::Custom, "yara.error", Severity::Info, "YARA scan failed on this file")
                            .anchor(blob.oid.clone())
                            .detail(e.to_string()),
                    );
                    return;
                }
            };
            for r in results.matching_rules() {
                let Some(m) = self.meta.get(&format!("{}:{}", r.namespace(), r.identifier())) else { continue };
                let mut f = Finding::new(m.threat, m.rule, m.severity, m.title.clone()).anchor(blob.oid.clone());
                let mut shown = 0;
                for p in r.patterns() {
                    let mut ranges = p.matches().map(|x| x.range());
                    let Some(first) = ranges.next() else { continue };
                    if shown == MAX_PATTERNS {
                        f = f.detail("…more patterns matched");
                        break;
                    }
                    let more = ranges.count();
                    let extra = if more > 0 { format!(" (+{more} more)") } else { String::new() };
                    f = f.detail(format!("{} at offset {}{extra}", p.identifier(), first.start));
                    shown += 1;
                }
                if blob.truncated {
                    f = f.detail(format!("Only the first {} bytes were scanned.", blob.bytes.len()));
                }
                out.push(f.detail(format!("User YARA rule `{}`.", r.identifier())));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shield_core::{BlobData, FileStatus};
    use std::sync::Arc;

    fn change(bytes: &[u8]) -> FileChange {
        FileChange {
            path: "src/x.js".into(),
            status: FileStatus::Added,
            old: None,
            new: Some(BlobData {
                oid: "ab".repeat(20),
                bytes: Arc::from(bytes),
                truncated: false,
                size: bytes.len() as u64,
                executable: false,
                symlink: false,
            }),
            commit: None,
            transited: false,
        }
    }

    fn src(s: &str) -> Vec<(String, String)> {
        vec![("test.yar".into(), s.into())]
    }

    #[test]
    fn metadata_maps_to_the_finding() {
        let d = compile(&src(
            r#"rule ev_loader { meta: severity = "high" threat = "T13" description = "eval of a base64 blob"
               strings: $a = "eval(atob(" condition: $a }
               rule plain { strings: $b = "hello" condition: $b }"#,
        ))
        .unwrap();
        assert_eq!(d.rule_count(), 2);
        let mut out = Vec::new();
        d.scan_file(&change(b"x; eval(atob('aGk=')); hello"), &mut out);
        out.sort_by_key(|f| f.rule);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].rule, "yara.ev_loader");
        assert_eq!(out[0].severity, Severity::High);
        assert_eq!(out[0].threat, Threat::T13);
        assert_eq!(out[0].title, "eval of a base64 blob");
        assert!(out[0].details[0].starts_with("$a at offset 3"), "{:?}", out[0].details);
        assert_eq!(out[0].anchor.as_deref(), Some("ab".repeat(20).as_str()));
        assert_eq!(out[1].rule, "yara.plain");
        assert_eq!(out[1].severity, Severity::Medium);
        assert_eq!(out[1].threat, Threat::Custom);

        let mut none = Vec::new();
        d.scan_file(&change(b"nothing here"), &mut none);
        assert!(none.is_empty());
    }

    #[test]
    fn bad_rules_are_errors() {
        let e = compile(&src("rule x { condition: nope }")).err().unwrap();
        assert!(e.contains("test.yar"), "{e}");
        let e = compile(&src(r#"rule x { meta: severity = "severe" condition: true }"#)).err().unwrap();
        assert!(e.contains("severity must be"), "{e}");
        let e = compile(&src(r#"rule x { meta: threat = "T99" condition: true }"#)).err().unwrap();
        assert!(e.contains("threat must be"), "{e}");
    }

    #[test]
    fn rule_files_are_found() {
        let dir = tempfile_dir();
        assert!(compile_dir(&dir).unwrap().is_none());
        std::fs::write(dir.join("a.yar"), "rule a { condition: true }").unwrap();
        std::fs::write(dir.join("b.yara"), "rule b { condition: true }").unwrap();
        std::fs::write(dir.join("notes.txt"), "not a rule").unwrap();
        let d = compile_dir(&dir).unwrap().unwrap();
        assert_eq!(d.rule_count(), 2);
        assert_eq!(d.files().len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn tempfile_dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("gs-yara-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
