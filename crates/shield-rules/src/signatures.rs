//! Known indicators shipped with git-shield (`data/signatures.toml`).

use crate::util::glob_match;
use aho_corasick::AhoCorasick;
use serde::Deserialize;
use shield_core::{Detector, FileChange, Finding, Severity, Threat};
use std::sync::LazyLock;

#[derive(Deserialize, Default)]
pub(crate) struct Signatures {
    #[serde(default)]
    pub decoy_task_label: Vec<Labelled>,
    #[serde(default)]
    payload_path: Vec<PathSig>,
    #[serde(default)]
    payload_file: Vec<FileSig>,
    #[serde(default)]
    ioc_string: Vec<StringSig>,
}

#[derive(Deserialize)]
pub(crate) struct Labelled {
    pub value: String,
    #[allow(dead_code)]
    pub source: String,
}

#[derive(Deserialize)]
struct PathSig {
    glob: String,
    campaign: String,
    #[serde(default)]
    severity: Option<String>,
    source: String,
}

#[derive(Deserialize)]
struct FileSig {
    name: String,
    campaign: String,
    #[serde(default)]
    severity: Option<String>,
    source: String,
}

#[derive(Deserialize)]
struct StringSig {
    value: String,
    campaign: String,
    #[serde(default)]
    severity: Option<String>,
    source: String,
}

pub(crate) static SIGS: LazyLock<Signatures> =
    LazyLock::new(|| toml::from_str(include_str!("../data/signatures.toml")).expect("data/signatures.toml is valid"));

static STRINGS: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(SIGS.ioc_string.iter().map(|s| s.value.as_str())).expect("ioc patterns"));

fn sev(s: &Option<String>) -> Severity {
    match s.as_deref() {
        Some("low") => Severity::Low,
        Some("medium") => Severity::Medium,
        Some("critical") => Severity::Critical,
        _ => Severity::High,
    }
}

pub fn is_decoy_label(label: &str) -> bool {
    SIGS.decoy_task_label.iter().any(|d| d.value.eq_ignore_ascii_case(label))
}

pub struct KnownIoc;

impl Detector for KnownIoc {
    fn name(&self) -> &'static str {
        "known-ioc"
    }

    fn interested(&self, c: &FileChange) -> bool {
        c.new.is_some()
    }

    fn scan_file(&self, c: &FileChange, out: &mut Vec<Finding>) {
        let Some(blob) = &c.new else { return };
        let name = c.path.rsplit('/').next().unwrap_or(&c.path);
        for s in SIGS.payload_path.iter().filter(|s| glob_match(&s.glob, &c.path)) {
            out.push(hit(
                sev(&s.severity),
                "Path matches a known worm artefact",
                &s.campaign,
                &s.source,
                &blob.oid,
                &s.glob,
            ));
        }
        for s in SIGS.payload_file.iter().filter(|s| s.name == name) {
            out.push(hit(
                sev(&s.severity),
                "File name matches a known payload",
                &s.campaign,
                &s.source,
                &blob.oid,
                &s.name,
            ));
        }
        if SIGS.ioc_string.is_empty() {
            return;
        }
        let old = c.old.as_ref().map(|o| o.bytes.clone());
        let mut seen = Vec::new();
        for m in STRINGS.find_iter(&*blob.bytes) {
            let s = &SIGS.ioc_string[m.pattern().as_usize()];
            if seen.contains(&m.pattern()) {
                continue;
            }
            seen.push(m.pattern());
            // Already present before this change: not new.
            if old.as_ref().is_some_and(|o| STRINGS.find_iter(&**o).any(|x| x.pattern() == m.pattern())) {
                continue;
            }
            out.push(hit(
                sev(&s.severity),
                "Content contains a known indicator",
                &s.campaign,
                &s.source,
                &blob.oid,
                &s.value,
            ));
        }
    }
}

fn hit(severity: Severity, what: &str, campaign: &str, source: &str, oid: &str, key: &str) -> Finding {
    Finding::new(Threat::Path, "sig.known-ioc", severity, format!("{what}: {campaign}"))
        .anchor(format!("{oid}:{key}"))
        .detail(format!("indicator: {key}"))
        .detail(format!("source: {source}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{added, modified, scan};

    #[test]
    fn signatures_load_and_match() {
        assert!(SIGS.payload_file.len() >= 2 && is_decoy_label("ESLint-Check"));
        let f = scan(&KnownIoc, &added(".github/workflows/shai-hulud-workflow.yml", b"on: push\n"));
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(scan(&KnownIoc, &added("pkg/setup_bun.js", b"x"))[0].severity, Severity::High);
        let body = b"curl https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7";
        assert_eq!(scan(&KnownIoc, &added("x.sh", body))[0].severity, Severity::Critical);
        assert!(scan(&KnownIoc, &modified("x.sh", body, &[body.as_slice(), b"\n"].concat())).is_empty());
        assert!(scan(&KnownIoc, &added("src/app.js", b"console.log(1)")).is_empty());
    }
}
