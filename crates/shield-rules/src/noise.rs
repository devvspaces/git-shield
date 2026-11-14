//! T12: whitespace / line-ending churn that hides real changes in a huge diff.

use shield_core::{Detector, FileChange, FileStatus, Finding, Severity, Threat};
use std::collections::HashMap;

/// Ignore small files; noise only matters when the diff is large.
const MIN_RAW_LINES: usize = 50;

/// Lines in `new` not matched by a line in `old` (multiset difference), plus
/// the reverse: an O(n), allocation-free approximation of the diff size.
fn changed_lines(old: &str, new: &str, hash: fn(&str) -> u64) -> usize {
    let mut counts: HashMap<u64, i32> = HashMap::with_capacity(old.len() / 32 + 16);
    for l in old.split('\n') {
        *counts.entry(hash(l)).or_default() += 1;
    }
    for l in new.split('\n') {
        *counts.entry(hash(l)).or_default() -= 1;
    }
    counts.values().map(|v| v.unsigned_abs() as usize).sum()
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0100_0000_01b3;

/// Exact line bytes (a CRLF conversion changes every line).
fn raw(l: &str) -> u64 {
    l.bytes().fold(FNV_OFFSET, |h, b| (h ^ u64::from(b)).wrapping_mul(FNV_PRIME))
}

/// Line with all whitespace runs collapsed to one separator and trimmed.
fn normalized(l: &str) -> u64 {
    let mut h = FNV_OFFSET;
    for word in l.split_whitespace() {
        for b in word.bytes() {
            h = (h ^ u64::from(b)).wrapping_mul(FNV_PRIME);
        }
        h = (h ^ 0x20).wrapping_mul(FNV_PRIME);
    }
    h
}

fn crlf_ratio(text: &str) -> f64 {
    let lines = text.matches('\n').count();
    if lines == 0 {
        return 0.0;
    }
    text.matches("\r\n").count() as f64 / lines as f64
}

pub struct NoiseMasking;

impl Detector for NoiseMasking {
    fn name(&self) -> &'static str {
        "noise-masking"
    }

    fn interested(&self, c: &FileChange) -> bool {
        c.status == FileStatus::Modified && c.old.is_some() && c.new.is_some()
    }

    fn scan_file(&self, c: &FileChange, out: &mut Vec<Finding>) {
        let (Some(old), Some(new)) = (&c.old, &c.new) else { return };
        if crate::util::printable_ratio(&old.bytes[..old.bytes.len().min(8192)]) < 0.9 {
            return; // binary
        }
        let (ot, nt) = (old.text(), new.text());
        // Lines split on '\n' only, so a CRLF conversion shows up as every line changing.
        let raw_n = changed_lines(&ot, &nt, raw);
        if raw_n < MIN_RAW_LINES {
            return;
        }
        let real_n = changed_lines(&ot, &nt, normalized);
        // Need at least 80% of the raw diff to be noise.
        if real_n * 5 > raw_n {
            return;
        }
        let (oc, nc) = (crlf_ratio(&ot), crlf_ratio(&nt));
        let eol = if oc < 0.1 && nc > 0.9 {
            Some("LF → CRLF")
        } else if oc > 0.9 && nc < 0.1 {
            Some("CRLF → LF")
        } else {
            None
        };

        let (sev, title) = match (real_n, eol) {
            (0, _) => (Severity::Info, "Whitespace / line-ending only change".to_string()),
            (_, Some(_)) => (Severity::Medium, format!("Line-ending rewrite hides {real_n} real changed lines")),
            (_, None) => (Severity::Low, format!("Whitespace churn hides {real_n} real changed lines")),
        };
        let mut f = Finding::new(Threat::T12, "noise.whitespace-masking", sev, title)
            .anchor(format!("{}..{}", old.oid, new.oid))
            .detail(format!("raw diff ≈ {raw_n} lines, ignoring whitespace ≈ {real_n} lines"));
        if let Some(e) = eol {
            f = f.detail(format!("line endings converted {e}"));
        }
        if real_n > 0 {
            f = f.detail("Review the real change with: git diff --ignore-cr-at-eol -w <range> -- <path>");
        }
        out.push(f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{modified, scan};

    fn body(n: usize) -> String {
        (0..n).map(|i| format!("line number {i} = value({i})\n")).collect()
    }

    #[test]
    fn crlf_only_is_info() {
        let old = body(200);
        let new = old.replace('\n', "\r\n");
        let f = scan(&NoiseMasking, &modified("a.py", old.as_bytes(), new.as_bytes()));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Info);
    }

    #[test]
    fn crlf_masking_real_change_is_medium() {
        let old = body(200);
        let new = old.replace("line number 7 =", "line number 7 = evil() ;").replace('\n', "\r\n");
        let f = scan(&NoiseMasking, &modified("a.py", old.as_bytes(), new.as_bytes()));
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].details[0].contains("ignoring whitespace ≈ 2"), "{:?}", f[0].details);
    }

    #[test]
    fn normal_edit_is_clean() {
        let old = body(200);
        let new = old.replace("line number 7 =", "line number 7 = x");
        assert!(scan(&NoiseMasking, &modified("a.py", old.as_bytes(), new.as_bytes())).is_empty());
    }
}
