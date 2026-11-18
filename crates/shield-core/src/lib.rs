//! Core data model and scan engine for git-shield.
//!
//! The engine is deliberately ignorant of git: `shield-git` turns a repository
//! delta into a [`ScanContext`], detectors in `shield-rules` turn that into
//! [`Finding`]s, and `shield-report` renders them.

mod context;
mod engine;
mod finding;

pub use context::{
    BlobData, CommitInfo, ConfigEntry, FileChange, FileStatus, ForcePushInfo, HookFile, LocalRepoState, Provenance,
    Rewrite, ScanContext, TipSource,
};
pub use engine::{Detector, Report, run};
pub use finding::{Finding, FindingId, Severity, Threat};

/// `YYYY-MM-DD HH:MM UTC` from unix seconds (no date crate needed for display).
pub fn utc_datetime(secs: i64) -> String {
    let (y, m, d) = civil(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", t / 3600, (t % 3600) / 60)
}

/// `YYYY-MM-DD` (UTC) from unix seconds.
pub fn utc_date(secs: i64) -> String {
    let (y, m, d) = civil(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod date_tests {
    #[test]
    fn dates() {
        assert_eq!(super::utc_date(0), "1970-01-01");
        assert_eq!(super::utc_datetime(1_794_310_490), "2026-11-10 11:34 UTC");
    }
}
