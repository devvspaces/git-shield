//! Optional GitHub lookups: a branch's push history (activity API), GitHub's
//! signature verification of commits (compare API) and pull-request merge
//! commits.
//!
//! Everything here degrades to "no data": callers get an `Err(String)` note to
//! show the user, never a panic, and the scan carries on offline.
//!
//! The token is only ever sent to the API base (`https://api.github.com`, or
//! `GIT_SHIELD_GITHUB_API` for GitHub Enterprise and tests), never to a host
//! taken from the repository.

pub mod cache;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const DEFAULT_API: &str = "https://api.github.com";
/// Default page budget (100 items per page) for the activity log and compare.
pub const MAX_PAGES: usize = 10;
/// Items per GraphQL request (aliases).
pub const GRAPHQL_CHUNK: usize = 100;
/// Requests in flight at once.
const PARALLEL: usize = 8;
const TIMEOUT: Duration = Duration::from_secs(10);
const GH_TIMEOUT: Duration = Duration::from_secs(5);

/// One push to a branch, as recorded by GitHub's activity log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Push {
    pub before: String,
    pub after: String,
    pub actor: String,
    /// Unix seconds.
    pub at: i64,
    /// `push`, `force_push`, `pr_merge`, `merge_queue_merge`, `branch_creation`, ...
    pub kind: String,
}

/// Kept for callers that only care about force-pushes.
pub type ForcePush = Push;

/// Events read from the activity log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActivityLog {
    /// Newest first.
    pub events: Vec<Push>,
    /// The page budget ran out while older events remained (and `since` was not reached).
    pub truncated: bool,
}

impl ActivityLog {
    /// Timestamp of the oldest event read.
    pub fn oldest(&self) -> Option<i64> {
        self.events.iter().map(|e| e.at).min()
    }
}

/// GitHub's view of one commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteCommit {
    pub sha: String,
    pub verified: bool,
    /// GitHub's verification reason: `valid`, `unsigned`, `invalid`, `unknown_key`, `bad_email`, ...
    pub reason: String,
    pub author_login: Option<String>,
    pub committer_login: Option<String>,
}

/// State of a pull request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PullState {
    Merged { merge_commit_sha: String },
    Open,
    ClosedUnmerged,
    NotFound,
}

pub struct Client {
    base: String,
    token: String,
    agent: ureq::Agent,
}

#[derive(Deserialize)]
struct Activity {
    before: String,
    after: String,
    timestamp: String,
    actor: Option<Actor>,
    #[serde(default)]
    activity_type: String,
}

#[derive(Deserialize)]
struct Compare {
    #[serde(default)]
    commits: Vec<CompareCommit>,
    #[serde(default)]
    total_commits: usize,
}

#[derive(Deserialize)]
struct CompareCommit {
    sha: String,
    commit: CompareInner,
    author: Option<Actor>,
    committer: Option<Actor>,
}

#[derive(Deserialize)]
struct CompareInner {
    verification: Option<Verification>,
}

#[derive(Deserialize)]
struct Verification {
    verified: bool,
    #[serde(default)]
    reason: String,
}

#[derive(Deserialize)]
struct Pull {
    #[serde(default)]
    state: String,
    #[serde(default)]
    merged: bool,
    merged_at: Option<String>,
    merge_commit_sha: Option<String>,
}

#[derive(Deserialize)]
struct Actor {
    login: String,
}

static API_OVERRIDE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Use `url` as the API base for clients built afterwards, unless
/// `GIT_SHIELD_GITHUB_API` is set (`git shield ci` passes `$GITHUB_API_URL`,
/// so GitHub Enterprise Server works inside Actions). The token is only ever
/// sent to this one base.
pub fn set_api_base(url: &str) {
    let url = url.trim().trim_end_matches('/');
    if url.starts_with("https://") {
        let _ = API_OVERRIDE.set(url.to_string());
    }
}

impl Client {
    /// Build a client from the environment: `GITHUB_TOKEN` / `GH_TOKEN`, else `gh auth token`.
    pub fn from_env() -> Result<Self, String> {
        let base = std::env::var("GIT_SHIELD_GITHUB_API")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| API_OVERRIDE.get().cloned())
            .unwrap_or_else(|| DEFAULT_API.into())
            .trim_end_matches('/')
            .to_string();
        let token = env_token().or_else(gh_token).ok_or_else(|| {
            "no GitHub token (set GITHUB_TOKEN or run `gh auth login`); skipped the force-push history check"
                .to_string()
        })?;
        Ok(Self::new(base, token))
    }

    pub fn new(base: String, token: String) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .http_status_as_error(false)
            .max_redirects(0)
            .build()
            .into();
        Client { base, token, agent }
    }

    fn get(&self, url: &str) -> Result<(String, Option<String>), String> {
        match self.get_status(url)? {
            (200, body, link) => Ok((body, link)),
            (status, body, _) => Err(http_error(status, &body)),
        }
    }

    /// Like [`Self::get`], but returns any HTTP status to the caller.
    fn get_status(&self, url: &str) -> Result<(u16, String, Option<String>), String> {
        if !url.strip_prefix(self.base.as_str()).is_some_and(|rest| rest.starts_with('/')) {
            return Err(format!("refusing to send the token to {url}"));
        }
        let resp = self
            .agent
            .get(url)
            .header("Authorization", &format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "git-shield")
            .call();
        Self::read(resp)
    }

    fn read(
        resp: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    ) -> Result<(u16, String, Option<String>), String> {
        let mut resp = resp.map_err(|e| format!("GitHub request failed: {e}"))?;
        let status = resp.status().as_u16();
        let link = resp.headers().get("link").and_then(|v| v.to_str().ok()).map(str::to_string);
        let body = resp.body_mut().read_to_string().map_err(|e| format!("GitHub response unreadable: {e}"))?;
        Ok((status, body, link))
    }

    /// GraphQL endpoint for this API base: `{base}/graphql`, or
    /// `https://host/api/graphql` for a GitHub Enterprise base `https://host/api/v3`.
    pub fn graphql_url(&self) -> String {
        match self.base.strip_suffix("/api/v3") {
            Some(host) => format!("{host}/api/graphql"),
            None => format!("{}/graphql", self.base),
        }
    }

    /// POST a GraphQL query; the token only ever goes to [`Self::graphql_url`].
    fn graphql(&self, query: &str, variables: serde_json::Value) -> Result<serde_json::Value, String> {
        let url = self.graphql_url();
        let body = serde_json::json!({ "query": query, "variables": variables }).to_string();
        let resp = self
            .agent
            .post(&url)
            .header("Authorization", &format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .header("User-Agent", "git-shield")
            .send(body.as_str());
        match Self::read(resp)? {
            (200, body, _) => {
                let v: serde_json::Value =
                    serde_json::from_str(&body).map_err(|e| format!("unexpected GitHub GraphQL response: {e}"))?;
                if v.get("data").is_none_or(|d| d.is_null()) {
                    let msg = v["errors"][0]["message"].as_str().unwrap_or("no data");
                    return Err(format!("GitHub GraphQL error: {msg}"));
                }
                Ok(v)
            }
            (status, body, _) => Err(http_error(status, &body)),
        }
    }

    /// States of many pull requests, [`GRAPHQL_CHUNK`] per request, in parallel.
    /// `Ok(None)`: the repository is not visible to the token.
    pub fn pulls_batch(
        &self,
        owner: &str,
        name: &str,
        numbers: &[u64],
    ) -> Result<Option<HashMap<u64, PullState>>, String> {
        let chunks: Vec<&[u64]> = numbers.chunks(GRAPHQL_CHUNK).collect();
        let mut out = HashMap::new();
        for r in parallel(&chunks, |chunk| {
            let fields: String = chunk
                .iter()
                .map(|n| format!("p{n}: pullRequest(number: {n}) {{ state mergeCommit {{ oid }} }} "))
                .collect();
            let q = format!("query($o: String!, $n: String!) {{ repository(owner: $o, name: $n) {{ {fields}}} }}");
            self.graphql(&q, serde_json::json!({ "o": owner, "n": name })).and_then(|v| parse_graphql_pulls(&v, chunk))
        }) {
            match r? {
                Some(m) => out.extend(m),
                None => return Ok(None),
            }
        }
        Ok(Some(out))
    }

    /// GitHub's verification of many commits by id, [`GRAPHQL_CHUNK`] per request.
    /// Ids GitHub does not know are left out. `Ok(None)`: the repository is not visible.
    pub fn commits_batch(&self, owner: &str, name: &str, shas: &[String]) -> Result<Option<Vec<RemoteCommit>>, String> {
        let shas: Vec<&String> =
            shas.iter().filter(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())).collect();
        let chunks: Vec<&[&String]> = shas.chunks(GRAPHQL_CHUNK).collect();
        let mut out = Vec::new();
        for r in parallel(&chunks, |chunk| {
            let fields: String = chunk
                .iter()
                .enumerate()
                .map(|(i, sha)| {
                    format!(
                        "c{i}: object(oid: \"{sha}\") {{ ... on Commit {{ oid signature {{ state }} \
                         author {{ user {{ login }} }} committer {{ user {{ login }} }} }} }} "
                    )
                })
                .collect();
            let q = format!("query($o: String!, $n: String!) {{ repository(owner: $o, name: $n) {{ {fields}}} }}");
            self.graphql(&q, serde_json::json!({ "o": owner, "n": name })).map(|v| parse_graphql_commits(&v))
        }) {
            match r? {
                Some(v) => out.extend(v),
                None => return Ok(None),
            }
        }
        Ok(Some(out))
    }

    /// One commit by id over REST (fallback when GraphQL is unavailable).
    /// `Ok(None)` when GitHub does not know it.
    pub fn commit(&self, owner: &str, name: &str, sha: &str) -> Result<Option<RemoteCommit>, String> {
        let url = format!("{}/repos/{owner}/{name}/commits/{}", self.base, encode(sha));
        match self.get_status(&url)? {
            (200, body, _) => {
                let c: CompareCommit =
                    serde_json::from_str(&body).map_err(|e| format!("unexpected GitHub commit response: {e}"))?;
                Ok(Some(remote_commit(c)))
            }
            (404 | 422, _, _) => Ok(None),
            (status, body, _) => Err(http_error(status, &body)),
        }
    }

    /// Login of the token's owner, or `None` for tokens without a user (an
    /// Actions `GITHUB_TOKEN` or another app installation token gets 403).
    pub fn viewer(&self) -> Result<Option<String>, String> {
        let body = match self.get_status(&format!("{}/user", self.base))? {
            (200, body, _) => body,
            (403, _, _) => return Ok(None),
            (status, body, _) => return Err(http_error(status, &body)),
        };
        let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        v["login"].as_str().map(|s| Some(s.to_string())).ok_or_else(|| "GitHub /user has no login".into())
    }

    /// Force-pushes to `branch`, newest first, reading at most `max_pages` pages.
    pub fn force_pushes(&self, owner: &str, name: &str, branch: &str, max_pages: usize) -> Result<ActivityLog, String> {
        let mut log = self.activity(owner, name, branch, Some("force_push"), None, max_pages, |_| false)?;
        log.events.retain(|p| p.kind.is_empty() || p.kind == "force_push");
        Ok(log)
    }

    /// Push-like events on `branch`, newest first. Paging stops at events
    /// older than `since` (unix seconds), when `stop` returns true for the
    /// events read so far, or after `max_pages` pages (then `truncated`).
    #[allow(clippy::too_many_arguments)]
    pub fn activity(
        &self,
        owner: &str,
        name: &str,
        branch: &str,
        kind: Option<&str>,
        since: Option<i64>,
        max_pages: usize,
        mut stop: impl FnMut(&[Push]) -> bool,
    ) -> Result<ActivityLog, String> {
        let filter = kind.map(|k| format!("&activity_type={}", encode(k))).unwrap_or_default();
        let mut url = Some(format!(
            "{}/repos/{owner}/{name}/activity?ref=refs%2Fheads%2F{}{filter}&per_page=100",
            self.base,
            encode(branch)
        ));
        let mut log = ActivityLog::default();
        for _ in 0..max_pages.max(1) {
            let Some(u) = url.take() else { break };
            let (body, link) = self.get(&u)?;
            let page = parse_activity(&body)?;
            let done = since.is_some_and(|s| page.iter().any(|p| p.at <= s));
            log.events.extend(page);
            if done || stop(&log.events) {
                return Ok(log);
            }
            url = link.as_deref().and_then(next_link);
        }
        log.truncated = url.is_some();
        Ok(log)
    }

    /// Commits in `base...head` as GitHub sees them, and the total GitHub
    /// reports. GitHub pages oldest first; when the range is longer than
    /// `max_pages` pages, the first page and then the newest pages are
    /// fetched, since the newest commits matter most. Pages after the first
    /// are fetched in parallel.
    pub fn compare(
        &self,
        owner: &str,
        name: &str,
        base: &str,
        head: &str,
        max_pages: usize,
    ) -> Result<(Vec<RemoteCommit>, usize), String> {
        let page = |n: &usize| -> Result<(Vec<RemoteCommit>, usize), String> {
            let url = format!(
                "{}/repos/{owner}/{name}/compare/{}...{}?per_page=100&page={n}",
                self.base,
                encode(base),
                encode(head)
            );
            parse_compare(&self.get(&url)?.0)
        };
        let (mut out, total) = page(&1)?;
        let pages = total.div_ceil(100);
        let max_pages = max_pages.max(1);
        let rest: Vec<usize> =
            if pages <= max_pages { (2..=pages).collect() } else { (pages + 2 - max_pages..=pages).collect() };
        for r in parallel(&rest, page) {
            out.extend(r?.0);
        }
        let total = total.max(out.len());
        Ok((out, total))
    }

    /// Can the token see this repository? (GitHub answers 404 for private
    /// repositories it cannot access, so a 404 elsewhere means nothing without this.)
    pub fn repo_visible(&self, owner: &str, name: &str) -> bool {
        matches!(self.get_status(&format!("{}/repos/{owner}/{name}", self.base)), Ok((200, _, _)))
    }

    /// State of pull request `number`.
    pub fn pull(&self, owner: &str, name: &str, number: u64) -> Result<PullState, String> {
        let url = format!("{}/repos/{owner}/{name}/pulls/{number}", self.base);
        match self.get_status(&url)? {
            (200, body, _) => parse_pull(&body),
            (404, _, _) => Ok(PullState::NotFound),
            (status, body, _) => Err(http_error(status, &body)),
        }
    }
}

/// Run `f` over `items`, at most [`PARALLEL`] at a time; results in order.
fn parallel<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let mut out = Vec::with_capacity(items.len());
    for group in items.chunks(PARALLEL) {
        std::thread::scope(|scope| {
            let handles: Vec<_> = group.iter().map(|it| scope.spawn(|| f(it))).collect();
            out.extend(handles.into_iter().map(|h| h.join().expect("GitHub request thread panicked")));
        });
    }
    out
}

/// PR states from a `pulls_batch` response. `None`: no such repository (or not visible).
pub fn parse_graphql_pulls(v: &serde_json::Value, numbers: &[u64]) -> Result<Option<HashMap<u64, PullState>>, String> {
    let repo = &v["data"]["repository"];
    if repo.is_null() {
        return Ok(None);
    }
    let mut out = HashMap::new();
    for &n in numbers {
        let pr = &repo[format!("p{n}")];
        let st = if pr.is_null() {
            PullState::NotFound
        } else {
            match pr["state"].as_str() {
                Some("MERGED") => match pr["mergeCommit"]["oid"].as_str() {
                    Some(oid) => PullState::Merged { merge_commit_sha: oid.to_string() },
                    None => continue,
                },
                Some("OPEN") => PullState::Open,
                Some("CLOSED") => PullState::ClosedUnmerged,
                _ => continue,
            }
        };
        out.insert(n, st);
    }
    Ok(Some(out))
}

/// Commits from a `commits_batch` response. `None`: no such repository.
pub fn parse_graphql_commits(v: &serde_json::Value) -> Option<Vec<RemoteCommit>> {
    let repo = v["data"]["repository"].as_object()?;
    let login = |c: &serde_json::Value, who: &str| c[who]["user"]["login"].as_str().map(str::to_string);
    Some(
        repo.values()
            .filter_map(|c| {
                let sha = c["oid"].as_str()?.to_string();
                // GraphQL states are the REST reasons in upper case; no signature is "unsigned".
                let reason = c["signature"]["state"].as_str().map_or("unsigned".to_string(), str::to_ascii_lowercase);
                Some(RemoteCommit {
                    sha,
                    verified: reason == "valid",
                    reason,
                    author_login: login(c, "author"),
                    committer_login: login(c, "committer"),
                })
            })
            .collect(),
    )
}

fn http_error(status: u16, body: &str) -> String {
    let msg = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["message"].as_str().map(str::to_string))
        .unwrap_or_default();
    format!("GitHub returned HTTP {status} {msg}").trim_end().to_string()
}

pub fn parse_activity(body: &str) -> Result<Vec<Push>, String> {
    let items: Vec<Activity> =
        serde_json::from_str(body).map_err(|e| format!("unexpected GitHub activity response: {e}"))?;
    Ok(items
        .into_iter()
        .filter_map(|a| {
            Some(Push {
                at: parse_time(&a.timestamp)?,
                actor: a.actor.map(|x| x.login).unwrap_or_default(),
                before: a.before,
                after: a.after,
                kind: a.activity_type,
            })
        })
        .collect())
}

pub fn parse_compare(body: &str) -> Result<(Vec<RemoteCommit>, usize), String> {
    let c: Compare = serde_json::from_str(body).map_err(|e| format!("unexpected GitHub compare response: {e}"))?;
    Ok((c.commits.into_iter().map(remote_commit).collect(), c.total_commits))
}

fn remote_commit(x: CompareCommit) -> RemoteCommit {
    let (verified, reason) = x.commit.verification.map_or((false, String::new()), |v| (v.verified, v.reason));
    RemoteCommit {
        sha: x.sha,
        verified,
        reason,
        author_login: x.author.map(|a| a.login),
        committer_login: x.committer.map(|a| a.login),
    }
}

pub fn parse_pull(body: &str) -> Result<PullState, String> {
    let p: Pull = serde_json::from_str(body).map_err(|e| format!("unexpected GitHub pull response: {e}"))?;
    Ok(if p.merged || p.merged_at.is_some() {
        match p.merge_commit_sha {
            Some(sha) => PullState::Merged { merge_commit_sha: sha },
            None => return Err("merged pull request without a merge_commit_sha".into()),
        }
    } else if p.state == "open" {
        PullState::Open
    } else {
        PullState::ClosedUnmerged
    })
}

/// The `rel="next"` URL of a `Link` header.
pub fn next_link(link: &str) -> Option<String> {
    link.split(',').find_map(|part| {
        let (url, rel) = part.split_once(';')?;
        rel.contains("rel=\"next\"").then(|| url.trim().trim_start_matches('<').trim_end_matches('>').to_string())
    })
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// `2026-11-12T11:19:26Z` → unix seconds.
pub fn parse_time(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-').map(|x| x.parse::<i64>());
    let (y, m, day) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let mut t = time.split('.').next()?.split(':').map(|x| x.parse::<i64>());
    let (hh, mm, ss) = (t.next()?.ok()?, t.next()?.ok()?, t.next()?.ok()?);
    // Days from civil (Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// `(owner, name)` for a GitHub remote URL; `None` for any other host.
pub fn repo_slug(url: &str) -> Option<(String, String)> {
    let url = url.trim();
    let path = if let Some(rest) = url.strip_prefix("git@github.com:") {
        rest
    } else {
        let rest = ["https://", "http://", "ssh://", "git://"].iter().find_map(|p| url.strip_prefix(p))?;
        let (host, path) = rest.split_once('/')?;
        let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
        let host = host.split_once(':').map_or(host, |(h, _)| h);
        if !host.eq_ignore_ascii_case("github.com") && !host.eq_ignore_ascii_case("www.github.com") {
            return None;
        }
        path
    };
    parse_slug(path.trim_end_matches('/'))
}

/// `owner/name` (optionally ending in `.git`).
pub fn parse_slug(s: &str) -> Option<(String, String)> {
    let (owner, name) = s.split_once('/')?;
    let name = name.strip_suffix(".git").unwrap_or(name);
    let ok = |x: &str| !x.is_empty() && x.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
    (ok(owner) && ok(name)).then(|| (owner.to_string(), name.to_string()))
}

fn env_token() -> Option<String> {
    ["GITHUB_TOKEN", "GH_TOKEN"].iter().find_map(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
}

/// `gh auth token`, run outside the repository with a minimal environment.
fn gh_token() -> Option<String> {
    let dir = tempfile::tempdir().ok()?;
    let mut cmd = Command::new("gh");
    cmd.args(["auth", "token", "--hostname", "github.com"])
        .current_dir(dir.path())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for k in ["PATH", "HOME", "XDG_CONFIG_HOME", "GH_CONFIG_DIR", "APPDATA", "USERPROFILE", "LOCALAPPDATA"] {
        if let Some(v) = std::env::var_os(k) {
            cmd.env(k, v);
        }
    }
    let mut child = cmd.spawn().ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait().ok()? {
            Some(status) if status.success() => break,
            Some(_) => return None,
            None if start.elapsed() > GH_TIMEOUT => {
                let _ = child.kill();
                return None;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    let mut s = String::new();
    child.stdout.take()?.read_to_string(&mut s).ok()?;
    let t = s.trim().to_string();
    (!t.is_empty()).then_some(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs() {
        let s = |o: &str, n: &str| Some((o.to_string(), n.to_string()));
        assert_eq!(repo_slug("git@github.com:MATADOR-TRUST/matador-legacy.git"), s("MATADOR-TRUST", "matador-legacy"));
        assert_eq!(repo_slug("https://github.com/o/r"), s("o", "r"));
        assert_eq!(repo_slug("https://user@github.com/o/r.git/"), s("o", "r"));
        assert_eq!(repo_slug("ssh://git@github.com:22/o/r.git"), s("o", "r"));
        assert_eq!(repo_slug("https://gitlab.com/o/r"), None);
        assert_eq!(repo_slug("https://github.com.evil.example/o/r"), None);
        assert_eq!(repo_slug("/tmp/remote.git"), None);
        assert_eq!(repo_slug("git@github-work:o/r.git"), None);
        assert_eq!(parse_slug("o/r/x"), None);
    }

    #[test]
    fn activity_and_links() {
        let body = r#"[{"id":1,"before":"aa","after":"bb","ref":"refs/heads/dev","timestamp":"2026-11-10T11:34:50Z",
            "activity_type":"force_push","actor":{"login":"mallory"}}]"#;
        let v = parse_activity(body).unwrap();
        assert_eq!(
            v,
            [Push {
                before: "aa".into(),
                after: "bb".into(),
                actor: "mallory".into(),
                at: 1_794_310_490,
                kind: "force_push".into()
            }]
        );
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_time("2000-03-01T00:00:00Z"), Some(951_868_800));
        let link = r#"<https://api.github.com/x?after=Y>; rel="next", <https://api.github.com/x?before=Z>; rel="prev""#;
        assert_eq!(next_link(link).as_deref(), Some("https://api.github.com/x?after=Y"));
        assert_eq!(next_link(r#"<https://a>; rel="prev""#), None);
        assert!(parse_activity("{\"message\":\"Not Found\"}").is_err());
    }

    #[test]
    fn compare_and_pulls() {
        let body = r#"{"total_commits":2,"commits":[
            {"sha":"aa","commit":{"verification":{"verified":true,"reason":"valid"}},"author":{"login":"al"},"committer":{"login":"web-flow"}},
            {"sha":"bb","commit":{"verification":{"verified":false,"reason":"unsigned"}},"author":null,"committer":null}]}"#;
        let (v, total) = parse_compare(body).unwrap();
        assert_eq!(total, 2);
        assert!(v[0].verified && v[0].committer_login.as_deref() == Some("web-flow"));
        assert_eq!((v[1].verified, v[1].reason.as_str(), v[1].author_login.as_deref()), (false, "unsigned", None));
        assert!(parse_compare("\"oops\"").is_err());

        let merged = r#"{"state":"closed","merged":true,"merged_at":"2026-11-10T00:00:00Z","merge_commit_sha":"cc"}"#;
        assert_eq!(parse_pull(merged).unwrap(), PullState::Merged { merge_commit_sha: "cc".into() });
        assert_eq!(parse_pull(r#"{"state":"open","merged":false,"merge_commit_sha":"dd"}"#).unwrap(), PullState::Open);
        assert_eq!(
            parse_pull(r#"{"state":"closed","merged":false,"merged_at":null,"merge_commit_sha":"dd"}"#).unwrap(),
            PullState::ClosedUnmerged
        );
    }

    #[test]
    fn graphql_batches() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"data":{"repository":{"p1":{"state":"MERGED","mergeCommit":{"oid":"aa"}},"p2":{"state":"OPEN","mergeCommit":null},
            "p3":{"state":"CLOSED","mergeCommit":null},"p4":null}},"errors":[{"type":"NOT_FOUND","path":["repository","p4"]}]}"#,
        )
        .unwrap();
        let m = parse_graphql_pulls(&v, &[1, 2, 3, 4]).unwrap().unwrap();
        assert_eq!(m[&1], PullState::Merged { merge_commit_sha: "aa".into() });
        assert_eq!((&m[&2], &m[&3], &m[&4]), (&PullState::Open, &PullState::ClosedUnmerged, &PullState::NotFound));
        let hidden: serde_json::Value = serde_json::from_str(r#"{"data":{"repository":null}}"#).unwrap();
        assert_eq!(parse_graphql_pulls(&hidden, &[1]).unwrap(), None);
        assert_eq!(parse_graphql_commits(&hidden), None);

        let v: serde_json::Value = serde_json::from_str(
            r#"{"data":{"repository":{"c0":{"oid":"aa","signature":{"state":"VALID"},"author":{"user":{"login":"al"}},"committer":{"user":null}},
            "c1":{"oid":"bb","signature":null,"author":{"user":null},"committer":{"user":null}},
            "c2":{"oid":"cc","signature":{"state":"MALFORMED_SIG"},"author":null,"committer":null},"c3":null}}}"#,
        )
        .unwrap();
        let mut c = parse_graphql_commits(&v).unwrap();
        c.sort_by(|a, b| a.sha.cmp(&b.sha));
        assert_eq!((c[0].verified, c[0].reason.as_str(), c[0].author_login.as_deref()), (true, "valid", Some("al")));
        assert_eq!((c[1].verified, c[1].reason.as_str()), (false, "unsigned"));
        assert_eq!(c[2].reason, "malformed_sig");
        assert_eq!(c.len(), 3);

        let c = Client::new("https://api.github.com".into(), "t".into());
        assert_eq!(c.graphql_url(), "https://api.github.com/graphql");
        let c = Client::new("https://ghe.example/api/v3".into(), "t".into());
        assert_eq!(c.graphql_url(), "https://ghe.example/api/graphql");
    }

    #[test]
    fn token_never_leaves_the_base() {
        let c = Client::new("http://127.0.0.1:1".into(), "t".into());
        assert!(c.get("https://evil.example/x").unwrap_err().contains("refusing"));
        assert!(c.get("http://127.0.0.1:12/x").unwrap_err().contains("refusing"));
    }
}
