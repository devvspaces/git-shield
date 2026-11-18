//! Optional GitHub lookups: the force-push history of a branch (activity API).
//!
//! Everything here degrades to "no data": callers get an `Err(String)` note to
//! show the user, never a panic, and the scan carries on offline.
//!
//! The token is only ever sent to the API base (`https://api.github.com`, or
//! `GIT_SHIELD_GITHUB_API` for GitHub Enterprise and tests), never to a host
//! taken from the repository.

use serde::Deserialize;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const DEFAULT_API: &str = "https://api.github.com";
/// Pages of 100 events fetched at most.
pub const MAX_PAGES: usize = 3;
const TIMEOUT: Duration = Duration::from_secs(10);
const GH_TIMEOUT: Duration = Duration::from_secs(5);

/// One force-push to a branch, as recorded by GitHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForcePush {
    pub before: String,
    pub after: String,
    pub actor: String,
    /// Unix seconds.
    pub at: i64,
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
}

#[derive(Deserialize)]
struct Actor {
    login: String,
}

impl Client {
    /// Build a client from the environment: `GITHUB_TOKEN` / `GH_TOKEN`, else `gh auth token`.
    pub fn from_env() -> Result<Self, String> {
        let base = std::env::var("GIT_SHIELD_GITHUB_API")
            .ok()
            .filter(|s| !s.is_empty())
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
        if !url.strip_prefix(self.base.as_str()).is_some_and(|rest| rest.starts_with('/')) {
            return Err(format!("refusing to send the token to {url}"));
        }
        let mut resp = self
            .agent
            .get(url)
            .header("Authorization", &format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "git-shield")
            .call()
            .map_err(|e| format!("GitHub request failed: {e}"))?;
        let status = resp.status().as_u16();
        let link = resp.headers().get("link").and_then(|v| v.to_str().ok()).map(str::to_string);
        let body = resp.body_mut().read_to_string().map_err(|e| format!("GitHub response unreadable: {e}"))?;
        if status != 200 {
            let msg = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v["message"].as_str().map(str::to_string))
                .unwrap_or_default();
            return Err(format!("GitHub returned HTTP {status} {msg}").trim_end().to_string());
        }
        Ok((body, link))
    }

    /// Login of the token's owner.
    pub fn viewer(&self) -> Result<String, String> {
        let (body, _) = self.get(&format!("{}/user", self.base))?;
        let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        v["login"].as_str().map(str::to_string).ok_or_else(|| "GitHub /user has no login".into())
    }

    /// Force-pushes to `branch`, newest first (at most [`MAX_PAGES`] pages).
    pub fn force_pushes(&self, owner: &str, name: &str, branch: &str) -> Result<Vec<ForcePush>, String> {
        let mut url = Some(format!(
            "{}/repos/{owner}/{name}/activity?ref=refs%2Fheads%2F{}&activity_type=force_push&per_page=100",
            self.base,
            encode(branch)
        ));
        let mut out = Vec::new();
        for _ in 0..MAX_PAGES {
            let Some(u) = url.take() else { break };
            let (body, link) = self.get(&u)?;
            out.extend(parse_activity(&body)?);
            url = link.as_deref().and_then(next_link);
        }
        Ok(out)
    }
}

pub fn parse_activity(body: &str) -> Result<Vec<ForcePush>, String> {
    let items: Vec<Activity> =
        serde_json::from_str(body).map_err(|e| format!("unexpected GitHub activity response: {e}"))?;
    Ok(items
        .into_iter()
        .filter_map(|a| {
            Some(ForcePush {
                at: parse_time(&a.timestamp)?,
                actor: a.actor.map(|x| x.login).unwrap_or_default(),
                before: a.before,
                after: a.after,
            })
        })
        .collect())
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
            [ForcePush { before: "aa".into(), after: "bb".into(), actor: "mallory".into(), at: 1_794_310_490 }]
        );
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_time("2000-03-01T00:00:00Z"), Some(951_868_800));
        let link = r#"<https://api.github.com/x?after=Y>; rel="next", <https://api.github.com/x?before=Z>; rel="prev""#;
        assert_eq!(next_link(link).as_deref(), Some("https://api.github.com/x?after=Y"));
        assert_eq!(next_link(r#"<https://a>; rel="prev""#), None);
        assert!(parse_activity("{\"message\":\"Not Found\"}").is_err());
    }

    #[test]
    fn token_never_leaves_the_base() {
        let c = Client::new("http://127.0.0.1:1".into(), "t".into());
        assert!(c.get("https://evil.example/x").unwrap_err().contains("refusing"));
        assert!(c.get("http://127.0.0.1:12/x").unwrap_err().contains("refusing"));
    }
}
