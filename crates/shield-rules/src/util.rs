use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

/// Interpreter invoked on a file whose extension is not a script.
pub(crate) static EXEC_ASSET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(node|nodejs|deno|bun|python[0-9.]*|py|bash|sh|zsh|ruby|perl|php|pwsh|powershell|osascript|wscript|cscript)(\.exe)?\b[^|;&]*?[\w./\\-]+\.(ttf|otf|woff2?|eot|svg|png|jpe?g|gif|ico|webp|bmp|css|scss|txt|md|json|lock|map|mp3|mp4|wav|pdf|csv|log|dat|bin)\b"#,
    )
    .unwrap()
});

/// Download-and-execute or encoded execution.
pub(crate) static REMOTE_EXEC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)((curl|wget|iwr|invoke-webrequest|invoke-restmethod|irm)\b[^\n]*\|\s*(sudo\s+)?(sh|bash|zsh|node|python[0-9.]*|iex|invoke-expression)\b)|(\b(base64\s+(-d|--decode)|frombase64string|atob\()|(-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,})|\beval\s*\()"#,
    )
    .unwrap()
});

/// Why a command line is dangerous on its own, if it is.
pub(crate) fn danger(cmd: &str) -> Option<&'static str> {
    if REMOTE_EXEC.is_match(cmd) {
        Some("downloads or decodes code to execute")
    } else if EXEC_ASSET.is_match(cmd) {
        Some("runs an interpreter on a non-script file (disguised payload)")
    } else {
        None
    }
}

/// A named thing in a config file that runs a command (a hook, a script, a server).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecEntry {
    /// Stable name within the file, e.g. `hooks.SessionStart[0]` or `scripts.postinstall`.
    pub key: String,
    pub command: String,
}

/// Entries of `new` that are absent from `old` or whose command changed.
pub(crate) fn changed_entries<'a>(old: &[ExecEntry], new: &'a [ExecEntry]) -> Vec<&'a ExecEntry> {
    new.iter().filter(|n| !old.iter().any(|o| o.key == n.key && o.command == n.command)).collect()
}

/// Lines of `new` (untrimmed) whose trimmed text does not occur in `old`; blank lines skipped.
pub(crate) fn added_lines<'a>(old: &str, new: &'a str) -> Vec<&'a str> {
    let seen: std::collections::HashSet<&str> = old.lines().map(str::trim).collect();
    new.lines().filter(|l| !l.trim().is_empty() && !seen.contains(l.trim())).collect()
}

/// Old and new text of a change (old is empty for additions).
pub(crate) fn texts(c: &shield_core::FileChange) -> Option<(String, String)> {
    let new = c.new.as_ref()?.text().into_owned();
    let old = c.old.as_ref().map(|o| o.text().into_owned()).unwrap_or_default();
    Some((old, new))
}

/// Repository-relative paths mentioned in a command line (`./x/y.js`, `public/a.ttf`).
pub(crate) fn refs_in(cmd: &str) -> Vec<String> {
    cmd.split(|c: char| c.is_whitespace() || "\"'`;|&()<>=,[]".contains(c))
        .filter(|t| {
            !t.is_empty()
                && !t.starts_with('-')
                && !t.starts_with('/')
                && !t.starts_with('~')
                && !t.starts_with('$')
                && !t.contains("://")
                && !t.contains('@')
                && t.rsplit('/').next().is_some_and(|name| name.contains('.') && !name.ends_with('.'))
                && (t.contains('/') || t.starts_with("."))
        })
        .map(|t| t.trim_start_matches("./").to_string())
        .filter(|t| !t.starts_with("..") && !t.is_empty())
        .collect()
}

/// Glob match with `*` (within a path segment), `**` (across segments) and `?`.
/// Case-sensitive; patterns without `/` match against the file name only.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let text = if pattern.contains('/') { text } else { text.rsplit('/').next().unwrap_or(text) };
    fn go(p: &[u8], t: &[u8]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some(b'*') if p.get(1) == Some(&b'*') => {
                let rest = p[2..].strip_prefix(b"/").unwrap_or(&p[2..]);
                (0..=t.len()).any(|i| (i == 0 || t[i - 1] == b'/') && go(rest, &t[i..])) || go(&p[2..], t)
            }
            Some(b'*') => (0..=t.len()).take_while(|&i| i == 0 || t[i - 1] != b'/').any(|i| go(&p[1..], &t[i..])),
            Some(b'?') => t.first().is_some_and(|&c| c != b'/') && go(&p[1..], &t[1..]),
            Some(&c) => t.first() == Some(&c) && go(&p[1..], &t[1..]),
        }
    }
    go(pattern.as_bytes(), text.as_bytes())
}

/// Parse JSON-with-comments (VS Code style). Returns `None` on failure.
pub fn parse_jsonc(text: &str) -> Option<Value> {
    jsonc_parser::parse_to_serde_value::<Value>(text, &jsonc_parser::ParseOptions::default()).ok()
}

/// Fraction of bytes in `sample` that are printable ASCII / common whitespace / UTF-8 continuation.
pub fn printable_ratio(sample: &[u8]) -> f64 {
    if sample.is_empty() {
        return 1.0;
    }
    let printable = sample.iter().filter(|&&b| matches!(b, b'\t' | b'\n' | b'\r' | 0x20..=0x7e) || b >= 0x80).count();
    printable as f64 / sample.len() as f64
}

pub fn is_lfs_pointer(bytes: &[u8]) -> bool {
    bytes.starts_with(b"version https://git-lfs.github.com/spec/v1")
}

/// Value as a string, accepting VS Code's `{ "value": "...", "quoting": ... }` form.
pub fn str_of(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => o.get("value").and_then(str_of),
        Value::Array(a) => Some(a.iter().filter_map(str_of).collect::<Vec<_>>().join(" ")),
        _ => None,
    }
}

/// Truncate a string for display.
pub fn clip(s: &str, max: usize) -> String {
    let s = s.replace('\n', "\\n");
    if s.chars().count() <= max { s } else { format!("{}…", s.chars().take(max).collect::<String>()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob_match("*.ttf", "public/fonts/a.ttf"));
        assert!(glob_match("public/fonts/fa-solid-*.ttf", "public/fonts/fa-solid-600.ttf"));
        assert!(!glob_match("public/*.ttf", "public/fonts/a.ttf"));
        assert!(glob_match("public/**/*.ttf", "public/fonts/a.ttf"));
        assert!(glob_match("**/.mcp.json", ".mcp.json"));
        assert!(glob_match("t4.*", "t4.mcp.server"));
        assert!(glob_match("a?c", "abc") && !glob_match("a?c", "a/c"));
    }

    #[test]
    fn refs_and_entries() {
        assert_eq!(refs_in("node ./public/fonts/x.ttf --flag"), ["public/fonts/x.ttf"]);
        assert_eq!(refs_in("bash .claude/hook.sh && curl https://x.example/a.sh"), [".claude/hook.sh"]);
        assert!(refs_in("npm run build").is_empty());
        let e = |k: &str, c: &str| ExecEntry { key: k.into(), command: c.into() };
        let old = [e("a", "x"), e("b", "y")];
        let new = [e("a", "x"), e("b", "z"), e("c", "w")];
        let ch: Vec<_> = changed_entries(&old, &new).iter().map(|x| x.key.as_str()).collect();
        assert_eq!(ch, ["b", "c"]);
        assert!(danger("curl -s https://x | bash").is_some());
        assert!(danger("node public/fonts/a.woff2").is_some());
        assert!(danger("npm ci").is_none());
    }
}
