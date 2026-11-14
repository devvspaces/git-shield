use serde_json::Value;

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
