//! T2: payloads disguised as binary assets (fake fonts/images).

use crate::util::{is_lfs_pointer, printable_ratio};
use aho_corasick::AhoCorasick;
use shield_core::{Detector, FileChange, Finding, Severity, Threat};
use std::sync::LazyLock;

const FONT_EXTS: &[&str] = &["ttf", "otf", "woff", "woff2", "eot", "ttc"];
const IMAGE_EXTS: &[&str] = &["png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "tif", "tiff", "avif"];
const MEDIA_EXTS: &[&str] = &["mp3", "mp4", "wav", "ogg", "webm", "mov", "pdf"];

const MARKERS: &[&str] = &[
    "require(",
    "import ",
    "function",
    "=>",
    "eval(",
    "process.",
    "Buffer.",
    "child_process",
    "exec(",
    "atob(",
    "fromCharCode",
    "module.exports",
    "const ",
    "let ",
    "var ",
    "new Function",
    "global[",
    "import os",
    "import base64",
    "__import__",
    "subprocess",
    "#!/",
    "powershell",
    "zlib",
];

static CODE_MARKERS: LazyLock<AhoCorasick> = LazyLock::new(|| AhoCorasick::new(MARKERS).unwrap());

fn expected_magic(ext: &str, b: &[u8]) -> Option<bool> {
    let m = |sig: &[u8]| b.starts_with(sig);
    Some(match ext {
        "ttf" => m(b"\x00\x01\x00\x00") || m(b"true") || m(b"OTTO") || m(b"typ1"),
        "otf" => m(b"OTTO") || m(b"\x00\x01\x00\x00"),
        "ttc" => m(b"ttcf"),
        "woff" => m(b"wOFF"),
        "woff2" => m(b"wOF2"),
        "eot" => b.len() > 36 && &b[34..36] == b"LP",
        "png" => m(b"\x89PNG\r\n\x1a\n"),
        "jpg" | "jpeg" => m(b"\xFF\xD8\xFF"),
        "gif" => m(b"GIF87a") || m(b"GIF89a"),
        "bmp" => m(b"BM"),
        "ico" => m(b"\x00\x00\x01\x00") || m(b"\x00\x00\x02\x00"),
        "webp" => b.len() > 12 && m(b"RIFF") && &b[8..12] == b"WEBP",
        "tif" | "tiff" => m(b"II*\x00") || m(b"MM\x00*"),
        "avif" => b.len() > 12 && &b[4..8] == b"ftyp",
        "pdf" => m(b"%PDF-"),
        "mp3" => m(b"ID3") || m(b"\xFF\xFB") || m(b"\xFF\xF3") || m(b"\xFF\xF2"),
        "mp4" | "mov" => b.len() > 12 && &b[4..8] == b"ftyp",
        "wav" => m(b"RIFF"),
        "ogg" => m(b"OggS"),
        "webm" => m(b"\x1A\x45\xDF\xA3"),
        _ => return None,
    })
}

pub struct DisguisedAsset;

impl Detector for DisguisedAsset {
    fn name(&self) -> &'static str {
        "disguised-asset"
    }

    fn interested(&self, c: &FileChange) -> bool {
        c.new.is_some()
            && c.extension_lower().is_some_and(|e| {
                let e = e.as_str();
                FONT_EXTS.contains(&e) || IMAGE_EXTS.contains(&e) || MEDIA_EXTS.contains(&e) || e == "svg"
            })
    }

    fn scan_file(&self, c: &FileChange, out: &mut Vec<Finding>) {
        let Some(blob) = &c.new else { return };
        let Some(ext) = c.extension_lower() else { return };
        let b: &[u8] = &blob.bytes;
        if b.is_empty() || is_lfs_pointer(b) {
            return;
        }

        if ext == "svg" {
            scan_svg(c, &blob.text(), &blob.oid, out);
            return;
        }

        if expected_magic(&ext, b) == Some(true) {
            return;
        }

        let sample = &b[..b.len().min(16 * 1024)];
        let text_like = printable_ratio(sample) > 0.97;
        let kind = if FONT_EXTS.contains(&ext.as_str()) {
            "font"
        } else if IMAGE_EXTS.contains(&ext.as_str()) {
            "image"
        } else {
            "media file"
        };

        if text_like {
            let markers: std::collections::BTreeSet<&str> =
                CODE_MARKERS.find_iter(sample).map(|m| MARKERS[m.pattern().as_usize()]).collect();
            let longest_line = sample.split(|&x| x == b'\n').map(<[u8]>::len).max().unwrap_or(0);
            if markers.len() >= 2 {
                out.push(
                    Finding::new(Threat::T2, "asset.code-disguised", Severity::Critical,
                        format!("`.{ext}` {kind} is actually source code"))
                        .anchor(blob.oid.clone())
                        .detail(format!("No valid .{ext} header; content is text with code markers: {}", markers.into_iter().collect::<Vec<_>>().join(", ")))
                        .detail(format!("size {} bytes, longest line {longest_line} chars", blob.size))
                        .detail("This is the fake-font technique used by DPRK 'Contagious Interview' campaigns: an auto-run task runs `node <font>`."),
                );
            } else {
                // Graded by evidence: one code marker is suspicious; plain text is
                // usually a placeholder (test fixtures, uploads), unless it is large
                // enough to carry an encoded payload. Anything a task or script
                // runs is escalated by `t13.payload-wired`.
                let sev = if markers.len() == 1 {
                    Severity::High
                } else if blob.size >= 1024 {
                    Severity::Medium
                } else {
                    Severity::Low
                };
                let mut f = Finding::new(
                    Threat::T2,
                    "asset.text-disguised",
                    sev,
                    format!("`.{ext}` {kind} contains text, not {kind} data"),
                )
                .anchor(blob.oid.clone())
                .detail(format!("No valid .{ext} header; {} bytes of mostly printable text", blob.size));
                if let Some(m) = markers.first() {
                    f = f.detail(format!("code marker: {m}"));
                }
                out.push(f);
            }
        } else if expected_magic(&ext, b) == Some(false) {
            let guessed = infer::get(b).map(|t| t.mime_type().to_string()).unwrap_or_else(|| "unknown".into());
            out.push(
                Finding::new(
                    Threat::T2,
                    "asset.wrong-format",
                    Severity::Medium,
                    format!("`.{ext}` file has the wrong binary format"),
                )
                .anchor(blob.oid.clone())
                .detail(format!("detected: {guessed}")),
            );
        }
    }
}

fn scan_svg(_c: &FileChange, text: &str, oid: &str, out: &mut Vec<Finding>) {
    let lower = text.to_ascii_lowercase();
    if !lower.contains("<svg") {
        out.push(
            Finding::new(Threat::T2, "asset.svg-not-svg", Severity::High, "`.svg` file does not contain SVG markup")
                .anchor(oid.to_string()),
        );
        return;
    }
    let script = lower.contains("<script") || lower.contains("javascript:") || on_handler(&lower);
    if script {
        out.push(
            Finding::new(Threat::T2, "asset.svg-script", Severity::Medium, "SVG contains script")
                .anchor(oid.to_string())
                .detail("Scripts in SVGs run when opened in a browser or previewed by some tools."),
        );
    }
}

fn on_handler(lower: &str) -> bool {
    ["onload=", "onerror=", "onclick=", "onmouseover=", "onbegin="].iter().any(|h| lower.contains(h))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{added, scan};

    #[test]
    fn js_in_font_is_critical() {
        let js =
            b"const _0x1=require('child_process');(function(){ eval(Buffer.from('aGk=','base64').toString()) })();";
        let f = scan(&DisguisedAsset, &added("public/fonts/fa-solid-600.ttf", js));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn real_fonts_and_images_are_clean() {
        assert!(scan(&DisguisedAsset, &added("a.woff2", b"wOF2\x00\x01\x00\x00rest")).is_empty());
        assert!(scan(&DisguisedAsset, &added("a.ttf", b"\x00\x01\x00\x00\x00\x10")).is_empty());
        assert!(scan(&DisguisedAsset, &added("a.png", b"\x89PNG\r\n\x1a\n....")).is_empty());
    }

    #[test]
    fn lfs_pointer_is_clean() {
        let p = b"version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 12\n";
        assert!(scan(&DisguisedAsset, &added("big.png", p)).is_empty());
    }

    #[test]
    fn text_in_image_is_graded_by_evidence() {
        let f = scan(&DisguisedAsset, &added("logo.png", b"fake-image-data"));
        assert_eq!(f[0].severity, Severity::Low, "small placeholder");
        let big = "lorem ipsum dolor sit amet ".repeat(60);
        assert_eq!(scan(&DisguisedAsset, &added("logo.png", big.as_bytes()))[0].severity, Severity::Medium);
        let one = format!("{big}\nrequire('x')");
        assert_eq!(scan(&DisguisedAsset, &added("logo.png", one.as_bytes()))[0].severity, Severity::High);
    }

    #[test]
    fn svg_with_script() {
        let f = scan(&DisguisedAsset, &added("i.svg", b"<svg onload=\"alert(1)\"></svg>"));
        assert_eq!(f[0].rule, "asset.svg-script");
    }
}
