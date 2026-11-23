//! Engine benchmarks on a synthetic delta: 20 commits, ~30k changed lines
//! across JS, Python, JSON and editor config, plus one CRLF-churn file. The
//! Phase 1 target is under 300 ms for `scan_range` on a developer machine.

use criterion::{Criterion, criterion_group, criterion_main};
use shield_fixtures as fx;
use shield_git::{GitRepo, ObjectId};
use std::hint::black_box;
use std::path::{Path, PathBuf};

struct Synthetic {
    _dir: tempfile::TempDir,
    repo: PathBuf,
    from: ObjectId,
    to: ObjectId,
}

fn module(lang: &str, seed: usize, lines: usize) -> String {
    let mut s = String::with_capacity(lines * 40);
    for i in 0..lines {
        match lang {
            "js" => s.push_str(&format!("export function f{seed}_{i}(x) {{ return x * {i} + {seed}; }}\n")),
            "py" => s.push_str(&format!("def f{seed}_{i}(x):\n    return x * {i} + {seed}\n")),
            _ => s.push_str(&format!("  \"key_{seed}_{i}\": {i},\n")),
        }
    }
    if lang == "json" { format!("{{\n{}  \"end\": 0\n}}\n", s) } else { s }
}

fn synthetic() -> Synthetic {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&repo).unwrap();
    let git = |args: &[&str]| fx::git(&repo, &home, args);
    git(&["init", "-q", "-b", "dev"]);
    fx::write(&repo, "README.md", "# bench\n");
    fx::write(&repo, "app/legacy.py", module("py", 0, 400));
    git(&["add", "-A"]);
    git(&["-c", "user.name=b", "-c", "user.email=b@example.com", "commit", "-q", "-m", "base"]);
    let from = git(&["rev-parse", "HEAD"]);
    for c in 0..20 {
        // 5 files per commit, ~300 lines each: ~30k lines in total.
        for k in 0..5 {
            let (lang, ext) = [("js", "js"), ("py", "py"), ("json", "json")][(c + k) % 3];
            fx::write(&repo, &format!("src/m{c}_{k}.{ext}"), module(lang, c * 10 + k, 300));
        }
        if c == 7 {
            fx::write(&repo, ".vscode/tasks.json", fx::tasks_json_payload());
        }
        if c == 13 {
            fx::write(&repo, "app/legacy.py", module("py", 0, 400).replace('\n', "\r\n"));
        }
        git(&["add", "-A"]);
        git(&["-c", "user.name=b", "-c", "user.email=b@example.com", "commit", "-q", "-m", &format!("change {c}")]);
    }
    let to = git(&["rev-parse", "HEAD"]);
    let oid = |s: &str| ObjectId::from_hex(s.as_bytes()).unwrap();
    Synthetic { from: oid(&from), to: oid(&to), repo, _dir: dir }
}

fn open(p: &Path) -> GitRepo {
    GitRepo::discover(p).unwrap()
}

fn benches(c: &mut Criterion) {
    let s = synthetic();
    let detectors = shield_rules::builtin();

    c.bench_function("scan_range", |b| {
        b.iter(|| {
            let repo = open(&s.repo);
            let ctx = repo.incoming(s.from, s.to, "bench").unwrap();
            black_box(shield_core::run(&detectors, &ctx))
        })
    });

    let ctx = open(&s.repo).incoming(s.from, s.to, "bench").unwrap();
    c.bench_function("delta_only", |b| b.iter(|| black_box(open(&s.repo).incoming(s.from, s.to, "bench").unwrap())));
    c.bench_function("detectors_only", |b| b.iter(|| black_box(shield_core::run(&detectors, &ctx))));

    #[cfg(feature = "yara")]
    {
        let sources: Vec<(String, String)> = (0..50)
            .map(|i| {
                (format!("r{i}.yar"), format!("rule r{i} {{ strings: $a = \"needle_{i}_x\" $b = /eval\\(atob\\([a-z]{{{}}}/ condition: $a or $b }}", i % 5 + 1))
            })
            .collect();
        let yara = shield_rules::yara::compile(&sources).unwrap();
        let with_yara = shield_rules::builtin_with(vec![Box::new(yara)]);
        c.bench_function("detectors_with_50_yara_rules", |b| b.iter(|| black_box(shield_core::run(&with_yara, &ctx))));
    }
}

criterion_group! {
    name = engine;
    config = Criterion::default().sample_size(20);
    targets = benches
}
criterion_main!(engine);
