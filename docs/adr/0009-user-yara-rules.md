# ADR 0009: User content rules in YARA, behind a default-on feature

- Status: accepted (2026-11-23). Part of Phase 6.

## Context
The built-in content rules cover the known techniques: auto-run tasks, fake fonts, agent hooks, lifecycle scripts and obfuscation. Teams also learn about new payloads from incident reports and from feeds that publish YARA rules. They need a way to add rules without a git-shield release.

YARA is the common language for this, and [yara-x](https://github.com/VirusTotal/yara-x) is VirusTotal's Rust implementation. It is heavy, though: a wasmtime/cranelift compiler, about 2.5 minutes of extra cold build time and about 10 MB of binary.

## Decision
- **Where rules live:** `~/.config/git-shield/rules/*.yar` (or `.yara`), next to `config.toml`, using the same resolution as ADR 0005. `$GIT_SHIELD_RULES` overrides the path.
  - Rules are never read from the scanned repository (ADR 0002). A repository that could ship rules could also ship a rule that matches nothing.
- **Compiling:** the rules are compiled once per run, at startup, and only for scanning commands. Any error stops the run with exit 3 and names the file and line:
  - a syntax error;
  - an unknown module;
  - a bad `severity` or `threat` metadata value.

  A rule that is silently off is worse than a stopped scan. `doctor` reports the rule count or the error instead of failing.
- **Metadata contract:**
  - `severity`: info, low, medium (the default), high or critical.
  - `threat`: T1–T13, or `YR`, a new `Threat::Custom`, which is the default.
  - `description`: the finding title.
- **Findings:**
  - One finding per matching rule and file version, with rule id `yara.<identifier>`.
  - The id is anchored on the blob, like the built-in content rules. So `--accept`, the trust store, and `[[allow]] rule = "yara.*"` work unchanged.
  - Details list up to 5 matched pattern names with their offsets. Matched bytes are not echoed.
- **Scope:** rules run on the incoming file versions, including transited ones, which are capped at Medium as usual. Size caps and LFS skipping are already applied upstream.
  - Each blob gets a 2 s timeout. A timeout or scan error is an Info finding, so it shows in `--verbose` and JSON without blocking.
- **Modules:** only the light ones: hash, math, string and time.
  - The PE, ELF, Mach-O and .NET parsers pull in a crypto stack and are about file formats that git-shield's own rules do not target. A rule that imports them fails to compile with a clear message.
- **Packaging:** cargo feature `yara`, on by default.
  - `--no-default-features` builds without yara-x (7.9 MB instead of 18.3 MB; a clean release build takes 36 s instead of 3 min).
  - Such a build notes rule files it cannot use, and `doctor` warns about them.
  - The GitHub Action (ADR 0008) builds without YARA, because a runner has no user rules directory.

## Consequences
- The cost on a 20-commit, ~30k-line delta is negligible. With 50 rules, the detectors take about 4.7 ms, the same as without rules, measured in `shield-bench`.
- Rule quality is the user's responsibility. A noisy rule is handled like any other: lower its `severity`, or allow it in `config.toml`.
- yara-x is pinned (`=1.23.0`). Upgrading it is a deliberate change, tested like any dependency bump.
