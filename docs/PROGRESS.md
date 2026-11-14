# Progress tracker

> **Read this first.** This file tracks where the work is. The design and phase scope are in [PLAN.md](PLAN.md), attack vectors are in [THREATS.md](THREATS.md), and decisions are in [adr/](adr/).
> Rule: every working session ends by updating **Current state** and adding a **Session log** entry, in the same commit as the code.

## Current state

| | |
|---|---|
| **Phase** | 1: Read-only engine and `scan` / `check` (mostly done) |
| **Last completed** | Engine, gix delta, T1/T2/T3/T7/T8/T12/path detectors, `scan` + `check`, fixture harness, 33 tests green |
| **Next task** | Finish Phase 1: `insta` snapshot tests of the terminal report; group repeated T12 findings into one summary finding. Then Phase 2 (`pull` + T10/T11 + trust store). |
| **Blockers** | None |
| **Perf** | `scan af20233d8..d9351023d` on matador-legacy (20 commits, 58 file versions): **~40 ms** warm (target < 300 ms) |

## Phase checklist

### Phase 0: Bootstrap and tracking ✅
- [x] Repo `~/projects/git-shield`, branch `master`, remote `git@github.com:devvspaces/git-shield.git`
- [x] Cargo workspace (edition 2024), MIT OR Apache-2.0, `rust-toolchain.toml`, `rustfmt.toml`
- [x] CI workflow (fmt, clippy -D warnings, test; macOS + Linux)
- [x] docs: PLAN, PROGRESS, THREATS, ADR 0001/0002, AGENTS.md, CLAUDE.md, README
- [x] Fixture harness `crates/shield-fixtures`: `matador_incident`, `clean_fast_forward`, `crlf_only`; inert payloads + PWNED marker assertions

### Phase 1: Read-only engine, `scan` / `check` (v0.1-alpha)
- [x] `shield-core`: Finding / Severity / Threat / stable FindingId, Detector trait, rayon engine, transited cap at Medium, report exit codes
- [x] `shield-git`: isolated gix open, rev resolve, upstream from config, merge-base, commit range, plain tree diff, per-commit transited detection, blob reads with caps, local config + hooks reader (no includes followed)
- [x] `shield-git::hardened`: git runner with execution points neutralised; `fetch`, `merge_ff_only`
- [x] Detectors: T1 tasks, T3 settings, T2 disguised assets, T7 local config/hooks, T8 attributes/submodules, T12 noise masking, path risk + symlink/exec-bit
- [x] CLI: `git shield scan [RANGE]`, `git shield check [REMOTE] [BRANCH]` (`--json`, `--verbose`, `--accept`, `--no-fetch`, `--allow-unsafe-config`, `-C`)
- [x] Preflight refuses to spawn git on Critical local config (GitSpawn)
- [x] Integration tests (8) incl. "fsmonitor never fires even with --allow-unsafe-config"
- [x] Verified on the real matador-legacy incident range
- [ ] `insta` snapshot tests for the terminal output
- [ ] Group T12 findings (10 files → one summary + per-file details) to reduce noise
- [x] Pushed to GitHub; CI green on macOS + Linux (run 43615839044)

### Phase 2: `git shield pull` gate (v0.1)
- [ ] `pull` = preflight → fetch → scan → decide → `merge --ff-only` (`--rebase` / `--merge` opt-in)
- [ ] T10: non-fast-forward / remote ref rewrote a previously seen tip (remote-tracking reflog + trust store)
- [ ] T11: duplicate-subject commits with a different SHA, signature dropped, "Merge pull request" not committed by GitHub, tz/date anomalies
- [ ] Trust store `.git/shield/trusted.json` (last accepted tip per ref, accepted ids + reason)
- [ ] Interactive confirm on TTY
- [ ] Fixture: the matador incident must block via T10/T11 even with the font removed

### Phase 3: Deep content detectors (v0.2)
- [ ] T4 AI-agent configs · T5 lifecycle scripts · T6 shell env · T9 devcontainer/CI · T13 obfuscation
- [ ] `signatures.toml` IOC list
- [ ] User allowlist; false-positive run over 10 popular repos (0 High)

### Phase 4: GitHub provenance, optional (v0.3)
- [ ] Activity API force-push actors, commit verification, PR merge SHA match, offline degradation, recorded-response tests

### Phase 5: clone / checkout / audit / install / doctor (v0.4)
- [ ] `clone`, `checkout`, `audit`, `install` (reference-transaction hook + alias), `doctor`, full signature verification

### Phase 6: yara-x rules, SARIF, GitHub Action, benchmarks (v0.5)
### Phase 7: cargo-dist releases, Homebrew, signed artifacts (v1.0)

## Known gaps / ideas (not yet scheduled)
- T12 multiset diff is an approximation (counts e.g. 12 vs git's 8 on `matador_admin/task.py`). Good enough for the ratio; swap in imara-diff if exact counts are needed.
- A transited payload is capped at Medium. Once T10/T11 exist, a forged commit carrying a transited payload should escalate (e.g. Critical "tampered history carried a payload").
- `read_local_state` reads `config` + `config.worktree` and skips includes. Consider reporting the include target path itself.
- Real-world note: VS Code's GitHub extension writes thousands of `github-pr-owner-number` values into `.git/config`. That once made the config read quadratic (fixed; keep a test in mind).

## Session log

### 2026-11-14: Session 1 (plan + Phase 0 + most of Phase 1)
- Researched attack vectors and existing tools. Wrote the phased plan (docs/PLAN.md); the user approved it with these decisions: subcommand + optional hooks; block-with-override; GitHub API in a later optional phase; tracking in docs/.
- Scaffolded the workspace: crates `git-shield`, `shield-core`, `shield-git`, `shield-rules`, `shield-report`, `shield-fixtures`.
- Implemented the Phase 1 engine, detectors, and CLI. Fixed a quadratic config read found on real data (2.2 s → 40 ms).
- Verified against matador-legacy `af20233d8..d9351023d`. It found the transited `eslint-check` folderOpen task and `allowAutomaticTasks` in forged commit `24f921bf2`, plus CRLF masking in 10 files (e.g. `agent/views.py` 19,521 raw lines → 71 real).
- Tests: 33 passing (24 detector unit, 1 engine, 8 CLI end-to-end). Clippy clean with `-D warnings`.
