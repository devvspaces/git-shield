# Progress tracker

> **Read this first.** This file tracks where the work is. The design and phase scope are in [PLAN.md](PLAN.md), attack vectors are in [THREATS.md](THREATS.md), and decisions are in [adr/](adr/).
> Rule: every working session ends by updating **Current state** and adding a **Session log** entry, in the same commit as the code.

## Current state

| | |
|---|---|
| **Phase** | 3 done (v0.2 content) → 5 next: `clone` / `checkout` / `audit` / `install` / `doctor` (Phase 4 remainder optional) |
| **Last completed** | Session 4: Phase 3. T4/T5/T6/T9/T13 detectors, `signatures.toml`, user allowlist (ADR 0005), FP run (0 High/Critical on 10 repos). 97 tests green |
| **Next task** | Phase 5: `git shield clone` (scan full tree before checkout) and `audit` (repos that arrive as files), then `doctor` |
| **Blockers** | None |
| **Perf** | Warm, release build, matador-legacy: `scan af20233d8..d9351023d` (20 commits, 58 file versions) **~30 ms**; `scan HEAD..origin/dev` with provenance **~20–90 ms** (target < 300 ms); GitHub lookup adds **~1–2 s** of network |

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
- [x] `insta` snapshot tests for the terminal output (`crates/git-shield/tests/snapshots.rs`; SHAs/ids redacted)
- [x] Group repetitive findings (≥4 of one rule, all ≤ Medium) into one block in the terminal report (display only; ids unchanged)
- [x] Pushed to GitHub; CI green on macOS + Linux (run 43615839044)

### Phase 2: `git shield pull` gate (v0.1)
- [x] `pull` = preflight (stricter: checkout-time drivers) → fetch → scan → decide → integrate the **scanned SHA** (`--ff-only` default; `--rebase` / `--merge` opt-in; diverged without a flag → exit 3)
- [x] T10 `t10.ref-rewritten`: previous tips (pre-fetch value, reflog within window, trust store) not contained in the new tip; maximal only; own `git push` transitions ignored
- [x] T11 `t11.rewritten-copy` (Critical when the signature is dropped or the committer changed), `t11.merge-not-by-github`, `t11.unusual-timezone`, `t11.date-anomaly`
- [x] `t10.tampered-payload`: Critical correlation when a rewrite/impersonation carried a transited High+ payload (`Finding.capped_from`)
- [x] Trust store in the user data dir (ADR 0003): ref tips + accepted ids with reason; honoured by every command
- [x] Interactive confirm on TTY (dialoguer, default no; non-TTY → exit 2, never hangs)
- [x] Fixture: the matador incident blocks via T10/T11 even with the font removed (`matador_incident_with(IncidentOpts { font: false })`)
- [x] `scan --previous-tip <REV>` for forensics; replays the real 2026-11-10 incident offline
- [x] `git shield trust list [--json]` / `trust forget <ID>… | --all | --ref <REF>`
- [x] `t11.merge-not-by-github` grouped per committer; skips commits already reported as rewritten copies

### Phase 3: Deep content detectors (v0.2) ✅
- [x] T4 AI-agent configs (`agents.rs`) · T5 lifecycle scripts (`lifecycle.rs`) · T6 shell env (`shellenv.rs`) · T9 devcontainer/CI (`ci.rs`) · T13 obfuscation (`obfuscation.rs`) + `t13.payload-wired`
- [x] `signatures.toml` IOC list (sourced entries only)
- [x] User allowlist (ADR 0005); false-positive run over 10 popular repos: 0 High/Critical (`scripts/fp-run.sh`)

### Phase 4: GitHub provenance, optional (v0.3)
- [x] Activity API force-push history + actors, offline degradation, fake-API tests (session 3, ADR 0004)
- [ ] Commit `verification` status for incoming commits, pusher vs author, PR merge-SHA match (`Merge pull request #N` must equal PR N's merge commit), per-SHA cache

### Phase 5: clone / checkout / audit / install / doctor (v0.4)
- [ ] `clone`, `checkout`, `audit`, `install` (reference-transaction hook + alias), `doctor`, full signature verification

### Phase 6: yara-x rules, SARIF, GitHub Action, benchmarks (v0.5)
### Phase 7: cargo-dist releases, Homebrew, signed artifacts (v1.0)

## Known gaps / ideas (not yet scheduled)
- T12 multiset diff is an approximation (counts e.g. 12 vs git's 8 on `matador_admin/task.py`). Good enough for the ratio; swap in imara-diff if exact counts are needed.
- ~~Escalate a transited payload carried by forged history~~ Done in session 2 (`t10.tampered-payload`).
- ~~Reflog window without a trust record misses old rewrites~~ Closed for GitHub remotes in session 3 (ADR 0004). Non-GitHub remotes still rely on the reflog (30 days without a record) or `--previous-tip`.
- ~~`t11.merge-not-by-github` noise on long ranges~~ Grouped per committer in session 3.
- ~~No way to list/forget stored acceptances~~ `git shield trust` in session 3.
- The GitHub activity log is read up to 3 pages (300 force-pushes). Very busy branches without a trust record could miss older events.
- `scan --github` needs the range to end at a remote-tracking ref (it derives remote/branch from it).
- Content rules see added lines and changed entries per file version. A payload split across two files or two commits only correlates via `t13.payload-wired` (refs) or `t10.tampered-payload`.
- `t9.workflow.remote-exec` (Medium) fires on common `curl … | sh` installer steps in CI. It was 10 hits across the FP repos. Consider an allowlist of well-known installer hosts.
- The signature list is small on purpose. Grow it only with sourced entries.
- `read_local_state` reads `config` + `config.worktree` and skips includes. Consider reporting the include target path itself.
- Real-world note: VS Code's GitHub extension writes thousands of `github-pr-owner-number` values into `.git/config`. That once made the config read quadratic (fixed; keep a test in mind).

## Session log

### 2026-11-14: Session 1 (plan + Phase 0 + most of Phase 1)
- Researched attack vectors and existing tools. Wrote the phased plan (docs/PLAN.md); the user approved it with these decisions: subcommand + optional hooks; block-with-override; GitHub API in a later optional phase; tracking in docs/.
- Scaffolded the workspace: crates `git-shield`, `shield-core`, `shield-git`, `shield-rules`, `shield-report`, `shield-fixtures`.
- Implemented the Phase 1 engine, detectors, and CLI. Fixed a quadratic config read found on real data (2.2 s → 40 ms).
- Verified against matador-legacy `af20233d8..d9351023d`. It found the transited `eslint-check` folderOpen task and `allowAutomaticTasks` in forged commit `24f921bf2`, plus CRLF masking in 10 files (e.g. `agent/views.py` 19,521 raw lines → 71 real).
- Tests: 33 passing (24 detector unit, 1 engine, 8 CLI end-to-end). Clippy clean with `-D warnings`.

### 2026-11-16: Session 2 (Phase 1 close-out + Phase 2)
- Report: rules with 4 or more findings at Medium or below render as one block (matador's 10 CRLF files are now one block). Headers are pluralised. `insta` snapshots cover matador check, blocked pull, clean, and CRLF-only.
- `shield-core`: `Provenance`/`Rewrite`/`TipSource` in `ScanContext`; `Finding.capped_from`.
- `shield-git`:
  - `provenance.rs` reads reflogs via gix `log_iter`, finds maximal non-ancestor previous tips, collects lost commits (cap 500), learns committer timezone habits (2,000-commit walk), and records parent times.
  - `trust.rs` is the trust store (ADR 0003).
  - `hardened.rs` gains `merge` and `rebase`, and sets the editors to `:`.
- `shield-rules/provenance.rs`: `RefRewritten`, `Impersonation`, and `TamperedPayload` (runs last).
- CLI: `git shield pull [REMOTE] [BRANCH] [--rebase|--merge] [--reason]`. Stored acceptances apply to `scan`/`check`/`pull`. `scan --previous-tip`.
- **Real-data verification (read-only, matador-legacy):**
  - `scan d9d45eff3..0a32698f4 --previous-tip d9d45eff3` is now **BLOCKED**. It reports `t11.rewritten-copy` Critical on `24f921bf2` (signature dropped; committer `GitHub` → `Hycienth E.O`; tz +0100 → -0800), plus `t10.ref-rewritten` High and the `t10.tampered-payload` Critical correlation.
  - `scan HEAD..origin/dev` is CLEAN. The reflog's 2026-11-12 attacker tip `d539f2feb` is correctly ignored because the user's own restore push replaced it. The first prototype flagged it, which led to the own-push rule.
- Tests: 52 (31 rule unit, 1 engine, 1 trust store, 15 CLI end-to-end, 4 snapshots). Clippy clean with `-D warnings`.

### 2026-11-18: Session 3 (closing the Phase 2 gaps)
- `t11.merge-not-by-github` is now one finding per (committer, problem), listing the commits. Its anchor is the committer, so one accept covers one impersonator. Commits already reported by `t11.rewritten-copy` are skipped. The matador blocked report lost its duplicate Medium.
- `git shield trust list [--json]` and `trust forget <ID>… | --all | --ref <REF>` (`TrustStore::forget`, `forget_all`, `forget_ref`).
- New crate `shield-github` (ureq =3.5.0 with rustls; 3.5.2 was under two weeks old). It reads the activity API's force-push log for the branch (ADR 0004). Wired into `check`/`pull` (opt-out `--no-github`) and `scan --github`; `--github-repo OWNER/NAME`.
  - `TipSource::GitHub`. `Rewrite` has `missing` and `push: Option<ForcePushInfo>`. Rewrites already in HEAD are Medium ("already in your branch").
  - `t10.ref-rewritten` is anchored on `rewrite:<old tip>` (stable across pulls), names the pusher, and handles missing objects.
  - `shield_core::utc_date`/`utc_datetime` helpers.
- Fixtures: `fake_github()` (a std TcpListener HTTP stub that counts hits) and `force_push_json()`. Eight new CLI tests cover:
  - an old force-push revealed;
  - an own push ignored;
  - a rewrite already in the branch, which warns only;
  - an unknown tip;
  - HTTP 500 and an unreachable API;
  - `--no-github` and `scan` making zero requests;
  - events before the last pull not repeated.
- **Real data (read-only, matador-legacy, the user's gh token):**
  - `scan --github HEAD..origin/dev` reports 3 Medium "already in your branch" rewrites by the compromised accounts: @Fidel-wole 2026-10-28 (`7d12a98e3`); @Shobayosamuel 2026-11-04 (`a1c96d040`); @Shobayosamuel 2026-11-11, which dropped PR #2934's merge `fa59f748c`, later restored in `3442cdb52`. The user's own 11-12 restore push is ignored.
  - The offline scan is still CLEAN. The incident replay still BLOCKS, and the warn range still warns (now with fewer duplicate merge findings).
- Tests: 67 (32 rule unit, 2 core, 2 trust, 3 github, 24 CLI, 4 snapshots).

### 2026-11-18: Session 4 (Phase 3: deep content detectors)
- Shared helpers in `shield-rules/src/util.rs`:
  - `danger()`: the REMOTE_EXEC / EXEC_ASSET regexes, moved out of vscode.rs;
  - `ExecEntry` + `changed_entries` (diff-aware), `added_lines`, `texts`;
  - `refs_in` (repo files a command runs);
  - `glob_match`, which is public (used by the allowlist).

  `Finding.refs` is new.
- **T4 `agents.rs`** (`t4.*`):
  - commands Claude Code / Gemini / Codex run by themselves: hooks, statusLine, apiKeyHelper & co, tool commands, `notify`;
  - MCP servers (Medium, High when auto-approved or `trust: true`, Critical on payload markers);
  - `enableAllProjectMcpServers`, API/proxy env redirects, `bypassPermissions` / broad Bash allows;
  - instruction files with invisible Unicode or covert fetch-and-run lines; Cursor `alwaysApply`;
  - VS Code agent auto-approve settings (in vscode.rs).
- **T5 `lifecycle.rs`**: npm lifecycle scripts; setup.py / conftest / sitecustomize module-level exec or network; build backends; `.pth`; Makefile / husky / .githooks / pre-commit.
- **T6 `shellenv.rs`**: `.envrc` commands beyond env setup, `source_url`; mise hooks / `env._.source`.
- **T9 `ci.rs`** (yaml-rust2 0.13.0):
  - devcontainer lifecycle commands (`initializeCommand` runs on the host → High), third-party features;
  - workflows: `toJSON(secrets)` anywhere (Critical), encoded secrets, `pull_request_target` checkouts, self-hosted runners on issue/discussion triggers, script injection, fetch-and-run steps, new workflows.
- **T13 `obfuscation.rs`**: off-screen code after 150+ blanks, decode-then-execute, long lines, high-entropy literals. Minified, vendored, compiled and generated code is skipped. `t13.payload-wired` (Critical) links a runner to a flagged target.
- **Signatures** (`data/signatures.toml`): Shai-Hulud workflow path / webhook UUID, Sha1-Hulud 2.0 `setup_bun.js` / `bun_environment.js` / `SHA1HULUD`, and the matador decoy label, each with a source URL. Unsourced decoy labels were dropped.
- **Allowlist** (ADR 0005): user `config.toml`; Critical needs a pinned `blob`; `git shield config path|check`. JSON output gains `accepted`.
- **Engine fixes:**
  - only the generic `path.sensitive` note is dropped when a specific finding exists (it used to drop every Path-threat finding, including signature hits);
  - reflogs are read only for remote-tracking refs (local amends and rebases were reported as rewrites; found on matador's last 300 commits).
- **FP run** (`scripts/fp-run.sh`, shallow `--no-checkout` clones, last 300 commits each): **0 High/Critical** after one fix (next.js `src/compiled/` bundle → skipped).

  | repo | commits | ms | crit | high | med | low | info |
  |---|---:|---:|---:|---:|---:|---:|---:|
  | microsoft/vscode | 300 | 3114 | 0 | 0 | 0 | 12 | 46 |
  | facebook/react | 300 | 872 | 0 | 0 | 4 | 52 | 116 |
  | vercel/next.js | 300 | 847 | 0 | 0* | 5 | 62 | 396 |
  | django/django | 300 | 479 | 0 | 0 | 8 | 38 | 7 |
  | rust-lang/cargo | 1089 | 820 | 0 | 0 | 1 | 52 | 5 |
  | kubernetes/kubernetes | 885 | 3963 | 0 | 0 | 0 | 227 | 0 |
  | langchain-ai/langchain | 300 | 1606 | 0 | 0 | 0 | 20 | 150 |
  | supabase/supabase | 300 | 639 | 0 | 0 | 0 | 19 | 55 |
  | home-assistant/core | 300 | 750 | 0 | 0 | 0 | 1 | 37 |
  | anthropics/claude-code | 398 | 1277 | 0 | 0 | 0 | 34 | 7 |

  \* 1 High before the `compiled/` fix. The commit counts above 300 come from merges inside the range.
- **Real data (read-only, matador-legacy):**
  - `scan af20233d8..d9351023d` still warns;
  - the incident replay still BLOCKS;
  - `scan HEAD..origin/dev` is CLEAN (~150 ms);
  - `scan HEAD~300..HEAD` has 0 High/Critical. Its 39 Medium include transited incident traces (`.vscode/tasks.json` folderOpen, a `.ttf` that is source code).
- Tests: 97.
