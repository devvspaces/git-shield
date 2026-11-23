# Progress tracker

> **Read this first.** This file tracks where the work is. The design and phase scope are in [PLAN.md](PLAN.md), attack vectors are in [THREATS.md](THREATS.md), and decisions are in [adr/](adr/).
> Rule: every working session ends by updating **Current state** and adding a **Session log** entry, in the same commit as the code.

## Current state

| | |
|---|---|
| **Phase** | 0–6 done (v0.5.0 tagged) → next: Phase 7 (cargo-dist releases, Homebrew, signed artifacts) |
| **Last completed** | Session 9: closed the known gaps: config includes followed, offline web-flow cache, parallel diff walk and audit, exact T12 counts, installer allowlist, `clone --recurse-submodules` (ADR 0010), tighter interpreter-on-asset check. 167 tests green |
| **Next task** | Phase 7, when the user asks |
| **Blockers** | None |
| **Perf** | Warm, release build, matador-legacy: `scan af20233d8..d9351023d` (20 commits, 58 file versions) **~30 ms**; `scan HEAD..origin/dev` with provenance **~20–90 ms** (target < 300 ms); GitHub lookup adds **~1–2 s** of network; local signature checks ~3 ms per signed commit (parallel), web-flow verdicts cached; forensic `scan --github` of 1,110 commits **cold ~8 s, warm ~4 s** with full coverage; offline `scan HEAD~300..HEAD` (1,113 commits) **1.2 s warm** (was 3.2 s), **0.75 s** with `--no-verify-signatures` (was 1.5 s); `audit` of 3,100 files 0.19 s warm. `shield-bench` (synthetic 20 commits, ~30k lines): `scan_range` **11.2 ms**, delta 6.7 ms (was 10.4), detectors 4.1 ms, with 50 YARA rules 4.2 ms. Release binary 18.3 MB (7.9 MB without `yara`); clean release build 3 min (36 s without) |

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
- [x] Commit `verification` status (compare API), PR merge-SHA match (`t11.pr-merge-mismatch`), pusher attribution, per-repo cache of immutable facts (session 6, ADR 0007)
- [x] Local GPG/SSH verification; bundled GitHub web-flow keys; `t11.signature-bad`, `t11.github-unverified`, `t11.signature-unverified`, `[[signing]] require` (`t11.unsigned-required`)

### Phase 5: clone / checkout / audit / install / doctor (v0.4)
- [x] `audit [path] [--rev REV]`: files on disk + .git/config/hooks; no symlink following; deps/build dirs skipped
- [x] `clone <url> [dir]`: no-checkout clone → whole-tree scan → `reset --hard <sha>` only if clean/accepted; trust tip recorded
- [x] `checkout <target>`: stricter preflight, HEAD→target tree scan, DWIM remote branches, post-switch HEAD check
- [x] `doctor`: git / VS Code-family / Claude Code user settings, read-only
- [x] `install` / `uninstall`: shell function for `git pull` (ADR 0006; the reference-transaction hook was tested and rejected)
- [x] Full GPG/SSH signature verification: done in the Phase 4 remainder (session 6)

### Phase 6: yara-x rules, SARIF, GitHub Action, benchmarks (v0.5) ✅
- [x] SARIF 2.1.0 (`--sarif FILE` on every scanning command): security-severity, stable fingerprints, accepted → suppressions, placeholder location for commit findings
- [x] `git shield ci`: ranges from push / pull_request events, forced push → previous tip, missing objects fetched by SHA, `--fail-on`, escaped annotations, job summary, `--accept-file` / `--accepts-path` (trusted side only) (ADR 0008)
- [x] `action.yml` (composite, built from the action's source, SHA-pinned actions) + dogfood workflow; verified on this repository (push and a throwaway PR)
- [x] User YARA rules via yara-x 1.23, feature `yara` on by default; metadata contract; hard error on bad rules; `doctor` status (ADR 0009)
- [x] `crates/shield-bench` (criterion) + `scripts/bench-real.sh`; CI builds the benches and runs a `--no-default-features` job
### Phase 7: cargo-dist releases, Homebrew, signed artifacts (v1.0)

## Known gaps / ideas (not yet scheduled)
- ~~T12 multiset diff is an approximation~~ Session 9: the reported count is a Myers diff with `git diff -w` semantics (imara-diff). It matches git on 114 of 117 real files, and on the rest is within 2–4 lines (git's Myers heuristics). `task.py` says 8, as git does.
- ~~Escalate a transited payload carried by forged history~~ Done in session 2 (`t10.tampered-payload`).
- ~~Reflog window without a trust record misses old rewrites~~ Closed for GitHub remotes in session 3 (ADR 0004). Non-GitHub remotes still rely on the reflog (30 days without a record) or `--previous-tip`. A GitLab or Gitea push-event API would be a future phase.
- ~~`t11.merge-not-by-github` noise on long ranges~~ Grouped per committer in session 3.
- ~~No way to list/forget stored acceptances~~ `git shield trust` in session 3.
- ~~Activity log read to 3 pages~~ Session 7: 10 pages by default, 50 with `scan --deep`, stopping at the trust record or the range base; a note names the date reached when the budget runs out.
- ~~`scan --github` off a remote-tracking ref skips the force-push log and pushers~~ Session 7: `--github-branch`, else a remote branch whose tip is the range end, else the default branch if it contains it. Feature branches are never guessed (their creation would claim every commit).
- ~~GitHub checks cover 300 commits / 100 PRs~~ Session 7: GraphQL batches (100 per request). Defaults: 2000 signed commits, 1000 PRs; `--deep`: 5000 each. REST fallback (100) when GraphQL is unavailable.
- ~~`clone`/`checkout` do not verify signatures~~ Session 7: they run the signature and PR rules over the history they bring in (clone: newest 50,000 commits; `require` is not applied to existing history).
- ~~Offline scans don't cache local signature verdicts~~ Session 9: per-repository cache `git-shield/local/<hash>.json`. Every final gpgv verdict against the bundled keyring is cached (good, bad, no key, expired, revoked).
- The action builds git-shield from source (~1 min cold, cached later). Phase 7 ships binaries. It builds without YARA: a runner has no user rules directory.
- Commit-level findings use the placeholder path `.git-shield/commits/<sha>` in SARIF. This is inherent: code scanning requires a physical location (verified on a live upload).
- Warm forensic scans with `--github` spend most of their time on the network: the activity log, and open or unknown PR states, which can change and so are not cached. The offline part is now ~0.75 s for 1,110 commits (was 1.3 s).
- The matador-legacy real-data run found five more forged "Merge pull request" commits still in `dev`. Details went to the user only; nothing was changed in that repo.
- Content rules see added lines and changed entries per file version. A payload split across two files or two commits only correlates via `t13.payload-wired` (refs) or `t10.tampered-payload`. More correlation is research, not scheduled.
- ~~`t9.workflow.remote-exec` noise on installer steps~~ Session 9: sourced installer allowlist (`data/installers.toml`); such steps are Low. The FP rerun (9 of the 10 repos; the claude-code shallow clone is missing an object) had no installer steps in its 300-commit windows. What it did surface is the "interpreter on a non-script file" check matching `python -m pip install -r requirements.txt`, `node -p "require('…/package.json')"` and prose in AGENTS.md. That check now requires the file to be the script argument. Result: Medium 13 → 1 across the repos, 0 High/Critical; a few of those files fall back to `path.sensitive` Low.
- The signature list is small on purpose. Grow it only with sourced entries.
- The `install` shell function only covers interactive shells. IDE pull buttons and scripts bypass it; the CI action (ADR 0008) covers those pushes on GitHub.
- ~~`audit` slow on large trees~~ Session 9: files are read in parallel after the walk; matador-legacy's 3,100 files take 0.19 s warm (1.0 s cold). Untracked `media/` test placeholders are Low (graded asset rule).
- ~~`clone` does not fetch submodules~~ Session 9: `clone --recurse-submodules` (ADR 0010). `pull` does not follow submodule pointer changes into the submodules yet.
- ~~`read_local_state` skips includes~~ Session 9: `include.path` and `includeIf.*.path` are followed (read only, with limits; ADR 0002 addendum). Settings found there refuse git in the preflight like any other.
- Real-world note: VS Code's GitHub extension writes thousands of `github-pr-owner-number` values into `.git/config`. That once made the config read quadratic. Fixed, and since session 9 covered by a regression test (10,000 values in under 2 s).

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

### 2026-11-18: Session 5 (Phase 5)
- `shield-git`:
  - `GitRepo::tree_scan` (whole tree as additions) and `tree_delta` (plain tree diff, no merge base);
  - `disk::scan_dir`: files on disk with git blob ids, symlinks recorded and not followed, `SKIP_DIRS`, `MAX_FILES`;
  - hardened `clone_no_checkout`, `reset_hard`, `checkout`;
  - `remote_names`.
- CLI:
  - `audit`, `clone`, `checkout`, `doctor`, `install`/`uninstall`;
  - shared `gate()` for block / prompt / accept, used by pull/clone/checkout;
  - `accepted()` works without a repo or store (plain folders);
  - `pull` accepts `--ff-only` and `--no-rebase` as no-ops.
- `asset.text-disguised` is graded:
  - one code marker → High;
  - plain text ≥ 1 KiB → Medium;
  - smaller → Low (it was always High).

  Found by auditing matador-legacy's untracked `media/` test uploads ("fake-image-data").
- **ADR 0006:** a scratch-repo test showed `merge --ff-only` and `reset --hard` write files before a rejecting `reference-transaction` hook runs. The hook plan was dropped for a shell function.
- **Real data (read-only):**
  - `audit` on matador-legacy gives 0 High after grading. It reports 2 Medium `t4.claude.permissions` for the local `.claude/settings.local.json` (`Bash(python:*)`).
  - `doctor` on this machine: WARN `safe.bareRepository`, info `transfer.fsckObjects`; nothing changed.
- Tests: 106.

### 2026-11-20: Session 6 (Phase 4 remainder)
- `shield-github`:
  - `compare` (per-commit `verification`; first page + newest pages), `pull` (`Merged{sha}` / `Open` / `ClosedUnmerged` / `NotFound`), `activity` (all push kinds), `repo_visible`;
  - `cache` (final verifications, merged PRs, compared ranges).
- `shield-git::signing`:
  - signature + payload via gix;
  - `gpgv` against bundled web-flow keys (empty GNUPGHOME), `gpg` against the user's keyring, `ssh-keygen -Y verify` / `check-novalidate`;
  - scrubbed env, temp cwd, timeout, parallel-safe;
  - `GitRepo::commit_ids` for push attribution.
- `shield-core`: `ScanContext.attest` (`Attestations`: local checks, GitHub verification, PR states, pushers, require flag).
- `shield-rules::signing`: `t11.pr-merge-mismatch`, `t11.signature-bad`, `t11.github-unverified`, `t11.signature-unverified`, `t11.unsigned-required`, `PushAttribution`. `github_merges` skips commits GitHub already answered for.
- CLI:
  - `--no-verify-signatures`;
  - `[[signing]] repo / allowed_signers / require` in the user config;
  - `scan --github` works on any range.
- **Safety fix found by tests:** GitHub answers 404 for repositories the token cannot see. PR 404s only count once the repository answered in the same run (else a note); otherwise every merge would have been a false Critical.
- **Real data (read-only, matador-legacy, GitHub reads only):**
  - `scan --github d9d45eff3..0a32698f4` (no `--previous-tip`) now BLOCKS with `t11.pr-merge-mismatch` Critical: PR #2921's real merge is `d9d45eff3`.
  - `scan --github HEAD~300..HEAD` gives 6 Critical `t11.pr-merge-mismatch`, each hand-checked against `gh api …/pulls/N`. Five are new forgeries: all unsigned, with the attacker's `-0800`/`-0700` timezone and content differing from GitHub's merge.
  - It also gives 1 Low: a web-flow-signed merge whose PR is recorded as closed and unmerged. GitHub made it, so it is not a forgery.
  - Time: cold 60 s → 15 s (parallel PR lookups, newest compare pages), warm 3.4 s.
  - Unchanged: `scan HEAD..origin/dev` CLEAN; incident replay BLOCKS; `af20233d8..d9351023d` warns; `audit` 2 Medium.
- Tests: 125.

### 2026-11-21: Session 7 (Phase 4 limits)
- `shield-github`:
  - GraphQL `pulls_batch` / `commits_batch` (100 aliases per request, 8 in flight); `repository: null` means "not visible" (no 404 guessing); REST `commit` fallback;
  - `activity` takes a page budget and a stop callback, and reports `truncated`; `compare` takes a page budget and fetches pages in parallel;
  - the cache also keeps local web-flow verdicts, keyed by the bundled keyring's hash.
- CLI:
  - `Budget` (activity pages, signed commits, PRs); `scan --deep`;
  - `scan --github --github-branch BRANCH`; conservative branch auto-detection;
  - `clone` / `checkout` run `shield_rules::signing_only()` over the commits they bring in and merge the findings (`Report::merge`); `--no-github` on both.
- GitHub lookups (compare page 1, commit verifications, PR states) run concurrently. Compare now fetches only its first page: GitHub's verdict on unsigned commits adds nothing, and signed ones go through GraphQL. 12 compare pages took 9.5 s.
- Push attribution: the newest push that brought a commit in wins; branch creations are skipped (they copy existing commits). Found on real data: a feature branch pushed today was credited with all of `dev`'s history.
- **Real data (read-only, matador-legacy, GitHub reads only):**
  - `scan --github HEAD~300..HEAD`: full coverage (no cap notes). It found 11 Critical `t11.pr-merge-mismatch`, up from 6; the old 100-PR cap hid five more. Each was hand-checked against `gh api …/pulls/N`: unsigned, committer not GitHub, tree differs from GitHub's merge. Details went to the user only.
  - Time: cold 14 s → 8 s, warm ~4 s.
  - `scan --github --github-branch dev d9d45eff3..0a32698f4` now also names the 11-10 force-push and reports the rewrite (`t10.ref-rewritten`, `t11.rewritten-copy`).
  - `clone` of matador (from the local path into a temp dir) BLOCKS on 9 forged merges in `dev`'s history and writes no files.
  - Unchanged: `scan HEAD..origin/dev` CLEAN; incident replay BLOCKS; `af20233d8..d9351023d` warns.
- Tests: 132.

### 2026-11-23: Session 8 (Phase 6)
- `shield-report::ci`: SARIF 2.1.0, GitHub workflow annotations (escaped: a title with `\n::error::` stays one line), Markdown job summary (escaped cells). `--sarif FILE` on every scanning command.
- `git shield ci` (`crates/git-shield/src/ci.rs`): see the event table in ADR 0008. `GitRepo::file_at` reads the accept file from the trusted commit. `shield_github::set_api_base` takes `$GITHUB_API_URL`. `viewer()` returns `None` on 403: Actions tokens have no user, and that used to skip the force-push log.
- `action.yml` + `.github/workflows/git-shield.yml`.
  - The first push run scanned `3b9ccb664..e6b7622b2` in 1.8 s, with no notes (activity API fine with an installation token), and uploaded SARIF. Code scanning shows `t9.workflow.added` (Low).
  - A throwaway draft PR (#1, closed, branch deleted) with a folderOpen task and a fake "Merge pull request #9999" commit: the job failed with exit 2 on `vscode.tasks.folder-open` High and `t11.pr-merge-mismatch` Critical (no PR #9999). Code scanning accepted both results, including the commit-level one at its placeholder path.
- YARA:
  - `shield-rules::yara` (feature `yara`; `rules_dir` / `rule_files` / `builtin_with` are ungated);
  - leaked `&'static Rules` plus a per-thread `Scanner`, re-created when the rule set changes;
  - detectors loaded once in `main.rs` (`DETECTORS` OnceLock).
- Benchmarks: `crates/shield-bench` (criterion 0.8.2, `default-features = false`): `scan_range` 11.7 ms on the 20-commit, ~30k-line synthetic delta (target < 300 ms).
- **Real data (read-only; a scratchpad clone of matador-legacy, deleted afterwards):**
  - `git shield ci` on a forced-push event `d9d45eff3 → 0a32698f4` BLOCKS from the event alone: `t10.ref-rewritten` High, `t11.rewritten-copy` and `t10.tampered-payload` Critical.
  - With the API it also gives `t11.pr-merge-mismatch` Critical and names the force-pusher.
  - That push would have failed the job.
- Tests: 153 (default) / 148 (`--no-default-features`).

### 2026-11-23: Session 9 (known gaps)
- Version 0.5.0 and the annotated tag `v0.5.0`, pushed.
- **Config includes** (`shield-git::local`):
  - `include.path` and `includeIf.*.path` are followed, with all conditions assumed true;
  - limits: regular files only, 1 MiB, 3 levels, each file once;
  - `ConfigEntry.source` records where an entry came from, and T7 points findings at the included file.
  - Tests: an `sshCommand` in an included file refuses git; an includeIf, a cycle and a FIFO are all handled.
- **Offline cache:** `Cache::load_local`, and `WebFlowVerdict.kind` for no key, expired and revoked. Tested with a real throwaway-key signature: the second run, with no `gpgv` on PATH, gives the same findings.
- **Speed:**
  - `GitRepo::incoming` diffs commits in parallel (`ThreadSafeRepository`, one handle per rayon thread) and keeps the dedupe in commit order. Findings and ids are identical to the previous build on two real ranges (160 and 26 findings).
  - `disk::scan_dir` reads files in parallel.
- **T12:** imara-diff 0.2 Myers over whitespace-stripped lines (`git -w` semantics, `lines()`). Snapshot text changed from "≈ N" to "N lines".
- **T9:** `data/installers.toml` (9 sourced entries). A `run:` step is downgraded only if every URL is https on the list, with no userinfo or port, no decoding and no `secrets.`.
- **`clone --recurse-submodules`** (ADR 0010):
  - `GitRepo::submodules`, `HardenedGit::clone_separate` / `config_set`;
  - URL resolution and validation, plus safe names and paths (unit tests);
  - fixture tests for a clean submodule (`git submodule status` initialized) and a payload submodule (whole clone blocked, only `.git` written);
  - verified on a public repository with two https submodules.
- Interpreter-on-asset (`util::runs_asset`): the asset must be the interpreter's script argument (`-m` means no script; `-c`/`-e`/`-p` code is checked recursively). FP run Medium 13 → 1.
- Regression test: 10,000 `github-pr-owner-number` values read in 0.19 s.
- **Real data (read-only):**
  - matador-legacy offline `scan HEAD~300..HEAD`: 1.2 s warm (0.75 s without signatures);
  - `audit` 0.19 s;
  - unchanged results: `HEAD..origin/dev` clean, incident replay blocks, `af20233d8..d9351023d` warns.
- Tests: 167.
