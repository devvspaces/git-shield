# git-shield: phased build plan

> Living document. Update it when scope or design changes, and add an entry to the Changelog at the bottom.
> Current status is in [PROGRESS.md](PROGRESS.md).

## Context

On 2026-11-10, `dev` in matador-legacy was force-pushed from a compromised teammate account. The real merge `d9d45eff3` was replaced with an unsigned copy, `24f921bf2`. That copy added `.vscode/tasks.json` with a hidden `runOn: folderOpen` task (`node ./public/fonts/fa-solid-600.ttf`, a JS payload disguised as a font), and it rewrote five large `.py` files to CRLF. The CRLF churn produced a 33k-line diff that hid a real change of about 1.2k lines. We caught it by hand with: fetch → fast-forward check → `%G?` signature check → GitHub activity API → `git diff --ignore-cr-at-eol` → `merge --ff-only`.

Existing tools each cover only part of this:
- **git-moat** does a scan-in-worktree pull. It is small, its maturity is unverified, and it has no provenance checks.
- **flynn** and **gitambush** audit `.git/config` and hooks. They are scanners, not gates.
- **sandbox-scan** and **clone-guard** match `folderOpen` only.
- **IDE Shepherd** guards VS Code at runtime.
- **gittuf** and **sequoia-git** enforce signing policy, but the whole team has to adopt them.
- **GuardDog** and **PRevent** target packages and PRs.

None of them combines (a) a gate before merge or checkout, (b) history and provenance checks (rewrites, impersonated merges, unsigned copies), (c) diffs that see through whitespace and CRLF noise, and (d) detectors for the 2026 vectors (AI-agent configs, fake-font payloads, GitSpawn-style config execution).

**Goal:** build `git-shield`, a fast Rust CLI (`git shield …`) that inspects incoming git changes before they touch your working tree, blocks high-risk ones, and never runs repo-controlled code itself. It will be open source at `git@github.com:devvspaces/git-shield.git`, in `~/projects/git-shield`.

## Decisions (from the user)

- **Integration:** a `git-shield` binary on PATH, so git exposes it as `git shield <cmd>`. Optional hooks: a `reference-transaction` hook to block risky local ref updates, and a shell alias so plain `git pull` goes through the shield.
- **On detection:** block High and Critical findings. Override per finding with `--accept <id>` or an interactive confirm. Lower severities only warn.
- **GitHub API checks:** optional, in the phase after the first usable offline release. Use `gh` auth or a token, and degrade gracefully when offline.
- **Tracking:** in-repo `docs/`, committed, so any human or AI can resume (see "Tracking system").
- **Commits/PRs:** no Claude attribution lines (the user's standing preference).

## Threat catalogue (what we detect)

| # | Vector | Trigger | Detection idea |
|---|---|---|---|
| T1 | `.vscode/tasks.json` `runOn: folderOpen` | Opening the folder in VS Code / Cursor | Parse JSONC. Flag folderOpen tasks, hidden presentation (`reveal: never`, `hide`, `echo:false`), and commands running `node` / `python` / `sh` on non-script files. Also flag `curl \| sh`. Decoy labels such as "eslint-check" are allowed in the signature list but not relied on. |
| T2 | Payload disguised as an asset (`.ttf`, `.woff2`, `.svg`, `.png`, `.css`) | Referenced by T1 or by package scripts | Mismatch between magic bytes and extension. Text or JS content inside a "font". Very high entropy. Very long lines. |
| T3 | `.vscode/settings.json` | Opening the folder | `task.allowAutomaticTasks: on`, interpreter or terminal env overrides, `*.path` settings pointing to repo files. |
| T4 | AI-agent configs (Miasma/Hades 2026) | Starting an agent session | `.claude/settings.json` hooks (SessionStart etc.), `.mcp.json` servers, `enableAllProjectMcpServers`, `.cursor/rules/*.mdc` with `alwaysApply` that contain run instructions, `.gemini/settings.json`, `AGENTS.md`/`CLAUDE.md` with shell directives (heuristic). |
| T5 | Package lifecycle scripts | Running install | `package.json` `pre/post/install`, `prepare`. `setup.py` / `pyproject` build hooks. `.pth` files. `conftest.py`. Makefile default target changes. |
| T6 | Shell environment | `cd` into the repo | `.envrc` (direnv), `.tool-versions`/mise tasks, `.nvmrc`-adjacent scripts. |
| T7 | Git-level execution | git commands after clone or copy | Local `.git/config` keys: `core.fsmonitor`, `core.hooksPath`, `core.pager`, `core.sshCommand`, `core.editor`, `diff.external`, `filter.*.{clean,smudge,process}`, `uploadpack.packObjectsHook`, `credential.helper`, `alias.*` with `!`. Non-sample hooks. Embedded bare repos. `safe.bareRepository`. |
| T8 | `.gitattributes` / `.gitmodules` | checkout, diff, `submodule update` | New `filter=` / `diff=` drivers. Submodule URL or path changes, `file://` / `ext::` URLs. Recursive-clone hook CVEs. |
| T9 | CI / devcontainer | Opening the container, CI runs | `.devcontainer` `postCreateCommand` / `postStartCommand`. `.github/workflows` added with `pull_request_target` or secrets exfiltration. |
| T10 | History rewrite / force-push | Pull after a compromised account pushes | Local branch or last trusted tip not an ancestor of the new remote tip. Remote ref moved backwards or sideways (compare reflog and the shield trust store). |
| T11 | Impersonated / duplicated commits | Same | Commit with the same subject, author, and parents as one we have seen but a different SHA. Signature dropped (was G/E, now N). GitHub merge commit not committed by `GitHub`. Committer timezone anomalies (e.g. -0800). Committer date earlier than the parent's, or a jump far into the past or future. |
| T12 | Noise masking | Code review | Files where the raw diff is much larger than the whitespace/CRLF-insensitive diff. Report the ratio, and run all content detectors on the normalized diff. |
| T13 | Obfuscated code in normal files | Running the app | Obfuscation markers (`eval(`/`Function(` + base64/hex/`fromCharCode`, `exec(compile(`, `marshal.loads`, zlib+b64 chains), long single lines, high-entropy string literals. Informational to Medium only, to limit false positives. |

## Architecture

**Core safety rule: git-shield never runs repo-controlled code.**
- All reading goes through **gitoxide (`gix`)** in-process: objects, refs, reflog, tree diff, blobs. No hooks, no fsmonitor, no filters, no pager.
- The only git subprocesses are `fetch` and the final `merge --ff-only` / `checkout`. They go through one hardened runner (`crates/shield-git/src/hardened.rs`). It:
  - sets `-c core.fsmonitor=false -c core.hooksPath=<empty temp dir> -c core.pager=cat -c diff.external= -c protocol.ext.allow=never -c submodule.recurse=false -c fetch.recurseSubmodules=false`. It does not override `core.sshCommand`, so the user's global value keeps working; a *local* `core.sshCommand` is Critical in the preflight;
  - sets `GIT_TERMINAL_PROMPT=0` (in non-interactive mode only);
  - refuses to start if the T7 local-config audit finds Critical keys, unless overridden.
- The tool's own configuration lives **only** in the user config dir (`~/.config/git-shield/config.toml`) plus a per-repo trust store in the user data dir (ADR 0003; originally planned for `.git/shield/`). A repo can never relax its own scanning.

**Cargo workspace layout** (`~/projects/git-shield`):
```
crates/
  git-shield/      # bin: clap CLI, commands, interactive prompts, exit codes
  shield-core/     # Finding, Severity, FindingId (stable hash), ScanContext, Detector trait, engine (rayon)
  shield-git/      # gix repo access: incoming delta, tree diff, blob reader, reflog, trust store, hardened git runner
  shield-rules/    # built-in detectors T1–T13 (one module per vector), path rules, signature list
  shield-report/   # terminal (colored, grouped), JSON; SARIF in Phase 6
  shield-github/   # Phase 4: activity API, commit verification, pusher/author checks
shield-fixtures/  # (publish=false) builds hostile-but-inert git repos for tests
docs/              # PLAN.md, PROGRESS.md, THREATS.md, adr/
```

**Scan pipeline (`git shield check` / `pull`):**
1. **Pre-flight:** audit local `.git/config` and hooks (T7) using gix's config parser, without running git.
2. **Fetch:** hardened `git fetch <remote> <branch>`. Objects only; the working tree is untouched.
3. **Delta:** compute `base = merge-base(HEAD, remote_tip)`, the commit list `base..remote_tip`, and the tree diff `HEAD-tree → remote-tree`. Also diff each commit individually, so payloads that were added and then removed are still reported (as "transited" Medium findings, like the `24f921bf2` → `f99dbe841` case).
4. **Provenance detectors** (T10, T11) run on the commit list, reflog, and trust store (user data dir, ADR 0003: last accepted tip per remote ref, plus accepted ids with reasons).
5. **Content detectors** (T1–T9, T12, T13) run on the changed blobs only, in parallel (rayon). An aho-corasick prefilter finds candidate files; each detector then parses only those. There are size caps, Git LFS pointers are skipped, and binaries are sniffed by magic bytes (the `infer` crate).
6. **Report and decide:** findings are sorted by severity. Exit codes: 0 clean, 1 warnings, 2 blocked, 3 error. In `pull`, if the result is blocked and not every blocking finding was accepted, abort before the merge. Otherwise run the hardened `merge --ff-only` (or `--rebase` / merge per flags) and update the trust store.

**Key crates:** `gix` (with the `blob-diff` and `revision` features), `clap` (derive), `rayon`, `aho-corasick`, `regex`, `jsonc-parser` or `json5` (for VS Code JSONC), `serde`/`serde_json`/`toml`, `infer` (magic bytes), `owo-colors`, `dialoguer` (prompts), `thiserror`/`anyhow`. Phase 4 adds `ureq` or `reqwest`. Phase 6 adds `yara-x` (VirusTotal's Rust YARA) and `serde-sarif`. Tests use `assert_cmd`, `tempfile`, `insta` (snapshots). Use crate versions that are at least two weeks old, pinned in `Cargo.lock`.

**Finding IDs** are a stable short hash of (rule id, path, blob or commit SHA), e.g. `GS-T1-3fa9c2`. That way `--accept GS-T1-3fa9c2` stays valid on re-runs and can be recorded in the trust store with a reason.

## Phases

Each phase ends with: green `cargo test` + `cargo clippy -D warnings`, the PROGRESS.md log updated, a tag.

### Phase 0: Bootstrap and tracking (v0.0)
- Create `~/projects/git-shield`, set the remote, and use branch `master` (per the user's init snippet).
- Cargo workspace, MIT OR Apache-2.0 license, `rust-toolchain.toml` (stable), CI (GitHub Actions: fmt, clippy, test on macOS and Linux).
- Write `docs/PLAN.md` (this plan, kept current), `docs/PROGRESS.md`, `docs/THREATS.md` (the expanded threat catalogue with sources), `docs/adr/0001-gix-for-reads-hardened-git-for-writes.md`, `docs/adr/0002-repo-cannot-configure-shield.md`, and `AGENTS.md` + `CLAUDE.md` ("read docs/PROGRESS.md first").
- **Fixture harness:** `tests/fixtures/build.rs`-style helpers that create temporary repos in Rust. They must include a faithful reproduction of the matador incident: a real merge → force-push of an unsigned copy with `.vscode` + fake-font JS + CRLF churn → a later cleanup commit. **All payloads are harmless** (`touch $TMP/PWNED`), and every test asserts the marker is never created.

### Phase 1: Read-only engine and `git shield scan` / `check` (v0.1-alpha)
- `shield-git`: open the repo with gix, resolve refs, compute merge-base, commit range, tree diff, blob reads, and whitespace/CRLF-normalized line diff (imara-diff via gix).
- `shield-core`: `Detector` trait (`fn scan(&self, ctx: &ScanContext, out: &mut Findings)`), severity model, parallel engine.
- Detectors: **T1, T2, T3, T7, T8, T12**, plus a path-risk list (any change under the T1–T9 paths is at least Info).
- Commands: `git shield scan [<rev-range>]` (no network) and `git shield check [<remote>/<branch>]` (hardened fetch + scan, no merge).
- Output: colored terminal report grouped by severity and commit, plus `--json`.
- **Done when:** `check` against the matador fixture reports the T1 + T2 + T12 findings, and the "transited" payload in the cleanup commit. Scanning a 20-commit / 30k-line delta takes under 300 ms on the user's machine.

### Phase 2: The gate, `git shield pull` (v0.1, first usable release)
- `pull` = pre-flight → fetch → scan → decide → hardened `merge --ff-only` (default). `--rebase` and `--merge` are opt-in.
- Provenance detectors **T10 and T11, offline**: non-fast-forward, the remote tip rewriting a previously trusted tip (trust store and reflog), duplicate-subject commits with changed SHA or signature, `%G?`-equivalent signature *presence* (full cryptographic verification is in Phase 5), timezone and date anomalies, "Merge pull request" commits whose committer isn't `GitHub`.
- Trust store (user data dir, ADR 0003) and `--accept <id> --reason "…"`. An interactive confirm is shown when on a TTY.
- **Done when:** on the matador fixture, `pull` blocks with exit code 2, and after `--accept` of all blocking IDs it fast-forwards. On a clean fixture it fast-forwards silently. The PWNED marker never appears.

### Phase 3: Deep content detectors (v0.2)
- **T4** (AI-agent configs), **T5** (package/lifecycle), **T6** (shell environment), **T9** (devcontainer / CI), **T13** (obfuscation heuristics, entropy, long lines).
- Shipped signature list (`shield-rules/data/signatures.toml`): known decoy labels, known payload paths, IOC strings from public Contagious Interview / StoatWaffle / Miasma write-ups.
- Allowlist support in the user config (path glob + blob hash). The false-positive budget is set by running against 10 popular real repos; the target is 0 High findings on them.

### Phase 4: GitHub provenance, optional (v0.3)
- `shield-github`: get auth from `gh auth token` or `GITHUB_TOKEN`. Look at the activity API for the target ref (force pushes and their actors), the commit `verification` status for incoming commits, the pusher vs commit author, and PR association (a commit claiming "Merge pull request #N" must match PR N's merge commit SHA).
- Graceful degradation when offline or without a token: a warning, never a crash. Results are cached per SHA.
- **Done when:** a recorded-API-response test reproduces the `24f921bf2` case: force-push by account X, fake merge not equal to PR #2921's real merge SHA → Critical.

### Phase 5: Clone, checkout, hooks, doctor (v0.4)
- `git shield clone <url>`: hardened `clone --no-checkout` → scan the full tree for T1–T9 → checkout only if clean or accepted.
- `git shield checkout <branch>`: scan the target tree vs HEAD before switching.
- `git shield audit [path]`: T7 audit of a directory that arrived as files (zip, tar, rsync). This is the GitSpawn case.
- `git shield install`: an optional `reference-transaction` hook (blocks `refs/heads/*` updates to a scanned-bad tip), plus a printed shell alias / function for `git pull` → `git shield pull`. `git shield uninstall` reverses it.
- `git shield doctor`: checks global hardening. It warns if VS Code `task.allowAutomaticTasks` is not `off`, if `core.fsmonitor` is unset globally, if `safe.bareRepository` is not `explicit`, and if Claude Code's `enableAllProjectMcpServers` is on. It suggests fixes and never changes them silently.
- Full signature verification: GPG via `gpgv` and SSH via `ssh-keygen -Y verify`, both run as hardened subprocesses on extracted payloads. Optional allowed-signers per repo in the user config.

### Phase 6: Extensibility and CI (v0.5)
- `yara-x` rule engine for user and community content rules (`~/.config/git-shield/rules/*.yar`). It runs on changed blobs only.
- SARIF output, `--ci` mode, a GitHub Action wrapper (scan the PR delta, upload SARIF).
- Benchmarks (`criterion`) on a large synthetic delta and on a real large repo (e.g. linux), so performance regressions are tracked.

### Phase 7: Release and distribution (v1.0)
- `cargo-dist` for prebuilt binaries (macOS arm64/x64, Linux, Windows), a Homebrew tap, `cargo install git-shield`.
- Signed releases and provenance (sigstore / GitHub attestations). git-shield is itself a supply-chain target, so its own release chain must be clean.
- Docs site / README with a threat matrix, plus a comparison with git-moat, flynn, and gittuf.

## Tracking system (so any AI or human can resume)

- **`docs/PLAN.md`:** the living plan (phases, scope, decisions). Edited when the plan changes, with a dated "Changelog" section at the bottom.
- **`docs/PROGRESS.md`:**
  - a **Current state** header (phase, last completed task, next task, blockers);
  - a per-phase checkbox list mirroring the tasks above;
  - an append-only **Session log** (date, what changed, commits, open questions).
- **`docs/adr/NNNN-*.md`:** one short record per architectural decision (context, decision, consequences). Plan changes that reverse an ADR add a new ADR that supersedes it.
- **`docs/THREATS.md`:** the threat catalogue with source links. New vectors are added here first, then become detector tasks.
- **`AGENTS.md` / `CLAUDE.md`:** short. They cover how to build and test, the core safety rule, and "Start by reading docs/PROGRESS.md, then docs/PLAN.md."
- Rule: every working session ends by updating PROGRESS.md (current state + log entry) in the same commit as the code.

## First implementation session (done 2026-11-14; see PROGRESS.md)
1. Phase 0 entirely: scaffold, docs, CI, matador fixture builder with harmless payloads.
2. Start Phase 1: gix delta + tree diff + T1/T2/T12 detectors, and `scan` running against the fixture.

## Verification

- `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` (unit + `assert_cmd` integration tests over the generated fixture repos).
- Fixture scenarios, each with expected findings in `insta` snapshots:
  - clean fast-forward
  - the matador force-push incident
  - fake-font payload
  - AI-agent hook (Phase 3)
  - `.git/config` fsmonitor (Phase 5)
  - submodule URL swap
  - CRLF-only churn (must give T12 Info and no false High)
- A safety assertion in every test: the PWNED marker file never exists after any `git shield` command.
- Manual check: run `git shield check origin/dev` in `~/projects/matador/matador-legacy`. The real history contains `24f921bf2`, so a scan across `af20233d8..d9351023d` must reproduce today's manual findings.
- Performance: `hyperfine 'git shield scan af20233d8..d9351023d'` in matador-legacy, target under 300 ms.

## Research sources
- VS Code tasks / fake fonts: [Abstract Security](https://www.abstract.security/blog/contagious-interview-tracking-the-vs-code-tasks-infection-vector), [OpenSourceMalware fake font](https://opensourcemalware.com/blog/dprk-contagious-interview-campaign-fake-font-uses-malicious-vs-code-fonts), [StoatWaffle](https://gbhackers.com/stoatwaffle-malware/)
- AI-agent configs: [Pillar: Hades/Miasma](https://www.pillar.security/blog/your-agents-answer-to-hades-how-one-commit-hijacks-4-ai-coding-tools), [Miasma on DEV](https://dev.to/toniantunovic/miasma-worm-how-opening-a-repo-in-claude-code-became-a-credential-theft-vector-5408)
- Git-config execution: [GitSpawn (THN)](https://thehackernews.com/2026/09/malicious-git-configs-can-make-claude.html), [Cobalt fsmonitor](https://www.cobalt.io/blog/red-team-technique-exploiting-git-fsmonitor-for-initial-access), [flynn](https://github.com/trapdoorsec/flynn), [gitambush](https://github.com/Nithinfgs/gitambush), [recursive-clone CVE](https://thehackernews.com/2026/11/git-patches-flaw-that-lets-malicious.html)
- Force-push / impersonation: [StepSecurity gpt-pilot](https://www.stepsecurity.io/blog/pythagora-io-gpt-pilot-compromised-on-github-shai-hulud-credential-stealer-blocked-by-python-linter), [Trigger.dev postmortem](https://trigger.dev/blog/shai-hulud-postmortem)
- Existing tools: [git-moat](https://awesome.ecosyste.ms/projects/github.com%2FJBGamond%2Fgit-moat), [sandbox-scan](https://docs.rs/crate/sandbox-scan/0.1.1/source/src/heuristics/vscode.rs), [IDE Shepherd](https://securitylabs.datadoghq.com/articles/ide-shepherd-release-article/), [GuardDog 3.0](https://securitylabs.datadoghq.com/articles/guarddog-3-0-release/), [gittuf](https://gittuf.github.io/design.html), [gix-diff](https://docs.rs/gix-diff)

## Changelog

- **2026-11-14:** Plan approved. Changes made during the first implementation session:
  - The fixture harness is a workspace crate, `crates/shield-fixtures` (publish = false), instead of `tests/fixtures/`. Rust builders are easier to keep correct than shell scripts.
  - The hardened runner no longer sets `protocol.file.allow=never`. It broke legitimate local-path remotes, and the submodule-over-file:// risk is already covered by `--no-recurse-submodules` / `submodule.recurse=false`.
  - Tree diffs use gix's plain `gix::diff::tree` + `Recorder`, not `diff_tree_to_tree`. The latter goes through the blob resource cache / attribute pipeline, which is driver-aware; the plain differ never touches drivers (ADR 0001).
  - The gix feature set is `revision`, `sha1`, `max-performance`, `parallel`; `blob-diff` is not needed.
- **2026-11-16 (session 2):** Phase 1 closed and Phase 2 built. Changes to the plan:
  - The trust store moved from `.git/shield/trusted.json` to the user data dir ([ADR 0003](adr/0003-trust-store-in-user-data-dir.md)). A `.git` that arrives as files must not carry its own acceptances.
  - `pull` integrates the **scanned commit id**, never the ref name, so a ref moving between scan and merge cannot slip unscanned commits in.
  - The `pull` preflight is stricter than `check`'s. It also refuses High local-config keys that fire on checkout or merge (filter/merge drivers, `gpg.program`) unless the hardened runner already neutralises them. Hardened git also sets `GIT_EDITOR`/`GIT_SEQUENCE_EDITOR` to `:`.
  - Reflog transitions made by the user's own `git push` never count as rewrites (restores, own rebases).
  - Added `scan --previous-tip <REV>` for forensics. It replays "I had X before" without a reflog, which is how the real 2026-11-10 incident was re-verified.
  - The report groups a rule with 4 or more findings at Medium or below into one block. This is display only; ids and JSON are unchanged.
- **2026-11-18 (session 3):** The GitHub activity-API slice of Phase 4 (force-push history and actors) was built early ([ADR 0004](adr/0004-github-force-push-history.md)). It closes the "old rewrite without local memory" gap. Commit verification and PR merge-SHA matching stay in Phase 4. Also added `git shield trust list/forget`, and `t11.merge-not-by-github` is grouped per committer.
- **2026-11-18 (session 4):** Phase 3 built. Changes to the plan:
  - Content detectors are diff-aware: they only report exec entries (hooks, scripts, servers, workflow steps) and lines that the incoming version added or changed.
  - Findings carry `refs` (repo files their command runs). `t13.payload-wired` correlates a runner with a disguised or obfuscated target.
  - Signatures hold only sourced entries. Generic asset names such as `fa-solid-*` are excluded because real Font Awesome files share them; T2's content check covers them.
  - Allowlist rules in [ADR 0005](adr/0005-user-allowlist.md): Critical findings need a pinned `blob`. JSON output gains `accepted`.
  - Reflog-based rewrite detection only reads remote-tracking refs. Local branch reflogs are the user's own amends and rebases.
  - The FP run uses shallow `--no-checkout` clones, because gix does not fetch promisor (blobless) objects on demand.
- **2026-11-18 (session 5):** Phase 5 (most of it). Changes to the plan:
  - The `reference-transaction` hook is dropped. Tested: git writes the working tree before the hook can reject the ref update ([ADR 0006](adr/0006-shell-function-not-reference-transaction-hook.md)). `install` adds a `git pull` → `git shield pull` shell function instead.
  - `audit` scans files on disk (not only `.git/config`). Symlinks are never followed, and dependency and build directories are skipped.
  - `clone` populates the working tree with `reset --hard <scanned sha>` after a no-checkout clone.
  - Full GPG/SSH signature verification is postponed to the Phase 4 remainder, next to GitHub's `verification` status.
