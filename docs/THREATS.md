# Threat catalogue

Each vector has an id that matches `shield_core::Threat` and the `GS-<id>-…` finding ids. **New vectors go here first**, then become detector tasks in PROGRESS.md.

Status: ✅ detector shipped · 🚧 partial · ⏳ planned (phase in brackets)

| Id | Vector | When it fires | Status |
|---|---|---|---|
| T1 | `.vscode/tasks.json` / `*.code-workspace` tasks with `runOptions.runOn: "folderOpen"` | Folder opened in VS Code / Cursor / Windsurf (after trust) | ✅ |
| T2 | Payload disguised as an asset (`.ttf`, `.woff2`, `.png`, `.svg`, …) | Executed by T1 / T5 (`node font.ttf`) | ✅ |
| T3 | `.vscode/settings.json`: `task.allowAutomaticTasks`, terminal env/profiles, interpreter paths into the repo | Folder opened | ✅ |
| T4 | AI-agent configs: `.claude/settings.json` hooks, `.mcp.json`, `enableAllProjectMcpServers`, `.cursor/rules/*.mdc` alwaysApply, `.gemini/settings.json`, AGENTS.md/CLAUDE.md shell directives | Agent session starts | ✅ (`agents.rs`; Codex `notify`, VS Code agent auto-approve, invisible Unicode too) |
| T5 | Lifecycle scripts: `package.json` pre/post/install & prepare, `setup.py`, `pyproject` build hooks, `.pth`, `conftest.py`, Makefile | install / test / interpreter start | ✅ (`lifecycle.rs`; also husky/.githooks, pre-commit) |
| T6 | Shell env auto-loaders: `.envrc` (direnv), mise/asdf hooks | `cd` into repo | ✅ (`shellenv.rs`) |
| T7 | Local `.git/config` execution keys (`core.fsmonitor`, `core.sshCommand`, `core.hooksPath`, `core.pager`, `diff.external`, `filter.*`, `uploadpack.packObjectsHook`, `alias.*=!`, includes…) and installed hooks | Any git command after a repo arrives *as files* (GitSpawn) | ✅ |
| T8 | `.gitattributes` custom filter/diff/merge drivers; `.gitmodules` URL swap, `ext::`, `update=!cmd`, path escape | checkout / diff / `submodule update` | ✅ |
| T9 | `.devcontainer` lifecycle commands; `.github/workflows` with `pull_request_target`, secret exfiltration | Container open / CI | ✅ (`ci.rs`; self-hosted runner backdoor, script injection) |
| T10 | History rewrite / force-push over a tip you had already seen | pull after an account compromise | ✅ offline (pre-fetch tip, reflog, trust store) + GitHub force-push log (ADR 0004) |
| T11 | Impersonated commits: copied merge with a new SHA, dropped signature, "Merge pull request" not committed by GitHub or not PR N's real merge, forged or invalid signatures, odd timezone, backdating | same | ✅ offline + local GPG/SSH verification + GitHub API (ADR 0004, 0007) |
| T12 | Whitespace / CRLF churn that buries a small real change in a huge diff | code review | ✅ |
| T13 | Obfuscated code (eval+base64/hex, `exec(compile(`, zlib+b64 chains, long single lines, high entropy) | running the app | ✅ (`obfuscation.rs`; off-screen code; `t13.payload-wired` correlation) |

## Detail and sources

### T1, T2, T3: editor auto-run (Contagious Interview / StoatWaffle / "fake font")
- DPRK-linked groups (WaterPlum / "Contagious Interview") ship repos with a hidden `.vscode/tasks.json`. The task uses `runOn: folderOpen`, hides itself (`reveal: never`, `hide`, `echo: false`, `close: true`), carries decoy labels like `eslint-check`, and runs `node` on a JS file disguised as a font (`public/fonts/fa-solid-*.ttf|woff2`).
- Matador incident (2026-11-10): forged commit `24f921bf2` added exactly this, plus `task.allowAutomaticTasks: true`.
- Sources: [Abstract Security](https://www.abstract.security/blog/contagious-interview-tracking-the-vs-code-tasks-infection-vector), [OpenSourceMalware: fake font](https://opensourcemalware.com/blog/dprk-contagious-interview-campaign-fake-font-uses-malicious-vs-code-fonts), [StoatWaffle](https://gbhackers.com/stoatwaffle-malware/), [Security Alliance](https://radar.securityalliance.org/vs-code-tasks-abuse-by-contagious-interview-dprk/).
- Detection: parse JSONC (BOM-tolerant); folderOpen → High, Critical with hiding, interpreter-on-asset, or download/decode. Assets: magic-byte check against the extension; text with ≥2 code markers → Critical. Don't rely on labels or filenames; they change.

### T4: AI coding-agent configs (Miasma / Hades worms, 2026)
- Stolen tokens are used to commit `.claude/settings.json` SessionStart hooks, `.cursor/rules/*.mdc` alwaysApply rules, `.gemini/settings.json`, and `.vscode/tasks.json` into every repo the victim can push to.
- Sources: [Pillar Security](https://www.pillar.security/blog/your-agents-answer-to-hades-how-one-commit-hijacks-4-ai-coding-tools), [Miasma](https://dev.to/toniantunovic/miasma-worm-how-opening-a-repo-in-claude-code-became-a-credential-theft-vector-5408), [Check Point findings on Claude Code project files](https://www.penligent.ai/hackinglabs/es/claude-code-project-files-became-an-rce-and-api-key-exfiltration-path-what-the-check-point-findings-change-for-ai-coding-assistants/).

### T7: git config execution (GitSpawn)
- `clone`/`fetch` never copy `.git/config`, but repos that arrive as files (archives, sandboxes, shared drives) do carry it. `core.fsmonitor` runs on nearly every command, including the `git status` that IDEs and agents run automatically.
- Sources: [GitSpawn (The Hacker News)](https://thehackernews.com/2026/09/malicious-git-configs-can-make-claude.html), [Cobalt: fsmonitor](https://www.cobalt.io/blog/red-team-technique-exploiting-git-fsmonitor-for-initial-access), [flynn](https://github.com/trapdoorsec/flynn), [gitambush](https://github.com/Nithinfgs/gitambush), [buried bare repos](https://github-redirect.dependabot.com/justinsteven/advisories/blob/main/2022_git_buried_bare_repos_and_fsmonitor_various_abuses.md).
- git-shield also refuses to spawn git when Critical keys are present, and always runs git with execution points neutralised (ADR 0001).

### T8: attributes and submodules
- A custom `filter=`/`diff=` attribute is harmless until a driver is defined. That pairing (an attribute in the repo, a driver set by a setup script or a poisoned config) is the attack. Submodule `ext::` URLs and `update = !cmd` execute directly. [Recursive-clone CVE, Nov 2026](https://thehackernews.com/2026/11/git-patches-flaw-that-lets-malicious.html).

### T10, T11: forced history and impersonation (Shai-Hulud family)
- Compromised accounts force-push rewritten tips that keep the author name, email, and date but drop signatures. In the matador case the committer timezone was -0800 and a "Merge pull request #2921" commit was not committed by GitHub.
- The decisive check is GitHub's own record: `pulls/N` → `merge_commit_sha` is the only commit the merge button produced, and GitHub signs it with its web-flow key. On matador-legacy this exposed five more forged merges still in `dev` (session 6).
- Sources: [StepSecurity: gpt-pilot](https://www.stepsecurity.io/blog/pythagora-io-gpt-pilot-compromised-on-github-shai-hulud-credential-stealer-blocked-by-python-linter), [Trigger.dev postmortem](https://trigger.dev/blog/shai-hulud-postmortem).

### T12: noise masking
- The matador forged commit converted 10 Python files to CRLF: a 68k-line raw diff covering about 1.2k lines of real change.
