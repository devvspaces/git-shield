# git-shield

**Inspect incoming git changes for supply-chain attacks *before* they touch your working tree.**

`git pull` is the moment a compromised teammate account, a hijacked CI token, or a worm reaches your machine. git-shield fetches objects only, scans what a pull *would* bring in, and blocks when it finds something dangerous. It never runs anything from the repository while doing so.

```console
# (abridged; from the matador-incident fixture, a replica of a real 2026 force-push attack)
$ git shield pull
git-shield: fetching origin dev (hardened, no checkout)…
git-shield · HEAD..origin/dev · 3 commits, 8 file versions scanned

 CRITICAL  GS-T10-…  Rewritten history carried a payload that was later removed

 CRITICAL  GS-T11-…  Commit 1f3c0a9e2 is a rewritten copy of 8d2b7c41a ("Merge pull request #2921 …")
           · Signature: original was signed, the copy is not.
           · Committer: GitHub <noreply@github.com> → Hycienth E.O <…>
           · Committer timezone: +0100 → -0800

 CRITICAL  GS-T2-…   `.ttf` font is actually source code
           public/fonts/fa-solid-600.ttf

 HIGH      GS-T10-…  `origin/dev` was rewritten (force-push): 8d2b7c41a is no longer in its history

 MEDIUM    GS-T1-…   Task `eslint-check` runs automatically when the folder is opened  [in history only]
           .vscode/tasks.json  @ 1f3c0a9e2
           · command: node ./public/fonts/fa-solid-600.ttf

BLOCKED: 4 finding(s) at high or above  (3 critical, 1 high, 4 medium, 1 low, 2 info)
git-shield: pull blocked; nothing was merged.
```

> Status: **Phase 7 in progress (v0.6.0, first binary release)**. `scan`, `check`, `pull`, `clone`, `checkout`, `audit`, `doctor`, `install`, `ci` (GitHub Action with SARIF) and user YARA rules are in. Signed binaries for macOS, Linux and Windows ship from v0.6.0. See [docs/PROGRESS.md](docs/PROGRESS.md).

## What it detects

| | |
|---|---|
| Editor auto-run | `.vscode/tasks.json` `folderOpen` tasks, hidden presentation, `allowAutomaticTasks` |
| Disguised payloads | JS/Python inside `.ttf` / `.woff2` / `.png`, scripts in SVG |
| Git execution | `core.fsmonitor`, `core.sshCommand`, hooks, filter/diff drivers (GitSpawn) |
| Submodules / attributes | URL swaps, `ext::`, `update=!cmd`, custom drivers |
| Noise masking | CRLF/whitespace churn hiding small real changes |
| History in transit | payloads added then removed in intermediate commits |
| Force-push / impersonation | a branch that dropped commits you had (or that GitHub logged as force-pushed by someone else), unsigned copies of signed merges, "Merge pull request" commits that are not the PR's real merge on GitHub, odd timezones and dates |
| Signatures | GPG/SSH signatures that do not verify, "GitHub" commits not signed by GitHub's key (checked offline), optional "require signed commits" per repo |
| AI-agent configs | Claude Code / Gemini / Codex hooks and helper commands, MCP servers, `enableAllProjectMcpServers`, API-endpoint redirects, invisible text or covert commands in AGENTS.md / CLAUDE.md / Cursor rules |
| Lifecycle scripts | npm install scripts, `setup.py` / `conftest.py` side effects, `.pth` files, build backends, Makefiles and repo git hooks that fetch-and-run |
| Shell env | direnv `.envrc` commands, mise hooks |
| Devcontainers / CI | `initializeCommand` (runs on the host), `toJSON(secrets)`, `pull_request_target` checkouts, self-hosted runner backdoors, script injection |
| Obfuscation | code hidden off-screen after long whitespace, decode-then-execute, huge lines, high-entropy blobs; and which task/hook/script runs them |
| Known indicators | a small, sourced list of worm artefacts (`crates/shield-rules/data/signatures.toml`) |
| Your own rules | YARA rules in `~/.config/git-shield/rules` ([ADR 0009](docs/adr/0009-user-yara-rules.md)) |

Full list with sources: [docs/THREATS.md](docs/THREATS.md).

## Install
```sh
brew install devvspaces/tap/git-shield                       # macOS / Linux
cargo install git-shield --locked                            # any platform with Rust
```
Or use the shell / PowerShell installer from the [latest release](https://github.com/devvspaces/git-shield/releases/latest):
```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/devvspaces/git-shield/releases/latest/download/git-shield-installer.sh | sh
```
```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/devvspaces/git-shield/releases/latest/download/git-shield-installer.ps1 | iex"
```
Then `git shield --help`: git picks up any `git-<name>` binary on PATH.

**Verify a download.** Every release archive has a SHA-256 file and a GitHub build attestation, which proves it was built by this repository's release workflow from the release tag ([ADR 0011](docs/adr/0011-release-chain.md)):
```sh
gh release download v0.6.0 --repo devvspaces/git-shield -p 'git-shield-aarch64-apple-darwin.tar.xz*'
shasum -a 256 -c git-shield-aarch64-apple-darwin.tar.xz.sha256
gh attestation verify git-shield-aarch64-apple-darwin.tar.xz --repo devvspaces/git-shield
```
Release tags are GPG-signed (`git tag -v v0.6.0`). From source: `cargo install --path crates/git-shield`.

On Windows, everything except `install` works. The shell function supports bash, zsh and fish, so use it from Git Bash or WSL. SSH-signature checks currently report "unchecked" on Windows.

## Usage
```sh
git shield pull                     # fetch + scan + fast-forward to exactly the scanned commit, or block
git shield pull --rebase            # same, rebasing local commits (or --merge)
git shield pull --accept GS-T10-… --reason "confirmed with Emeka"   # proceed past a reviewed finding (remembered)
git shield check                    # fetch (hardened) + scan HEAD..upstream; never merges
git shield check origin dev         # explicit remote/branch
git shield scan HEAD..origin/dev    # offline scan of a local range (uses the reflog to spot rewrites)
git shield scan A..B --previous-tip X   # forensics: "I had X before; was it rewritten away?"
git shield check --json             # machine-readable
git shield check --accept GS-T2-…   # mark a reviewed finding as accepted
git shield trust list               # what this repo has accepted / last pulled tips
git shield trust forget GS-T2-…     # un-accept (or --all, or --ref origin/dev)
git shield clone <url> [dir]        # clone without checkout, scan the whole tree, then check out (or block)
git shield clone --recurse-submodules <url>   # same for every submodule; nothing is checked out unless all pass
git shield checkout feature         # scan what switching would write, then switch
git shield audit [path]             # a repo/folder that arrived as files: scan files + .git/config, run nothing
git shield doctor                   # check your git / editor / agent settings (read-only)
git shield install --write          # make plain `git pull` go through `git shield pull` (shell function)
```
`install` adds a small shell function (bash, zsh, fish) between markers in your rc file; `git shield uninstall` removes it, and `GIT_SHIELD_BYPASS=1 git pull` skips it once. IDE pull buttons and scripts that call git directly are not covered. A git hook can't do this job: git writes the files before a hook can refuse the update ([ADR 0006](docs/adr/0006-shell-function-not-reference-transaction-hook.md)).
Reviewed something your team uses on purpose (an MCP server, a hook)? Allow it in your own config, never the repo's ([ADR 0005](docs/adr/0005-user-allowlist.md)):
```toml
# ~/.config/git-shield/config.toml   (git shield config path / check)
[[allow]]
rule = "t4.mcp.server"
path = ".mcp.json"
repo = "github.com/acme/*"
reason = "our docs MCP server, reviewed 2026-11"
# Critical findings are only allowed with `blob = "<content id>"` pinned.
```
For GitHub remotes, `check` and `pull` also ask GitHub:
- the branch's force-push and push log, so a rewrite is caught even if this machine never saw the old tip, and findings name who pushed;
- each incoming commit's signature verification;
- whether every "Merge pull request #N" commit is PR N's real merge commit.

They use `GITHUB_TOKEN` or your `gh` login. The token is only sent to api.github.com. Answers that cannot change are cached in `~/.cache/git-shield`. Use `--no-github` to skip this, or `scan --github` to add it to a local scan. Without a token it notes the skip and carries on.

`clone` and `checkout` run the signature and "Merge pull request" checks over the history they bring in, so a fresh clone with forged merges is blocked before any file is written. For forensic scans of long ranges:
```sh
git shield scan --github --deep A..B                 # read far more history, commits and PRs
git shield scan --github --github-branch dev A..B    # whose push history explains a range that is not a ref
```

Signed incoming commits are also verified locally with `gpgv` / `gpg` / `ssh-keygen` (`--no-verify-signatures` to skip). Commits claiming GitHub as committer are checked against GitHub's published keys, bundled with git-shield ([ADR 0007](docs/adr/0007-commit-signatures-and-pr-merge-commits.md)). To require signatures for a repository:
```toml
[[signing]]
repo = "github.com/acme/*"
require = true                                      # unsigned incoming commits block
allowed_signers = "~/.config/git-shield/acme_signers"   # ties SSH signatures to committers
```
Exit codes: `0` clean · `1` warnings · `2` blocked · `3` error.

## In CI (GitHub Actions)
The local commands protect people who run them. The action checks every push and pull request on GitHub, so it also catches a force-push made from any IDE or script:
```yaml
# .github/workflows/git-shield.yml
name: git-shield
on:
  push:
    branches: [main, dev]
  pull_request:
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
      security-events: write     # code-scanning upload
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: devvspaces/git-shield@<release commit SHA>   # e.g. the v0.6.0 tag's commit
        with:
          fail-on: high                       # default; medium/low/critical also work
          accepts-path: .github/git-shield-accept.toml   # optional
```
- **What is scanned:** a pull request is scanned as `base..head`; a push as `before..after`.
  - A forced push is checked as a rewrite of the old tip. The action fetches that tip by SHA when the checkout lacks it.
  - The branch's push log on GitHub names who pushed, and the PR and signature checks run as in `check`.
- **What the job shows:** findings appear as annotations, in the job summary, and, via SARIF, in the repository's code-scanning alerts.
- **When it fails:** the job fails only on findings at or above `fail-on` that were not accepted.
- **Accept files:** an accept file lists reviewed ids:
  ```toml
  [[accept]]
  id = "GS-T9-1a2b3c4d"
  reason = "our installer step, reviewed 2026-11"
  ```
  It is read from the PR base or from the branch before the push, never from the commits being scanned. So a pull request cannot accept its own findings.
- **Which binary runs:** the action downloads the release binary for its own version. It runs it only after the SHA-256 and the build attestation (release workflow, matching tag) both check out. Without a release for that version, it builds from the action's own source. `build-from-source: "true"` forces the source build. Pinned to a release commit, setup takes seconds. `@master` between releases runs the last release.
- **Safe on untrusted pull requests:** git-shield never runs the repository's code, so the `pull_request` trigger is safe even for forks. Prefer `pull_request` over `pull_request_target`.

Outside Actions, `git shield ci --event FILE --event-name push` works with any saved payload. `--sarif FILE` is available on every scanning command.

## How it stays safe
- All reading goes through [gitoxide](https://github.com/GitoxideLabs/gitoxide) in-process: no hooks, no fsmonitor, no filters, no pager.
- `git fetch` runs with those execution points disabled, and only after the local config passes an audit.
- `pull` refuses to run if local config would execute programs on checkout or merge, and integrates the scanned commit id (not the ref name).
- The scanned repo cannot configure or allowlist anything. Acceptances live in your user data dir, never in `.git/` ([ADR 0003](docs/adr/0003-trust-store-in-user-data-dir.md)).

## License
MIT OR Apache-2.0
