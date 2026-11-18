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

> Status: **early development (Phase 2 done)**. `scan`, `check` and the `pull` gate work offline, with an optional GitHub force-push lookup; deep content detectors (AI-agent configs, lifecycle scripts) are next. See [docs/PROGRESS.md](docs/PROGRESS.md).

## What it detects

| | |
|---|---|
| Editor auto-run | `.vscode/tasks.json` `folderOpen` tasks, hidden presentation, `allowAutomaticTasks` |
| Disguised payloads | JS/Python inside `.ttf` / `.woff2` / `.png`, scripts in SVG |
| Git execution | `core.fsmonitor`, `core.sshCommand`, hooks, filter/diff drivers (GitSpawn) |
| Submodules / attributes | URL swaps, `ext::`, `update=!cmd`, custom drivers |
| Noise masking | CRLF/whitespace churn hiding small real changes |
| History in transit | payloads added then removed in intermediate commits |
| Force-push / impersonation | a branch that dropped commits you had (or that GitHub logged as force-pushed by someone else), unsigned copies of signed merges, "Merge pull request" commits not made by GitHub, odd timezones and dates |
| *Coming* | AI-agent configs, lifecycle scripts, devcontainers/CI, obfuscation, GitHub commit verification |

Full list with sources: [docs/THREATS.md](docs/THREATS.md).

## Install (from source)
```sh
cargo install --path crates/git-shield
git shield --help        # git picks up any `git-<name>` binary on PATH
```

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
```
For GitHub remotes, `check` and `pull` also read the branch's force-push log, so a rewrite is caught even if this machine never saw the old tip. They use `GITHUB_TOKEN` or your `gh` login. The token is only sent to api.github.com. Use `--no-github` to skip this, or `scan --github` to add it to a local scan. Without a token it notes the skip and carries on.
Exit codes: `0` clean · `1` warnings · `2` blocked · `3` error.

## How it stays safe
- All reading goes through [gitoxide](https://github.com/GitoxideLabs/gitoxide) in-process: no hooks, no fsmonitor, no filters, no pager.
- `git fetch` runs with those execution points disabled, and only after the local config passes an audit.
- `pull` refuses to run if local config would execute programs on checkout or merge, and integrates the scanned commit id (not the ref name).
- The scanned repo cannot configure or allowlist anything. Acceptances live in your user data dir, never in `.git/` ([ADR 0003](docs/adr/0003-trust-store-in-user-data-dir.md)).

## License
MIT OR Apache-2.0
