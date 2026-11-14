# git-shield

**Inspect incoming git changes for supply-chain attacks *before* they touch your working tree.**

`git pull` is the moment a compromised teammate account, a hijacked CI token, or a worm reaches your machine. git-shield fetches objects only, scans what a pull *would* bring in, and blocks when it finds something dangerous. It never runs anything from the repository while doing so.

```console
# (abridged example from the matador-incident fixture)
$ git shield check
git-shield: fetching origin dev (hardened, no checkout)…
git-shield · HEAD..origin/dev · 3 commits, 9 file versions scanned

 CRITICAL  GS-T2-5b0c…  `.ttf` font is actually source code
           public/fonts/fa-solid-600.ttf
           · No valid .ttf header; content is text with code markers: const , require(, …

 MEDIUM    GS-T1-8eff…  Task `eslint-check` runs automatically when the folder is opened  [in history only]
           .vscode/tasks.json  @ 24f921bf2
           · command: node ./public/fonts/fa-solid-600.ttf
           · hidden from the user: reveal, echo:false, close:true, hide:true, isBackground

 MEDIUM    GS-T12-a3cd…  Line-ending rewrite hides 71 real changed lines
           agent/views.py
           · raw diff ≈ 19521 lines, ignoring whitespace ≈ 71 lines

BLOCKED: 1 finding(s) at high or above
```

> Status: **early development (Phase 1)**. `scan` and `check` work; the `pull` gate is next. See [docs/PROGRESS.md](docs/PROGRESS.md).

## What it detects

| | |
|---|---|
| Editor auto-run | `.vscode/tasks.json` `folderOpen` tasks, hidden presentation, `allowAutomaticTasks` |
| Disguised payloads | JS/Python inside `.ttf` / `.woff2` / `.png`, scripts in SVG |
| Git execution | `core.fsmonitor`, `core.sshCommand`, hooks, filter/diff drivers (GitSpawn) |
| Submodules / attributes | URL swaps, `ext::`, `update=!cmd`, custom drivers |
| Noise masking | CRLF/whitespace churn hiding small real changes |
| History in transit | payloads added then removed in intermediate commits |
| *Coming* | force-push / impersonated merges, AI-agent configs, lifecycle scripts, GitHub provenance |

Full list with sources: [docs/THREATS.md](docs/THREATS.md).

## Install (from source)
```sh
cargo install --path crates/git-shield
git shield --help        # git picks up any `git-<name>` binary on PATH
```

## Usage
```sh
git shield check                    # fetch (hardened) + scan HEAD..upstream; never merges
git shield check origin dev         # explicit remote/branch
git shield scan HEAD..origin/dev    # offline scan of a local range
git shield check --json             # machine-readable
git shield check --accept GS-T2-…   # mark a reviewed finding as accepted
```
Exit codes: `0` clean · `1` warnings · `2` blocked · `3` error.

## How it stays safe
- All reading goes through [gitoxide](https://github.com/GitoxideLabs/gitoxide) in-process: no hooks, no fsmonitor, no filters, no pager.
- `git fetch` runs with those execution points disabled, and only after the local config passes an audit.
- The scanned repo cannot configure or allowlist anything.

## License
MIT OR Apache-2.0
