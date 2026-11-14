# ADR 0001: gitoxide for all reads, a hardened `git` only for fetch/merge

- Status: accepted (2026-11-14)

## Context
The tool exists to inspect repositories that may be hostile. Running `git` inside such a repo can execute attacker-controlled programs: `core.fsmonitor`, hooks (including `reference-transaction` on fetch), `core.pager`, filter/diff/textconv drivers, `core.sshCommand`, and so on. A scanner that triggers the payload is worse than no scanner.

## Decision
- All reading (refs, objects, commit range, merge-base, tree diffs, blobs, local config) is done in-process with **gitoxide** (`gix`):
  - opened with `open::Options::isolated()` (no global/system config, no env overrides);
  - tree diffs use the plain `gix::diff::tree` + `Recorder`: no rename tracking, no blob/attribute pipeline, no drivers;
  - local config is parsed with `gix::config::File::from_path_no_includes`.
- `git` subprocesses are only used for network/worktree mutation (`fetch`, `merge --ff-only`). They go through `shield_git::hardened::HardenedGit`, which:
  - neutralises fsmonitor, hooks (empty `core.hooksPath`), pager, `diff.external`, the `ext::` protocol, and submodule recursion;
  - strips `GIT_CONFIG_PARAMETERS` / `GIT_CONFIG_COUNT`.
- Before any `git` spawn, the T7 preflight runs. Critical local config means a refusal unless `--allow-unsafe-config`.

## Consequences
- Fast (no process spawns for scanning) and safe by construction.
- We depend on gix's API, which changes between minor versions. Pin it in `Cargo.lock` and upgrade deliberately.
- `-c` overrides only cover known keys. The preflight audit is the defence for unknown ones; keep the T7 key list current.
