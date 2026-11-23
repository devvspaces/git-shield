# ADR 0002: A repository can never configure or relax git-shield

- Status: accepted (2026-11-14)

## Context
Many scanners read a config file from the repo they scan (`.toolrc`, allowlists). An attacker who controls the repo would simply allowlist their payload.

## Decision
git-shield reads configuration only from:
1. the user config dir (`~/.config/git-shield/config.toml`, Phase 3+);
2. the per-repo trust store, written only by git-shield after an explicit `--accept` or pull. It lives in the user data dir, not `.git/` (see [ADR 0003](0003-trust-store-in-user-data-dir.md));
3. command-line flags.

No tracked file in the scanned repository influences rules, severities, or allowlists.

## Consequences
- Teams cannot ship a shared allowlist in-repo. If needed later, it has to be an explicit opt-in pointing at a *signed* or out-of-repo source, recorded as a new ADR.

## Addendum (2026-11-23): config includes are read, never executed
The local-config audit (T7, and the preflight that refuses to run git) now follows `include.path` and every `includeIf.*.path`, treating every condition as true. Git applies those files, so a `core.sshCommand` or `credential.helper` placed in one runs just like one in `.git/config`. Before this change, git-shield reported only the include line itself, as Medium.

Included files are only *read*, with gix and without includes of their own:
- regular files only (no FIFOs or devices);
- at most 1 MiB each, 3 levels deep, each file once.

Their settings are checked by the same rules and are reported at the included file's path. This changes what git-shield inspects, not what configures it: nothing in an included file can lower a finding.

The one deliberate exception to "no repository file affects git-shield" is the CI accept file in [ADR 0008](0008-ci-mode-and-github-action.md). It is read only from reviewed history, and only when the workflow author opts in.
