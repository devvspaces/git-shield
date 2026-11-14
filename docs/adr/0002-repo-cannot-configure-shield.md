# ADR 0002: A repository can never configure or relax git-shield

- Status: accepted (2026-11-14)

## Context
Many scanners read a config file from the repo they scan (`.toolrc`, allowlists). An attacker who controls the repo would simply allowlist their payload.

## Decision
git-shield reads configuration only from:
1. the user config dir (`~/.config/git-shield/config.toml`, Phase 3+);
2. the per-repo trust store in `.git/shield/` (untracked; written only by git-shield after an explicit `--accept`, Phase 2+);
3. command-line flags.

No tracked file in the scanned repository influences rules, severities, or allowlists.

## Consequences
- Teams cannot ship a shared allowlist in-repo. If needed later, it has to be an explicit opt-in pointing at a *signed* or out-of-repo source, recorded as a new ADR.
