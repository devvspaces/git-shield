# ADR 0005: The allowlist lives in the user's config; Critical needs pinned content

- Status: accepted (2026-11-18). Builds on ADR 0002 (the repo cannot configure git-shield) and ADR 0003 (the trust store is in the user data dir).

## Context
Phase 3 adds detectors for things some teams use on purpose: MCP servers, agent hooks, devcontainer commands, npm `prepare` scripts. Those teams need a durable "we reviewed this" that is broader than one finding id. That decision must not be something an attacker can ship with the repository.

## Decision
- The allowlist is `[[allow]]` entries in the **user** config:
  1. `$GIT_SHIELD_CONFIG`;
  2. else `$XDG_CONFIG_HOME/git-shield/config.toml`;
  3. else `~/.config/git-shield/config.toml`.

  Nothing is ever read from the scanned repository.
- An entry matches on:
  - `rule`: a glob, required;
  - `path`: a glob, optional;
  - `blob`: a prefix of the content id the finding is anchored on, optional, at least 7 hex characters;
  - `repo`: a glob over `github.com/OWNER/NAME` or the remote URL, optional.

  `reason` is required, and an entry with only a broad rule is rejected. Unknown keys are errors.
- Matching findings are **accepted**, not hidden. They appear in the report and in JSON `accepted`, and they do not block.
- **Critical findings are only covered by an entry that pins `blob`.** A broad glob that would match a Critical finding prints a note and is not applied, so it cannot silence a new payload that lands on an allowed path.
- An invalid config is an error (exit 3), never silently ignored.

## Consequences
- Teams can keep a reviewed MCP server or hook quiet across pulls. Changing its content still produces a new finding when pinned by `blob`, and still re-blocks if it turns Critical.
- `git shield config path|check` shows and validates the file.
