# ADR 0003: The trust store lives in the user data directory, not in `.git/`

- Status: accepted (2026-11-16). Amends ADR 0002 item 2 and PLAN.md's `.git/shield/trusted.json`.

## Context
`git shield pull` remembers two things per repository: the last tip pulled through git-shield for each ref, and the finding ids the user accepted (with a reason). The plan put this in `.git/shield/trusted.json`.

`.git/` is not tracked, but it is not trustworthy either. A repository that arrives *as files* (a zip, a tarball, rsync, a shared drive, an agent sandbox: the GitSpawn class) brings its own `.git/` directory. An attacker could ship a `.git/shield/trusted.json` that pre-accepts their findings, or a fake "last trusted tip" that hides a rewrite.

## Decision
- The store is kept under the user's data directory: `$GIT_SHIELD_HOME`, else `$XDG_DATA_HOME/git-shield`, else `~/.local/share/git-shield`.
- The file is `repos/<first 16 hex of sha256(canonical common git dir)>.json`. It records `repo_path`, and is ignored if `repo_path` does not match the repository being scanned.
- Only git-shield writes it: `pull` after a successful integration (ref tip), plus `--accept`/interactive acceptances (id, reason, tip, time). Writes are atomic.
- Reflog entries written by the user's own `git push` are treated as deliberate. The tip they replaced is never reported as rewritten. This covers restoring a branch after an attack, and force-pushing your own rebase.

## Consequences
- Moving or re-cloning a repository starts with an empty store. Previous acceptances do not follow, which is the safe default.
- `GIT_SHIELD_HOME` lets tests and unusual setups relocate the store. It is an environment variable, so it is controlled by the user, never by the repository.
