# ADR 0004: Ask GitHub for a branch's force-push history (opt-out in check/pull, opt-in in scan)

- Status: accepted (2026-11-18). Moves the activity-API slice of Phase 4 forward; the rest of Phase 4 (commit verification, PR merge-SHA match) is unchanged.

## Context
Offline rewrite detection (T10) needs to remember a previous tip: the pre-fetch value, the reflog, or the trust store. A user who pulled before installing git-shield has none of these. The same is true for a repo whose reflog expired (after 30 days without a trust record, git-shield ignores the reflog). In matador-legacy, three force-pushes by the compromised accounts (10-28, 11-04, 11-11; one dropped PR #2934's merge) were invisible offline.

GitHub records every force-push in the repository activity log: `GET /repos/{o}/{r}/activity?activity_type=force_push`, which returns `before`, `after`, actor and time.

## Decision
- New crate `shield-github` (ureq + rustls). The token comes from `GITHUB_TOKEN` / `GH_TOKEN`, else `gh auth token`. That runs from a temp dir with a scrubbed environment and a 5 s timeout.
- The token is only sent to the API base: `https://api.github.com`, or `GIT_SHIELD_GITHUB_API` for GHES and tests. Pagination links pointing elsewhere are refused. The owner/name comes from the remote URL only when its host is exactly `github.com`, or from `--github-repo OWNER/NAME`.
- `check` and `pull` query by default (they already use the network); `--no-github` disables it. `scan` keeps its "no network" promise and queries only with `--github`.
- A force-push counts when all of these hold:
  - it was made by someone other than the token's owner;
  - it happened after the trust store's record for the ref;
  - its `after` is still in the history being pulled.

  Its `before` then becomes a previous tip (`TipSource::GitHub`) for the existing T10/T11 detectors. Missing `before` objects are fetched by SHA (at most 5) in `check`/`pull`. When they are still missing, a finding is reported from the API data alone.
- If the rewritten result is already in the user's HEAD (pulled before git-shield was watching), the finding is **Medium** ("already in your branch"). It is visible but does not block a pull that brings nothing new.
- `t10.ref-rewritten` is anchored on the replaced tip (`rewrite:<sha>`), so an acceptance survives later pulls.
- Every failure (no token, offline, HTTP errors, rate limit) prints one `note:` line and the scan continues offline.

## Consequences
- Old rewrites are caught without local memory, and findings name the pusher (`@login`, time).
- `check`/`pull` add one or two HTTPS round trips (about 1 s on matador-legacy).
- No new trust is placed in the repository: it cannot pick the host the token goes to.
