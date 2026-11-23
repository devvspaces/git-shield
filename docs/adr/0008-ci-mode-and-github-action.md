# ADR 0008: `git shield ci`, SARIF, and a GitHub Action

- Status: accepted (2026-11-23). Part of Phase 6.

## Context
Every local command protects only the person who runs it. IDE pull buttons, scripts and teammates without git-shield go around it (ADR 0006).

The attack that started this project was a force-push straight to an integration branch. A check that runs on GitHub, on every push and pull request, sees that push whoever made it and with whatever tool. Its results have to reach people where they already look: the job status, annotations on the diff, and the repository's code-scanning alerts.

## Decision
**`git shield ci`** is a subcommand, not a `scan` flag, so the event handling stays in one place (`crates/git-shield/src/ci.rs`). It reuses the scan pipeline as is.

The range comes from the event payload (`$GITHUB_EVENT_PATH`, `$GITHUB_EVENT_NAME`, or `--event` / `--event-name`), never from the checked-out tree:

| Event | Range | Also |
|---|---|---|
| `pull_request`, `pull_request_target` | `base.sha..head.sha` | Push history of the head branch, only when it lives in the same repository |
| `push`, branch created (`before` all zeros) | default branch..`after` | |
| `push` | `before..after` | |
| `push`, forced (or `before` is not an ancestor of `after`) | `before..after` | `before` is a previous tip, so `t10.ref-rewritten` and `t11.rewritten-copy` apply with no reflog and no trust store |
| `push` deleting the ref | nothing; exit 0 | |
| any other event | the given range, else `HEAD~1..HEAD`, with a note | |

- **Missing objects:** an object that is not in the checkout, typically a force-pushed-away `before`, is fetched once by SHA with the hardened runner. The action does this itself before the scan, using the job token. If the fetch fails, a note says so, and GitHub's force-push log still reports the rewrite.
- **Inside Actions:**
  - the repository comes from `$GITHUB_REPOSITORY`;
  - the API base comes from `$GITHUB_API_URL` (GHES), unless `GIT_SHIELD_GITHUB_API` is set. The token is still sent only to that one base.
- **Installation tokens:** `/user` answers 403 for Actions' `GITHUB_TOKEN`. That now means "no viewer": nobody's force-pushes are excluded as "your own". It no longer means "skip the force-push log". The activity, compare, GraphQL and pulls endpoints all work with `contents: read` and `pull-requests: read`.
- **Outputs:**
  - The usual terminal report, in the job log.
  - Workflow commands: `::error` for unaccepted findings at or above `--fail-on`, `::warning` for other Medium and above, `::notice` for Low. Repository text is escaped (`%`, CR and LF in messages; also `:` and `,` in properties), so a commit summary cannot start a workflow command of its own.
  - Markdown appended to `$GITHUB_STEP_SUMMARY`. Every table cell is escaped, so no links, images or HTML come from repository text.
  - SARIF with `--sarif FILE` (available on every scanning command).
- **Exit status:** 2 when an unaccepted finding is at or above `--fail-on` (default `high`, as `pull` blocks); 0 otherwise; 3 on error. Warnings never fail the job unless `--fail-on` says so.
- **Accepting findings in CI:**
  - `--accept`, the user config (`GIT_SHIELD_CONFIG`) and `--accept-file FILE` work as usual.
  - `--accepts-path PATH` reads `[[accept]] id/reason` entries from the repository, but only at the trusted side of the event: the PR base, or the branch before the push (for a new branch, the default branch). Never from the incoming commits.

    This is the one place a repository file affects git-shield. It is narrow: the workflow author opts in, and the file must already be in reviewed history. A pull request that adds its own acceptances has no effect until it is merged.

**SARIF 2.1.0**, written by hand: the subset is small, and that avoids another dependency.
- One `rules[]` entry per rule id, with the threat as description, `security` plus threat tags, and `security-severity` (Critical 9.5, High 8.0, Medium 5.5, Low 3.0, Info 1.0).
- `partialFingerprints.gitShieldId/v1` holds the finding id, so alerts stay stable across runs.
- Accepted findings remain as `suppressions: [{kind: external}]`, so the decision stays visible.
- Code scanning needs a location for every result. Commit-level findings (T10, T11) point at a placeholder path, `.git-shield/commits/<sha>`, with the commit in the message.

**The action** is a composite `action.yml` at the repository root.
1. It builds git-shield with `--no-default-features` from the action's own source, never from the repository being scanned.
2. It fetches a force-pushed-away `before`.
3. It runs `git shield ci`.
4. It uploads SARIF with `if: always()`. Fork PRs are skipped, because their token cannot write code-scanning results.

- **Inputs** reach the shell only through `env:`, never through `${{ }}` inside `run:`.
- **Pinning:** third-party actions are pinned by commit SHA, at least two weeks old.
- **Untrusted PRs:** git-shield never runs repository code, so the `pull_request` trigger is safe for fork PRs. `pull_request_target` is not needed.
- **Dogfooding:** `.github/workflows/git-shield.yml` runs the action (`uses: ./`) on this repository.

## Consequences
- **Real data:** a forced-push event replaying the 2026-11-10 incident blocks.
  - Offline, from the event alone: `t10.ref-rewritten` High, `t11.rewritten-copy` and `t10.tampered-payload` Critical.
  - With the API: the same, plus `t11.pr-merge-mismatch` Critical and the pusher's name.
- **Cost on GitHub-hosted runners:**
  - The cold build adds about a minute until Phase 7 ships prebuilt binaries. The cache cuts it to seconds.
  - The scan of a normal push takes about 2 s.
- **The placeholder path for commit findings** is visible in code scanning as a file that does not exist. That is the price of putting commit-level results in a file-oriented format; the message carries the real commit.
