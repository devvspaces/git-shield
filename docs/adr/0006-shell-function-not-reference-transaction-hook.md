# ADR 0006: Gate plain `git pull` with a shell function, not a git hook

- Status: accepted (2026-11-18). Replaces PLAN.md Phase 5's "`reference-transaction` hook that blocks `refs/heads/*` updates to a scanned-bad tip".

## Context
The plan was a `reference-transaction` hook that rejects moving a branch to a tip git-shield had blocked. We tested it against git (scratch repo, hook rejecting `refs/heads/main` in the `prepared` state):

- `git merge --ff-only other` prints "Fast-forward", **writes the new files to the working tree and index**, and only then fails: "ref updates aborted by hook".
- `git reset --hard other` behaves the same way.

So the hook cannot stop a payload from reaching disk. It only leaves HEAD pointing at the old commit while the working tree holds the new files, which is worse than useless. Git has no hook that runs before a fast-forward updates the working tree: `pre-merge-commit` only fires for merge commits.

## Decision
- `git shield install` prints a shell function (bash/zsh, or fish) that sends `git pull …` to `git shield pull …`. With `--write` it adds the function to the shell rc file between `# >>> git-shield >>>` markers, idempotently. `git shield uninstall` removes the block.
- The function honours `GIT_SHIELD_BYPASS=1` for a deliberate one-off.
- `git shield pull` accepts `--ff-only` and `--no-rebase` as no-ops, so common `git pull` habits keep working.
- No git hooks are installed.

## Consequences
- Plain `git pull` in an interactive shell is gated, which covers the common case. IDE "pull" buttons and scripts that call git directly are not covered. `doctor` and the README say so.
- Rc files are only changed on request, and the change is reversible.
