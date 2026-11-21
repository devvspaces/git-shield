# ADR 0007: Verify commit signatures locally, and check "Merge pull request" commits against GitHub

- Status: accepted (2026-11-20). Completes Phase 4, together with ADR 0004. Also absorbs Phase 5's "full GPG/SSH signature verification".

## Context
Until now, git-shield only checked whether a signature was *present* (the `gpgsig` header). Anyone can write a commit that says `committer GitHub <noreply@github.com>` and summary "Merge pull request #2921", with or without a garbage signature. In the matador incident the forged `24f921bf2` was only caught because a rewrite was visible: a previous tip, the reflog, or GitHub's force-push log. A forged merge that arrives without a visible rewrite got a single Medium (`t11.merge-not-by-github`).

GitHub knows the truth for both questions:
- `pulls/{n}` gives `merge_commit_sha`, the one commit GitHub's merge button produced.
- `compare/{base}...{head}` gives `commit.verification` for every commit in the range.

GitHub's own merges are signed with its published web-flow keys, so their signatures can also be checked offline.

## Decision
- **Local verification** (`shield-git::signing`, on by default, `--no-verify-signatures` to skip):
  - The signature and the exact signed bytes come from gix (`CommitRefIter::signature`).
  - `gpgv`, `gpg` and `ssh-keygen` run from an empty temp dir, with a scrubbed environment and a 5 s timeout.
  - Repository config (`gpg.program`, `gpg.ssh.program`) is never consulted.
- **Commits claiming GitHub as committer** are checked with `gpgv` against a bundled keyring, in an empty `GNUPGHOME`, so the user's keyring cannot vouch for them.
  - The keyring is `crates/shield-git/data/github-web-flow.gpg`, dearmored from <https://github.com/web-flow.gpg> on 2026-11-20. It holds:
    - `5DE3 E050 9C47 EA3C F04A 42D3 4AEE 18F8 3AFD EB23`, expired 2024-01-16;
    - `9684 79A1 AFF9 27E3 7D1A 566B B569 0EEE BB95 2194`.
  - A signature made before the key expired still counts as good: `EXPKEYSIG` with the `VALIDSIG` timestamp earlier than `KEYEXPIRED`.
  - Verified on real matador merges from 2022 and 2026.
- **Other GPG signatures** are checked with `gpg --verify` (no key auto-retrieval) against the user's own keyring.
- **SSH signatures** are checked with `ssh-keygen -Y verify` when an allowed-signers file is known: from `[[signing]] allowed_signers`, else global `gpg.ssh.allowedSignersFile`. Without one, `check-novalidate` only proves the signature is intact.
- **GitHub** (same opt-in/opt-out as ADR 0004):
  - one `compare` per range, paged; when the range is longer than 3 pages, the first page and the newest pages;
  - `pulls/{n}` for every distinct "Merge pull request #N" (up to 100, in parallel);
  - the activity log (all push kinds) to name who pushed each incoming commit.
- **When a 404 counts as "PR does not exist":** GitHub answers 404 for anything the token cannot see. A 404 counts only after the repository answered in the same run (a successful compare, or `GET /repos/{o}/{n}`). Otherwise the PR checks are skipped with a note.
- **Cache:** `$XDG_CACHE_HOME/git-shield/github/OWNER__NAME.json` holds only facts that cannot change:
  - final verifications (`valid`, `unsigned`, `invalid`, malformed);
  - merged PRs' merge SHAs;
  - ranges already compared.

  Local verification results are not cached, because keyrings change.

**Rules** (`shield-rules::signing`):

| Rule | When | Severity |
|---|---|---|
| `t11.pr-merge-mismatch` | The commit is not PR N's merge (different SHA, open, closed unmerged, or no such PR) | Critical |
| `t11.pr-merge-mismatch` | The same, but the commit is web-flow signed (GitHub made it; e.g. an upstream merge or a merge later rewritten away) | Low |
| `t11.signature-bad` | Local `BADSIG` / failed SSH check, or GitHub `invalid` / `malformed_*` | High; Critical when the committer claims to be GitHub |
| `t11.github-unverified` | Committer claims GitHub, signed, but neither the web-flow keys nor GitHub's API vouch for it | Critical |
| `t11.signature-unverified` | GitHub `bad_email` / `unverified_email` / `no_user`, grouped per committer. `unknown_key` is ignored as too common | Low |
| `t11.unsigned-required` | Only with `[[signing]] require = true` for the repository: unsigned commits | High |
| `t11.unsigned-required` | Same, for signed commits that could not be tied to the committer | Medium |

Pusher attribution adds a detail ("Arrived in a force-push by @X on …") to commit-level T10/T11 findings. It is evidence, not a rule: direct pushes of other people's commits are normal in rebase workflows.

## Consequences
- The 2026-11-10 forgery is Critical with no local memory at all (`scan --github d9d45eff3..0a32698f4`). On matador-legacy's `dev`, the same check found five more forged "Merge pull request" commits. All five are unsigned, have the attacker's `-0800`/`-0700` timezone and differ in content from GitHub's merge.
- **Cost:**
  - Local verification adds about 3 ms per signed commit, run in parallel: ~0.9 s for 300 signed commits, negligible for normal pulls.
  - A cold GitHub check of a 1,136-commit range takes ~15 s (100 PR lookups). Warm, it takes ~1 s.
- Commits are the only thing verified. Tags, and pushes that bypass GitHub's activity log (GHES without it), are out of scope.

## Addendum (2026-11-21): limits revisited

Session 6 left caps of 300 commits and 100 PRs per scan, read the activity log to 3 pages, and skipped signatures on `clone`/`checkout`.

**GraphQL:**
- PR states and commit verifications are fetched through GraphQL, 100 per request (`{base}/graphql`, or `https://host/api/graphql` for a GHES base ending in `/api/v3`). The token guard allows only that URL.
- `repository: null` means the token cannot see the repository, so nothing is concluded from it.
- When GraphQL fails as a whole, git-shield falls back to REST, capped at 100 lookups.

**What is looked up:**
- Only signed commits are looked up on GitHub. For unsigned ones, GitHub's verdict is always `unsigned`, which is already known.
- Compare fetches only its first page. It proves the repository answers and covers short pulls in one request.

**Budgets:**

| | `check` / `pull` / `scan` | `scan --deep`, `clone`, `checkout` |
|---|---|---|
| Activity pages | 10 | 50 |
| Signed commits (local and GitHub) | 2000 | 5000 |
| PR numbers | 1000 | 5000 |

Every cap that is hit prints a note.

**Activity log:**
- Reading stops at the trust record, at a push that left the branch inside the range base, or once every incoming commit is explained.
- Branch creations are not counted as introducing commits.

**Cache:** local verdicts against the bundled web-flow keyring are cached, keyed by the keyring's hash. They cannot change for a given build. Other local verdicts are still not cached.

**Clone and checkout:**
- They run only the signing rules (`pr-merge-mismatch`, `signature-bad`, `github-unverified`, …) over the history they bring in. Clone covers the newest 50,000 commits.
- The rules that compare a pull with your previous state do not apply.
- `[[signing]] require` is not applied to a clone's existing history.

**Ranges that don't end at a remote-tracking ref** use, in order:
1. `--github-branch`;
2. a remote branch whose tip is the range end;
3. the remote's default branch, if it contains the range end.

The upstream feature branch is never guessed. It contains the whole integration branch, so its creation would claim every commit.

