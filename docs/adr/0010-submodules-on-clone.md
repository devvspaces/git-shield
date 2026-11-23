# ADR 0010: Submodules on `clone`: scan everything, then check out everything

- Status: accepted (2026-11-23).

## Context
`git clone --recurse-submodules` fetches and checks out every submodule. Each one is a separate repository with its own history and its own payloads. Until now, `git shield clone` checked out only the superproject and printed a note when `.gitmodules` existed, so users either skipped submodules or ran plain git for them, unchecked.

Submodules also carry attacks of their own: option injection in URLs, `ext::` transports, names and paths that escape into `.git/` (CVE-2017-1000117, CVE-2018-11235). git-shield already reports these in `.gitmodules` (T8). The clone path must not trigger them itself.

## Decision
`git shield clone --recurse-submodules` (opt-in, like git's flag):
1. Clone and scan the superproject without a checkout, as before.
2. Read `.gitmodules` and the gitlinks from the **scanned commit**, never from a working tree. For each submodule, up to 3 levels deep and 50 in total:
   - The name and path must be relative, with no `.` or `..` components and no `.git` component.
   - The URL is resolved the way git does relative URLs: each `../` drops one component of the superproject URL, and never climbs past `scheme://` or an scp-style `host:`.
   - Only `https://`, `http://`, `ssh://`, `git://`, scp-style `user@host:path` and relative URLs are accepted. URLs starting with `-` or using a transport helper (`::`) are refused. A local path is accepted only when the superproject itself is local.
   - The submodule is cloned with the hardened runner, without a checkout, straight into `.git/modules/<name>`.
   - A pinned commit missing from the clone is fetched by SHA once; if it is still missing, the submodule is left uninitialized with a note.
   - Its tree at the pinned commit is scanned with the same rules, plus the signature and PR pass. Finding paths are prefixed with the submodule path.
3. All reports are merged, and one gate decides. If anything blocks, **nothing** is checked out: the superproject and every submodule stay as `.git` data only.
4. Otherwise the superproject gets `reset --hard`. Each submodule then gets a `.git` file and `core.worktree` (git's own layout) and is checked out detached at the pinned commit. Finally `submodule.<name>.url` and `.active` are written to the parent's config, so `git submodule status` and later `git submodule update` work as usual.

Without the flag, `clone` says up front that submodules exist and are not fetched.

## Consequences
- A payload in a submodule blocks the whole clone, before any file is written anywhere (tested).
- Verified on a public repository with two https submodules. `git submodule status` shows both initialized at their pinned commits, with clean worktrees.
- Updating submodules later (`git submodule update`) is plain git and is not checked. `git shield pull` does not follow submodule changes yet.
