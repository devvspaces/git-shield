# Releasing git-shield

See [ADR 0011](adr/0011-release-chain.md) for why the chain looks like this.

## One-time setup (done for v0.6.0)
- **Tap:** a public repo `devvspaces/homebrew-tap`.
- **`release` environment:** in git-shield → Settings → Environments.
  - Required reviewer: the maintainer.
  - Deployment tags: `v*` only.
  - Secrets:
    - `HOMEBREW_TAP_TOKEN`: a fine-grained PAT with access to `devvspaces/homebrew-tap` only, permission Contents read and write.
    - `CARGO_REGISTRY_TOKEN`: a crates.io token with the `publish-new` and `publish-update` scopes. Once the crates exist, limit it to `git-shield*`.

## Regenerating release.yml
`dist generate` overwrites the hand edits. Re-apply them:
- pin every `uses:` to a commit;
- set top-level `permissions: contents: read`, with `contents: write` only on `plan`, `host` and `announce`;
- add `environment: release` on `host` and `publish-homebrew-formula`;
- use the `github-actions[bot]` identity for the tap commit;
- point the crates job at `./.github/workflows/publish-crates.yml`.

## Each release
1. **Check that `master` is green:** CI on Linux, macOS and Windows, the lean build, and the git-shield scan.
2. **Bump the version.** Change `workspace.package.version` and the five `version = "=X.Y.Z"` pins in the root `Cargo.toml`, then run `cargo build` to update `Cargo.lock`.
3. **Run the local checks:**
   - `cargo package --workspace --exclude shield-fixtures --exclude shield-bench`
   - `dist plan`
4. **Update the docs:** PROGRESS (current state and a session log entry), the PLAN changelog, and the README if commands changed. Commit as "Version X.Y.Z".
5. **Tag and push:** `git tag -s vX.Y.Z -m "git-shield X.Y.Z: …"` (signed), check it with `git tag -v vX.Y.Z`, then `git push origin master vX.Y.Z`.
6. **Approve the run.** Open the `Release` run in Actions and approve the `release` environment once the builds are green.
7. **Verify the release:**
   ```sh
   gh release download vX.Y.Z --repo devvspaces/git-shield -p 'git-shield-aarch64-apple-darwin.tar.xz*'
   shasum -a 256 -c git-shield-aarch64-apple-darwin.tar.xz.sha256
   gh attestation verify git-shield-aarch64-apple-darwin.tar.xz --repo devvspaces/git-shield
   brew upgrade devvspaces/tap/git-shield && git shield --version
   cargo install git-shield --locked --version X.Y.Z --root "$(mktemp -d)"
   ```
8. **Check the action.** Run the action pinned to the release commit, without `build-from-source`. The log must show "Download and verify git-shield" passing, not a source build.
