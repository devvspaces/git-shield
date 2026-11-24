# ADR 0011: Release chain: cargo-dist, build attestations, signed tags

- Status: accepted (2026-11-24).

## Context
git-shield runs on developer machines and in CI, before untrusted code. That makes it worth attacking: a poisoned release would run everywhere git-shield is trusted to protect. Until v0.5.0 everyone built it from source, including the GitHub Action, which took about a minute on a cold runner.

Binaries are needed for macOS (arm64, x64), Linux (x64, arm64) and Windows. A user has to be able to check that a download is exactly what the release workflow built from a given tag, without trusting the download host or a long-lived key.

## Decision
- **Builds:** [cargo-dist](https://github.com/axodotdev/cargo-dist) generates `.github/workflows/release.yml`.
  - It builds the five targets on GitHub-hosted runners, with default features (YARA included).
  - It publishes archives, per-archive `.sha256` files, a `sha256.sum` manifest, shell and PowerShell installers, and a Homebrew formula pushed to `devvspaces/homebrew-tap`.
  - Every third-party action in the workflow is pinned to a commit.
  - Binaries are built with `cargo-auditable`, so the exact dependency list is embedded and `cargo audit bin` can check a shipped binary.
- **Provenance:** every archive and installer gets a GitHub build attestation (SLSA provenance signed through Sigstore). Anyone can check it with `gh attestation verify <file> --repo devvspaces/git-shield`.
  - The attestation names the workflow file, the commit and the tag.
  - There is no git-shield signing key to steal or rotate. The signing identity is the release workflow itself, checked against GitHub's OIDC issuer.
- **Tags:** release tags are annotated and GPG-signed by the maintainer. Only a pushed `v*` tag starts a release.
- **Approval gate:** the publish jobs (GitHub Release, Homebrew, crates.io) run in a `release` environment that requires the maintainer's approval. Its secrets are visible only to that environment:
  - `HOMEBREW_TAP_TOKEN`: fine-grained, Contents write on the tap only;
  - `CARGO_REGISTRY_TOKEN`: publish scope, for the git-shield crates only.
- **crates.io:** the six crates are published in dependency order after the binaries are built. The internal crates are named `git-shield-*` (`shield-core` was taken); their Rust paths are unchanged.
- **The action:** `action.yml` downloads the Linux or macOS archive for the action's own version. It runs it only if two checks pass:
  - the SHA-256 matches;
  - `gh attestation verify --signer-workflow devvspaces/git-shield/.github/workflows/release.yml --source-ref refs/tags/v<version>` succeeds.

  If either check fails, the job fails. If there is no release for that version (an unreleased commit), it builds from the action's own source as before. `build-from-source: true` forces that, and git-shield's own dogfood workflow uses it.

## Consequences
- A tampered archive, a binary from another workflow or tag, or a re-uploaded asset is rejected by the action, and by any user who runs `gh attestation verify`.
- Pinning the action to a release commit gives a run of a few seconds instead of a cold build.
- `@master` between releases runs the last release's binary, not master's code, because the version in `Cargo.toml` only changes at release time. Use `build-from-source: true` to test master.
- The workflow installs dist itself from axodotdev's GitHub release (`cargo-dist-installer.sh` for a pinned version), as the generated workflow does. That download is trusted, not verified. It runs only in the release workflow, not on users' machines.
- `release.yml` carries hand edits after `dist generate` (pins, permissions, environments). `allow-dirty = ["ci"]` lets dist accept them, and `docs/RELEASING.md` says to re-apply them after regenerating.
- A compromise of the maintainer's GitHub account can still produce a valid release. The signed tag and the environment approval make that visible, but do not prevent it. Reproducible builds are not attempted yet.
