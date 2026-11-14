# Agent / contributor guide

**Start here:** read [`docs/PROGRESS.md`](docs/PROGRESS.md) (current state, next task), then [`docs/PLAN.md`](docs/PLAN.md) (phases, architecture). Attack vectors are in [`docs/THREATS.md`](docs/THREATS.md); decisions are in [`docs/adr/`](docs/adr/).

## Build and test
```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test            # unit + end-to-end tests over generated fixture repos
cargo build --release # binary: target/release/git-shield (also usable as `git shield`)
```

## Non-negotiable rules
1. **git-shield never executes repository-controlled code.** Read through gix only (ADR 0001). Any new `git` subprocess must go through `shield_git::hardened::HardenedGit`.
2. **The scanned repo cannot configure git-shield** (ADR 0002).
3. **Test payloads are inert.** Fixtures live in `crates/shield-fixtures`. Every end-to-end test asserts that the `PWNED` marker never appears.
4. A new detector needs: a `docs/THREATS.md` row, unit tests (positive and a benign negative), and an end-to-end fixture when it affects blocking.
5. End every session by updating `docs/PROGRESS.md` (Current state + Session log) in the same commit as the code.
6. Commit messages: plain, imperative, no AI attribution trailers.

## Layout
- `crates/git-shield`: CLI (clap)
- `crates/shield-core`: Finding / Severity / Detector / engine
- `crates/shield-git`: gix access + hardened runner
- `crates/shield-rules`: detectors (one module per family)
- `crates/shield-report`: terminal / JSON output
- `crates/shield-fixtures`: inert hostile repos for tests
