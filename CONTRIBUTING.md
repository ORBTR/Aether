# Contributing

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/).

Format: `<type>(<scope>): <subject>`

Types:
- `feat:` new user-facing feature (bumps MINOR)
- `fix:` bug fix (bumps PATCH)
- `perf:` performance improvement
- `refactor:` code change that neither adds feature nor fixes bug
- `docs:` documentation only
- `test:` test additions/fixes
- `chore:` build/tooling changes
- `ci:` CI configuration

Add `!` after type for breaking changes, or `BREAKING CHANGE:` footer:

    feat!: rename canonical.PRC to CanonicalPRCAddress

    BREAKING CHANGE: per-chain PRC map removed; callers must use the single constant.

Scope (optional): which subsystem — `wallet`, `escrow`, `btc`, `wasm`, etc.

Example commits:

    feat(wallet): add identity-only mode for BIP44 accounts
    fix(escrow): correct fee BPS rounding in refund path
    feat(btc)!: switch to taproot escrow; breaking fee-output format

## Release automation

Releases are managed by [release-please](https://github.com/googleapis/release-please).
On every push to `main`, release-please parses commits and opens/updates a release PR
with the proposed version bump and generated CHANGELOG. Merging that PR creates a
`vX.Y.Z` git tag; the existing `release.yml` workflow then fires on the tag.
