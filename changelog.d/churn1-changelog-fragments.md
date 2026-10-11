### Changed
- **Unreleased changelog entries now live in `changelog.d/`, one fragment file per PR**,
  instead of in `CHANGELOG.md`'s `## Unreleased` section, so merging one PR no longer
  conflicts every other open PR. `scripts/changelog-assemble.sh vX.Y.Z` merges them into
  `CHANGELOG.md` at release time (`RELEASING.md`); `--check` validates them in CI.
