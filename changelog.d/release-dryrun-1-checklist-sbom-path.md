### Fixed
- **The frontend SBOM no longer records the build machine's directory.** `keyorix-server_frontend_sbom.cdx.json` carried cdxgen's `LocalNodeModulesPath` (an absolute path such as `/home/runner/work/...`) on two components. `web/scripts/build-frontend-sbom.mjs` now drops those properties and refuses to write an SBOM that still contains the repository path.

### Documentation
- **Release checklist.** `docs/releases/RELEASE-CHECKLIST.md` gives the order of work and the exact commands for cutting a release, including a local rehearsal of `make release` and the post-tag verification. `scripts/changelog-dedupe.sh` finds the changelog fragments a side-branch patch release already published, so they are not printed twice in the next minor.
