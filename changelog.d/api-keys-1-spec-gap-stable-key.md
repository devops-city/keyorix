### Changed

- `web/scripts/check-api-contract.mjs`: `KNOWN_VIOLATIONS` entries are now keyed by `<file> <METHOD> <path template>` (e.g. `secrets.ts POST /api/v1/secrets/{dyn}/transfer-ownership`) instead of `file:LINE`, so edits above a call in `web/src/services/*` no longer shift the key and conflict with parallel PRs. The same 18 spec gaps are tolerated; a new unlisted call, a second call to a listed key and a stale entry all still fail.

### Fixed

- `web/pnpm-lock.yaml`: removed a duplicated `source-map-js@1.2.2` block (packages and snapshots) that made `pnpm install` fail with `ERR_PNPM_BROKEN_LOCKFILE`.
