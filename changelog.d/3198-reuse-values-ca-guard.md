### Security
- **The entrypoint refuses to publish anything but a certificate as `KEYORIX_PUBLIC_CA_FILE`.** `KEYORIX_LOCAL_CA_FILE` is copied to a world-readable (0644) file on the volume shared with the web container; the entrypoint now exits non-zero, creating no public file, when the source is not a regular file, contains any `PRIVATE KEY` PEM block, or is not a PEM `CERTIFICATE` bundle (nothing else allowed, at most 256 KiB). The copy is made privately (0600) and the copy is what is checked. Guarded by `server/entrypoint_public_cert_test.go`.

### Fixed
- **`helm upgrade --reuse-values` from chart 0.95.x to 0.96.x no longer fails with `nil pointer evaluating interface {}.enabled`.** `--reuse-values` drops the new chart's defaults, so `secureBaseline.*`, `web.hsts.*`, `web.trustedProxies`, `postgresql.runAsUser`/`migrateOwnership` and `auth.existingSecretKeys.*` were missing. The chart now fills in a missing value with its `values.yaml` default (an explicit value, `secureBaseline.enabled=false` included, is kept); `secureBaseline` stays on by default. Guarded by `TestHelmReuseValues_*`, which renders the chart with only the 0.95.3 values file. `--reset-then-reuse-values` (Helm 3.14+) is still the recommended flag.

### Documentation
- `docs/UPGRADING.md`: the 0.96.0 Helm upgrade command uses `--reset-then-reuse-values` and says which flag works with which chart; stale "latest is v0.95.3" text removed. `QUICK_START.md`, `docs/SELF_HOSTING.md` and `INSTALL-WITH-AI.md` no longer present v0.95.3 as the newest release (v0.96.0 has `admin generate-secrets` and `mfa enroll`).

### Testing
- The Helm chart hardening tests (`deploy/hardening`) now run with `secureBaseline.enabled` both `true` and `false`, so the opt-out is covered by the existing CI job.
