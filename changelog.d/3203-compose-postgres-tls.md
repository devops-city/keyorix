### Security
- **The Compose stack's PostgreSQL now serves TLS, and the server connects with `ssl_mode: verify-full`.**
  `keyorix.docker.yaml` had `ssl_mode: prefer`, which falls back to plaintext whenever the TLS
  attempt fails (anything on the network path that answers "no TLS" gets the password exchange in
  the clear). `scripts/selfhost/init-secrets.sh` now also generates a self-signed Postgres
  certificate and key (`secrets/postgres_tls.crt`, `.key`, named `postgres`, needs `openssl`); the
  `postgres` service runs with `ssl=on` from them and the server uses the certificate as its
  `ssl_root_cert`, so the connection is encrypted and the server is authenticated, and a Postgres
  without TLS (or with another certificate) makes the server refuse to start. **Upgrade from
  v0.96.x:** pull the new files, run `./scripts/selfhost/init-secrets.sh` (it keeps every existing
  secret and adds the pair), bump the image pins, `docker compose up -d`; the data volume is not
  touched (docs/UPGRADING.md). Guarded by `TestComposeSecureConfig_NoInsecureSettingInEffect`,
  `TestComposeConfig_DatabaseIsVerifyFullWithRootCert` and the init-secrets tests in deploy/.
- **`ssl_mode: prefer` and `allow` are now a registered insecure setting.**
  `storage.database.insecure_allow_plaintext_database_fallback` is in effect when the effective
  sslmode (including a `dsn` with no `sslmode`, which is the driver's default `prefer`) can fall
  back to plaintext. `admin validate --posture` counts it as a deviation and the server logs it at
  boot. If you run an external Postgres with `prefer`/`allow`, switch to `require`, or better
  `verify-full` with `ssl_root_cert`.

### Testing
- `scripts/demo/check.sh --postgres` generates the Postgres certificate with the real
  `init-secrets.sh`, and its compose project, published port and image names are overridable
  (`KEYORIX_DEMO_CHECK_PG_PROJECT`, `_PORT`, `_WEB_IMAGE`, `KEYORIX_DEMO_IMAGE`) so a shared Docker
  host can run it without touching another run's resources.
