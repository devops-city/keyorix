### Security
- **`keyorix-server admin init` writes the secure baseline** (ADR-112 §4):
  `admin validate --posture` reports zero deviations on a fresh install. TLS is
  on and required, with a generated self-signed certificate
  (`certs/server.crt`/`.key`); API rate limiting is on; `/metrics` requires a
  generated token read from the new `server.http/grpc.metrics_token_file`
  (`secrets/metrics_token`). All generated files are `0600` and never printed.
  An existing config is not changed and nothing is generated for it.
  `admin init --dev` writes the previous relaxed config, labelled DEV-ONLY.
  Guarded by `server/admin_init_secure_baseline_test.go`.
- **The CLI can trust a private CA or self-signed server certificate:**
  `keyorix config set ca_file <path>`, `KEYORIX_CA_FILE`, or `--ca-file`. The
  CLI then trusts exactly that file's certificates, the same on macOS and Linux
  (`SSL_CERT_FILE` is ignored on macOS). `login` remembers the CA file it used.
