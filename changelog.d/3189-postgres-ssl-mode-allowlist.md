### Security
- **PostgreSQL `ssl_mode` is checked against what the connection really does.** `ssl_mode` next
  to a `dsn` used to be silently ignored, so `ssl_mode: verify-full` with a dsn saying
  `sslmode=disable` connected in plaintext and was not reported. Now, when both are set, the
  dsn's own `sslmode` must equal `ssl_mode` or the server **refuses to start**. An `ssl_mode` (or
  dsn `sslmode`, or `PGSSLMODE`) outside `disable`, `allow`, `prefer`, `require`, `verify-ca`,
  `verify-full` is refused at start-up with the list of valid values. The insecure-settings warning
  (`storage.database.insecure_disable_database_tls`) and `admin validate --posture` now read the
  effective sslmode: the dsn's, then `PGSSLMODE`, then the driver default `prefer`, including the
  URL `ssl=true` alias. **Upgrade note:** see docs/UPGRADING.md.
