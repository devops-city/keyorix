- **INV-STORAGE-postgres-password-on-parsed-config** The PostgreSQL password from
  `KEYORIX_DB_PASSWORD`, `KEYORIX_DB_PASSWORD_FILE` or `storage.database.password` never becomes
  part of a connection string. `config.ResolvePostgresConnConfig` parses `storage.database.dsn`
  (or the field-built DSN, which carries no password) with `pgx.ParseConfig` — the driver's own
  parser — sets the password on the parsed config, and every connection
  (`createPostgresStorage`, `OpenGormDB`, `serverguard`, admin restore and verify-audit) is
  opened from that config with `stdlib.OpenDB`. So host, port, sslmode, sslrootcert and every
  other setting are exactly what pgx reads from the configured DSN, whatever bytes the password
  holds, and whatever DSN shape a hand-written splice would have misread. Why: #3159 spliced the
  password into the DSN; a keyword DSN ending in `\` let the password inject
  `sslmode=disable host=…`, and a URL with `?` in the userinfo made pgx connect to a different
  host with `sslmode=prefer` (REVIEW-3162B, on main since v0.96.0). Guard:
  `internal/config/postgres_credentials_guard_test.go:TestPostgresCredentialsReachTheDriverOnlyAsParsedConfig`
  (type-checked: no package outside internal/config reads `DatabaseConfig.DSN`, `.Password` or
  `.GetPassword()`); `internal/config/postgres_dsn_test.go`
  (`TestResolvePostgresConnConfig_PasswordCannotChangeTheConnection`, both `_Review3162B_` repros);
  open-ended by
  `internal/config/postgres_dsn_fuzz_test.go:FuzzResolvePostgresConnConfig_PasswordCannotChangeConnection`
  ((DSN, password) pairs against pgx's parse of the DSN alone); real server:
  `postgres_dsn_password_test.go:TestPostgresDSN_InjectionPasswordReachesRealServer` (pg-gated).
  **Not covered**: DSNs that do not come from `storage.database` (dynamic-secrets engines,
  `admin verify-audit --pg-dsn`).
