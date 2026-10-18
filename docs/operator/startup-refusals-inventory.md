# Startup and command refusals: inventory and how it was built

This is the maintainer-side list behind [startup-refusals.md](startup-refusals.md) (the
operator page). It records **how the list was established, what it recognises and what it
does not**, then every refusal found, grouped the same way as the operator page. Line
numbers are from the tree this was written against and will drift; the operator page and
its guard test (`internal/refusaldocs`) match on message text, not on lines.

## How the list was established

A "refusal" here is any place where a boot or an `admin` command stops with an error the
operator reads: a `log.Fatalf` in `server/main.go`, or an error value that `main` (or an
`admin` command) turns into one. All of the server's fatal exits are in `server/main.go`:
`log.Fatalf` appears only there (the other `log.Fatal`/`os.Exit` hits in non-test code are
comments, and `os.Exit(admin.Execute(...))` which only forwards an `admin` return code). So
the inventory is the set of error values that can reach those exits, plus the `admin`
command errors.

Call forms searched, in non-test `.go` files:

- `log.Fatal`, `log.Fatalf`, `log.Fatalln`, `os.Exit(` (whole `server/` and `internal/`);
- `fmt.Errorf(` and `errors.New(` including the multi-line form (`Errorf(` at end of line);
- `panic(` and `os.Stderr` writes in the boot path (one hit: `logging.Setup(..., os.Stderr)`);
- string constants that are later wrapped in `fmt.Errorf("%s", const)`
  (`singleWriter*Error`, `auditDurabilityStandardSQLiteUnsupportedError`,
  `errUndeclaredTransactionPooler`), found by reading the call sites;
- the words `refus`, `must`, `fail-closed` in comments, to find refusals built another way.

Directories and files covered: `server/main.go`, `server/adr112_grace.go`,
`server/http_server.go`, `server/lock_loss.go`, `internal/config/*` (config.go,
database_tls.go, database_pooler.go, postgres_dsn.go, postgres_session_tag.go,
tls_ciphers.go, insecure_*.go, startup_validation_state.go, require_mfa_state.go),
`internal/storage/factory.go` and `postgres_open.go`, `internal/serverguard`,
`internal/solewriter`, `internal/keyfiles`, `internal/startup`, `internal/secretenv`,
`internal/crypto/passphrase.go`, `internal/encryption/exclusive_lock.go`,
`internal/encryptionops`, and `server/admin` (backup, restore, restore_postgres,
admin.go, init, recovery_key, recover_admin).

Not searched (so not in the list):

- Messages assembled at run time from variables (`fmt.Errorf(msg)` with `msg` built
  elsewhere; `describeMountedInputMismatch`; the `%s` values inside connector/rotation
  messages). The text around the variable is listed; the variable part is not.
- Refusals in code the boot path only reaches through an interface (storage drivers other
  than SQLite/PostgreSQL, KMS/TPM/Shamir key providers, SIEM/notification/evidence
  targets). Their errors are wrapped as `failed to init ...` in `server/main.go` and listed
  as one family.
- `server/admin` commands other than backup, restore, encryption, init, recovery-key,
  recover-admin and the shared lock check (`validate`, `audit`, `login-lockout`,
  `check-admin-password`, `generate-secrets`, `posture` were read only for `--force` and
  lock behaviour).
- The `keyorix` CLI (`cli/`, out of scope for this item) and the Helm chart / entrypoint
  scripts (`deploy/helm`, `deploy/docker`; container-only refusals are marked
  "pending e2e VM" in the report).
- The 70-odd per-table `failed to migrate <table> table` errors in
  `internal/storage/factory.go` (lines ~2038-2835) are one family, see "Database".
- Anything added after this tree: HA-SECRET-KEYS-1 and KEYSET-MANIFEST-1 are expected to
  add refusals in `server/main.go` and `internal/config`; the guard test reports them as
  undocumented rather than failing.

## Inventory

`R` = reproduced with the native binary for the operator page, `C` = from code only.

### Configuration (Validate, `Configuration is invalid:` / `Failed to load configuration:`)

| | Where | Message (stable part) |
|---|---|---|
| R | config.go:3009 | `invalid storage.type` |
| C | config.go:3001 | `storage.type is not set: no storage configuration found` |
| R | config.go Load, unknown_key.go | `failed to unmarshal config` (unknown / misplaced key; names the YAML section: `check its spelling and section in docs/CONFIGURATION.md`) |
| C | config.go:2628 | `failed to read config file` |
| R | config.go:2903 | `HTTP server is enabled but no port is specified` |
| C | config.go:2907 | `gRPC server is enabled but no port is specified` |
| C | config.go:2917 | `autocert is enabled but no domains are specified` |
| R | config.go:2921 | `TLS is enabled but cert_file or key_file is missing` |
| C | config.go:2931-2934 | `gRPC TLS auto_cert is not supported`, `gRPC TLS is enabled but cert_file or key_file is missing` |
| C | config.go:2964 | `postgres storage requires either database.dsn or all of host, name, and user` |
| C | config.go:2981 | `database path is not specified` |
| C | config.go:2791 | `database.path ... must not contain ".."` |
| R | config.go:3035 | `unsupported language` |
| C | config.go:3038 | `unsupported fallback language` |
| C | config.go:3016-3019 | `max_secret_size ... must not be negative`, `exceeds the hard ceiling` |
| R | config.go:3304 | `server.http.allowed_origins must not contain "*"` |
| C | config.go:3308-3311 | `allowed_origins entry ... is not a valid origin` / `must use http or https` |
| R | config.go:3287 | `remote cannot back a server process` |
| C | config.go:394, 438 | `server.log.format: unknown value`, `on_sink_stall: unknown value` |
| C | config.go:892, 912 | `audit_durability: unknown value`, `audit_durability is ... but the deprecated` |
| R | config.go:927 | `standard is only supported with PostgreSQL` |
| R | secretenv.go:71 / config.go:2526 | `set exactly one (the secret may come from the environment or from a file, never both)` |
| C | config.go:612 | `both metrics_token and metrics_token_file are set` |
| C | config.go:3095-3098 | `is not a Go duration`, `is outside the allowed range` (one-time-password expiry) |
| C | config.go:2868 | `is not an IP address` |
| C | config.go:3130-3241 | connector checks: unrecognized type / scope, missing scope, project, `project_id`, malformed `account_id` |
| C | config.go:3339, 3378 | SAML `insecure_allow_idp_initiated_saml` unsupported; `cross-seam audience collision` |
| C | config.go:3405-3429 | WebAuthn: `rp_id is not set`, `no rp_origins`, `rp_origin ... must use https`, host/rp_id mismatch |
| C | main.go:862 | `Invalid secret_name_policy` |
| C | main.go:188-189 | `logging.Setup` failure printed under the `Configuration is invalid:` prefix |
| C | main.go:228 | `Failed to initialize i18n system` |
| C | main.go:148 | `invalid file descriptor` (`--passphrase-fd`) |

### TLS (listeners and database)

| | Where | Message (stable part) |
|---|---|---|
| R | main.go:2160 | `listener has no TLS but security.require_transport_tls is set` |
| R | tls_ciphers.go:81, refused by Config.Validate | `is not a recognized, secure TLS 1.2 cipher suite` |
| C | tls_ciphers.go:21 | `is not a recognized TLS mode` |
| C | main.go:600 | `no PEM certificates found in` |
| C | main.go:2647 | `invalid TLS configuration` |
| C | main.go:2665 | `autocert: cannot create cert cache dir` |
| C | main.go:2049, 2522-2528 | `failed to bind HTTP listener`, `failed to listen on gRPC port` |
| R | database_tls.go:255 | `but no CA certificate is configured` |
| R | database_tls.go:87 | `is not a valid sslmode` |
| R | database_tls.go:286 | `cannot be combined with storage.database.dsn` |
| C | database_tls.go:144 | `when dsn is set` (ssl_mode vs dsn disagree) |
| C | database_tls.go:304 | `ssl_root_cert is set but storage.database.ssl_mode is disable` |
| C | database_tls.go:193-233 | CA file: not a regular file, `writable by group or others, refusing to trust it`, larger than limit, `contains a private key`, no PEM certificate |
| C | database_tls.go:340, 345 | `selects a PostgreSQL connection service` (dsn / `PGSERVICE`) |
| C | database_tls.go:454-603 | connection string syntax errors (`malformed`, `unterminated`, `forbidden NUL byte`) |
| C | postgres_dsn.go:69, 289 | `dsn already contains a password`, `the PostgreSQL driver's connection settings differ from what the TLS` |

### Database and storage

| | Where | Message (stable part) |
|---|---|---|
| C (j7) | serverguard.go:321 | `connect to postgres for server-presence check` (Postgres unreachable; real output is in j7) |
| C | factory.go:427, 437 | `storage.type is not set`, `invalid storage.type` (storage factory, CLI callers) |
| C | factory.go:595 | `no database found at ... require_existing_path is set` |
| C | factory.go:483-491 | `failed to create database directory`, `failed to pre-create database file` |
| C | factory.go:626 | `failed to connect to database` |
| C | factory.go migrateError | `failed to migrate database` (wrapper of the family below); the epoch/floor checks are wrapped `checked before migrating; nothing was migrated` |
| C | factory.go:1264 | `cannot create unique index on ... pre-existing group(s) of rows already share a value` |
| C | factory.go:2038-2835, 3081-3585 | ~70 `failed to migrate <table> table` / `failed to create ... index` (one family: a migration step failed; the wrapped driver error is the cause) |
| C | main.go:768 | `secret-value encryption did not engage` |
| C | main.go:814 | `notification channel URL encryption backfill failed` |
| C | main.go:908-1173 | `failed to init <SIEM / notification / evidence / credential delivery / OIDC / WebAuthn>` family |
| C | main.go:1281 | `connector(s) with unresolvable project binding` |
| C | main.go:2940, 3110-3135 | `which this server binary was not built with` (no-cloud build tags) |
| C | main.go:2990 | `audit.checkpoint_notary` |
| C | pooler: database_pooler.go:60-100 | pooler / native_read_pool_max misuse (see HA) |

### Keys and secrets files

| | Where | Message (stable part) |
|---|---|---|
| R | startup/validation.go, securefiles.FixFilePerms | `permissions or ownership audit found unresolved issues: <file and problem>` (the cause is in the refusal since STARTUP-HARDEN-1) |
| R | startup/validation.go explicitFirstBootRefusal | `no key material exists` (explicit `enable_file_permission_check` on a brand-new install) |
| C | main.go enforceKeyFilePermissions | `key material is readable beyond its owner`, `key material is owned by an account the server does not trust` (#3410) ... `refusing to start (chmod 600 and chown` |
| C | startup/validation.go:456-515 | `KEK salt path is unsafe`, `DEK path is unsafe`, `KEK salt file not found`, `has invalid size`, `wrapped DEK file not found`, `is too small`, `unsafe or relative database path`, `cannot open database file` |
| C | keyfiles/consistency.go:282, 329 | `key material is an incomplete set`, `looks mixed from different generations` |
| R | main.go:556 / exclusive_lock.go:89 | `another process already holds the DEK lock` |
| R | main.go:512 | `no master passphrase is available` |
| R | keymanager_lifecycle.go unwrapDEK, main.go initializeEncryption | `wrong passphrase or corrupted key file`, `KEK derivation from the master passphrase read from` (names the source) |
| R | secretenv.go:277 | `refusing to trust it; chmod 0600/0400` (secret file too open) |
| C | secretenv.go:109-268 | `secret file is empty`, `too large`, `is not a regular file` |
| C | passphrase.go readPassphraseFile | `is group- or world-readable (mode`, `(the user the server runs as) or to root` (`--passphrase-file`, #3410) |
| C | raw_providers.go FileKeyProvider.KEK | `refusing to trust it as key material`, `(the user the server runs as) or to root` (file KEK, #3410) |
| C | main.go:569-576 | `DEK-rotation crash recovery failed` |
| C | main.go:729 | `bootstrap token:` |
| R | config.go EnforceSecretFilePermissions | `refused until the file is fixed` (override offered only for files that are not key material) |

### Upgrade, epoch, rollback

| | Where | Message (stable part) |
|---|---|---|
| R | factory.go:1116 | `is newer than this binary's schema epoch` (no floor recorded, ADR-097) |
| R | factory.go:1078 | `database declares a minimum compatible schema epoch of` (ADR-101) |
| C | factory.go:1071, 1094 | `is not a valid integer -- refusing to start rather than guess` |
| C | factory.go:1074 | `is below 1, which no version of Keyorix` |
| C | factory.go:1059-1063 | `failed to read schema epoch`, `failed to read minimum compatible schema epoch` |
| C | factory.go:1264 | duplicate rows block a new unique index (see Database) |
| R | restore.go:810 | `refusing to restore: this backup's audit trail` (rollback protection) |
| C | restore.go:282 | `backup archive's schema epoch` ... `upgrade this binary before restoring it` |

### Security posture (insecure-setting registry)

The registry (`insecure_settings_registry.go`) is **warn-only** at boot: every setting in
effect prints a `WARNING: <key> is in effect` line (seen in every reproduction on the page).
It refuses in two places only:

| | Where | Message (stable part) |
|---|---|---|
| C | insecure_audit_skip_reads.go:50 | `is refused while the compliance profile` (unreachable today: `complianceProfileGates` is empty) |
| C | main.go:2160 | `security.require_transport_tls` (see TLS) |

Warnings that are *not* refusals, listed so nobody searches for them here:
`security.enable_file_permission_check is false`, ADR-112 grace-period lines, the
cleartext/trusted-proxy lines, `no recovery key is configured`.

### HA and multi-replica

| | Where | Message (stable part) |
|---|---|---|
| R | config.go:2984 | `storage.database.single_writer is only supported with storage.type postgres` |
| R | config.go:2975 | `single_writer is not supported with storage.database.pooler pgbouncer-transaction` |
| C | config.go:2972 | `single_writer allows exactly one server, but` |
| R | config.go (pooler) | `applies only to storage.type postgres; remove it` |
| C | database_pooler.go:64, 96 | `is not supported; use`, `native_read_pool_max ... is out of range` |
| C | postgres_open.go:120 | `a transaction-mode connection pooler (for example PgBouncer pool_mode=transaction)` |
| C | solewriter.go:249, 364, 388 | `another Keyorix server holds the single-writer lock`, `other Keyorix server(s) are attached to this database` |
| C | solewriter.go:311 | `PostgreSQL 13 or later is required` |
| C | fence.go:350-375 | `fence verification failed`, `has an unexpected definition`, `a fenced table has a child or a parent table`, `security table ... does not exist` |
| C | fence.go:524 | `holds this database (backend pid` (non-single-writer boot refused) |
| C | main.go:377 | `never runs without its write fence` |
| C | serverguard.go:274, 364 | `an admin operation is running against this database; retry when it finishes` |
| R | admin.go:195 | `appears to be using this database` |
| C | admin.go:180, 197 | `--force cannot override it`, `cannot connect to the database to check for a running server` |
| R | main.go:2049 | `failed to bind HTTP listener` (port in use) |

### Admin commands

| | Where | Message (stable part) |
|---|---|---|
| R | backup.go:245 | `each backup is a distinct artifact` |
| R | restore.go:1036 | `restore refuses to overwrite it` |
| R | restore.go:810 | rollback (see Upgrade) |
| C | restore.go:278, 626 | `restore refuses to mix formats`, `restore refuses to mix backends` |
| C | restore_postgres.go:100 | `restore refuses to overwrite it` (Postgres target not empty) |
| C | backup.go:561 | `changed during the backup -- refusing to write an archive` |
| C | restore.go:774-786 | high-water value does not parse; `could not read the rollback-protection witness file` |
| C | restore.go:1198-1208 | `was created concurrently during restore` |
| C | backup.go:122, restore.go:133, init.go:188, recover_admin.go:76 | `--output is required`, `--input is required`, `--secure-files and --dev cannot be combined`, `--user is required` |
| C | encryptionops/dek.go:123, kek.go:39, auth_encryption.go:177 | `Re-run with --confirm` family |
| C | encryptionops/dek.go:115, kek.go:36 | `must run on the server host` |
| C | encryptionops/dek.go:140, kek.go:71 | `stop the running server before rotating` |
| C | encryptionops/kek.go:54 | `new passphrase must differ from the old passphrase` |
| C | encryptionops/migrate_provider.go:65-236 | `--to-*` option checks, `verification failed`, `re-wrap failed -- no changes made` |
