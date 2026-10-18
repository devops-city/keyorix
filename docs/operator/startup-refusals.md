# Why did Keyorix refuse to start (or to run this command)?

Keyorix fails closed: when a setting, a key file, the database or another running process
is not in a state it can safely work with, `keyorix-server` exits with status 1 and one
line saying why, instead of starting in a weaker mode. This page lists those refusals:
the message you will see, what it means, how to fix it, and whether the fix is safe to do
on a live install.

[j7-troubleshooting.md](j7-troubleshooting.md) covers failures that are not refusals
(an unreachable database, an expired certificate). Start there when the server *runs* but
something is wrong. Start here when it **will not start**, or an `admin` command stops
with `Error:`.

**First step for any of them:** `keyorix-server admin diagnose --config ./keyorix.yaml`
runs the checks that start-up depends on and tells you which one fails, without opening a
listener. Most configuration refusals below also show up there.

## How to read an entry

- **Message** is what the process prints. In "Real output" blocks the text is pasted from
  a run of the native `keyorix-server` binary (SQLite, a throwaway data directory, a
  throwaway passphrase); the data directory is shown as `<datadir>` and unrelated start-up
  lines are cut (marked `...`). Entries marked **from code** were read from the source and
  not run: wording is exact, the surrounding lines are not.
- **Match** is the stable part of the message, with no paths, numbers or values. Search
  your logs for it. A test (`internal/refusaldocs`) fails when a Match text no longer
  exists in the Go sources, so an entry here cannot silently go stale.
- **In place?** says whether the fix is safe on a running install: *yes* (a config edit and
  a restart), *stop first* (the server must be down while you act), or *no* (read the linked
  procedure before touching anything, because a wrong move loses data or access).

Where the log line has a prefix (`Configuration is invalid:`, `startup validation:`,
`transport security:`, `failed to initialize core service:` ...) it names the stage that
refused; the prefix order is also the order the checks run, so an earlier prefix means the
later checks have not run yet.

Contents: [Configuration](#configuration) · [TLS](#tls) ·
[Database and storage](#database-and-storage) · [Keys and secret files](#keys-and-secret-files) ·
[Upgrade, schema epoch and rollback](#upgrade-schema-epoch-and-rollback) ·
[Security posture](#security-posture) · [HA and multiple replicas](#ha-and-multiple-replicas) ·
[Admin commands](#admin-commands) · [What this page does not cover](#what-this-page-does-not-cover)

---

## Configuration

These come from reading and validating `keyorix.yaml` and exit before anything is opened.
The fix is always an edit to the file (or env var) and a restart: **in place: yes**.

### Unknown or misplaced key

Real output:

```
Failed to load configuration: failed to unmarshal config: yaml: unmarshal errors:
  line 9: field webauthn not found in type config.SecurityConfig
```

**Match:** `failed to unmarshal config`

**Cause.** The file is parsed strictly. A key that does not exist, is misspelled, or sits
under the wrong section is an error, not ignored. The message names the Go type of the
section (`config.SecurityConfig` means "under `security:`"), not the YAML path.
**Fix.** Check the key's spelling and section against
[CONFIGURATION.md](../CONFIGURATION.md); `line N` is the line in your file. **In place:** yes.

### Wrong `storage.type`

Real output:

```
Configuration is invalid: invalid storage.type "sqllite": must be one of "local", "sqlite", "postgres", "postgresql", or "remote"
```

**Match:** `must be one of "local", "sqlite", "postgres", "postgresql", or "remote"`

**Cause.** Typo in `storage.type`. **Fix.** Use one of the listed values (`remote` is
refused for a server, see below). **In place:** yes. Same text as in
[j7](j7-troubleshooting.md#wrong-or-typod-config-value).

### `storage.type` missing — from code

```
storage.type is not set: no storage configuration found -- specify "local", "postgres", "postgresql", or "remote" explicitly
```

**Match:** `storage.type is not set: no storage configuration found`

**Cause.** Seen by tools that load the config without the server's own default. The server
itself treats a missing `storage:` block as local SQLite, so you meet this from `admin`
commands run against a config with no `storage.type`. **Fix.** Set `storage.type`. **In place:** yes.

### `storage.type: remote` on a server

Real output:

```
Configuration is invalid: storage.type: remote cannot back a server process: remote storage is a CLI/client mode only, not a deployable server backend (this includes a scheduler-only process with server.http.enabled and server.grpc.enabled both false -- server/main.go always starts its background schedulers regardless of either flag) — see ADR-083
```

**Match:** `remote cannot back a server process`

**Cause.** `remote` is the CLI's way of talking to a server; a server needs SQLite or
PostgreSQL. **Fix.** Put `remote` in the *client's* config only; give the server
`sqlite` or `postgres`. **In place:** yes. See [ADR-083](../adr-083-remote-storage-cli-only.md).

### Config file unreadable — from code

```
Failed to load configuration: failed to read config file "<path>": ...
```

**Match:** `failed to read config file`

**Cause.** The file named by `KEYORIX_CONFIG_PATH` (or `keyorix.yaml` in the working
directory) does not exist or cannot be read by the server's user. **Fix.** Fix the path or
the file's owner and mode. **In place:** yes.

### Listener enabled without a port

Real output:

```
Configuration is invalid: HTTP server is enabled but no port is specified
```

**Match:** `HTTP server is enabled but no port is specified`

**Cause.** `server.http.enabled: true` with no `port`. **Fix.** Add `port: "8080"` (the
gRPC equivalent is below). **In place:** yes.

### gRPC listener problems — from code

```
gRPC server is enabled but no port is specified
gRPC TLS is enabled but cert_file or key_file is missing
gRPC TLS auto_cert is not supported; provide cert_file and key_file
```

**Match:** `gRPC server is enabled but no port is specified`,
`gRPC TLS is enabled but cert_file or key_file is missing`

**Cause / fix.** Same as the HTTP entries; gRPC cannot use `auto_cert`. **In place:** yes.

### Unsupported language

Real output:

```
Configuration is invalid: unsupported language: xx. Supported languages: en, ru, es, fr, de
```

**Match:** `Supported languages: en, ru, es, fr, de`

**Cause / fix.** `locale.language` (or `fallback_language`) is not one of the five shown.
**In place:** yes.

### Wildcard CORS origin

Real output:

```
Configuration is invalid: server.http.allowed_origins must not contain "*" — list explicit origins (e.g. https://app.example.com); a wildcard origin defeats the CORS allowlist
```

**Match:** `a wildcard origin defeats the CORS allowlist`

**Cause / fix.** List each origin as `scheme://host[:port]`. Entries that are not origins, or
use a scheme other than http/https, are refused with a similar message. **In place:** yes.

### Other value checks — from code

Each of these is a single-line refusal with the offending key and value in the message; the
fix is to correct the value. **In place:** yes.

| Match | What it means |
|---|---|
| `exceeds the hard ceiling of` | `secrets.limits.max_secret_size` is above 1 MiB |
| `server.log.format: unknown value` | `server.log.format` must be `text` or `json` |
| `storage.database.audit_durability: unknown value` | allowed: `strict`, `standard` |
| `is not a Go duration` | an expiry written as `7d`; use hours (`168h`) |
| `both metrics_token and metrics_token_file are set` | set exactly one |
| `autocert is enabled but no domains are specified` | `tls.auto_cert` needs `domains` |
| `connector(s) missing required "scope"` | every Connect connector needs `scope: project` or `platform` (ADR-082) |
| `cross-seam audience collision` | an SSO `client_id` is also a machine-federation audience; use distinct ones |
| `webauthn is enabled but rp_id is not set` | WebAuthn needs `rp_id` and `rp_origins` |
| `keyorix has no SAML assertion-replay cache` | a provider sets `insecure_allow_idp_initiated_saml` (or `allow_idp_initiated`); IdP-initiated SAML is not supported, remove the key |
| `refusing cross-host redirect to` | OIDC discovery was redirected to another host (a scheme downgrade is refused the same way); configure the issuer URL that serves its own discovery document |

### Two sources for one secret

Real output (a master passphrase given both as a variable and a file):

```
Configuration is invalid: secret source misconfigured: both KEYORIX_MASTER_PASSWORD and KEYORIX_MASTER_PASSWORD_FILE are set; set exactly one (the secret may come from the environment or from a file, never both)
```

**Match:** `set exactly one (the secret may come from the environment or from a file, never both)`

**Cause.** A secret is available as `KEYORIX_X` and `KEYORIX_X_FILE`; both are set (an
empty-but-set variable counts). **Fix.** Unset one. **In place:** yes. See
[SELF_HOSTING.md](../SELF_HOSTING.md#3-configuration-env-and-secrets).

---

## TLS

### Cleartext listener with `require_transport_tls`

Real output:

```
startup validation warning: Database file <datadir>/keyorix.db does not exist yet — treating as first boot; it is created at 0600
Startup validation passed (config, file permissions, encryption keys, database).
HTTP server will bind http://127.0.0.1:18080
transport security: HTTP listener has no TLS but security.require_transport_tls is set: refusing to serve credentials/secrets in cleartext (enable tls or front it with a TLS-terminating proxy and unset the requirement)
```

**Match:** `listener has no TLS but security.require_transport_tls is set`

**Cause.** You asked for TLS to be mandatory and a listener has none. **Fix.** Enable
`server.http.tls` with a certificate and key, or terminate TLS in a proxy in front and set
`security.require_transport_tls: false` (the server then warns on every start that it is
serving cleartext). **In place:** yes. Note the earlier "Startup validation passed" line:
the TLS check runs after it. See [hardening guide](../security/hardening-guide.md).

### TLS enabled without certificate

Real output:

```
Configuration is invalid: TLS is enabled but cert_file or key_file is missing
```

**Match:** `TLS is enabled but cert_file or key_file is missing`

**Cause / fix.** `server.http.tls.enabled: true` needs both `cert_file` and `key_file`
(or `auto_cert` with `domains`). **In place:** yes.

### Weak or misspelled cipher suite

Real output:

```
transport security: HTTP tls.allowed_ciphers: "TLS_RSA_WITH_RC4_128_SHA" is not a recognized, secure TLS 1.2 cipher suite (allowed: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305) — weak/deprecated suites (RC4, 3DES, CBC-mode) are rejected outright
```

**Match:** `is not a recognized, secure TLS 1.2 cipher suite`

**Cause / fix.** `tls.allowed_ciphers` names a suite outside the allowed list. Use names
from the list, or remove the key. Under `tls_mode: strict` the list has no effect. **In place:** yes.

### TLS certificate files — from code

```
no PEM certificates found in <path>
invalid TLS configuration: ...
```

**Match:** `no PEM certificates found in`

**Cause.** `cert_file` (or a CA bundle) exists but holds no PEM certificate, or the
certificate and key do not pair. **Fix.** Re-export the file as PEM; check that `cert_file`
and `key_file` belong together. **In place:** yes. (The server does *not* refuse an expired
certificate; see [j7](j7-troubleshooting.md#expired-tls-certificate).)

### Database TLS: verify mode without a CA

Real output:

```
Configuration is invalid: storage.database.ssl_mode is verify-full but no CA certificate is configured, so the database server's certificate would be checked against whatever trust store the process happens to find (PGSSLROOTCERT, ~/.postgresql/root.crt or the OS store) -- refusing to start. Set storage.database.ssl_root_cert to the PEM file of the CA that signed the database server's certificate, or to "system" to trust the OS CA store.
```

**Match:** `but no CA certificate is configured`

**Cause.** `verify-ca` or `verify-full` with no `ssl_root_cert`. **Fix.** Set
`storage.database.ssl_root_cert` to the CA file, or `system`. **In place:** yes.

### Database TLS: invalid `ssl_mode`

Real output:

```
Configuration is invalid: storage.database.ssl_mode "verfy-full" is not a valid sslmode; use one of: disable, allow, prefer, require, verify-ca, verify-full
```

**Match:** `is not a valid sslmode`

**Fix.** Use one of the listed modes. **In place:** yes.

### Database TLS: `ssl_root_cert` together with `dsn`

Real output:

```
Configuration is invalid: storage.database.ssl_root_cert cannot be combined with storage.database.dsn: the dsn is used as-is, so the key would be ignored; put sslrootcert=<path> in the dsn, or use host/name/user fields instead of dsn
```

**Match:** `cannot be combined with storage.database.dsn`

**Cause / fix.** A `dsn` is passed to the driver unchanged, so Keyorix's own TLS keys
cannot also apply. Put `sslrootcert=` in the dsn, or drop the dsn for the field form.
**In place:** yes.

### Database TLS: CA file problems and other TLS-vs-dsn conflicts — from code

| Match | What it means |
|---|---|
| `writable by group or others, refusing to trust it` | the CA file is group/other-writable; `chmod go-w` it |
| `contains a private key` | the CA file holds a private key; name the certificate only |
| `selects a PostgreSQL connection service` | `service=`/`servicefile=` in the dsn, or `PGSERVICE` set: the service file could override TLS settings; remove it |
| `storage.database.dsn already contains a password and` | a password in the dsn and in the separate password setting or variable the message names; keep one |
| `ssl_root_cert is set but storage.database.ssl_mode is disable` | a CA with TLS off; set a verify mode or remove the CA |
| `when dsn is set it is used as-is and ssl_mode is ignored` | `ssl_mode` is set beside a dsn that has no or a different `sslmode`; put `sslmode=` in the dsn, or remove `ssl_mode` |
| `the PostgreSQL driver's connection settings differ from what the TLS check validated` | the driver would read the TLS settings differently from Keyorix's own check (the message says what: for example the host name would not be verified); write `sslmode` and `sslrootcert` plainly in `storage.database` (or the dsn) |

**In place:** yes (config edit, restart).

### Port already in use

Real output:

```
HTTP server error: HTTP server failed to start: failed to bind HTTP listener: listen tcp 127.0.0.1:18080: bind: address already in use
exit=1
```

**Match:** `failed to bind HTTP listener`

**Cause.** Another process (often an earlier `keyorix-server`) holds the port.
**Fix.** `lsof -i :<port> -sTCP:LISTEN`, stop that process or change `port`. **In place:** yes.
(Unlike what j7 said in an earlier version, the process now exits with status 1.)

---

## Database and storage

### PostgreSQL unreachable

From [j7](j7-troubleshooting.md#postgres-unreachable) (real output there, not re-run here):

```
connect to postgres for server-presence check: failed to connect to `user=keyorix database=keyorix`:
	[::1]:59999 (localhost): dial error: dial tcp [::1]:59999: connect: connection refused
```

**Match:** `connect to postgres for server-presence check`

**Cause / fix.** See j7. The check names the host and port it tried. **In place:** yes.

### Database file missing when it must exist — from code

```
no database found at <path> (configured database.path: "<path>") and database.require_existing_path is set: ...
```

**Match:** `no database found at`

**Cause.** `database.require_existing_path` is set and the file is not there (a volume that
did not mount, or a wrong path). **Fix.** Fix the mount or path; do **not** remove the
setting to "make it start", that would create an empty database beside your real one.
**In place:** stop first.

### A migration cannot create a unique index — from code

```
cannot create unique index on <table> (<columns>): <n> pre-existing group(s) of rows already share a value under "<index>" — ...
```

**Match:** `cannot create unique index on`

**Cause.** An upgrade adds a uniqueness rule (for example case-folded names) and your data
already has duplicates. The upgrade stops before changing anything. **Fix.** The message
names the table and rows; rename or remove the duplicates (on a copy first), then start the
new version. **In place:** no, read [UPGRADING.md](../UPGRADING.md) and take a backup first.

### A migration step failed — from code

```
failed to initialize core service: failed to initialize storage: failed to migrate database: failed to migrate <table> table: <driver error>
```

**Match:** `failed to migrate database`

**Cause.** One of roughly seventy migration steps (one per table or index) failed; the last
part is the database's own error: usually permissions (the database user cannot `ALTER`/`CREATE`),
a full disk, or a read-only database. **Fix.** Take a backup, fix the cause the database
error names (DDL rights, disk space, a read-only mount), then restart: the migration runs
again from the start of start-up. **In place:** stop first.
[UPGRADING.md](../UPGRADING.md).

---

## Keys and secret files

### Master passphrase not provided

Real output:

```
failed to initialize core service: failed to initialize encryption: encryption is enabled with the password key provider but no master passphrase is available (KEYORIX_MASTER_PASSWORD is not set (and no --passphrase-fd/--passphrase-file/--passphrase-stdin was given; KEYORIX_MASTER_PASSWORD_FILE works too)); set KEYORIX_MASTER_PASSWORD, pass --passphrase-fd/--passphrase-file/--passphrase-stdin, or configure storage.encryption.key_provider (file/env/aws-kms)
```

**Match:** `no master passphrase is available`

**Cause.** Encryption is on and the server was not given the passphrase. **Fix.** Provide
it by one of the listed ways (a `0600` file is best). **In place:** yes.
[SELF_HOSTING.md](../SELF_HOSTING.md), section 4.

### Wrong master passphrase

Real output:

```
storage: opening existing SQLite database at <datadir>/keyorix.db (configured: "<datadir>/keyorix.db")
failed to initialize core service: failed to initialize encryption: failed to initialize encryption (KEK derivation): failed to initialize key manager: failed to unwrap DEK: failed to unwrap DEK — wrong passphrase or corrupted key file: GCM open failed: cipher: message authentication failed
```

**Match:** `wrong passphrase or corrupted key file`

**Cause.** The passphrase does not open the wrapped key (`dek.enc`), or the key file or
`salt.bin` is damaged or from a different install. **Fix.** Try the right passphrase first.
If you changed it deliberately, check that `admin encryption rotate-kek` finished. If a key
file is damaged, restore the matching `dek.enc` **and** `salt.bin` from backup. **Never**
delete the key files to "start fresh": a new key cannot open existing data.
**In place:** no. [j6-key-rotation.md](j6-key-rotation.md), [drill-backup-restore.md](drill-backup-restore.md).

### Key file readable by others (explicit `enable_file_permission_check`)

Real output (`dek.enc` at mode 644, `security.enable_file_permission_check: true` set):

```
[WARN] File dek.enc has mode 644 but expected 600
startup validation: file permission validation failed: file permission validation failed: permissions or ownership audit found unresolved issues
```

**Match:** `permissions or ownership audit found unresolved issues`

**Cause.** The line that says what is wrong is the `[WARN]` line *above* the refusal (it is
printed without a timestamp). Here a key file is group/other-readable. The same refusal
covers a missing key file or database that other files say should exist (next entry).
**Fix.** `chmod 600` the named file (and `chown` it to the server's user). With
`security.enable_file_permission_check` absent, Keyorix applies the same rule to key
material by default; on a Kubernetes Secret mount use `defaultMode: 0400`. **In place:**
yes: permissions only. See the [hardening guide](../security/hardening-guide.md).

### A key file is missing on a later start

Real output (`salt.bin` deleted, database and `dek.enc` present):

```
[WARN] Cannot open file salt.bin: open salt.bin: no such file or directory
startup validation: file permission validation failed: file permission validation failed: permissions or ownership audit found unresolved issues
```

**Match:** `permissions or ownership audit found unresolved issues`

**Cause.** The database exists, so this is not a first boot, but `salt.bin` (or `dek.enc`)
is gone: an unmounted key volume, a restore that missed a file, or a deletion.
**Fix.** Restore **both** key files from the same backup, or mount the right volume. Do not
start with the files missing: with the check off, the server would generate a *new*
salt and key over your encrypted data, and every value would become unreadable.
**In place:** no. [SELF_HOSTING.md](../SELF_HOSTING.md), sections 4 and 5.

> **First install trap.** The same refusal appears on a *brand-new* install if you write
> `security.enable_file_permission_check: true` explicitly before the first start
> (`[WARN] Cannot open file dek.enc ... salt.bin ... keyorix.db`): an explicit `true` does not
> treat "nothing exists yet" as a first boot. Leave the key unset for the first start (the
> default already enforces the check), or create the key material first.

### Key file set incomplete or mixed — from code

```
key file consistency: key material is an incomplete set: present (<files>); missing (<files>) — this is not a state any provisioning path produces; restore the full set from one backup, or remove the partial files and let first-boot generation recreate them
key file consistency: key material group looks mixed from different generations: <files> — this is a BEST-EFFORT mtime heuristic ...
```

**Match:** `key material is an incomplete set`, `key material group looks mixed from different generations`

**Cause.** Only some files of one key set are present, or their modification times differ by
more than the tolerance (typically a partial restore, or a backup of one file taken
before a rotation). **Fix.** Restore the whole set from one backup. If the files really
belong together (the second message is a heuristic), `touch` them to a common time.
"Remove the partial files and let first boot recreate them" is only right on an install that
has **no data yet**. **In place:** no.

### Key files readable by others, or owned by another account — from code

```
key file security: key material is readable beyond its owner: <path> (mode 644) — refusing to start (chmod 600 and chown the files to the server's user, or set security.insecure_allow_unsafe_file_permissions to override)
key file security: key material is owned by an account the server does not trust: <path> (owned by uid 1000; the server runs as uid 1001 and trusts only that uid and root, because the owner can replace the file) — refusing to start (...)
```

**Match:** `key material is readable beyond its owner`, `key material is owned by an account the server does not trust`

**Cause.** This is the always-on second check of the wrapped DEK, the KEK salt and the TLS
private keys. The first form: group or other can read the file. The second (#3410): the
file belongs to an account other than the server's own uid and root, and whoever owns a
file can rewrite it, whatever its mode. **Fix.** `chmod 600` the file and
`chown <server user> <file>` (or `chown root`); prefer that to the override. On Compose the
key volume is created owned by the server's uid 1001, and on Helm the files are written by
the pod's uid, so only a hand-copied or hand-restored file normally shows this. With
`security.enable_file_permission_check` unset, a TLS key only warns; in the ADR-112
upgrade grace period, with the check off or with the override, both forms only warn.
**In place:** yes.

### Key file contents invalid — from code

| Match | What it means |
|---|---|
| `KEK salt file not found` | `storage.encryption.salt_path` points at nothing |
| `wrapped DEK file not found` | `storage.encryption.dek_path` points at nothing |
| `has invalid size` | salt is not 32 bytes: truncated or wrong file |
| `to be a valid wrapped key` | the wrapped DEK file is too small to be one: truncated |

**In place:** no: restore from backup, do not recreate.

### Secret file too open

Real output (`KEYORIX_MASTER_PASSWORD_FILE=mp.txt` at mode 644):

```
secret file security: secret file "mp.txt": mode 0644 is too open (accessible to other users) -- refusing to trust it; chmod 0600/0400, or mount it from the orchestrator owned by another user (e.g. root) with a group the process belongs to (fsGroup / group_add) and mode 0440 -- refusing to start (or set security.insecure_allow_unsafe_file_permissions to override)
```

**Match:** `refusing to trust it; chmod 0600/0400`

**Cause.** A file behind a `KEYORIX_*_FILE` variable (database password, bootstrap token,
master passphrase ...) is readable by others. **Fix.** `chmod 0600`; on Kubernetes use
`fsGroup` with mode `0440`. **Do not use the override for the master passphrase file:**
with it set, this check only warns and the server then stops anyway with
`no master passphrase is available (... mode 0644 is too open ...)`, because key
material files are refused with no override. **In place:** yes.

### Another process holds the key lock

Real output (second server started on the same data directory):

```
failed to initialize core service: failed to initialize encryption: failed to acquire the encryption key lock: another process already holds the DEK lock (a live server, or a concurrent rotation): resource temporarily unavailable
```

**Match:** `another process already holds the DEK lock`

**Cause.** A server (possibly one you thought you stopped), or an `admin encryption`
operation, holds `dek.lock`. Two servers may not share one SQLite data directory.
**Fix.** Find and stop the other process (`lsof <datadir>/dek.lock`), then start again.
For several replicas on one PostgreSQL database, follow the supported topology in
ADR-039 rather than pointing two servers at one key directory. **In place:** stop first.
[ADR-039](../adr-039-ha-deployment.md), [j7](j7-troubleshooting.md#port-already-in-use).

### Secret file or passphrase file content — from code

| Match | What it means |
|---|---|
| `secret file is empty` | the file behind `KEYORIX_*_FILE` is empty |
| `is group- or world-readable (mode` | `--passphrase-file` is not `0600` |
| `(the user the server runs as) or to root` | `--passphrase-file`, or the KEK file of `key_provider: file`, is owned by an account other than the server's user and root (#3410: that account could replace it); the message names the owner uid. `chown` it. No override |
| `refusing to trust it as key material` | the KEK file of `key_provider: file` is not `0600`/`0400`; `chmod` it. No override |
| `secret-value encryption did not engage` | encryption is configured but did not start; the server refuses to store secrets in plaintext. Check the key provider settings and earlier log lines |
| `refusing to start rather than leave a webhook credential unencrypted at rest` | the start-up pass that encrypts stored notification URLs failed; fix the database error shown first (permissions, disk) and restart |
| `DEK-rotation crash recovery failed` | an interrupted `admin encryption rotate` could not be completed on start; do **not** delete files; see [j6](j6-key-rotation.md) |

---

## Upgrade, schema epoch and rollback

### Database newer than this binary (no compatibility floor)

Real output (schema epoch edited to 999 to stand in for a newer release):

```
storage: opening existing SQLite database at <datadir>/keyorix.db (configured: "<datadir>/keyorix.db")
failed to initialize core service: failed to initialize storage: failed to migrate database: database schema epoch 999 is newer than this binary's schema epoch 3 (recorded at 2026-10-17T21:52:34+02:00, 23s ago) -- this database was migrated by a newer version of Keyorix. Two things produce this, and this process cannot tell them apart on its own: (a) a rolling upgrade in progress -- ... (b) this binary was downgraded against a schema a newer version already migrated -- if so, upgrade this binary to match, or restore a backup taken before the newer version ran. No minimum compatible schema epoch is recorded, so nothing declares this schema safe for an older binary. Refusing to start is the safe default in both cases (ADR-097, ADR-101)
```

**Match:** `is newer than this binary's schema epoch`

**Cause.** A newer Keyorix has already migrated this database. **Fix.** (a) During a rolling
upgrade this pod's old image is about to be replaced: wait. (b) After a downgrade: run the
newer version again, or restore a backup taken *before* it first ran. Do **not** edit
`system_metadata` to make the number match: the older code does not understand the newer
schema. **In place:** no. [UPGRADING.md §7 Rollback](../UPGRADING.md#7-rollback),
[ADR-097](../adr-097-schema-epoch-downgrade-guard.md).

### Database declares a compatibility floor above this binary

Real output (floor edited to 999):

```
failed to initialize core service: failed to initialize storage: failed to migrate database: database declares a minimum compatible schema epoch of 999 (database schema epoch 3), above this binary's schema epoch 3 (floor recorded at 2026-10-17T21:52:34+02:00, 30s ago) -- a migration this database has already applied was declared unsafe for binaries this old, so this binary must not run against it. If this is a rolling upgrade, this pod is expected to be replaced by the new image; if this binary was rolled back, roll forward to a version with schema epoch 999 or later, or restore a backup taken before the newer version ran. Refusing to start (ADR-101)
```

**Match:** `database declares a minimum compatible schema epoch of`

**Cause.** A migration this database already ran says older binaries must not use it: the
dangerous rollback. **Fix.** Roll forward to a release at or above the stated epoch, or
restore a pre-upgrade backup. **In place:** no. The message prints the numbers it saw; in
this reproduction both were hand-edited, in a real rollback they come from the release.
[UPGRADING.md §7](../UPGRADING.md#7-rollback), [ADR-101](../adr-101-schema-epoch-compatibility-floor.md).

### Stored epoch unreadable — from code

```
stored schema epoch "<value>" is not a valid integer -- refusing to start rather than guess whether this database is ahead of this binary (ADR-097)
stored minimum compatible schema epoch <n> is below 1, which no version of Keyorix writes -- refusing to start rather than trust a corrupted compatibility floor (ADR-101)
```

**Match:** `is not a valid integer -- refusing to start rather than guess`,
`is below 1, which no version of Keyorix`

**Cause.** `system_metadata.schema_epoch` or `schema_min_compatible_epoch` was edited or
corrupted. **Fix.** Restore the database from backup; do not hand-edit. **In place:** no.

### Restore: backup is from a newer version — from code

```
Error: backup archive's schema epoch <n> is newer than this binary's schema epoch <m> (ADR-097) -- this backup was taken by a newer version of Keyorix; upgrade this binary before restoring it
```

**Match:** `backup archive's schema epoch`

**Fix.** Restore with the same or a newer release than took the backup. **In place:** yes
(nothing was changed).

### Restore: older than this host's own history (rollback protection)

Real output (restoring a backup taken before the last two audit events, over the running data directory):

```
Error: refusing to restore: this backup's audit trail (9 event(s)) is 2 event(s) BEHIND this host's own last known state (12 event(s)) -- restoring it would silently un-revoke any user/credential access revoked since this backup was taken. Pass --allow-rollback if this is a genuine disaster-recovery restore of an intentionally older backup
```

**Match:** `refusing to restore: this backup's audit trail`

**Cause.** The archive has fewer audit events than this host already holds, so restoring it
would bring back access that was revoked since. **Fix.** Use a newer backup. For a real
disaster recovery onto this host, `--allow-rollback` records the override in the audit
trail; afterwards, re-check who has access. **In place:** no.
[drill-backup-restore.md](drill-backup-restore.md), [UPGRADING.md §4](../UPGRADING.md#4-backup-format-v1-vs-v2).

---

## Security posture

Settings named `insecure_*` (and the ones the secure-by-default baseline, ADR-112, turned on)
do not make the server refuse to start when you relax them: each one in effect prints a
`WARNING: <key> is in effect` line on **every** start. The refusals in this group are about
a *secure* setting that cannot be satisfied.

Look at the first lines of a start:

```
WARNING: server.insecure_disable_api_ratelimit is in effect (true; config: server.http.ratelimit.enabled, server.grpc.ratelimit.enabled) — removes per-principal API rate limiting
```

The text before `(true;` is the setting's registry name; the keys after `config:` are what you
actually write in `keyorix.yaml`. Careful: for `security.insecure_allow_cleartext_transport`
the line points to `security.require_transport_tls`; writing the registry name itself as
a key is rejected as an unknown key (see the first entry).

### Cleartext listener under `require_transport_tls`

See [TLS](#cleartext-listener-with-require_transport_tls).

### Skipping read audit under a compliance profile — from code (not reachable today)

```
storage.database.insecure_audit_skip_reads: true is refused while the compliance profile <name> is active: ...
```

**Match:** `is refused while the compliance profile`

The list of compliance profiles is empty in this release, so the refusal cannot occur yet.
Listed so it is not a surprise when the first profile ships.

### Binary built without a connector or rotation backend — from code

```
connect: connector "<name>" has type "<type>", which this server binary was not built with (excluded by the no<provider> build tag) — rebuild without -tags no<provider>, or remove this connector
```

**Match:** `which this server binary was not built with`

**Cause.** A minimal build (for example `-tags nogcp`) with a config that uses that
provider. **Fix.** Use the full build, or remove the connector/rotation backend.
**In place:** yes.

---

## HA and multiple replicas

### `single_writer` on SQLite

Real output:

```
Configuration is invalid: storage.database.single_writer is only supported with storage.type postgres: it relies on PostgreSQL session advisory locks and triggers; remove the setting
```

**Match:** `storage.database.single_writer is only supported with storage.type postgres`

**Fix.** Remove the setting, or move to PostgreSQL. **In place:** yes.
[single-writer.md](../single-writer.md).

### `single_writer` with a transaction pooler

Real output:

```
Configuration is invalid: storage.database.single_writer is not supported with storage.database.pooler pgbouncer-transaction: its holder lock and session tag are session-scoped; use pgbouncer-session or connect directly
```

**Match:** `is not supported with storage.database.pooler pgbouncer-transaction`

**Fix.** Point `single_writer` at a session-mode pooler or the database directly.
**In place:** yes. [postgresql-poolers.md](../postgresql-poolers.md).

### `pooler` on SQLite

Real output:

```
Configuration is invalid: storage.database.pooler "pgbouncer-session" applies only to storage.type postgres; remove it
```

**Match:** `applies only to storage.type postgres; remove it`

**Fix.** Remove `pooler` (and `native_read_pool_max`, which has the same rule). **In place:** yes.

### `audit_durability: standard` on SQLite

Real output:

```
Configuration is invalid: storage.database.audit_durability: standard is only supported with PostgreSQL; SQLite runs strict only -- remove the setting or set it to strict
```

**Match:** `standard is only supported with PostgreSQL`

**Fix.** Remove the setting or use `strict`. **In place:** yes.
[UPGRADING.md §6c](../UPGRADING.md#6c-postgresql-audit-durability-now-defaults-to-standard).

### Undeclared transaction-mode pooler — from code

```
storage.database: two open connections were served by the same PostgreSQL backend (pid <n>), so a transaction-mode connection pooler (for example PgBouncer pool_mode=transaction) is between Keyorix and PostgreSQL. Session advisory locks and cached prepared statements are not safe there. Set storage.database.pooler: pgbouncer-transaction (docs/postgresql-poolers.md), or run the pooler in session mode
```

**Match:** `a transaction-mode connection pooler`

**Cause.** The start-up probe found a pooler you did not declare. **Fix.** Declare
`storage.database.pooler: pgbouncer-transaction`, or switch the pooler to session mode.
**In place:** yes (before the server is up). [postgresql-poolers.md](../postgresql-poolers.md).

### `single_writer` and more than one replica — from code

| Match | What it means |
|---|---|
| `storage.database.single_writer allows exactly one server, but` | `security.auth_rate_limit_fallback.replicas` declares more than one |
| `another Keyorix server holds the single-writer lock` | a second server started against the same database; stop it |
| `other Keyorix server(s) are attached to this database` | same, discovered when the first one starts |
| `holds this database (backend pid` | a *non*-single-writer server started against a database a single-writer server holds; stop one of them |
| `PostgreSQL 13 or later is required` | `single_writer` needs PostgreSQL 13+ |
| `fence verification failed` | the write-fence triggers are not all present |
| `has an unexpected definition` | a fence trigger was altered; the message gives the `DROP TRIGGER` to run, then restart |
| `a fenced table has a child or a parent table` | table inheritance bypasses the fence; remove it |
| `never runs without its write fence` | the fence could not be installed; fix the cause shown before it |

**In place:** stop first for the lock messages (one writer at a time is the point);
the fence ones need a DBA's care: [single-writer.md](../single-writer.md).

### An admin operation is running — from code

```
an admin operation is running against this database; retry when it finishes
```

**Match:** `an admin operation is running against this database`

**Cause.** A server start collided with a running `admin` command (backup, restore,
rotation). **Fix.** Wait for the command to finish, then start. **In place:** yes.

---

## Admin commands

### An admin command while the server is running

Real output (server running on the same SQLite database, `admin backup`):

```
Error: on SQLite, admin backup needs the database to itself -- stop the server first (a live backup without downtime needs Postgres): a Keyorix server (or another admin command) appears to be using this database (another process holds this database (a live server, or another admin command) via <datadir>/keyorix.db.server.lock) — admin commands must not run concurrently with either; stop it first, or pass --force if you are certain this is safe.
With Docker Compose, run admin commands in a throwaway container while the server is stopped:
  docker compose stop backend
  docker compose run --rm backend ./keyorix-server admin <command>
  docker compose start backend
```

**Match:** `appears to be using this database`

**Cause / fix.** Stop the server, or run the command in a throwaway container as shown.
`--force` skips the check, and is only right if you know nothing else is writing. With
`single_writer`, `--force` is refused outright (`--force cannot override it`, from code).
**In place:** stop first. [j7](j7-troubleshooting.md#an-admin-command-while-the-server-is-still-running).

### Backup output already exists

Real output:

```
Error: --output "b1.kxb" already exists -- each backup is a distinct artifact, pick a new path (e.g. include a timestamp)
```

**Match:** `each backup is a distinct artifact`

**Fix.** Pick a new file name. Nothing was overwritten. **In place:** yes.

### Restore over a non-empty destination

Real output:

```
Error: database "<datadir>/keyorix.db" already exists and is not empty -- restore refuses to overwrite it (pass --overwrite-existing if you are certain, e.g. this is a genuine disaster-recovery restore; the normal flow is restoring into a fresh/empty data dir)
```

**Match:** `restore refuses to overwrite it`

**Cause.** Restore will not replace a live database. **Fix.** Restore into an empty data
directory and switch over, or `--overwrite-existing` for a disaster recovery (and read the
rollback entry above: it may follow). The same message exists for a non-empty PostgreSQL
target. **In place:** no. [drill-backup-restore.md](drill-backup-restore.md).

### Other restore and backup refusals — from code

| Match | What it means |
|---|---|
| `restore refuses to mix formats` | the archive format differs from what this binary expects; use the release that wrote it |
| `restore refuses to mix backends` | an SQLite archive into PostgreSQL, or the reverse; see [SELF_HOSTING.md "Moving from SQLite to Postgres"](../SELF_HOSTING.md#moving-from-sqlite-to-postgres) |
| `changed during the backup` | a key file changed while the backup ran (rotation in progress); nothing was written, retry |
| `could not read the rollback-protection witness file` | the host's witness file is unreadable or corrupt; investigate before restoring, it is not treated as absent |
| `restore refuses a partial/mismatched key-file set` | the archive holds a different number of key files than this config's encryption settings expect; restore with the config the backup was taken with |
| `restore refuses a mismatched key-file set` | a key file in the archive is for another path than this config's `dek_path`/`salt_path` |
| `backup archive's manifest signature is invalid` | the archive is corrupted or was altered; use another copy |
| `restore refuses unlisted entries` | the archive contains a file its own manifest does not list; do not use it |
| `restore refuses non-regular entries` | the archive contains a link or device entry; do not use it |
| `refusing to generate a TLS certificate` | `admin init --secure-files` found the system clock implausible (a device with no RTC and no NTP reads a date long before this build); a certificate made now would expire when the clock is corrected. Set the clock, or place your own certificate and key at the paths the message names |
| `already exists -- refusing to overwrite` | the `--output` file of `admin recovery-key rotate` already exists; choose another path or remove the old file deliberately |
| `could not be checked because the config file failed to load` | `admin verify-audit` without `--anchor` could not read the config to see whether `audit.offline_anchor_path` is set, so it will not silently verify without it; pass `--anchor` or fix the config load error shown after it |

### Rotation commands — from code

| Match | What it means |
|---|---|
| `Re-run with --confirm` | rotation changes keys/rewraps data and is not run without `--confirm` (dry-run first for the DEK) |
| `stop the running server before rotating` | the key lock is held; stop the server |
| `must run on the server host` | the config says `storage.type: remote`; run on the server's host |

**In place:** stop first. [j6-key-rotation.md](j6-key-rotation.md).

---

## What this page does not cover

- The full list of every refusal found, how it was built and what the search could not see:
  [startup-refusals-inventory.md](startup-refusals-inventory.md). A test logs the refusals in
  the code that this page does not mention yet; that log is not a failure, because
  messages built at run time from variables cannot be found by reading source.
- Container- and Helm-level failures (a pod that crash-loops before `keyorix-server` runs,
  entrypoint secret-file checks) — see [j8-kubernetes.md](j8-kubernetes.md).
- Warnings (the server runs): the `WARNING:` lines. They are listed in the
  [hardening guide](../security/hardening-guide.md).
