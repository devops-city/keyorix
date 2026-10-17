# Keyorix configuration reference

This is the operator reference for `keyorix.yaml`. Every block is optional unless
noted; an absent block uses the documented default. Secrets (DB password, master
passphrase, SIEM/SMTP tokens) should come from **environment variables**, not the
file — see [Environment variables](#environment-variables).

The config file is located via, in order: an explicit path argument, then
`KEYORIX_CONFIG_PATH`, then `keyorix.yaml` in the working directory.

## Contents

- [Environment variables](#environment-variables)
- [environment](#environment) · [locale](#locale) · [server](#server) · [storage](#storage)
- [storage.encryption + key_provider](#encryption--kek-providers) (ADR-004, ADR-038)
- [secrets](#secrets) · [security + require_mfa](#security) (ADR-034)
- [webauthn](#webauthn) (ADR-036) · [dynamic_secrets](#dynamic_secrets) (ADR-035, ADR-058) — includes [revocation semantics by backend](#credential-revocation-semantics-by-backend)
- [oidc](#oidc) (ADR-031) · [session](#session) · [password_policy](#password_policy) (ADR-025)
- [soft_delete + purge](#soft_delete--purge) (ADR-032) · [data_retention](#data_retention) (A.5.33) · [recertification](#recertification) (A.5.18) · [notifications](#notifications) · [compliance_digest](#compliance_digest) · [evidence_delivery](#evidence_delivery) · [rotation_reminders](#rotation_reminders) · [audit_checkpoints](#audit_checkpoints) (ADR-029) · [jit_access_expiry](#jit_access_expiry) · [break_glass](#break_glass) · [dual_control](#dual_control) (A.5.3) · [classification](#classification) (A.5.12/A.5.13) · [audit.siem](#auditsiem)
- [scim](#scim) (RFC 7644) · [sso](#sso) (OIDC) · [membership](#membership) (ADR-022) · [credential_delivery](#credential_delivery) (ADR-028)

---

## Environment variables

Sensitive values are read from the environment when set, overriding any value in
the file:

| Variable | Used for |
|---|---|
| `KEYORIX_MASTER_PASSWORD` | KEK passphrase (required for the default `password` key provider) |
| `KEYORIX_CONFIG_PATH` | path to the config file |
| `KEYORIX_DB_PASSWORD` | PostgreSQL password |
| `KEYORIX_API_KEY` | API key for remote-client mode |
| `KEYORIX_SIEM_TOKEN` | SIEM push token (`audit.siem`) |
| `KEYORIX_SCIM_TOKEN` | SCIM provisioning bearer token (`scim`) |
| `KEYORIX_SSO_<NAME>_CLIENT_SECRET` | per-provider OIDC client secret (`sso`) |
| `KEYORIX_SMTP_PASSWORD` | SMTP relay password (`credential_delivery.smtp`) |
| `KEYORIX_DOMAIN` | substituted into `server` origins in the shipped example configs |
| _(operator-named)_ | the raw KEK, when `key_provider.type: env` (see [key_provider](#encryption--kek-providers)) |

### Secrets from files (`<NAME>_FILE`)

Every secret the server reads from the environment can instead be read from a
file, by setting `<NAME>_FILE` to the file's path. This is the Docker-secrets
and Kubernetes-Secret-volume convention: the value never appears in
`docker inspect`, `/proc/<pid>/environ` or a child process's environment.

```sh
KEYORIX_DB_PASSWORD_FILE=/run/secrets/db_password
KEYORIX_MASTER_PASSWORD_FILE=/run/secrets/master_password
KEYORIX_BOOTSTRAP_TOKEN_FILE=/run/secrets/bootstrap_token
```

Supported for: `KEYORIX_MASTER_PASSWORD`, `KEYORIX_DB_PASSWORD`,
`KEYORIX_BOOTSTRAP_TOKEN`, `KEYORIX_API_KEY`, `KEYORIX_SIEM_TOKEN`,
`KEYORIX_SCIM_TOKEN`, `KEYORIX_SSO_<NAME>_CLIENT_SECRET`, `KEYORIX_SMTP_PASSWORD`,
`KEYORIX_EVIDENCE_WEBHOOK_TOKEN`, `KEYORIX_NOTIFY_SMTP_PASSWORD`,
`KEYORIX_NOTIFY_WEBHOOK_TOKEN`, `KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET`,
`KEYORIX_NOTIFY_SLACK_WEBHOOK`, `KEYORIX_NOTIFY_TEAMS_WEBHOOK`, and the
operator-named variables: the `key_provider` `env_var` and `shamir_share_env`
entries, a rotation backend's `dsn_env`, and a Vault connector's `token_env`
(default `VAULT_TOKEN`). `KEYORIX_CONFIG_PATH` is a path, not a secret, and has no
`_FILE` form.

Rules (all enforced at startup; the server refuses to start rather than guess):

- **`X_FILE` set:** the file is read and one line terminator is removed: one
  trailing `\n`, then one trailing `\r` (so `\n`, `\r\n` or a lone `\r`). Nothing
  else is trimmed -- no leading or trailing spaces, no second newline -- so a secret
  may contain them. The container entrypoint and `keyorix system init` apply the
  same rule. For
  `KEYORIX_MASTER_PASSWORD_FILE` this yields the same bytes as
  `--passphrase-file`, so both derive the same KEK. (The plain
  `KEYORIX_MASTER_PASSWORD` *environment variable* keeps its historical
  whitespace trim; a passphrase with leading/trailing spaces must be supplied from
  a file.) Symlinks are followed (Kubernetes mounts every Secret key as one).
- **Both `X` and `X_FILE` set:** error, naming both variables. There is no
  precedence. An empty variable counts as unset, so `X=${X:-}` passthrough in a
  compose file does not trigger this.
- **File missing, unreadable, empty, not a regular file, or larger than 1 MiB:**
  error. The server does not fall back to `X` or to a value in `keyorix.yaml`.
- **Nothing is logged:** errors and warnings name the variable and the path, never
  the value or the file contents.
- **File permissions -- key material is refused, other secrets follow the
  file-permission policy.** The rule is the one the KEK file and
  `--passphrase-file` already follow: `0600` or `0400`. One exception exists for
  files an orchestrator mounts: a file *not owned by the running user* may also be
  group-readable (`0440`, or `0640`) when its group is one the process belongs to --
  which is exactly what a Kubernetes Secret volume with `fsGroup` produces (the
  kubelet makes it root-owned, group = `fsGroup`, and adds group-read even with
  `defaultMode: 0400`) and what a Docker secret with `group_add` looks like. Access
  for *other*, group-write and setuid/setgid/sticky are never accepted, and a
  group-readable file owned by the running user is refused.
  - **Master password (`KEYORIX_MASTER_PASSWORD_FILE`), key-provider KEK
    (`key_provider.env_var`) and Shamir shares (`shamir_share_env`):** a file that
    breaks the rule is **always refused**, in the server, the CLI and every admin
    command alike. There is no override. The check runs on the opened file
    descriptor, so the file cannot be swapped between the check and the read.
  - **`KEYORIX_ADMIN_PASSWORD_FILE` / `KEYORIX_BOOTSTRAP_TOKEN_FILE`** (the
    container entrypoint's first-boot bootstrap and `keyorix system init`): the
    entrypoint and the CLI refuse a file that breaks the rule, always. (The server's
    own read of `KEYORIX_BOOTSTRAP_TOKEN_FILE` follows the last bullet.) Both
    resolve `_FILE` with the same rules as the server, so a `_FILE`-only deployment
    auto-bootstraps.
  - **All other `*_FILE` secrets** (database password, API/SIEM/SCIM tokens, SSO,
    SMTP, notification and evidence secrets, Vault token, ...): the same rule, but
    with the policy of the other key files -- refused at startup when
    `security.enable_file_permission_check` is on and
    `security.allow_unsafe_file_permissions` is off, otherwise a loud warning.
    While the ADR-112 upgrade grace period is active (an upgraded deployment that
    never set `security.enable_file_permission_check` explicitly), these files only
    warn and the boot is recorded as softened; set the key to `true` once the files
    comply. Key material above never gets this grace.
- **`--passphrase-fd`, `--passphrase-file` and `--passphrase-stdin` still win**
  over `KEYORIX_MASTER_PASSWORD[_FILE]`, as they do over the plain variable.

For a raw KEK (`key_provider.type: env`) the file holds the hex or base64 form,
as the variable would. A 32-byte raw key ending in a newline byte cannot be
stored this way; use `key_provider.type: file` for raw keys.

---

## environment

```yaml
environment: production   # development | staging | production
```

## locale

```yaml
locale:
  language: en
  fallback_language: en
```

## server

```yaml
server:
  http:
    enabled: true
    host: "127.0.0.1"             # bind address; default 127.0.0.1 (this machine only). "0.0.0.0" = all interfaces
    port: "8080"
    protocol_versions: ["1.1", "2.0"]
    swagger_enabled: false        # keep false in production
    web_assets_path: /app/web/dist
    domain: keyorix.example.com   # effective domain (also the WebAuthn RP ID basis)
    allowed_origins:
      - https://keyorix.example.com
    tls:
      enabled: false              # commonly terminated at a reverse proxy
      auto_cert: false            # ACME/autocert when true — needs a public domain and inbound 80/443
      cert_file: ""               # PEM certificate (chain), for TLS without ACME — see below
      key_file: ""                # PEM private key matching cert_file
      domains: []                 # ACME only: domains to request certs for
      cert_cache_dir: "certs"     # ACME only: where autocert persists certs between restarts
      allowed_ciphers: []         # optional allowlist of TLS 1.2 cipher suite names; leave empty for the built-in secure default
    tls_mode: ""                  # "" (default: TLS 1.2 floor, forward-secret AEAD only) | "strict" (TLS 1.3 only)
    trusted_proxies: []           # IPs/CIDRs of your TLS-terminating proxy/LB; their X-Forwarded-For/-Proto are honored (client IP, HSTS, Secure cookies). HTTP only
    hsts_preload: false           # add "preload" to Strict-Transport-Security (see below). HTTP only
    ratelimit:
      enabled: true
      requests_per_second: 50
      burst: 100
    metrics_token: ""             # GET /metrics then requires "Authorization: Bearer <token>"
    metrics_token_file: ""        # or read the token from this file (secret-file rules, see below); set one, not both
  access_log:
    on_sink_stall: block          # block (default) | drop — what a request does when the access-log sink stalls (see below)
  log:
    format: text                  # text (default) | json — one JSON object per log line; see docs/operations/logging.md
  grpc:
    # Partial surface, off by default. HTTP is the complete interface; enable this
    # only if you need it, and read docs/adr-105-grpc-scope-and-parity.md first —
    # governance controls such as classification cannot be set over gRPC.
    enabled: false
    host: "127.0.0.1"             # same default and meaning as server.http.host
    port: "9090"
    protocol_versions: ["2.0"]
    reflection_enabled: false     # keep false in production
    tls:
      enabled: false
    tls_mode: ""                  # same two values as server.http.tls_mode above
    ratelimit:
      enabled: true
      requests_per_second: 25
      burst: 50
```

`auto_cert` is ACME — it needs a public domain and inbound 80/443, so it does not work
for a local, internal-only, or air-gapped deployment. For those, set `cert_file`/
`key_file` to a PEM cert and key instead (gRPC's `tls:` block takes the same two
fields; `domains`/`cert_cache_dir`/`allowed_ciphers` apply to HTTP only). A quick
self-signed pair for local use:

```sh
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem \
  -days 365 -subj "/CN=localhost"
```

Then set `server.http.tls.enabled: true`, `cert_file: ./cert.pem`, `key_file: ./key.pem`.
Browsers will warn on the self-signed cert (expected) — use a CA-issued one, or the
bundled Caddy `tls` profile ([SELF_HOSTING.md](SELF_HOSTING.md) §7), for anything
beyond local testing.

**`tls_mode: strict`** (ADR-112 §3) switches a listener from the default TLS
posture (1.2 floor, restricted to forward-secret AEAD cipher suites — see
`tls.allowed_ciphers` above) to TLS 1.3 only, with no fallback to 1.2. The
default itself is **not** an `insecure_` opt-out: NIST SP 800-52 Rev. 2
requires servers to support both 1.2 and 1.3, BSI TR-02102-2 prefers 1.3
while planning 1.2's phase-out, and OT/legacy clients still commonly need
1.2 — `tls_mode: strict` is an explicit upgrade an operator opts INTO when
every client can be required to speak 1.3. `tls.allowed_ciphers` has no
effect under strict mode (TLS 1.3 negotiates its own, always-AEAD suite set)
and logs a warning if both are set.

**Strict-Transport-Security (HSTS).** The backend sends
`Strict-Transport-Security: max-age=31536000; includeSubDomains` only on a request
that reached the client over TLS:

- the listener serves TLS itself (`server.http.tls.enabled`), or
- the TCP peer is listed in `server.http.trusted_proxies` and its
  `X-Forwarded-Proto` is `https` (TLS terminated at your load balancer).

It is never sent for plain http, and `X-Forwarded-Proto` from any peer not in
`trusted_proxies` is ignored, so a client cannot turn HSTS on by forging the
header. If the header has several values, the last one counts (the one your proxy
added); your proxy must set or overwrite `X-Forwarded-Proto`, not pass a
client's value through. `trusted_proxies` is the same list that governs
`X-Forwarded-For` for client IPs, rate limits and audit.

- `max-age` is one year, the web nginx's default too.
- `includeSubDomains` is always sent. A secrets manager's session cookies should
  not share a domain with a sibling host left on plain http. If some subdomains
  of yours cannot do https, have your proxy replace the header.
- `preload` is off unless you set `hsts_preload: true`. Preload-list submission
  covers the whole registrable domain and is slow to undo, so only the domain's
  owner should opt in.

**Secure cookies.** The same decision, made once per request, sets the `Secure`
attribute of every cookie the server sets: the session cookie (`kx_session`), the
CSRF cookie (`csrf_token`) and the impersonation stash cookie
(`kx_admin_session`), including the ones that clear them on logout. A cookie is
`Secure` when the listener serves TLS itself, or when the request came from a peer
in `server.http.trusted_proxies` with `X-Forwarded-Proto: https`; otherwise it is
not. So behind a TLS-terminating load balancer, list the balancer in
`trusted_proxies` and the cookies are `Secure` with no other setting. Without that
entry they go out without `Secure`, exactly as before. A forged
`X-Forwarded-Proto: https` from any other peer changes nothing, and `Secure` is
never removed from a cookie that has it today.

**HTTP only.** `trusted_proxies` and `hsts_preload` are read by the HTTP server
only. The keys parse under `server.grpc` too (both listeners share one config
shape) but the gRPC server never reads them, so setting either there logs a
`WARNING` at every start and has no effect. Set them under `server.http`.

The web container's nginx makes its own HSTS decision and strips the backend's
header from proxied API responses ([SELF_HOSTING.md](SELF_HOSTING.md), "HSTS
behind a TLS-terminating load balancer").

### gRPC keepalive and connection limits (`server.grpc.keepalive`)

Durations are Go duration strings (`"15m"`); an unset or unparseable value takes the
default. Only the gRPC server reads this block (the keys parse under `server.http` too,
but have no effect there).

| Key | Default | Meaning |
|---|---|---|
| `time` | `5m` | idle time before the server pings the client |
| `timeout` | `20s` | how long the server waits for the ping ack before closing |
| `min_time` | `5m` | the shortest ping interval the server accepts from a client |
| `permit_without_stream` | `false` | accept client pings while no RPC is in flight |
| `max_connection_age` | `1h` | a connection is asked to close after this age |
| `max_connection_age_grace` | `30s` | time for in-flight RPCs after that |
| `max_connection_idle` | `15m` | close a connection with no RPC in flight (keepalive acks alone never reclaim it); new in v0.97.0 (#3312) |
| `handshake_timeout` | `10s` | a new connection must finish its TLS handshake and HTTP/2 preface in this time; new in v0.97.0 (#3312) |

The two new keys cannot be set to 0 to switch the bound off. The server also caps a gRPC
connection at 128 concurrent RPCs and 64 KiB of metadata, and REST request headers at
64 KiB (not configurable).

## storage

```yaml
storage:
  type: local                     # local (SQLite) | postgres | remote
  database:
    # SQLite:
    path: /app/data/keyorix.db
    # require_existing_path: false  # default false. When true, the server
    #   REFUSES to start if the SQLite file above does not already exist,
    #   instead of creating a new, empty one in its place — see
    #   "Refusing to vivify a missing database" below.
    # PostgreSQL (recommended for production) — set type: postgres above:
    # dsn: "host=db user=keyorix dbname=keyorix port=5432 sslmode=require"
    # ...or field by field: host, port, name, user, and
    # ssl_mode: require           # disable | allow | prefer | require | verify-ca | verify-full
    #   (default require; any other value is refused at start-up)
    # ssl_root_cert: pg-ca.pem    # CA that signed the database's certificate; REQUIRED
    #   with verify-full/verify-ca, or "system" for the OS CA store. See
    #   "PostgreSQL TLS" below.
    # password: ""                # prefer KEYORIX_DB_PASSWORD (or KEYORIX_DB_PASSWORD_FILE);
    #   see "PostgreSQL password precedence" below
    # max_open_conns: 8          # default: 8 for SQLite, 25 for Postgres (see below)
    # max_idle_conns: 8          # default: the effective max_open_conns
    # native_read_pool_max: 8    # POSTGRES ONLY. Cap of the separate pool the machine
    #   credential lookup and the node-stamp read run on. Default 8 (unchanged); 1 to
    #   1000, and never more than max_open_conns. Counted in the boot-time connection
    #   headroom warning. Raise it only if pg_stat_activity shows requests waiting on
    #   that pool; each unit is one more PostgreSQL connection per replica.
    conn_max_lifetime_minutes: 30
    # audit_flusher_linger_window: ""  # e.g. "1ms"; default "" (0, no deliberate
    #   wait — the audit-chain batching flusher commits whatever is already
    #   queued immediately, instead of waiting for more writers to join the
    #   same batch). A nonzero window trades per-request latency for larger
    #   audit batches. Leave it at the default unless the
    #   keyorix_audit_flusher_batch_size/_flushes_total metrics (exposed on
    #   the server's /metrics endpoint) show a reason for your own load shape.
    # audit_durability: standard   # strict | standard. Default: standard on
    #   PostgreSQL; SQLite runs strict only (standard REFUSES TO START there).
    #   strict: the audit commit waits for the disk sync, no audit entry is lost
    #   to any crash. standard: the audit row is still committed before the
    #   secret is returned (a failed audit write still fails the request), but
    #   the disk sync is not awaited; an OS crash or power loss can lose the
    #   last few hundred ms of audit entries as a tail (about 3 x PostgreSQL's
    #   wal_writer_delay, 600 ms at its default). Config file only. See
    #   docs/security/hardening-guide.md §5a. The old
    #   insecure_audit_skip_durable_sync (true = standard, false = strict) is a
    #   deprecated alias for one minor release.
    # insecure_audit_skip_reads: false  # INSECURE when true (ADR-112 Amendment 4):
    #   successful secret-value reads write NO audit row and no access-log row
    #   (REST, gRPC, render, copy, connector reads, and every client through
    #   the API). Writes, permission changes, authentication, denied reads
    #   (native and federated, at both settings) and admin actions are still
    #   audited. WARNING + audit event at every start,
    #   posture deviation, security.audit_reads_skipped in /system/info, web UI
    #   banner. Config file only; refused by a compliance profile. See
    #   docs/security/hardening-guide.md §5b.
    # pooler: none                # none (default) | pgbouncer-session | pgbouncer-transaction.
    #   POSTGRES ONLY. Names the connection pooler in front of PostgreSQL;
    #   pgbouncer-transaction changes how statements and advisory locks are
    #   run. See docs/postgresql-poolers.md.
```

### PostgreSQL TLS

`ssl_mode` sets how the server's connection to PostgreSQL is protected, and
`ssl_root_cert` names the CA that signed the database server's certificate.
`ssl_mode` takes only the six values below (the PostgreSQL driver's own set,
case-sensitive). Any other value is refused at start-up with the list of valid
ones, instead of failing later at the first connection:

```
storage.database.ssl_mode "verify_full" is not a valid sslmode; use one of: disable, allow, prefer, require, verify-ca, verify-full
```

| `ssl_mode` | Encrypted | Server certificate checked |
|---|---|---|
| `disable` | no | no (reported by `admin validate --posture` as `storage.database.insecure_disable_database_tls`) |
| `allow` | only if the server insists | no. Tries plaintext first. Reported by `admin validate --posture` as `storage.database.insecure_allow_plaintext_database_fallback` |
| `prefer` | only if the TLS attempt succeeds | no. Falls back to plaintext whenever TLS fails, including when anything on the network path answers "no TLS". Reported by `admin validate --posture` as `storage.database.insecure_allow_plaintext_database_fallback` (a `dsn` with no `sslmode` is `prefer` too) |
| `require` (default) | yes | no. With `ssl_root_cert` set, the chain is checked against it (libpq/pgx behaviour), but the host name is not |
| `verify-ca` | yes | chain against `ssl_root_cert`, not the host name |
| `verify-full` | yes | chain against `ssl_root_cert` **and** the host name in `host` |

**`verify-full` and `verify-ca` require `ssl_root_cert`.** Without it the
server refuses to start (`admin init` and `admin validate --posture` report the
same error):

```
storage.database.ssl_mode is verify-full but no CA certificate is configured, so the database
server's certificate would be checked against whatever trust store the process happens to find
(PGSSLROOTCERT, ~/.postgresql/root.crt or the OS store) -- refusing to start. Set
storage.database.ssl_root_cert to the PEM file of the CA that signed the database server's
certificate, or to "system" to trust the OS CA store.
```

Before this check, a `verify-full` config with no CA connected anyway and
verified against whatever the PostgreSQL driver found on its own: the
`PGSSLROOTCERT` environment variable, `~/.postgresql/root.crt` of the user
running the server, or the operating system's CA store. Neither of the first
two is part of the Keyorix config, so the trust anchor depended on the host.

`ssl_root_cert` values:

- **A path to a PEM file** with the CA certificate(s), passed to the driver as
  `sslrootcert`. A relative path is relative to the config file's directory
  (like `database.path`); `..` is refused. The file is checked at start-up and
  on every connection the server or an `admin` command opens, with the same
  rules as the CLI's `--ca-file`: it must exist, be a regular file of at most
  1 MiB, hold at least one PEM certificate and no private key, and must not be
  writable by group or others (`chmod go-w`). A file that fails any check is a
  refusal, never a fallback to other roots.
- **`system`**: trust the operating system's CA store, for a database whose
  certificate a public CA issued. pgx then always verifies the host name, as
  with `verify-full`.

With `dsn:` instead of fields, put the CA in the connection string
(`sslrootcert=/path/ca.pem` or `?sslrootcert=...`); the same rules apply to a
`dsn` whose `sslmode` (or `PGSSLMODE`, when the dsn has none) is
`verify-full`/`verify-ca`. `ssl_root_cert` together with `dsn` is refused,
because the dsn is used as-is and the key would be ignored. `ssl_root_cert`
with `ssl_mode: disable` is refused too: the connection would be neither
encrypted nor verified.

**`ssl_mode` together with `dsn`.** The dsn is used as-is, so `ssl_mode` used
to be silently ignored next to it: `ssl_mode: verify-full` with a dsn saying
`sslmode=disable` connected in plaintext. Now, when both are set, the dsn must
state `sslmode` itself and it must equal `ssl_mode`, or the server refuses to
start (`ssl=true` in a URL dsn is the driver's alias for `sslmode=require`).
Leaving `ssl_mode` out next to a `dsn` is fine.

**The effective sslmode.** With a `dsn`, the sslmode is the dsn's own; when
the dsn has none, `PGSSLMODE`; otherwise the driver's default, `prefer`. With
`sslrootcert=system` the driver always runs `verify-full`. Start-up
validation, the insecure-settings warnings and `admin validate --posture` all
read this effective value, so a dsn with `sslmode=disable` is reported as
`storage.database.insecure_disable_database_tls` whatever `ssl_mode` says.

**Connection-service files are refused.** `service=` or `servicefile=` in the
`dsn`, or the `PGSERVICE` environment variable, make the PostgreSQL driver read
`sslmode`, `sslrootcert` and `host` from a `pg_service.conf` that Keyorix does
not inspect, which would sidestep the CA requirement above. The server and the
`admin` commands refuse to start with such a setting; put the same settings in
`storage.database` (or the `dsn`) instead. `PGSERVICEFILE` on its own does
nothing (the driver reads a service file only when a service is selected) and
is not refused.

The Helm chart passes `externalDatabase.sslRootCert` through as
`ssl_root_cert` (it does not mount the file; mount it yourself, or use
`system`). `admin validate --posture` prints one informational line saying
what is encrypted and what is verified against which CA.

### PostgreSQL password precedence

The database password comes from `KEYORIX_DB_PASSWORD`, or the file named by
`KEYORIX_DB_PASSWORD_FILE` (setting both is refused, as for every `<NAME>_FILE`
secret), or `storage.database.password` -- see
[Secrets from files](#secrets-from-files-name_file). How it combines with the
connection settings:

| `storage.database.dsn` | A password source is set | Result |
|---|---|---|
| empty (host/port/name/user fields) | yes | the password is used for the connection |
| set, **no** password in it | yes | the password is used with the DSN's settings |
| set, no password in it | no | DSN used as written (e.g. trust auth, `.pgpass`) |
| set, **with** a password (`password=...` or `postgres://user:pw@...`) | no | DSN used as written |
| set, **with** a password | **yes** | **refused at startup** |

The password is never written into the DSN: Keyorix parses the DSN with the
PostgreSQL driver's own parser and sets the password on the parsed settings, so
no character in it (quotes, backslashes, spaces, `=`, `?`, `@`, ...) can change
the host, `sslmode`, `sslrootcert` or any other setting the DSN names. A DSN the
driver cannot parse is refused at startup.

The last row is an error, not a silent choice: the server and every command that
opens the database (`admin migrate`, `admin validate`, `admin restore`, ...) stop
with `storage.database.dsn already contains a password and KEYORIX_DB_PASSWORD is
also set; ... remove the password from storage.database.dsn ... or unset
KEYORIX_DB_PASSWORD`. Fix it by keeping the password in one place only. The
message names the setting and never prints either password or the DSN.

If Postgres rejects the credentials (SQLSTATE `28P01` or `28000`), or the server
(or a proxy/pooler in front of it) drops the connection while authenticating, the
server and the admin commands stop with one message: `postgres authentication failed
for user "..." at host:port ... Check the database user ... and the password source:
KEYORIX_DB_PASSWORD, KEYORIX_DB_PASSWORD_FILE, storage.database.password, or the
password in storage.database.dsn`. It never contains the password or the DSN; the
server also prints the driver's own text on a second line with the password and DSN
redacted. A connection reset during the login exchange is treated as an
authentication failure only when it happens after the TCP connection was
established; a refused or timed-out connection is reported as before.

### Starting with PostgreSQL: `admin init --storage-type postgres`

`keyorix-server admin init` writes a SQLite config by default and creates the
SQLite file. For a PostgreSQL deployment run `admin init --storage-type postgres`
in a fresh directory: the config is written with `storage.type: postgres` and no
SQLite path, and nothing SQLite is created. Set `storage.database.dsn` (or the
host/name/user fields plus `KEYORIX_DB_PASSWORD`) and run `admin init` again to
finish. `--storage-type` only applies to a config init writes; with an existing
config of a different type init refuses and changes nothing.

### Refusing to vivify a missing database

`require_existing_path` (SQLite only, default `false`).

A mistyped `path`, or a volume mount that silently failed to attach, does not produce an error
today — SQLite happily creates the file, the migration runs, and you get a healthy-looking
server with zero secrets in it, while your real data sits untouched at the path you meant. An
absolute `path` does not help: it stops two processes diverging onto two different files, but a
single wrong absolute path still vivifies cleanly.

Set `require_existing_path: true` and the server refuses to start instead:

```
no database found at /app/data/keyorix.db (configured database.path: "/app/data/keyorix.db")
and database.require_existing_path is set: run 'keyorix system init --database' to create one
deliberately, or verify database.path and the working directory -- refusing to create a new,
empty database in its place
```

(The command the message names is stale: the supported way to create the database is
`keyorix-server admin init --database`, below.)

Create the database deliberately with `keyorix-server admin init --database` (which creates the file
with `O_CREATE|O_EXCL`), then start the server.

In-memory DSNs (`:memory:`, `...?mode=memory`) are unaffected — there is no file that could
pre-exist. The Postgres backend is unaffected too.

**Why this is off by default:** the shipped first-boot paths (`server/entrypoint.sh`,
`docker-compose.yml`) start the server directly and let it create the database, so turning this
on by default would break every first boot that does not run `keyorix-server admin init --database`
first. Turn it on once your deployment creates the file explicitly — which is exactly the point:
after that, a missing file can only mean something went wrong.
### Single-writer mode (`single_writer`)

`storage.database.single_writer` (default `false`, PostgreSQL only) declares this server the only writer
of its database. A second server, an admin command with `--force`, or any SQL session that writes to a
security table is refused while it runs; revocations made through the server stay immediate. The server
refuses to start if the database-side write fence cannot be installed and verified. Not supported with
more than one replica, with SQLite, or behind PgBouncer transaction pooling. Operations, the emergency
two-step for a direct database change, and where the state is shown: [single-writer.md](single-writer.md).

### Audit commit durability (`audit_durability`)

`storage.database.audit_durability` (ADR-112 Amendment 3) chooses whether the
audit commit for a secret read waits for the disk sync. At both levels the
audit record is committed **before** the secret value is returned, and a failed
audit write fails the request.

| Level | Meaning | Backends |
|---|---|---|
| `strict` | Waits for the disk sync. No audit entry is lost to any crash or power loss. | PostgreSQL, SQLite (SQLite's only level and default) |
| `standard` | Does not wait for the disk sync (`SET LOCAL synchronous_commit = off` on the audit transaction only). A server process crash loses nothing; an OS crash, power loss or PostgreSQL crash can lose up to ~600 ms of audit entries as a tail, never a gap. | PostgreSQL only; the PostgreSQL default |

Secret writes, revocations and rotations commit durably at both levels.
`audit_durability: standard` on SQLite refuses to start: `PRAGMA synchronous`
is per-connection and the pool is shared, so relaxing it would relax every
table. Every start logs one `INFO` line with the effective level;
`admin validate` and `GET /api/v1/system/info` (`security.audit_durability`)
report it, and a change between starts is audited. Neither level is a posture
deviation. Comparison with Vault/OpenBao's file audit device and how to choose:
[`security/hardening-guide.md` §5a](security/hardening-guide.md#5a-audit-durability-levels).

`insecure_audit_skip_durable_sync` is a deprecated alias for one minor release
(`true` = `standard`, `false` = `strict`); it logs a deprecation line, and
setting both keys to conflicting levels refuses to start.
### Log format (`server.log.format`)

`text` (default) keeps the existing human-readable lines. `json` writes every log line as
one JSON object with `ts`, `level` and `msg`, and the HTTP access log and panic lines also
carry `request_id`, `principal_type` and `route`. Any other value refuses to start. Fields,
request-id behaviour and what is and is not redacted: [operations/logging.md](operations/logging.md).

### Access log when the sink stalls (`server.access_log.on_sink_stall`)

The HTTP access log is written through a 1 MiB in-memory queue to the process
log (stdout, a pipe to a log collector). If that sink stalls and the queue fills:

| `on_sink_stall` | Behaviour |
|---|---|
| `block` (default) | Requests wait for the sink. No access-log line is ever lost; every request stalls while the sink does. |
| `drop` | Keeps serving secrets when the log sink stalls; access-log lines past the 1 MiB queue are dropped and reported; the audit trail is unaffected. |

`drop` is opt-in, config-file only, and never silent:

- a counter, `access_log_dropped`, plus the effective mode `access_log_on_sink_stall`,
  in `GET /api/v1/system/info` (`security`);
- a warning line at most once per 10 s while drops happen (with the count since the
  previous warning), and one `access log sink recovered, N lines dropped in total`
  line when the sink catches up;
- the mode at startup and, when `drop`, in `keyorix-server admin validate` (posture).

Any other value is rejected at startup. The Helm chart sets it with
`server.accessLog.onSinkStall`.

## Encryption & KEK providers

Envelope encryption (ADR-004): a per-process **DEK** encrypts secrets/tokens and
is stored on disk wrapped by a **KEK**. `key_provider` selects where the KEK comes
from (ADR-038). When `encryption.enabled` is true and no `key_provider` is set,
the default `password` provider is used.

```yaml
storage:
  encryption:
    enabled: true
    dek_path: /app/keys/data.key  # wrapped DEK (never the raw key)
    salt_path: /app/keys/kek.salt # KEK salt (password provider only)

    # key_provider — default is "password" when omitted.
    key_provider:
      type: password              # password | file | env | exec | shamir | tpm | aws-kms | gcp-kms | azure-kms

      # type: file — read raw key material from a path (mounted CSI/sealed
      # secret, KMS sidecar output). Accepts 32 raw bytes, hex, or base64.
      # file_path: /etc/keyorix/kek.key

      # type: env — read the KEK (hex or base64) from the named env var's value.
      # env_var: KEYORIX_KEK

      # type: exec — run a resolver command and read the KEK (32 raw bytes, or
      # hex/base64) from its stdout. argv form (no shell); fetches from any
      # external secret store Keyorix has no built-in client for.
      # exec_command: ["op", "read", "op://vault/keyorix-kek/value"]

      # type: shamir — reconstruct the KEK from K-of-N Shamir shares (no single
      # custodian holds it). Provide at least the threshold many shares (hex/base64)
      # via files and/or env vars. Generate with `keyorix-server admin encryption shamir-split`.
      # shamir_share_files: [/etc/keyorix/share-1.hex, /etc/keyorix/share-2.hex, /etc/keyorix/share-3.hex]
      # shamir_share_env: [KX_KEK_SHARE_1, KX_KEK_SHARE_2]
      # shamir_commitment is also printed by shamir-split — set it so reconstruction
      # is verified by a real HMAC commitment, not just a forgeable framing check
      # (#429). Safe to store here in the clear: it's one-way, reveals nothing about
      # the KEK.
      # shamir_commitment: 3f9a…

      # type: tpm — seal the KEK to the host TPM 2.0. The KEK is generated and sealed
      # on first start; only the sealed blob (wrapped_key_path) is on disk, and it is
      # unsealable only on this machine's TPM.
      # tpm_device: /dev/tpmrm0
      # wrapped_key_path: keys/kek.tpm

      # type: aws-kms / gcp-kms / azure-kms — envelope-wrap the KEK with a cloud
      # KMS/HSM key (ADR-041); the wrapping key stays in the KMS/HSM. Credentials
      # come from the standard cloud environment (AWS: env/instance-profile/IRSA;
      # GCP: ADC; Azure: DefaultAzureCredential / managed identity).
      # kms_key_id: arn:aws:kms:eu-west-1:123456789012:key/abcd-…                  # aws-kms
      # kms_key_id: projects/p/locations/eu/keyRings/r/cryptoKeys/keyorix-kek      # gcp-kms
      # kms_key_id: https://myvault.vault.azure.net/keys/keyorix-kek               # azure-kms
      # wrapped_key_path: keys/kek.kms
```

- **`password`** (default): KEK = PBKDF2-SHA256(`KEYORIX_MASTER_PASSWORD`, salt,
  600 000). Requires `KEYORIX_MASTER_PASSWORD`. This is byte-identical to all
  prior releases — existing `dek.key` files keep working.
- **`file`** / **`env`**: the KEK is externally managed (e.g. injected by a KMS,
  CSI driver, or sealed/SOPS secret). `KEYORIX_MASTER_PASSWORD` is **not** required.
- **`exec`**: the KEK is produced on stdout by an operator-configured resolver
  command (`exec_command`, an argv run **without a shell**) — e.g. `op read …`
  (1Password), `sops -d kek.enc`, `vault read -field=kek …`, or a CSI/sidecar
  helper. Output is 32 raw bytes or a hex/base64 encoding thereof. The command runs
  at startup (fail-closed, 30s timeout) and `KEYORIX_MASTER_PASSWORD` is **not**
  required. The argv is trusted deployment config, like `file_path`/`env_var`.
- **`shamir`**: the KEK is split into **N Shamir shares** with a **K-of-N**
  threshold, so no single custodian holds it and at least K must combine to unseal
  (separation of duties for the master key). Generate with `keyorix-server admin encryption
  shamir-split --shares N --threshold K` (the KEK is never printed/stored — only the
  shares are, plus a `shamir_commitment` value). Provide at least K shares at
  startup via `shamir_share_files` and/or `shamir_share_env` (each a hex/base64
  share); the server reconstructs the KEK in memory. Also set `shamir_commitment` —
  without it, reconstruction falls back to a 4-byte magic check that (#429) an
  attacker holding threshold-1 genuine shares can forge to make ANY chosen value
  reconstruct; with it, the reconstructed KEK is verified against a real HMAC-SHA256
  commitment computed at split time. `KEYORIX_MASTER_PASSWORD` is **not** required.
  Move an existing install onto it with `keyorix-server admin encryption migrate-provider
  --to-type shamir --to-shamir-share-files … --to-shamir-commitment …`. ⚠️ Losing
  more than N-K shares makes the KEK — and all data — permanently unrecoverable;
  store and back up shares separately.
- **`tpm`**: the KEK is **sealed to the host TPM 2.0** (`tpm_device`, default
  `/dev/tpmrm0`) and only unsealable on that machine. A random KEK is generated and
  sealed on first start; only the **sealed blob** (`wrapped_key_path`) touches disk,
  so the KEK can't be recovered from a stolen disk alone. `KEYORIX_MASTER_PASSWORD`
  is **not** required; startup needs the TPM reachable (fail-closed). ⚠️ The sealed
  blob is bound to *this* TPM — it cannot be unsealed on another host, so back up the
  data under a portable provider (or re-seal per host) and note that a TPM
  clear/replacement makes the blob unrecoverable. Move an existing install on with
  `keyorix-server admin encryption migrate-provider --to-type tpm --to-wrapped-key-path keys/kek.tpm`.
  ⚠️ **No PCR policy binding yet**: the seal is bound to "this TPM chip", not to a
  verified/measured boot state — no PolicyPCR session is used. Any code capable of
  asking the TPM to unseal the blob succeeds regardless of firmware/bootloader/kernel
  integrity, so this provider does **not** currently protect against a compromised
  boot chain on an otherwise-genuine, present TPM. This is a deliberate deferral, not
  an oversight: Keyorix ships as a plain binary/container with no owned host OS image
  or update hook, so it has no way to detect an impending firmware/bootloader/kernel
  patch and reseal beforehand, and there is no recovery/escrow fallback if a legitimate
  host update changes the PCR values — `migrate-provider` itself needs to unseal the
  *current* blob first, so it can't rescue a PCR-mismatched one. Adding PCR binding
  without also building that update-integration and recovery story would trade a
  narrow, known limitation for a silent risk of a routine host patch permanently
  destroying the KEK (and every secret under it); see `internal/crypto/tpm_provider.go`
  for the full reasoning.
- **`aws-kms`** / **`gcp-kms`** / **`azure-kms`** (ADR-041): the KEK is a random key
  **wrapped by a cloud KMS/HSM key**; only the wrapped blob is on disk
  (`wrapped_key_path`), unwrapped via the KMS at startup. The wrapping key never
  leaves the KMS/HSM. `kms_key_id` is an AWS key ID/ARN/alias, a GCP crypto-key
  resource name, or an Azure Key Vault key identifier URL.
  `KEYORIX_MASTER_PASSWORD` is **not** required. Startup needs the KMS reachable
  (fail-closed).

> Rotating the **DEK** (`keyorix-server admin encryption rotate`) re-encrypts all rows under a
> new DEK and is independent of the provider.
>
> **Switching providers** (e.g. password → a cloud KMS) is
> `keyorix-server admin encryption migrate-provider --to-type <type> … --confirm` (ADR-041): it
> re-wraps the DEK under the target provider's KEK **without re-encrypting any
> data** (fast, no DB lock), verifies the target unwraps it, and keeps a backup of
> the previous wrapped DEK. Migrating `--to-type password` reads the new passphrase
> from `KEYORIX_NEW_MASTER_PASSWORD` and doubles as a master-passphrase rotation.
> After it succeeds, update `key_provider` in this config to the target before the
> next restart (the command prints the exact block).

If `encryption.enabled` is false, secrets and tokens are stored in **plaintext** —
acceptable only for local development.

---

## secrets

```yaml
secrets:
  chunking:
    enabled: true
    max_chunk_size_kb: 64
    max_chunks_per_secret: 100
  limits:
    max_secrets_per_user: 10000
```

## security

File-permission self-checks, plus the **deployment-wide MFA mandate** (ADR-034).

**Both `enable_file_permission_check` and `require_mfa` default to `true` when
omitted** (ADR-112, secure-by-default baseline) — a fresh install enforces both
from its first start with no config changes needed: the first admin to log in is
asked to enrol MFA (TOTP or passkey) before doing anything else, and a problem
with the encryption key material or the database file (missing, undersized,
readable beyond its owner) refuses to start. The config file and TLS cert/key —
inputs an orchestrator usually mounts (a Kubernetes ConfigMap/Secret is
root-owned 0644 by default) — only get a warning naming the file, the mismatch
and the fix while the key is left at its default; set
`enable_file_permission_check: true` explicitly to refuse on those too.

The files behind `KEYORIX_*_FILE` secret variables ([above](#secrets-from-files-name_file))
count as key material: strict on the default as well (accessible to other users,
or writable by the group, refuses to start), with the same upgrade grace period
as the key files.

The shipped `keyorix.docker.yaml` and Helm chart **omit this key on purpose**, so
they run with the check on (the default) and the bind-mounted / ConfigMap-mounted
config file only warns. Writing `enable_file_permission_check: true` into either
would audit that orchestrator-owned file strictly and the container would refuse
to start.

**Upgrading an existing deployment** that never set
`enable_file_permission_check`: the server tells a fresh install from an upgrade
by its database (users already exist). An upgrade gets a grace period — a
problem the startup checks find is logged as a loud `ADR-112` warning instead of
refusing to start. The grace period ends for good the first time the deployment
boots with the checks passing (recorded in the database as
`adr112.file_permission_check.enforced`); from then on it fails closed like a
fresh install. Setting the key explicitly (`true`, or `false` to opt out
visibly) also ends it.

While in the grace period the deployment is **not** reported as compliant: every
start logs `WARNING: security.insecure_skip_startup_validation is in effect
(grace-warn-only)`, and `admin validate --posture` counts it as a deviation. The
setting's state (`off`, `grace-warn-only`, `enforcing-implicit` or
`enforcing-explicit`) is recorded in the start-to-start settings diff, so
entering or leaving the grace period is audited. The first start after upgrading
to this version records one such change, because the recorded value changed
from `true`/`false` to these names.

`require_mfa` on an upgraded deployment that never set it gets the same kind of
grace period: MFA is **not** enforced yet, and every start logs a loud `ADR-112
grace period` warning. Have every interactive admin enrol, then set
`require_mfa: true` explicitly to enforce it (or `false` to opt out visibly). A
fresh install is enforced from its first start and recorded in the database
(`adr112.require_mfa.enforced`), so it stays enforced after its admins exist.

`require_mfa` is an ADR-112 opt-out like the `insecure_*` settings: its registry
entry is `security.insecure_disable_mfa_requirement`. An explicit
`require_mfa: false` logs `WARNING: security.insecure_disable_mfa_requirement is
in effect (off)` on every start, is recorded in the start-to-start settings
diff, and `admin validate --posture` counts it as a deviation. The grace period
reads `grace-not-enforced` and is treated the same way. (The YAML key keeps its
current name; only the registry identifier carries the `insecure_` prefix.)

| State (settings-diff value) | When | Counts as a deviation |
|---|---|---|
| `off` | `require_mfa: false` written in the config | yes |
| `grace-not-enforced` | key absent, upgraded deployment inside the grace period | yes |
| `enforcing-implicit` | key absent, fresh install or past the grace period | no |
| `enforcing-explicit` | `require_mfa: true` written in the config | no |

The first start after upgrading to this version records one settings-diff
change for this entry, because it did not appear in the previous snapshot.

```yaml
security:
  enable_file_permission_check: true
  auto_fix_file_permissions: true
  insecure_allow_unsafe_file_permissions: false   # deprecated alias: allow_unsafe_file_permissions
  require_mfa: true               # false = don't mandate a second factor for interactive login
  login_lockout:
    enabled: false                # opt-in per-account lockout (brute-force protection)
    max_attempts: 5               # failed password logins within the window before locking
    window: "15m"                 # consecutive-failure window
    base_cooldown: "1m"           # lock duration for the first lockout
    max_cooldown: "1h"            # ceiling for the exponential backoff
    insecure_disable_login_lockout: false   # deprecated alias: disabled
  auth_rate_limit_fallback:
    replicas: 1                   # server replicas sharing the auth rate limits (see below)
```

**Auth rate limits during a database fault** (`auth_rate_limit_fallback`). The auth
rate limits are kept in the database, so they hold across replicas:
- the per-IP login, password-reset and SSO/SAML-begin budgets;
- the per-account lockout.

If that storage fails, no limit is switched off. Each server process enforces the same
limits from memory until the database recovers (ADR-040 amendment). While it does:

- **Each replica counts on its own.** With `replicas: N`, each process allows 1/N of
  every limit (at least one attempt), so the cluster as a whole stays near the normal
  limit. Set it to your replica count. Left at `1` with several replicas, an attacker
  who reaches every replica gets up to N times the limit during the outage. Normal
  operation is unaffected: a count read from the database is already cluster-wide.
- **Password reset is tighter.** Each replica allows half the per-IP reset limit,
  divided by `replicas`, and at most the same number of reset emails per account per
  window. Requests over the limit still get the usual "if that email is registered"
  response; the email is just not sent.
- **It is visible.** Every fallback writes an `auth.rate_limit_error` audit event and
  increments `keyorix_auth_rate_limit_fallback_total{budget}`. `/health` reports
  `"auth_rate_limit": "degraded"` until no limit has needed the fallback for one
  limit window (15 minutes). It names no budget, account or address, and `/health`
  still returns 200.

Every setting named `insecure_*` is part of ADR-112's opt-out rule: it weakens
the baseline below its secure default, is warned about at every start it's in
effect, appears in the start-to-start settings diff audit, is reported as a
deviation by the posture report below, and (renamed settings only, for now)
keeps its old name working as a deprecated alias that also warns when used.

**`keyorix-server admin validate --posture`** (ADR-112 §4) reports every
secure-baseline deviation in one place instead of warnings scattered across
separate start-up log lines, and exits non-zero if any is found. **Every
security-weakening setting in effect counts** — encryption-at-rest disabled,
database TLS disabled, unauthenticated `/metrics`, a log-delivered setup link —
because of what it does, independently of whether its `insecure_` naming has
been settled yet. Also reported: `enable_file_permission_check` disabled, a real
file-permission/encryption/database problem, an incomplete key-file set, a
cleartext listener contradicting `require_transport_tls`, and an admin without
MFA or a passkey.

Each deviation says whether it comes from a **shipped default** or an
**explicit** config choice, so "this install has not been hardened yet" is
distinguishable from "someone turned this off" — both count toward the exit
code. *Explicit* means the config file literally writes the setting's key (even
to its default value — `server/config/production.yaml` writes
`require_transport_tls: false`, so there it is explicit); *shipped default*
means the file is silent and the weak state is what an absent key resolves to.
A key that arrives only through a YAML merge key (`<<:`) reads as not written.
Startup checks are reported only if they ran: validation stops at the first
failed check, and any check after it is listed as "not evaluated" rather than
as a second failure. An upgraded deployment in the `enable_file_permission_check`
or `require_mfa` grace period is a deviation even when nothing is wrong yet, because
the server would only warn, or not enforce at all, if something were. The report
works this out from the database the same way the server does; if it cannot read
the database it counts the deviation instead of assuming the deployment enforces.
A setting on its implicit default with a real problem is also its own deviation. Only TLS mode and the KEK salt
file's age are informational: no rotation-age threshold is defined anywhere in
this codebase, so a number there would be a guess.

Like every `admin` command, `admin validate --posture` needs the database to
itself: it refuses while the server runs (stop it, or in Docker Compose use
`docker compose stop backend` then `docker compose run --rm backend ./keyorix-server admin validate --posture`).

### The generated config is the secure baseline

`keyorix-server admin init` writes a config on which `admin validate --posture`
prints `No deviations found.` (ADR-112 §4; guarded in CI by
`server/admin_init_secure_baseline_test.go`). In the same run it generates the
files that config references, each `0600` in a `0700` directory, and prints
none of their contents:

| File | What | Config key |
|---|---|---|
| `certs/server.crt`, `certs/server.key` | self-signed ECDSA P-256 certificate for `localhost`, the host name, `127.0.0.1`, `::1`, valid 397 days | `server.http/grpc.tls.cert_file`/`key_file`, with `tls.enabled: true` and `security.require_transport_tls: true` |
| `secrets/metrics_token` | 32 random bytes, base64url | `server.http/grpc.metrics_token_file` |

Rate limiting is on (`50`/`100` HTTP, `25`/`50` gRPC, as in
`server/config/production.yaml`); the request-body cap stays at its default.

- **Existing files are kept.** A certificate/key pair or token already at those
  paths is used as is (only one of cert/key present is an error). To use your own
  certificate, put it there before `admin init`, or change `cert_file`/`key_file`.
- **An existing config is never changed**, and nothing is generated for it
  (ADR-112: no silent change on upgrade). Re-running `admin init` next to one is a
  no-op for the config.
- **Fail closed.** A missing certificate, or an unreadable/empty
  `metrics_token_file`, stops the server at startup. `metrics_token_file` follows
  the secret-file rules (regular file, one trailing newline stripped, not readable
  by others; the startup permission check covers it). Setting both
  `metrics_token` and `metrics_token_file` is refused.
- **The CLI must trust the self-signed certificate:**
  `keyorix config set ca_file /abs/path/certs/server.crt` (stored in the CLI's
  credentials file), `KEYORIX_CA_FILE`, or `--ca-file` on one command, in that
  order of precedence: flag, env, stored. The CLI then trusts exactly that file's
  certificates (not the OS store); a missing file, one with no certificate, one
  holding a private key, or one writable by group/others is refused. `admin init`
  prints the exact line. `SSL_CERT_FILE` only works on Linux.
- **Behind a TLS-terminating proxy** instead: set `server.http.tls.enabled: false`,
  list the proxy in `server.http.trusted_proxies`, and accept that the posture
  report then lists `security.insecure_allow_cleartext_transport` if you also set
  `require_transport_tls: false` (it must be false for a cleartext listener to start).

Docker Compose and Helm reach the same baseline by default since v0.96.0
(`docker-compose.yml` with `keyorix.docker.yaml`, and the chart's
`secureBaseline.enabled`; docs/SELF_HOSTING.md §7);
`keyorix-server admin init --secure-files` is the generation step on its own,
for a config an orchestrator supplies.

**`admin init --dev`** writes the relaxed config for a throwaway local demo: TLS
off and not required, rate limiting off, no metrics token. Its first lines are a
`DEV-ONLY CONFIG` banner naming those three, and the posture report lists them
and exits 1. It generates no certificate or token. `require_mfa` stays on. The
demo and e2e scripts in `scripts/` that talk plain HTTP use it explicitly.

### Hardening an older config (clearing the posture report)

A config written by an earlier `admin init` (or a `keyorix.docker.yaml` from before
v0.96.0) is a dev baseline: on it the report lists the three `insecure_*` settings below
(cleartext transport, unauthenticated `/metrics`, no API rate limit), and exits
1. Upgrading does not change it. Verified on a fresh SQLite install: setting
exactly these keys makes `admin validate --posture` print `No deviations found.`
and exit 0 (the startup warning text for each is the `insecure_*` name, not the
YAML key, so the mapping is:)

| Report names | Set in `keyorix.yaml` |
|---|---|
| `security.insecure_allow_cleartext_transport` | `server.http.tls.enabled: true` (with `cert_file`/`key_file`) and `security.require_transport_tls: true`; or terminate TLS at a proxy you trust and list it in `server.http.trusted_proxies` |
| `server.insecure_allow_unauthenticated_metrics` | `metrics_token: "<long random string>"` or `metrics_token_file: <path to a 0600 file>` on **both** `server.http` and `server.grpc` (the entry checks both listeners); `/metrics` then answers 401 without `Authorization: Bearer <token>` and 200 with it |
| `server.insecure_disable_api_ratelimit` | `server.http.ratelimit.enabled: true` and `server.grpc.ratelimit.enabled: true` (the entry checks both listeners, even with gRPC off) |

Also keep the key and config files `0600` and owned by the server's user. The
Docker Compose stack since v0.96.0 does this for you: its entrypoint copies the
bind-mounted `keyorix.docker.yaml` (which arrives as the host's owner/mode,
typically `0664`, uid 1000, while the container runs as uid 1001) to a private
0600 file owned by uid 1001 (#2922). A hand-rolled container setup that mounts the
config directly needs `chmod 600 keyorix.docker.yaml && sudo chown 1001 keyorix.docker.yaml`,
or the report counts a file-permission deviation.

The renamed settings, with the deprecated name each still accepts (same
meaning, a start-up warning when the old name is used; when both are set the
new name wins and the old one is reported). `[]` marks a list: the rename
applies to every entry.

| Deprecated name | Current name |
|---|---|
| `security.allow_unsafe_file_permissions` | `security.insecure_allow_unsafe_file_permissions` |
| `security.login_lockout.disabled` | `security.login_lockout.insecure_disable_login_lockout` |
| `security.recover_admin.keyless_mode` | `security.recover_admin.insecure_keyless_admin_recovery` |
| `audit.siem.allow_private_network_target` | `audit.siem.insecure_allow_private_network_siem_target` |
| `audit.siem.allow_insecure_transport` | `audit.siem.insecure_allow_plaintext_siem_transport` |
| `evidence_delivery.webhook.allow_private_network_target` | `evidence_delivery.webhook.insecure_allow_private_network_evidence_target` |
| `evidence_delivery.webhook.allow_insecure_transport` | `evidence_delivery.webhook.insecure_allow_plaintext_evidence_transport` |
| `notifications.webhook.allow_private_network_target` | `notifications.webhook.insecure_allow_private_network_notify_target` |
| `notifications.webhook.allow_insecure_transport` | `notifications.webhook.insecure_allow_plaintext_notify_transport` |
| `dynamic_secrets.allow_private_network_targets` | `dynamic_secrets.insecure_allow_private_network_dynamic_secret_targets` |
| `dynamic_secrets.allow_insecure_transport` | `dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport` |
| `storage.encryption.key_provider.kms_allow_context_fallback` | `storage.encryption.key_provider.insecure_allow_kms_context_fallback` |
| `storage.encryption.key_provider.allow_weaker_fallback` | `storage.encryption.key_provider.insecure_allow_weaker_kek_fallback` |
| `storage.encryption.key_provider.fallbacks[].kms_allow_context_fallback` | `storage.encryption.key_provider.fallbacks[].insecure_allow_kms_context_fallback` |
| `storage.encryption.key_provider.fallbacks[].allow_weaker_fallback` | `storage.encryption.key_provider.fallbacks[].insecure_allow_weaker_kek_fallback` |
| `sso.providers[].trust_asserted_email` | `sso.providers[].insecure_trust_saml_asserted_email` |
| `sso.providers[].saml.allow_idp_initiated` | `sso.providers[].saml.insecure_allow_idp_initiated_saml` |
| `audit_checkpoints.disabled` | `audit_checkpoints.insecure_disable_audit_checkpoints` |

With `require_mfa: true` (the default), an interactive (session-authenticated) user
**without** a second factor is confined to the MFA-enrolment endpoints until they
enrol. A TOTP secret **or** a passkey satisfies it. Non-interactive credentials —
personal access tokens, machine tokens, OIDC — are **exempt** so automation is
never broken. Per-project MFA (ADR-037) is set per project via the API
(`PUT /projects/{id}` `{ "require_mfa": true }`), independent of this flag.

An account that must also replace its password (a one-time password from `admin
recover-admin` or `user create --one-time-password`, an admin-forced reset, an expired
password) and has no second factor logs in to a **setup session**: at most 15 minutes,
confined to `change-password` and MFA/passkey enrolment, in either order. When both are
done the session ends and the next login is a normal two-step MFA login (#3024;
walkthrough in [operator/j5-lost-admin.md](operator/j5-lost-admin.md)). Every other
endpoint answers 403 with `pending_steps`.

**One-time passwords expire.** Every one-time password the system issues is stored with an
expiry, and the command or API call that issues it reports that time (UTC):

```yaml
security:
  recovery_one_time_password_ttl: 24h   # keyorix-server admin recover-admin (default 24h)
  one_time_password_ttl: 72h            # keyorix user create --one-time-password (default 72h)
```

Both are Go durations (write days as hours: `168h`). Leave a key empty for the default; a value
that is set but is not a duration, is zero or negative, or exceeds 168h (7 days) is refused at
start-up with the key named, rather than silently becoming the default. There is deliberately
no setting that means "never expires". The 24h default for recovery is
because it is an admin credential printed on a terminal and should be used the same day; the
72h default for new users covers a weekend between an admin creating an account and the
colleague first logging in. After the expiry, login with the password is refused exactly like
a wrong password (same response, no hint that it was merely late), audited server-side as
`auth.one_time_password_expired` (written asynchronously, so the refusal costs the same time as a
wrong password), and counted toward `login_lockout`. Expiry is enforced at login only: a session
that already exists keeps working, and `change-password`, own-profile updates and re-authentication
inside that session do not re-check it. A new password (the
user's own, via `change-password` or a setup link) removes the expiry, so a password the user
chose never expires this way. A fresh admin-forced reset (`user force-password-reset`) issues no
password and has no expiry (but see *Upgrading*). To get an account past an expired one-time password: re-run
`recover-admin` (admins, on the host), have **another administrator reissue it** (below), or
`user resend-setup-link` / re-create the user.

**Reissuing a one-time password** (REISSUE-1). An administrator issues a new one-time
password for an existing user — one whose first password expired, was lost, or who was never
told it:

```sh
keyorix user reissue-one-time-password bob@example.com     # or a numeric user ID
```

REST `POST /api/v1/users/{id}/reissue-one-time-password`, gRPC `UserService.ReissueOneTimePassword`.

- **Who:** the same permission as creating a user with a one-time password (`users.write`), plus
  the usual admin-rank ceiling over the target (you cannot reissue the password of an account
  that holds permissions you do not). There is no separate step-up or re-authentication: none of
  the existing user-management actions (suspend, force-logout, `require-password-reset`, resend
  setup link) asks for one, and this action is no more powerful than they are.
- **What the admin gets:** a freshly generated password, printed **once** — it is not stored
  in clear, is never written to the audit log, and a repeated call issues a different one — and
  the UTC time it expires (`security.one_time_password_ttl`, default 72h).
- **What happens to the account:** it goes to `password_reset_required` like a newly created
  one-time-password user, so the first login is confined to `change-password` (and, under
  `require_mfa`, to MFA enrolment, as in the setup session above); any login lockout is cleared;
  and **every existing session of the user ends**. Personal access tokens are treated as
  `user require-password-reset` treats them: the restriction applies to them at once (they stop
  working for anything but the password change) and they are revoked when the user sets the new
  password, like any password change. An enrolled second factor is **kept** — reissuing a
  password must not be a way to strip MFA from someone else's account; an MFA device that is
  lost needs its own reset.
- **Refused:** your own account (`400`, use `keyorix-server admin recover-admin` — see
  [operator/j5-lost-admin.md](operator/j5-lost-admin.md)); an account managed by an external
  identity provider (SSO/SCIM — a local password would bypass the IdP; `409`); a suspended or
  inactive account (`409` — reactivate it first, deliberately, rather than having a password
  reissue reactivate it); an actor who does not meet the rank ceiling (`403`). A refusal changes
  nothing.
- **Audit:** `user.one_time_password_reissued` (actor = the administrator, the description
  names the target and the expiry) and the existing `credential.displayed_out_of_band`; neither
  contains the password.

*Upgrading:* accounts already in `password_reset_required` when this version first starts
have no recorded expiry and cannot be told apart (a one-time password, an admin-forced reset
and an expired-password gate leave the same state), so they get **24 hours from the upgrade**.
An account whose owner changes the password in that window is unaffected; one that does not
is then refused at login until an admin re-issues access. **This includes accounts an admin
forced to reset and accounts held by the password max-age gate**, not only one-time passwords.
This happens once, in the same migration (SQLite and PostgreSQL) that adds the column, and is
logged at start-up with the count.

*Mixed-version rollouts:* the schema epoch is unchanged, so replicas still running the previous
version keep accepting an expired one-time password until they are upgraded. Expiry is fully in
force only once every replica runs this version; do not count on it during a rolling upgrade.

**Per-account login lockout** (`login_lockout`, opt-in) is brute-force protection
distinct from the per-IP rate limiter (ADR-040): after `max_attempts` failed
password logins within `window`, the account is locked for a cooldown that **backs
off exponentially** across repeated lockouts (`base_cooldown` × 2ⁿ, capped at
`max_cooldown`). While locked, even a correct password is refused. A successful login
clears the counter; an admin can clear a lock immediately with
`POST /api/v1/users/{id}/unlock` (`users.write`). It binds to the account (not the
IP), so rotating source IPs cannot evade it, and the lock auto-expires (no scheduler).

> **Tradeoff — account-lockout denial of service.** Because the lock binds to the
> account, anyone who knows a username can deliberately fail logins to keep that
> account locked. This is inherent to *any* account-bound lockout; here it is bounded
> by `max_cooldown` (the lock always self-heals) and an admin can clear it instantly.
> Keep `base_cooldown`/`max_cooldown` short enough that a lock-out attack degrades to a
> brief wait rather than a lasting denial — a large `max_cooldown` (e.g. hours) turns
> this defense into a weapon an attacker can wield against your users.

---

## webauthn

Phishing-resistant passkeys / FIDO2 as a second factor (ADR-036). Disabled by
default; when off, the passkey endpoints return 501 and login is unchanged.

```yaml
webauthn:
  enabled: true
  rp_id: keyorix.example.com           # effective domain, no scheme/port
  rp_display_name: Keyorix             # shown by the authenticator
  rp_origins:                          # full origins permitted to authenticate
    - https://keyorix.example.com
```

`rp_id` must be the registrable domain serving the app; `rp_origins` must include
the exact origin(s) the browser uses. A passkey satisfies `require_mfa`.

---

## dynamic_secrets

On-demand, short-lived database credentials (ADR-035). The API
(`/api/v1/dynamic-secrets/...`) is always served when the server runs; this block
only controls the **auto-revoke sweeper** that drops leases at expiry.

```yaml
dynamic_secrets:
  sweep_enabled: true            # revoke active leases past their TTL
  sweep_interval: "1m"           # cadence (Go duration); default 1m
  max_lease_ttl: "720h"          # install-wide ceiling on any lease's TTL; default 90d (#97)
```

`max_lease_ttl` is a hard, **install-wide** ceiling applied on top of (and always at
least as strict as) every config's own `max_ttl_seconds` — it exists so that an
operator who leaves a config's `max_ttl_seconds` at its default of "unset = no
ceiling" still can't end up minting a 100-year lease. It is a Go duration string;
unset or unparseable falls back to **90 days**. Set it tighter for your environment
(e.g. `"24h"`) if 90 days is too generous. It applies uniformly to every backend,
including the cloud-IAM ones below, and is enforced at both issue and renew time.

Targets are registered via the API — or from the terminal with
`keyorix dynamic-secret create` (the admin DSN is read from the
`KEYORIX_DYNAMIC_ADMIN_DSN` env var or a hidden prompt, never a flag) — with an
admin DSN, a backend type (`postgres`, `mysql`, `mongodb`, `redis`, `aws-sts`, `gcp`,
`azure`, or `kubernetes`), an optional creation template, and a default TTL
(`default_ttl_seconds`). Each config can also set its own, tighter ceiling via
`max_ttl_seconds` (0 = no per-config ceiling beyond the install-wide
`max_lease_ttl` above) — every issued lease's requested `ttl_seconds` is clamped to
whichever of the config's `max_ttl_seconds` and the install-wide `max_lease_ttl` is
smaller. The creation template form depends on the backend:
- SQL backends (`postgres`, `mysql`) — an SQL grant template using `{{name}}`.
- `mongodb` — a JSON role spec (`{"roles": [{"role": "readWrite", "db": "app"}]}`);
  the admin DSN is a MongoDB connection URI.
- `redis` — whitespace-separated ACL rule tokens (`~app:* +@read +@write`); the
  admin DSN is a Redis URI (`redis://:pass@host:6379/0`, or `rediss://…` for TLS)
  for a user that holds the `+acl` command.
- `aws-sts` (cloud IAM) — the "admin DSN" is instead a small JSON config:
  `{"role_arn":"arn:aws:iam::123456789012:role/keyorix-dyn","region":"eu-west-1","duration_seconds":3600}`
  (only `role_arn` is required). Issuing a lease calls `sts:AssumeRole` and returns
  short-lived **AWS credentials** (`access_key_id` / `secret_access_key` /
  `session_token`) rather than a username/password. The optional creation template is
  an inline **STS session policy** (JSON) that scopes the assumed role down. AWS
  credentials for the AssumeRole call itself come from the standard chain
  (env / instance-profile / IRSA), like the KMS and S3 integrations. STS credentials
  are **self-expiring and cannot be revoked or renewed** — a revoke is a no-op and a
  renew is refused (issue a new lease); minimum duration is 15 minutes (AWS limit).
- `gcp` (cloud IAM) — the JSON config is
  `{"service_account":"sa@project.iam.gserviceaccount.com","scopes":[...],"lifetime_seconds":3600}`
  (`service_account` required; `scopes` defaults to `cloud-platform`). Issuing mints a
  short-lived **service-account access token** (`access_token` field) via the IAM
  Credentials API; the caller's ADC identity (GOOGLE_APPLICATION_CREDENTIALS /
  workload identity) must hold `roles/iam.serviceAccountTokenCreator` on the target SA.
- `azure` (cloud IAM) — the JSON config is
  `{"scopes":["https://management.azure.com/.default"]}`. Issuing acquires a short-lived
  **Azure AD (Entra) access token** (`access_token` field) via DefaultAzureCredential
  (env / managed identity / workload identity).
- `kubernetes` (cloud IAM, ADR-058) — the JSON config is
  `{"namespace":"default","service_account":"my-app","audiences":[...],"revocable":true}`
  (`namespace` and `service_account` required; `api_server`/`ca_cert`/`token` are
  optional, for calling a cluster other than the one Keyorix runs in — omit them to
  use the standard in-cluster identity). Issuing mints a short-lived **ServiceAccount
  token** (`token` field) via the Kubernetes `TokenRequest` API. This is the one
  backend where `Revoke` can be a **real, immediate invalidation** rather than a
  no-op — see [Credential revocation semantics by backend](#credential-revocation-semantics-by-backend)
  below.

Like `aws-sts`, the `gcp` and `azure` backends mint **self-expiring tokens** — revoke
is a no-op, renew is refused, and they issue with the sweeper off (the cloud enforces
expiry); the optional creation template is unused by `gcp`/`azure`/`kubernetes`.
`kubernetes` tokens are likewise self-expiring and non-renewable, but — unlike the
other three — can opt into real early revocation; see below.

> **Enable the sweeper for MySQL, MongoDB and Redis targets.** Their accounts have
> no `VALID UNTIL` equivalent, so a lease TTL is enforced *only* by the sweeper —
> issuing is refused while it is disabled. PostgreSQL roles additionally carry a
> DB-level expiry (belt-and-suspenders). `aws-sts`, `gcp`, `azure`, and `kubernetes`
> are exempt: the cloud/cluster enforces the credential's expiry, so they can issue
> with the sweeper off.

### Credential revocation semantics by backend

`POST …/leases/{leaseID}/revoke` always marks a lease `revoked` in Keyorix and stops
it from being renewed or reissued from — but what that means for the underlying
credential **at the provider** differs by backend, and this is not a temporary gap:
for three of the four cloud-IAM backends, it is a permanent, well-understood
property of how that provider's temporary credentials work.

| Backend | Does `Revoke` invalidate the credential early? |
|---|---|
| `postgres`, `mysql`, `mongodb`, `redis` | Yes — the role/user/account is dropped on the target immediately. |
| `aws-sts` | **No.** The AWS credential remains valid until it naturally expires. |
| `azure` | **No.** The Entra access token remains valid until it naturally expires. |
| `gcp` | **No.** The OAuth2 access token remains valid until it naturally expires. |
| `kubernetes` | **No by default; yes if the config sets `"revocable":true`.** |

**Why AWS-STS, Azure, and GCP can't be revoked early.** These backends hand back a
self-contained, provider-signed temporary credential (an AWS STS session, an Azure
AD access token, a GCP OAuth2 access token). The resource providers that accept
these credentials validate them locally — by checking the signature and the
expiry embedded in the credential itself — rather than calling back to the issuer
on every request to ask "is this still valid?" That per-request liveness check is
exactly what makes early revocation possible, and none of these three token types
have it. Each provider does offer a broader mechanism that *could* be automated
(e.g. AWS's role-wide session-revocation policy, disabling the underlying identity),
but every one of them would invalidate **every other concurrent credential sharing
that same role/identity**, not just the one lease being revoked — an unacceptable
blast radius for a single-lease `Revoke` call, so Keyorix does not wire it up. This
is a genuine, industry-wide limitation of how these cloud providers' temporary-
credential models work, not a missing Keyorix feature: any tool that mints
credentials through the same provider APIs runs into the identical constraint.

**Why Kubernetes is different.** A Kubernetes `TokenRequest` token can be bound to
a live Kubernetes object via `spec.boundObjectRef`; the API server checks that
object's live existence on **every single request** the token is used for,
independent of the token's own expiry. Setting `"revocable":true` on a
`kubernetes` dynamic-secret config makes Keyorix create a dedicated, per-lease
`Secret` and bind the issued token to it; `Revoke` then deletes that `Secret`,
which invalidates the token immediately — a real revoke, scoped to that one lease
only. It is off by default because it requires the calling identity to also hold
`create`+`delete` on `secrets` in the target namespace, on top of the `create` on
`serviceaccounts/token` every `kubernetes` config already needs — a deliberate,
per-config opt-in rather than a silent new requirement. See
[ADR-058](adr-058-kubernetes-dynamic-secrets.md) for the full design.

**What to do about it, as an operator:**

- **Use the shortest practical TTL.** Set a tight `default_ttl_seconds`/
  `max_ttl_seconds` per config, and keep the install-wide `max_lease_ttl` above
  tight for your environment — the TTL is the only bound on exposure for
  `aws-sts`/`azure`/`gcp` leases, since `Revoke` cannot shorten it.
- **If on-demand early revocation is a hard requirement, prefer the `kubernetes`
  backend with `"revocable":true`.** It is the only backend with a real,
  immediate revoke.
- **Otherwise, treat `aws-sts`/`azure`/`gcp` leases as "live until natural expiry
  even after a Keyorix-side revoke," and plan incident response accordingly.** A
  Keyorix `Revoke`/`revoke-all` call stops Keyorix from trusting or renewing the
  credential, but if you need to guarantee the credential itself stops working
  immediately (e.g. a suspected leak), the actual remediation is at the cloud
  provider directly: disable or delete the underlying IAM role, service principal
  credential, or service account that the lease was minted from. That is available
  to operators today even though Keyorix cannot do it per-lease without affecting
  every other concurrent lease on the same identity.

---

## oidc

Machine-identity federation: trust external OIDC issuers (e.g. Kubernetes
projected service-account tokens) and map verified JWTs to machine identities
(ADR-031). Disabled = OIDC auth off.

**Network reachability, for air-gapped deployments.** Every configuration
below verifies tokens by fetching `jwks_uri` live from the issuer — this
requires an identity provider that's reachable from wherever Keyorix runs,
even if that reachability stays entirely inside a private network with no
internet egress ("**Shape A**": an enclave with a reachable internal IdP —
Keycloak, ADFS, Entra ID on-prem/hybrid, or an in-cluster Kubernetes issuer;
see ADR-075). This is the deployment this section documents, and it's what
"air-gapped" means for OIDC federation today. A stricter, genuinely
disconnected deployment with **no** identity provider reachable at all
("**Shape B**") — the bar a strict zero-network-calls interpretation of
air-gapped would require — is not yet supported for OIDC federation; if
that's your requirement, use ADR-030 opaque machine tokens or ADR-027 PATs
instead, neither of which calls out to any external service.

```yaml
oidc:
  enabled: true
  issuers:
    - name: prod-k8s
      issuer: https://kubernetes.default.svc          # must equal the JWT `iss`
      jwks_uri: https://kubernetes.default.svc/openid/v1/jwks   # https required
      audiences: ["keyorix"]                            # JWT `aud` must contain one
```

## session

Short-lived access tokens with silent refresh. Absent = a 24h access window and no
absolute ceiling (refreshable indefinitely — the legacy behaviour).

```yaml
session:
  access_ttl: "30m"     # access-token window before a refresh is needed (default 24h)
  absolute_ttl: "12h"   # hard cap on total session lifetime; "" or "0" = no ceiling
```

## password_policy

Password rules (ADR-025). Absent = conservative built-in defaults; when present,
the install's values fully replace them.

```yaml
password_policy:
  min_length: 12
  require_uppercase: true
  require_lowercase: true
  require_digit: true
  require_special: true
  reject_personal_info: true
  reject_common_passwords: true
  history_count: 5        # disallow reuse of the last N passwords
  max_age_days: 90        # 0 = no maximum age
```

---

## soft_delete & purge

Soft delete with a retention window, and an opt-in purge scheduler that hard-deletes
expired soft-deleted rows (ADR-032).

```yaml
soft_delete:
  enabled: true
  retention_days: 90      # grace period before a purge may remove (default 30)

purge:
  enabled: true
  schedule: "24h"         # Go duration between purge runs (default 24h)
```

## data_retention

An opt-in background scheduler that enforces **per-record-type retention windows**
on the compliance records Keyorix would otherwise accumulate indefinitely (ISO 27001
A.5.33 / GDPR storage-limitation / DORA record-keeping). Each `*_days` value is a
retention window in days; **`0` (the default) keeps that record type forever**. The
job hard-deletes records past their window, never touches active/open/pending rows,
and cascades to dependent rows (campaign items, request approvals).

It is **legal-hold-gated** — while a hold is active nothing is purged — and
single-replica-gated (ADR-039). Two things it deliberately never deletes: the
**audit trail** (append-only tamper-evidence, ADR-029) and **soft-deleted rows**
(those are the separate ADR-032 `purge` above).

```yaml
data_retention:
  enabled: true
  schedule: "24h"                              # Go duration between runs (default 24h)
  anomaly_alerts_days: 90                      # ACKNOWLEDGED access-anomaly alerts, on detected_at
  anomaly_alerts_unacked_ceiling_days: 730     # UNACKNOWLEDGED alerts — generous absolute-age safety net
  closed_access_reviews_days: 730              # closed recertification campaigns + items, on closed_at
  break_glass_days: 365                        # non-active emergency-access activations, on created_at
  resolved_access_requests_days: 365           # terminal-state access requests + approvals, on resolved_at
```

`anomaly_alerts_days` only ages out alerts a human has already **acknowledged** — a
never-acknowledged alert is still a live, unreviewed signal and is never purged by
that window alone, no matter how old (#415). `anomaly_alerts_unacked_ceiling_days`
is a separate, independent, and deliberately much longer window: a safety net so an
alert stream nobody ever acknowledges cannot accumulate rows forever (a
disk-exhaustion surface — the creation-time dedup window alone is trivially defeated
by varying the secret/type/actor/IP). Set it generously (a year or more) so it only
catches truly-ancient, almost-certainly-abandoned alerts, never a reasonable
operational review backlog.

The configured windows surface in the compliance posture (`keyorix compliance report`
→ "Data retention") as evidence that storage-limitation is actively enforced.

## recertification

An opt-in background scheduler that enforces an **access-recertification cadence**
(ISO 27001 A.5.18, "review access rights at planned intervals"). On each run it
walks every project and finds those **due for review** — never reviewed, or whose
most-recent review campaign closed more than `cadence_days` ago — that have no
campaign currently open. For each due project: when `auto_open` is true it opens a
fresh recertification campaign (system-actored, snapshotting current access);
otherwise it sends the project's admins an in-app reminder to open one. It also
nudges admins of an in-flight campaign that still has pending items. Reminders
de-dupe against an unread one, so they don't pile up. Single-replica-gated (ADR-039);
opening a campaign is a create, not a delete, so it runs even under a legal hold.

The cadence also drives the compliance posture's **projects-overdue** count (and
`keyorix compliance report` → Access governance → "overdue for recert"), so the
overdue signal is visible to auditors even before you enable `auto_open`.

`cadence_days` is also the **look-back of the "last used" column** in the access review
and in a campaign's items: a user with no secret activity in the last `cadence_days`
days (at most 366) shows no last use, meaning "none within the review period", not
"never". It applies whether or not the scheduler is enabled. See
[recertification-activity-window.md](recertification-activity-window.md).

```yaml
recertification:
  enabled: true
  schedule: "24h"        # Go duration between runs (default 24h)
  cadence_days: 90       # a project is due this many days after its last campaign closed (default 90)
  auto_open: false       # true = auto-open a campaign for overdue projects; false = remind admins only
```

## notifications

External delivery channels for the in-app notifications Keyorix already creates —
access-request approvals, anomaly alerts, rotation and recertification reminders, and
break-glass activations (ISO 27001 A.5.5 / SOC 2 operational alerting). Each
notification is still written to the in-app bell; when a channel is enabled it is
**also** fanned out, best-effort and asynchronously (a slow or down endpoint drops
rather than stalling the triggering action).

Two channels are available; enable either or both (both → each notification is
delivered to all). The **webhook** channel POSTs each notification as a JSON body
(`{user_id, email, type, title, message, project_id, link}`) to `endpoint`,
optionally bearer-authenticated. The **email** channel sends a plaintext message to
the recipient via the operator's SMTP relay (same settings as `credential_delivery`).

```yaml
notifications:
  webhook:
    enabled: true
    endpoint: "https://hooks.example.com/keyorix"
    token: ""                    # prefer the KEYORIX_NOTIFY_WEBHOOK_TOKEN env var
    insecure_skip_verify: false  # TLS verification off — self-signed endpoints only
  email:
    enabled: true
    host: "smtp.example.com"
    port: 587
    username: "keyorix"
    password: ""                 # prefer the KEYORIX_NOTIFY_SMTP_PASSWORD env var
    from: "keyorix@example.com"
    tls: "starttls"              # starttls | implicit | none(dev-only) — none requires KEYORIX_ALLOW_INSECURE_SMTP=true
  slack:
    enabled: true
    webhook_url: ""              # prefer the KEYORIX_NOTIFY_SLACK_WEBHOOK env var
  teams:
    enabled: true
    webhook_url: ""              # prefer the KEYORIX_NOTIFY_TEAMS_WEBHOOK env var
```

The **slack** and **teams** channels POST to an incoming-webhook URL (Slack: a
`{text}` message; Teams: a MessageCard). The webhook URL embeds the platform's secret
token, so set it via the env var.

> Secrets are read from `KEYORIX_NOTIFY_WEBHOOK_TOKEN` / `KEYORIX_NOTIFY_SMTP_PASSWORD`
> / `KEYORIX_NOTIFY_SLACK_WEBHOOK` / `KEYORIX_NOTIFY_TEAMS_WEBHOOK` when set, falling
> back to the YAML value — keep secrets out of the config file.

### Runtime-managed channels: URL encryption at rest, and one upgrade caveat

A notification channel created at runtime (the channel CRUD API, as opposed to
the `notifications:` block above) stores its destination URL **encrypted** when
`storage.encryption.enabled` is set — the URL embeds the platform's bearer
token, so it is treated as a credential. The ciphertext is bound to the
channel's own id, so it cannot be moved to another channel's row, and the URL
never appears in an audit diff.

**If you are upgrading an install that already had runtime channels**, the first
boot after the upgrade migrates each row's URL into the encrypted column and
clears the old plaintext one. That clears it from anything that *reads* the
database — but not from its storage: the old bytes survive in SQLite free pages
and the WAL, and in PostgreSQL dead tuples, until reclaimed. If you treat those
webhook URLs as credentials, run a `VACUUM` (PostgreSQL: `VACUUM FULL` or
`pg_repack` on `notification_channels`) after that first boot. Keyorix does not
do this for you: `VACUUM` is a long, exclusive, whole-database operation and
must not fire implicitly from a startup path.

If the migration cannot complete, the server **refuses to start** rather than
serve with webhook credentials still in plaintext on an install that asked for
encryption. The error names the channel to investigate.

## compliance_digest

An opt-in scheduler that periodically **broadcasts a compliance summary** to the
configured notification channels (Slack/Teams/webhook) — a continuous-monitoring
digest of the control matrix + posture: controls pass/gap, projects overdue for
recertification, rotation gaps, unclassified secrets, open anomalies, and active risk
exceptions. It's a single broadcast per run (one message to the channel), and a no-op
when no [`notifications`](#notifications) channel is configured. Single-replica-gated
(ADR-039).

```yaml
compliance_digest:
  enabled: true
  schedule: "168h"   # Go duration between digests (default 24h; e.g. 168h = weekly)
```

## evidence_delivery

An opt-in background scheduler that periodically generates the **auditor evidence
pack** (the same bundle as `keyorix compliance export` / `GET /compliance/evidence`
— the posture plus the records that substantiate it) and writes it as a timestamped
JSON file to `output_dir`, for off-box archival/backup (ISO 27001 / SOC 2 continuous
evidence). Files are named `keyorix-evidence-<UTC-timestamp>.json` (mode `0600`; the
directory is created `0700` if absent).

Each export also emits a `compliance.evidence_exported` audit event, so an installed
[`audit.siem`](#auditsiem) forwarder receives the delivery signal too. Read-only, so
it runs even while a legal hold is active. Single-replica-gated (ADR-039).

Deliver to a local directory, an off-box **webhook** (POST of the pack JSON), an
**S3-compatible object store**, or any combination. At least one target must be
configured when enabled; when several are set the pack fans out to all of them.

```yaml
evidence_delivery:
  enabled: true
  schedule: "24h"                           # Go duration between exports (default 24h)
  output_dir: "/var/lib/keyorix/evidence"   # local archive; omit to deliver off-box only
  webhook:
    enabled: true
    endpoint: "https://evidence.example.com/keyorix"
    token: ""                               # prefer the KEYORIX_EVIDENCE_WEBHOOK_TOKEN env var
    insecure_skip_verify: false             # TLS verification off — self-signed endpoints only
  object_store:
    enabled: true
    bucket: "acme-compliance-evidence"      # required when enabled
    prefix: "keyorix/evidence/"             # optional key prefix
    region: "eu-west-1"
    endpoint: ""                            # optional — set for S3-compatible stores (MinIO/R2/…)
    use_path_style: false                   # set true for MinIO and some gateways
    lock_mode: ""                           # "" | governance | compliance (S3 Object Lock / WORM)
    lock_retain_days: 0                     # retention window; required (>0) when lock_mode is set
    legal_hold: false                       # place an indefinite S3 Object Lock legal hold on each object
```

> The off-box targets let evidence survive the node without a mounted volume. A file
> write is the primary durable target (its failure is fatal); an off-box delivery
> failure is recorded in the audit note but does not fail the export when a file was
> also written. The webhook token is read from `KEYORIX_EVIDENCE_WEBHOOK_TOKEN` when
> set.
>
> **Object store.** Works with AWS S3 and S3-compatible stores (MinIO, Cloudflare R2,
> Backblaze B2, GCS interop) — point `endpoint` at the store and set `use_path_style:
> true` where required. The pack is uploaded to `<prefix><filename>` and, when signed,
> the detached signature to `<prefix><filename>.sig`. **Credentials are never taken in
> Keyorix config**: they resolve via the standard AWS credential chain
> (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars, shared config, or
> instance/workload identity).
>
> **Object Lock (WORM).** Set `lock_mode` to `governance` or `compliance` (with
> `lock_retain_days`) to stamp every uploaded pack and signature with an S3 Object
> Lock retention period, so the evidence cannot be overwritten or deleted before it
> expires — tamper-resistant archival an auditor can rely on. `compliance` mode cannot
> be shortened or removed by anyone (including the root account) until expiry;
> `governance` allows override by principals with the `s3:BypassGovernanceRetention`
> permission. **The bucket must be created with Object Lock enabled** (a bucket
> property Keyorix cannot set); this configures the per-object retention applied on
> write. A misconfigured bucket surfaces as a delivery error (non-fatal when a local
> file was also written).
>
> **Legal hold.** `legal_hold: true` additionally places an S3 Object Lock *legal
> hold* on each uploaded object — an **indefinite** hold with no expiry date that
> blocks deletion/overwrite until a principal with `s3:PutObjectLegalHold` explicitly
> clears it (e.g. for litigation/investigation preservation). It is independent of
> `lock_mode` (use either or both); like retention it requires the bucket to have
> Object Lock enabled.

When **encryption is enabled**, each exported pack is **signed**: a detached
`<file>.json.sig` is written next to it (and the webhook delivery carries the
signature in the `X-Keyorix-Evidence-Signature` header). The signature is an HMAC
keyed by a DEK-derived key the database/DBA does not hold, so an archived pack's
authenticity is provable later — verify with `keyorix compliance verify --file
<pack>` (it asks the server, which recomputes the HMAC; a signature made under a
pre-rotation DEK is reported as unverifiable rather than tampered).

### Who "the project's admins" are (all project-level alerts)

Every notification addressed to "the project's admins" — new and
awaiting-approval access requests, anomaly alerts, secret-expiry, rotation,
certificate-expiry and access-recertification reminders, and break-glass
activation / overdue-review alerts — goes to the same audience:

- members holding an approver role on that project (`project_admin`,
  `system_admin`, `admin`, `super_admin`), **and**
- every active **install-wide admin** (an admin-bypass role held at global scope,
  directly or through a group whose membership of them is global; a member of
  that group scoped to a single project does not count), because they have admin
  authority on every project even though they hold no project-scoped role row.

Each person is notified once however many grants they hold. Deactivated,
suspended, deprovisioned or deleted accounts are never notified, and the person who filed an access request
is never alerted about their own request. License-expiry and machine-credential
expiry have no project and go to every install-wide admin; personal-token,
role-grant and read-quota reminders go to the owner of the item.

## rotation_reminders

An opt-in background scheduler that notifies project admins (in-app) of secrets
**overdue or approaching** their rotation deadline under an active rotation policy —
proactive rotation hygiene (a NIS2/ISO control). One standing reminder per project
per admin; once read, a still-overdue secret nudges again on the next run.
Single-replica-gated (ADR-039) so admins aren't notified N times in HA.

```yaml
rotation_reminders:
  enabled: true
  schedule: "24h"         # Go duration between reminder runs (default 24h)
```

## certificate_expiry

An opt-in background scan (ADR-055) that parses **certificate-typed** secrets and
notifies project admins (in-app) of certificates that are **expired or expiring**
within `lead_days`, using the certificate's *real* `notAfter` (not the manually-set
`expiration` field, which cert secrets usually leave unset). One standing reminder per
project per admin, de-duplicated like the rotation reminder; single-replica-gated
(ADR-039). The scan reads certificate values to extract the expiry only — it never
exposes the value or any private key, and skips suspended secrets. Opt-in (default off).

```yaml
certificate_expiry:
  enabled: true
  schedule: "24h"         # Go duration between scans (default 24h)
  lead_days: 30           # warn this many days before notAfter (default 30)
```

## audit_checkpoints

An opt-in background scheduler that signs the audit hash-chain head (ADR-029) so
**tail-truncation and genesis re-seed are detectable on-box**, not just via an
off-box anchor. Each run records a `(chained_events, head_id, head_hash)`
checkpoint with an HMAC keyed by a DEK-derived key the database/DBA does not hold;
`keyorix audit verify` (and `GET /audit/verify`) then enforce the live chain
against the latest checkpoint. Single-replica-gated (ADR-039).

**Requires encryption enabled** — the signing key is derived from the DEK, so with
encryption off the scheduler logs a warning and does nothing.

```yaml
audit_checkpoints:
  enabled: true
  schedule: "12h"         # Go duration between checkpoint writes (default 24h)
  insecure_disable_audit_checkpoints: false   # deprecated alias: disabled
```

**Retention purges and checkpoints work together** (#3257). An audit retention
purge (`POST /api/v1/admin/jobs/purge-audit-logs`) may
remove events a checkpoint already certified. In the same transaction as the
delete, the purge records the cumulative number of chained events it has removed
in the signed retention anchor (`audit_retention_anchor`, HMAC under the same
checkpoint key). A checkpoint certifies **chained events present + chained events
removed by signed purges**, and `audit verify` compares the same sum, so a purge
below a certified count verifies and checkpointing continues. Anything the signed
anchor does not account for — a raw `DELETE`, a forged or inflated count, an
anchor rewritten without the key — still reads as truncation. Consequences worth
knowing:

- `chained_events` on a checkpoint written after a purge is larger than
  `chained_events` from `audit verify` (which counts rows present); the
  difference is the signed purged count.
- A purge that removes the latest checkpoint's head event still fails the
  head-row check until a newer checkpoint exists; keep `audit_checkpoints.schedule`
  well inside the retention window (the default 24h is).
- A purge that empties the audit table entirely leaves no row to anchor on, so
  its count is not recorded.
- Anchors written by older versions carry no count and are read as 0 removed
  (the previous behaviour). Do not downgrade below this version after a purge:
  older versions cannot read the new anchor layout and report the chain broken.

**External-notary anchoring** (`audit.checkpoint_notary`, opt-in). The checkpoint
HMAC is keyed by a DEK-derived key the running server holds — which detects
truncation/rewrite by a *database* actor, but an attacker who also obtains the DEK
could forge a checkpoint. Anchoring each written checkpoint to an external **RFC
3161 timestamp authority (TSA)** adds an independent, signed proof-of-existence over
the checkpoint's canonical bytes that binds it to a third party's clock and signing
key — which that attacker does not control, and cannot backdate. The TSA token is
stored on the checkpoint and re-verifiable offline. Anchoring is **best-effort**: a
TSA failure leaves the checkpoint un-anchored (still a valid checkpoint) and the
next write retries — it never blocks checkpointing.

```yaml
audit:
  checkpoint_notary:
    enabled: true
    type: rfc3161                  # the only type today (default)
    url: https://freetsa.org/tsr   # TSA timestamp-query endpoint
    timeout: "15s"                 # Go duration for the TSA round-trip (default 15s)
    ca_cert_path: /etc/keyorix/tsa-ca.pem  # PEM of the TSA's trusted root/CA cert(s)
```

> `ca_cert_path` is the **trust anchor** used to *verify* a stored anchor's issuer.
> Verification chains the token's signer to one of these roots (with the
> time-stamping EKU), so a self-signed/untrusted token — which the very actor the
> anchor defends against (a DEK + database-write attacker) could otherwise mint — is
> rejected. Without `ca_cert_path`, anchoring still records tokens but verification
> **fails closed** (it will not assert an unverifiable proof). Supply the TSA's CA
> bundle (e.g. FreeTSA's `cacert.pem`).
>
> The new checkpoint's anchor (asserted time + TSA) is shown by
> `keyorix audit checkpoint`. Requires `audit_checkpoints` to be doing the writing
> (which requires encryption — the checkpoint signing key is DEK-derived).

**Offline anchor source** (`audit.offline_anchor_path`, ADR-108 §B4, opt-in). An
always-on external notary (above) needs live network access, which an air-gapped
install by definition does not have. `keyorix-server admin audit export-checkpoint`
writes the latest signed checkpoint to a file for transfer onto write-once media
(a burned CD/DVD, a WORM-mode USB stick, an object-lock bucket) held OUTSIDE this
host; `keyorix-server admin verify-audit` cross-checks the live chain against that
file as an anchor genuinely outside the host's blast radius — the same protection
an RFC 3161 timestamp gives, without needing an always-on TSA. `offline_anchor_path`
lets an operator configure this file's location once instead of passing `--anchor`
on every offline verification run; an explicit `--anchor <path>` on the command
line always takes precedence over this setting.

```yaml
audit:
  offline_anchor_path: /media/offline-anchor/checkpoint-export.json
```

> The file at this path must be the exact, unmodified output of `admin audit
> export-checkpoint` — `verify-audit` fails closed (a hard, exit-3 error) if the
> configured path does not exist or is not readable; it never silently proceeds as
> if no anchor had been configured. It also fails closed (reported as an
> unauthenticated, advisory-only anchor — see `verify-audit --help`) if the file's
> signature does not verify under the checkpoint key supplied to that same run via
> `--checkpoint-key-file`. The same fail-closed rule applies one level up: if
> `--anchor` is not passed and the config FILE ITSELF exists but fails to load
> (bad YAML, a permissions problem), that is also a hard exit-3 error, never a
> silent fallback to "no anchor" — a config file that genuinely does not exist
> is the only case tolerated without one (e.g. a `--db`-only offline host with
> no config at all). Every report (human and `--json`) states which source
> served the anchor via `anchor_source`: `"flag"`, `"config
> (audit.offline_anchor_path)"`, or `"none"`. See
> `docs/design-b4-offline-audit-verify.md` §10 Q5.

## jit_access_expiry

An opt-in background sweeper for **just-in-time / time-bound access**. A role grant
can carry an expiry — set it by approving an access request with a TTL (`keyorix
request review --action approve --ttl 4h …`, or `grant_ttl` on the resolve API).
An expired grant **stops authorizing immediately** (the authorization queries
filter on expiry, so access is denied the moment the TTL passes — independent of
this sweep); the sweeper then reclaims the rows and writes a `role.expired` audit
event for each. Single-replica-gated (ADR-039).

Leaving this disabled does not weaken enforcement — expired grants are still
denied at authorization time — it only means the expired rows linger until a
sweeper (anywhere) runs.

```yaml
jit_access_expiry:
  enabled: true
  schedule: "1h"          # Go duration between expiry sweeps (default 1h)
```

## break_glass

Opt-in **self-service emergency access** (incident response — NIS2/DORA). **Disabled
by default** (a deliberate secure default): until `break_glass.enabled: true` is set
and the server restarted, every activation attempt is refused with
`permission denied: break-glass is not enabled on this server; set
break_glass.enabled: true in keyorix.yaml and restart`. When enabled, any
**member of the project** (a user holding a role scoped to that project, directly or
through a group; a global role such as the install-wide viewer does not count) can
`POST /api/v1/projects/{id}/break-glass` (or run `keyorix break-glass activate`) to
**immediately** self-grant the configured emergency role at that project — no
approval. A non-member is refused with `403 permission denied: break-glass is
available only to members of the project`, so in practice it elevates a lower project
role (for example `project_viewer`) to the emergency role. The role is added on top of
what the member already holds, so a user who can already read a secret sees the *extra*
permissions (printed by `activate`), not new read access. The activation is **time-bound** (it
auto-expires via the JIT mechanism, so it stops authorizing on its own), requires a
**written justification**, is **loudly audited** (`break_glass.activated`), and
**alerts the project's admins**. Each activation is a queryable record for post-hoc
review (`GET …/break-glass`, `keyorix break-glass list`): a caller with `roles.read` at
the project lists every activation (`"scope": "project"`); any other current member of
the project lists only their own, active, expired and revoked (`"scope": "own"`), and
learns nothing about anyone else's. The own view shows state, timestamps, justification,
expiry, and whether it was reviewed (`reviewed_at`) and revoked (`state`, `revoked_at`),
but omits the reviewer's note and the reviewer's and revoker's identities (`review_note`,
`reviewed_by`, `revoked_by`, `revoked_by_machine_identity_id`); `"scope": "project"`
carries them. A non-member, a machine
identity without `roles.read`, and a restricted personal access token whose restriction
does not allow `roles.read` at the project are refused with 403. Listing is not audited
(it never was).

Deliberately not RBAC-gated on the *emergency* permissions — the point is access the
caller does *not* have — but gated on project membership, so the controls are: it
must be enabled here, the caller must belong to the project, every use is
justified + audited + alerted, the grant expires, and an admin can revoke it early.

Operating it from the CLI (verified end to end with a `project_viewer` user):
`keyorix break-glass activate --project-id N --justification "..." --ttl 1h`,
then the activating user's own `keyorix break-glass list --project-id N` shows it
under "Your break-glass activations", an admin's `list` shows every activation of the
project, and the admin can `keyorix break-glass revoke
--project-id N --activation-id ID`. There is no CLI command for the review below:
call `POST /api/v1/projects/N/break-glass/ID/review` with `{"note": "..."}` and a
bearer token (response `Break-glass activation reviewed`).

`POST …/break-glass/{activationId}/review` (ADR-112 §3) records a separate,
after-the-fact check — who reviewed it, when, and a note — exactly once per
activation. Activation itself stays single-person by design (decided
2026-10-02: an emergency path needing a second person fails exactly when it's
needed); review is not a second approver, it's the record that someone
independent looked afterwards. Three things are refused:

- **the activating user reviewing their own activation** (403). This is what
  makes single-person activation acceptable at all; self-review would collapse
  it to one person end to end.
- **an unattributable reviewer** (403) — a machine identity, or an
  unauthenticated local-CLI invocation. A review attributed to nobody records
  accountability to nobody.
- **reviewing a still-active activation** (400). Revoke it or let it expire
  first; a reviewer cannot assess access that is still being used.

`review_window` is how long an activation may go unreviewed before it is
reported. Past that it shows up as `emergency_access.unreviewed_activations`
in the compliance posture report (alongside
`oldest_unreviewed_age_hours` and the `review_window_hours` it was measured
against), and a recurring check — on startup, then every 6h — logs a
`SECURITY:` warning and writes one `break_glass.review_overdue` audit event
per pass.

That reporting is the entire enforcement, deliberately. An unreviewed
activation is never locked out, never cut short, and never blocks the user who
activated it: an emergency path that unfiled paperwork can disable fails
exactly when it is needed. The check runs even when `enabled: false`, because
an install that has since turned break-glass off can still be holding
unreviewed activations from when it was on.

```yaml
break_glass:
  enabled: true
  emergency_role: "project_developer" # role granted on activation — must be
                                       # contained (no roles.assign); "project_admin"
                                       # is REJECTED at activation time
  default_ttl: "4h"                 # grant lifetime when none is requested
  max_ttl: "24h"                    # ceiling on a requested TTL
  review_window: "72h"               # how long an activation may go unreviewed
                                      # before it's a posture-report deviation
```

## dual_control

**N-of-M approval (dual control)** for access-request grants (ISO 27001 A.5.3 /
SOX): instead of one admin's approval granting the role immediately, a request
requires `required_approvals` **distinct** approvers — and never the requester
(maker ≠ checker) — before the role is granted. Each sign-off is audited; the
request listing shows the M-of-K progress and remaining approvers are notified. A
value of `1` (the default) keeps the single-approval behaviour.

```yaml
dual_control:
  required_approvals: 2   # distinct approvers needed per access request (default 1)
```

## classification

Whether the **"restricted" data-classification label** (the highest tier;
`public`/`internal`/`confidential`/`restricted`, see `internal/core/classification.go`)
changes read-time behaviour. **Disabled by default** — today, "restricted" is
purely informational metadata; setting `restricted_requires_approval: true` for
the first time is a **breaking behaviour change** for any deployment that already
has "restricted" secrets, since they were previously readable like any other with
sufficient RBAC. Opt in deliberately, only once you also have a plan for
approving requests (below) — otherwise every "restricted" secret's value becomes
permanently unreadable the moment you enable this.

When enabled, reading a "restricted" secret's **value** (not its metadata —
`GetSecret`/listing are unaffected) requires an approved, **secret-scoped**
access request: `keyorix request secret-access --secret-id <id> --user
<email>` to request it, `keyorix request review --id <id> --action approve
--by <admin-email>` to approve it (an administrator at the secret's project).
This reuses the same `AccessRequest` model/flow as `dual_control` above
(ADR-024), narrowed with a `SecretID` rather than granting a role. A read whose
acting principal cannot be identified as a specific user — a machine/service
identity, for instance — is **always denied** when this is on: there is no
"wait for approval" for automation, and no bypass for it either.

```yaml
classification:
  restricted_requires_approval: false   # opt-in; see above before enabling
```

## anomaly_alerts

**Proactive alerting** for detected access anomalies (NIS2 detection & response).
Anomaly detection (off-hours / new-IP / new-user access to secrets) always runs on
the scan schedule; when this is enabled, each **newly detected** anomaly is also
pushed out — an in-app alert to the project's admins **and** a
`security.anomaly_detected` audit event (which the SIEM forwarder picks up, so
anomalies reach your SOC). Each anomaly is announced once. Single-replica-gated
(ADR-039). Opt-in (default off — detection still runs and alerts are visible via
`keyorix anomalies list` / the API, just not pushed).

```yaml
anomaly_alerts:
  enabled: true
  schedule: "1h"          # Go duration between scan+alert passes (default 1h)
```

### anomaly_alerts.ml — Isolation Forest detection (ADR-050)

An optional **machine-learning** detection pass that complements the statistical rules
above. Each scan trains a per-secret [Isolation Forest](https://en.wikipedia.org/wiki/Isolation_forest)
on the secret's 30-day access baseline and flags accesses whose joint pattern (hour,
IP rarity, user rarity) is a multivariate outlier — catching two things the binary
rules miss: a **known-but-rare** actor or IP (the new-user/new-IP rules only see
"known"), and **combinations** that are unremarkable signal-by-signal. Flagged accesses
emit an `ml_outlier` anomaly alert that flows through the same list / acknowledge /
alert / retention paths as every other alert. Metadata only — no secret value is ever
examined.

`ml.enabled` is **independent** of `anomaly_alerts.enabled`: it gates whether the scan
additionally runs the ML pass; `anomaly_alerts.enabled` gates whether detected
anomalies are pushed out. Opt-in (default off).

```yaml
anomaly_alerts:
  enabled: true
  ml:
    enabled: true
    threshold: 0.60       # anomaly-score cutoff in (0.5,1.0); higher = fewer alerts (default 0.60)
    num_trees: 100        # forest size (default 100)
    sample_size: 256      # per-tree subsample ψ (default 256)
    seed: 1               # RNG seed; fixed so scoring is reproducible (default 1)
```

## audit.siem

Native push of audit events to a SIEM. The token is read from `KEYORIX_SIEM_TOKEN`
when set, so it need not be written to the file.

```yaml
audit:
  siem:
    enabled: true
    provider: splunk            # splunk | datadog | webhook
    endpoint: https://siem.example.com/services/collector
    # token: ""                 # prefer KEYORIX_SIEM_TOKEN
    insecure_skip_verify: false # never true in production
```

## scim

SCIM 2.0 provisioning (RFC 7644). When enabled, Keyorix serves `/scim/v2` so an
identity provider (Okta, Entra ID, …) can **provision, update, deactivate, and
deprovision users** automatically. The endpoints are authenticated by a single
**static bearer token** the IdP presents — separate from the session/PAT auth — and
emit SCIM-format JSON, not the API envelope.

A SCIM `userName` (typically an email/UPN) maps to the user's email; a compliant
alphanumeric Keyorix username is **derived** from it, and the IdP's `externalId` is
stored for reconciliation. Provisioned users have no usable password (they sign in
via SSO or set one out-of-band) and start in `pending_first_login`; SCIM
`active:false` (or DELETE) suspends the account and terminates its sessions.

Both the **Users** and **Groups** resources are supported (plus
`ServiceProviderConfig`): groups map to native Keyorix groups (displayName → name),
with PUT replacing the full member set and PATCH adding/removing members.

```yaml
scim:
  enabled: true
  token: ""        # prefer the KEYORIX_SCIM_TOKEN env var — the IdP's bearer token
```

> Set `token` only via `KEYORIX_SCIM_TOKEN`. Point your IdP's SCIM connector at
> `https://<host>/scim/v2` with that token as the bearer credential.

## sso

Human single-sign-on login via **OIDC** (authorization-code flow). When enabled, the
login page offers a "Sign in with <provider>" button: the user authenticates at their
IdP and Keyorix mints the same session a password login would — so an IdP-provisioned
([`scim`](#scim)) user, who has no password, can actually sign in. SSO logins bypass
Keyorix-local MFA (the IdP is the authenticator).

Each provider's endpoints are **discovered** from its issuer
(`/.well-known/openid-configuration`), so only the issuer + client credentials +
redirect URL are needed. On callback Keyorix verifies the id_token (signature against
the issuer's JWKS, issuer, audience = `client_id`, expiry, and the nonce it issued)
and maps the identity to a Keyorix user — by the IdP subject (matched against the SCIM
`externalId`) first, then by email. By default there is **no auto-provisioning**: the
account must already exist (provision it via SCIM or invite). A suspended user is
refused.

Same network-reachability caveat as [`oidc`](#oidc) above: SSO login needs live
discovery + JWKS reachability to the IdP on every login, so it needs a reachable
identity provider (Shape A) — a fully disconnected deployment with no IdP at all
(Shape B) isn't supported for SSO login either. A provider whose discovery fails
doesn't take the whole server down (see below), but login via that provider won't
work until the IdP is reachable again.

```yaml
sso:
  enabled: true
  providers:
    - name: okta                 # also the URL slug: /auth/sso/okta/login
      issuer: https://your-tenant.okta.com
      client_id: 0oa...
      client_secret: ""          # prefer the KEYORIX_SSO_OKTA_CLIENT_SECRET env var
      redirect_url: https://keyorix.example.com/auth/sso/okta/callback
      scopes: [openid, profile, email]
      auto_provision: false      # JIT-create an account on first login (default off)
      default_role: system_viewer # baseline role for JIT-provisioned users
      group_sync: false          # reconcile native group memberships from the IdP (default off)
      groups_claim: groups       # id_token claim carrying group names (default "groups")
      group_role_map:            # map IdP groups → Keyorix system roles (optional)
        keyorix-admins: system_admin
        keyorix-auditors: system_auditor
```

> The client secret is read from `KEYORIX_SSO_<NAME>_CLIENT_SECRET` (name upper-cased,
> e.g. `KEYORIX_SSO_OKTA_CLIENT_SECRET`). Register the `redirect_url` exactly as above
> at the IdP. A provider whose discovery fails at startup is skipped with a warning,
> not fatal.

**Just-in-time (JIT) provisioning.** Set `auto_provision: true` on a provider to
JIT-create a Keyorix account the first time an identity that matches no existing user
signs in — useful when an IdP isn't wired for SCIM push. The account is created
**active** and passwordless (the IdP is the authenticator), with the IdP subject
stored as its `externalId` for future reconciliation, and is granted `default_role`
(`system_viewer` when unset; an unknown role grants nothing — least-privilege on
misconfiguration). The JIT creation is audited as `auth.sso_jit_provisioned`. The IdP
must return an `email` claim (request the `email` scope), or the login is refused. A
later SCIM push for the same `externalId` reconciles to the same account. Leave
`auto_provision` off to require that accounts be provisioned ahead of time.

> **Email trust.** An email an IdP explicitly marks unverified (`email_verified:
> false`) is not used to match an existing account or to provision a new one — only
> the subject (`externalId`) match applies for that login. An absent `email_verified`
> claim is treated as trusted (it is optional in OIDC; some enterprise IdPs such as
> Entra ID omit it for a configured, trusted issuer).

**Group sync (JIT group membership).** Set `group_sync: true` to reconcile a user's
**native Keyorix group memberships** from the IdP's group claim on each login — so the
IdP drives group-based access without a separate SCIM push. The named claim
(`groups_claim`, default `groups`; some IdPs use `roles`) is read from the verified
id_token and the IdP is treated as **authoritative**: the user is added to native
groups whose name matches an asserted group and **removed from native groups it did
not assert**, so revoking a group at the IdP deprovisions the matching Keyorix access
on next login. Only groups that **already exist natively** (provisioned via
[`scim`](#scim) Groups or by an admin) are touched — an asserted group with no native
counterpart is ignored, and groups are never created or deleted. The net change is
audited as `auth.sso_groups_synced`.

> Because it is authoritative, **do not mix `group_sync` with manual group assignment**
> for SSO users — a manually-added membership not asserted by the IdP is removed on the
> next login. If the `groups_claim` is **absent** from the id_token (e.g. the IdP only
> emits groups at the userinfo endpoint, or behind a scope you didn't request), the
> sync is a safe no-op — it never strips memberships on a missing claim. Ensure the IdP
> is configured to emit the group claim in the id_token (in Okta, add a groups claim to
> the ID token; in Entra, configure the optional `groups` claim).

**Group → role mapping.** `group_role_map` maps an IdP group (from the same
`groups_claim`) to a Keyorix **system role**, so the IdP can drive role assignment
directly — e.g. members of `keyorix-admins` become `system_admin` on login. It is
**authoritative only over the mapped roles**: on each login the user is granted the
roles their asserted groups map to and **loses any mapped role they no longer
qualify for**, while roles *not* named in the map are never touched (so manually
granted roles are safe). Like `group_sync`, an absent groups claim is a no-op (it
won't strip roles), an unknown role name is skipped, and roles are bound at global
scope. This works independently of `group_sync` (you can map roles without syncing
group memberships, or both). Changes are audited as `auth.sso_roles_synced`.

> Because it is authoritative over the mapped roles, prefer managing those roles
> **only** through the IdP — a mapped role granted manually to an SSO user is removed
> on their next login if the IdP doesn't assert the corresponding group.
>
> ⚠️ **Security — the mapped IdP groups become privilege grants.** Membership of any
> group named in `group_role_map` directly drives Keyorix authorization on every
> login, and a group mapped to `system_admin` confers **global administrator** access.
> Only map groups whose membership is **governed by your IdP administrators** (e.g. an
> Okta/Entra group whose roster only IdP admins can change) — never a self-service,
> open-enrolment, or user-requestable group, or anyone who can join that group at the
> IdP gains the mapped Keyorix role. Treat the mapping like handing out the role
> itself: scope it to the least-privileged role that fits, and reserve admin mappings
> for tightly controlled groups. Keyorix trusts the IdP's `groups` claim (verified
> id_token) as the source of truth, so the IdP's group governance *is* your Keyorix
> RBAC governance for these roles.

**A reconcile that cannot be fully applied refuses the login.** For a SAML or OIDC
provider, if any part of `group_sync` or `group_role_map` fails to apply on login — most
importantly a **removal** the IdP asked for (the user was dropped from a group at the
IdP) — the login is **refused** and no session is issued, because a session would carry
the access the IdP just revoked. Steps that did apply before the failure are kept (the
next successful login converges the rest). Each refusal is audited as a failed
`auth.sso_reconcile_refused` event naming every step that failed and what had already
been applied, and the browser is told the login was refused because the IdP's group or
role assertion could not be applied.

> **The last administrator.** If the IdP stops asserting the group (or mapped role) that
> makes a user the install's **only** administrator, Keyorix's last-admin guard refuses
> the removal and that user's SSO login stays refused — the IdP's revocation wins. This
> is audited as `auth.sso_reconcile_last_admin_removal_refused`, logged with the two ways
> back: re-add the user to the admin group at the IdP, or run
> `keyorix-server admin recover-admin <user>` with the recovery key on the server host
> (it works for an SSO-only account that never had a password: it issues a one-time
> password), then create a second administrator. Keep at least two administrators, and
> a recovery key, on an SSO-managed install.

> **SAML: empty vs. absent groups attribute.** A groups attribute that is **present with
> no values** means "this user is in no groups": every synced membership and mapped role
> is removed. A groups attribute that is **absent** from the assertion is a no-op
> (memberships and roles are left as they are), as for a missing OIDC claim — make sure
> your IdP releases the attribute on every assertion.

## membership

Project-membership onboarding mode (ADR-022).

```yaml
membership:
  validation_mode: allowlist    # open | allowlist (default) | idp
```

## credential_delivery

How a brand-new principal receives their first-credential setup link (ADR-028).

```yaml
credential_delivery:
  mode: smtp                    # auto | smtp | out_of_band | log
  setup_token_ttl: "24h"        # single-use link lifetime (default 24h)
  base_url: https://keyorix.example.com   # required for any link-producing mode
  smtp:
    host: smtp.example.com
    port: 587
    username: keyorix@example.com
    # password: ""              # prefer KEYORIX_SMTP_PASSWORD
    from: keyorix@example.com
    tls: starttls               # starttls | implicit | none (dev only)
```

`out_of_band` / `log` return or log the link instead of emailing it (useful when no
mail relay is available). A link-producing mode with an empty `base_url` is a
misconfiguration — link minting refuses it rather than emitting a relative link.

`mode: log` writes a live, usable setup link to the application log (dev/test only) and
`smtp.tls: none` sends mail — and any relay credentials — in cleartext. Both are refused
at startup unless the operator explicitly opts in by setting
`KEYORIX_ALLOW_INSECURE_LOG_DELIVERY=true` (for `mode: log`) or
`KEYORIX_ALLOW_INSECURE_SMTP=true` (for `smtp.tls: none`), mirroring how other insecure
toggles in this codebase require an explicit acknowledgement rather than defaulting on.
The same `KEYORIX_ALLOW_INSECURE_SMTP` gate also applies to `notify.smtp.tls: none` for
the notification-email channel.

## connect

**Keyorix Connect** (ADR-043) is opt-in **read-through federation** to external
secret stores: it proxies an authorized, audited read of a secret's *current* value
held in an external store, without importing or persisting it. Disabled by default;
with no connectors the `/connect` endpoints are not served.

```yaml
connect:
  enabled: true
  # Every connector below MUST declare scope: — a missing or unrecognized value
  # fails server boot unconditionally (ADR-082). There is no escape hatch: adding
  # scope: to an existing connector takes minutes, and an unscoped connector would
  # deny every read anyway (ownership has no entry for it), so a bypass would only
  # defer the failure from "boot" to "every read," not actually restore access.
  connectors:
    - name: prod-aws            # API path key (unique); GET /api/v1/connect/prod-aws/secret?ref=…
      type: aws-secrets-manager # aws-secrets-manager | gcp-secret-manager | azure-key-vault | vault
      region: eu-west-1         # AWS region (aws-secrets-manager)
      account_id: "111111111111" # optional: pins the connector to one AWS account (12 digits);
                                  # a full-ARN ref naming a DIFFERENT account is rejected before
                                  # the backend call. A bare secret-name ref is unaffected either
                                  # way — see the note below for why this field is optional, not
                                  # required like gcp-secret-manager's project_id.
      scope: project             # project | platform (ADR-082) — required
      project: payments          # Keyorix project name (not ID) that owns this connector;
                                  # required when scope is "project", omit when "platform"
      allowed_refs:             # optional prefix allowlist — a ref must match one
        - keyorix/              # (defense-in-depth on top of the backend's IAM scope)
    - name: prod-gcp
      type: gcp-secret-manager  # ref is the version resource name (creds from ADC)
      project_id: my-proj       # REQUIRED: pins the connector to one GCP project (#431);
                                 # a ref naming a different project is rejected before the backend call
                                 # (a GCP project ID — unrelated to Keyorix's own project: below)
      scope: project
      project: payments
      allowed_refs:
        - projects/my-proj/secrets/keyorix-
    - name: prod-azure
      type: azure-key-vault     # ref is the secret name (or name/version); creds from DefaultAzureCredential
      address: https://myvault.vault.azure.net/   # the Key Vault URL
      scope: project
      project: payments
      allowed_refs:
        - keyorix-
    - name: shared-vault
      type: vault               # ref is the read path; KV v2 is unwrapped
      address: https://vault.example.com:8200
      token_env: VAULT_TOKEN    # env var holding the Vault token (default VAULT_TOKEN)
      scope: platform           # org-wide connector — no project:; requires the caller
                                 # to hold connect.platform.use in addition to connect.read
      allowed_refs:
        - secret/data/keyorix/
```

- Reads are **read-only** and gated by the dedicated `connect.read` permission
  (ADR-044) — distinct from `secrets.read`, so external-store access is granted
  explicitly (it ships granted to `admin` / `system_admin`); each is audited as
  `connect.secret_read`. The value is returned to the caller and never stored.
- `ref` (query parameter) is connector-specific — for **AWS Secrets Manager** it is
  the secret **name or ARN** (a binary secret is returned base64-encoded); for **GCP
  Secret Manager** it is the **version resource name**
  (`projects/P/secrets/NAME/versions/latest`); for **Azure Key Vault** it is the
  **secret name** (optionally `name/version`; a bare name reads the current version)
  within the connector's `address` vault; for **Vault** it is the **read path**
  (e.g. `secret/data/myapp` for KV v2, whose inner `data` map is returned). GCP
  credentials come from ADC / workload identity; Azure from `DefaultAzureCredential`
  (managed/workload identity / env / CLI); the Vault token comes from `token_env`.
- Backend credentials come from the **ambient identity chain** (AWS: env /
  instance-profile / IRSA; GCP: ADC; Azure: `DefaultAzureCredential`; Vault:
  `token_env`), never from this config. A backend failure surfaces as `502 Bad Gateway`.
- Unlike Vault (pinned to one `address`) and Azure Key Vault (pinned to one `address`
  vault URL), a GCP Secret Manager ref carries **its own project ID**. `project_id`
  is therefore **required** for every `gcp-secret-manager` connector — a missing
  `project_id` **fails server boot** (there is no escape hatch): without it, a
  connector could address secrets in **any** GCP project the ambient ADC identity
  can reach, regardless of which Keyorix tenant it is scoped to (a confused-deputy
  gap). `project_id` pins the connector to one project: any ref naming a different
  project is rejected before the backend call, both at config-load time and again at
  read time (defense in depth, in case a connector is ever constructed through a path
  that bypasses config validation). **Breaking change**: an existing deployment
  upgrading from before this requirement landed must add `project_id` to every
  `gcp-secret-manager` connector before upgrading — see CHANGELOG.md.
- `aws-secrets-manager`'s `account_id` is the AWS sibling of `project_id` above, but
  **optional, not required** — the risk shape is narrower. The Secrets Manager
  `SecretId` accepts either a bare secret name (always resolved within the ambient
  credential's own AWS account — no confused-deputy gap is possible for that shape)
  or a full ARN (`arn:PARTITION:secretsmanager:REGION:ACCOUNT:secret:NAME`), which
  CAN name a different account, but only succeeds if that target account's own
  resource policy has separately granted this connector's identity cross-account
  access (a double opt-in, unlike GCP's single-opt-in ambient-reach gap). Setting
  `account_id` (12 digits) pins the connector: any ARN-shaped ref naming a different
  account is rejected before the backend call, both at config-load time (a malformed,
  non-12-digit value fails boot) and again at read time (defense in depth). Leaving
  it unset is a legal, still-supported configuration — `server/main.go` logs a
  startup recommendation, not a failure — and a bare-name ref is never checked
  against the pin either way, since it never carries a competing account segment.
- A federated read is bounded by up to **three** controls: the backend identity's IAM
  policy (the load-bearing one — scope the connector's credentials to exactly the
  intended secrets); optionally the per-connector **`allowed_refs`** prefix allowlist
  enforced in Keyorix before the backend call; and optionally **per-reference RBAC
  grants** (ADR-045) — a `(role, connector, ref_prefix)` allowlist. Set the IAM policy
  for sure: any holder of `connect.read` can otherwise read every secret the
  connector's identity can reach.
- **Per-reference RBAC (ADR-045)** scopes *which roles* may read *which refs* on a
  connector. It is opt-in per connector: a connector with **no** grants behaves as
  before (governed by `connect.read` + `allowed_refs`), but once a connector has any
  grant it is **deny-by-default** — only a caller holding a role with a matching
  ref-prefix grant may read, and a denied read is audited. A grant pattern is a
  **prefix** by default; one containing glob metacharacters (`*`, `?`, `[`) matches as
  a shell-style glob (`*` does not cross `/`), e.g. `prod/*/db`. Manage grants at
  `GET /api/v1/connect/ref-grants` (`roles.read`), `POST /api/v1/connect/ref-grants`
  and `DELETE /api/v1/connect/ref-grants/{id}` (`roles.write`). To keep an admin role's
  blanket access while scoping others, give it an **empty-prefix** grant (matches every
  ref) on the connector.
