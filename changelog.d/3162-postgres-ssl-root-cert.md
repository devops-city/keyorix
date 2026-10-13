### Security
- **PostgreSQL `verify-full` now needs a named CA: `storage.database.ssl_root_cert`.** The server
  had `ssl_mode: verify-full` but no way to say which CA signed the database's certificate, so the
  driver verified against whatever it found (`PGSSLROOTCERT`, `~/.postgresql/root.crt`, the OS
  store). The new key is passed as `sslrootcert` (a PEM file, relative to the config file's
  directory, or `system` for the OS store). `verify-full`/`verify-ca` without it, or with a
  missing, unreadable, empty, key-bearing or group/world-writable CA file, **refuses to start**
  with an error naming the key; the same check runs on every connection an `admin` command opens,
  and applies to `sslrootcert` in a `dsn`. `ssl_root_cert` with `dsn` or with `ssl_mode: disable`
  is refused rather than ignored. `admin init` and `admin validate --posture` report the
  database TLS posture (a `database-tls` deviation when the server would refuse to start). Helm:
  `externalDatabase.sslRootCert`. **Upgrade note:** a config that already uses `verify-full`
  must add `ssl_root_cert` (or `sslrootcert=` in the dsn) before upgrading; see
  docs/UPGRADING.md and docs/CONFIGURATION.md "PostgreSQL TLS".
- **The settings the driver connects with are re-checked against what the TLS check validated.**
  After the connection config is built (the password set on the driver's own parse of the DSN, see
  the `KEYORIX_DB_PASSWORD` entry), Keyorix refuses to start unless its host, port, database and
  user are the configured ones and every connection attempt is encrypted and, for `verify-ca`/
  `verify-full`, verifies against exactly the validated CA (and the host name for `verify-full`).
  This catches any difference between how the check and the driver read a connection string.
