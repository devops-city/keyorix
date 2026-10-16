### Security
- **The read cache no longer trusts a PostgreSQL session that skips triggers (#3361).** With `session_replication_role = replica` (Helm `postgresql.settings`, `ALTER ROLE/DATABASE ... SET`, a DSN option or an operator's session) the `secret_nodes` cache-epoch trigger did not fire, so a suspended secret could keep reading as active. The trigger is now `ENABLE ALWAYS` (converged at start-up), the cache trusts its stamp only for an `ENABLE ALWAYS` trigger on an `origin` session, the server (and the DEK-rotation admin command) refuses to start unless `session_replication_role` is `origin`, and the Helm chart refuses `postgresql.settings.session_replication_role`. Upgrade note: a database or role with a non-`origin` default must have it removed before the new server starts.

### Fixed
- **Nested named locks no longer stall every named lock on a replica (#3358).** A nested `WithNamedLock` call waited in the in-process queue while holding one of the 8 named-lock pool sessions; with enough concurrent role changes for one user across projects, every named lock in the process (secret creation's included) waited until the request contexts ended. A nested call on PostgreSQL now waits in PostgreSQL on the session it already holds.

### Documentation
- **Helm quick start keeps secrets off the command line.** The chart README now creates the Secret from owner-only files and installs with `auth.existingSecret` (values file or `--set-file` as alternatives), and the install NOTES warn when the passwords came from Helm values. `docs/operator/j8-kubernetes.md` follows the same steps.

### Testing
- **The Helm pod-hardening guard checks every container (#3360).** Container-level `runAsUser: 0` / `runAsNonRoot: false` and any `capabilities.add` beyond `NET_BIND_SERVICE` now fail it, and it is calibrated against the opt-in root `postgresql.migrateOwnership` init container.
