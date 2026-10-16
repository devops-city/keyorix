# Single-writer authoritative cache mode (`storage.database.single_writer`)

Status: **design approved 2026-10-15** (Andrei), built in dependency order:
1. fence + holder lock + epoch + lease, no cache change (this spec's first PR);
2. the generated storage wrapper (in-process invalidation) and its trigger oracle;
3. authoritative caches for machine-token reads, then the A/B.

Decisions recorded with the approval:
- The name is `storage.database.single_writer`, valid only with the write fence (no `insecure_` name).
  If the fence cannot be installed or verified at start-up, the server refuses to start.
- Refusing direct SQL to the security tables while the server runs is accepted. The emergency
  two-step (terminate the server's lock session, then run the change) is documented in
  `docs/single-writer.md` and in the posture output, and tested.
- Opt-in and off by default; with the setting off, behaviour does not change.

Origin: a store that is the only writer of its own storage needs no freshness check on its caches.
Keyorix confirms credential, node, role and schedule state with one statement per request because
other writers may exist. This mode makes the server the only writer of the tables those caches are
derived from, and so lets it skip that statement.

## As built (deviations from the text below, PR 1)

- **Holder lock key**: the two-key form `pg_try_advisory_lock(0x4B53574C /* "KSWL" */,
  hashtext(current_schema()))`, not a single bigint. Two installs in different schemas of one database do
  not collide, and the fence looks up the holder for the *fenced table's* schema, so a session on another
  `search_path` writing schema-qualified names meets the same fence.
- **One trigger function per write, AFTER, not BEFORE**: the fence check and the epoch bump are one
  `AFTER` trigger (`keyorix_sole_writer_guard`). Raising in an AFTER trigger aborts the statement just as
  well, and it avoids the row-level BEFORE return-value trap. Every object the functions touch is
  qualified with `TG_TABLE_SCHEMA`.
- **Census**: the poller compares a fingerprint (md5 over every `trg_ksw_*` trigger's
  `pg_get_triggerdef` + `tgenabled` + catalog row `xmin`, the functions' `prosrc` + `xmin`, and every
  `pg_inherits` child of a fenced table) with the one recorded inside the install transaction. Any
  change means `confirming` until restart. The `xmin` is what catches a change undone before the next
  poll (REVIEW-SINGLE-WRITER-1 F1): `DISABLE TRIGGER; write; ENABLE ALWAYS TRIGGER` in one transaction,
  the same split over two transactions, DROP + identical CREATE, CREATE OR REPLACE with the same body.
  Each rewrites the catalog row; no SQL statement can restore its `xmin`. Catalog VACUUM FREEZE keeps
  it (tested; VACUUM FULL checked by hand). A child table is read through its fenced parent but its writes fire none of the
  parent's triggers, so InstallFence refuses to start with one and the census treats a new one as
  tampering. Alternatives considered: an event trigger on `ddl_command_end` (needs a superuser to
  install, and `ALTER EVENT TRIGGER ... DISABLE` is not itself seen by event triggers, so it would
  move the hole rather than close it) and a per-row write epoch (a schema change on 12 tables, and a
  superuser who can disable the trigger can write the column too). Neither beats the catalog row
  version.
- **Per row, not per statement** (REVIEW-SINGLE-WRITER-2 N2): INSERT, UPDATE and DELETE are guarded
  `FOR EACH ROW` on every fenced table and on `keyorix_sole_writer` / `keyorix_write_epoch`; only
  TRUNCATE is per statement. A statement-level trigger fires only for the table the statement names,
  so after `ALTER TABLE <fenced> INHERIT p` or `ATTACH PARTITION <fenced>` a write through `p` fired
  none of them. Row triggers fire on the table holding the row; a TRUNCATE of a parent fires each
  truncated child's TRUNCATE trigger. The guard bumps the epoch once per transaction (it skips the
  row when its `xmin` is already this transaction's), so a multi-row write costs one epoch update.
  The census also covers inheritance in both directions (a covered table as child or as parent;
  InstallFence refuses either) and every column of a covered table (`pg_attribute` name, type and
  `xmin`), which catches `ALTER COLUMN ... TYPE ... USING` (rewrites every row, no DML trigger fires)
  and `RENAME COLUMN`. A zero-row DML statement is no longer refused: it fires no row trigger and
  changes nothing.
- **No name resolution** (REVIEW-SINGLE-WRITER-2 N1): the three functions are created with
  `SET search_path = pg_catalog, pg_temp` and qualify every catalog and function they use
  (`pg_catalog.pg_database`, `pg_catalog.format`, ...). Before, a temp table named `pg_database` (pg_temp
  is searched before pg_catalog for relations unless pg_catalog is listed) or a function or operator of
  the same name in a schema the writer put first changed what the check saw, with TEMP and DML rights
  only. The pinned search_path is what also fixes the operators (`=`, `+`): qualification alone does
  not, and a test shows an `=` shadow red without it. The guard's own sessions (holder, admin checks)
  read their schema once and then pin the same search_path, qualifying every Keyorix object with that
  schema. The census includes the functions' `proconfig`.
- **Epoch by row version, not value** (REVIEW-SINGLE-WRITER-2 N3): the poller compares the epoch row's
  `xmin` as well as `n`. A session that passes the fence (a copied tag) can move `n` back in its own
  transaction; it cannot give the row an old `xmin`.
- **Residual, not detectable from SQL**: a superuser (or a member of `pg_execute_server_program` /
  `pg_write_server_files`) can change table data below SQL (native code, the data directory,
  `pg_resetwal`) with no trigger firing and no catalog row changing. That window is the memo TTL
  (5 min) or the next server write. It is reported as a `single_writer` posture deviation when the
  server's own role has those rights; other superusers in the cluster are stated in
  docs/single-writer.md "Residual risks".
- **Settle** is kept as an explicit barrier. InstallFence already waits for older writers through
  locks (CREATE TRIGGER's table lock on a first boot; the epoch row the writer's own trigger holds on a
  later boot), so removing Settle does not turn its test red. Documented, not hidden.
- **Lost lock**: any poll error is followed by a ping of the holder session; a dead session means
  `confirming` until restart. The lease alone already stops authoritative answers.
- **Mode off**: every PostgreSQL boot without the setting refuses while a holder is live and removes a
  fence an earlier single-writer boot left (`solewriter.CheckOff`).
- **In-process invalidation (PR 2) is a pgx QueryTracer, not a generated storage wrapper.** Every
  connection a single-writer server opens reports its statements (`config.SetSoleWriterQueryTracer`,
  `solewriter.Tracker`). A statement that can write and names a fenced table marks its connection's
  transaction; at COMMIT/ROLLBACK (or at the statement's end outside a transaction) the tracker's
  generation moves. It uses the same exclusions as the triggers: bookkeeping-only UPDATE, system_metadata
  rows other than the fenced key. This sees raw SQL and every storage method alike with no per-method
  classification to keep in sync. The trigger is the oracle (`TestTracker_EveryEpochMoveIsAWriteTheTrackerSaw`:
  the epoch moved means the generation moved, per storage write path). `ROLLBACK TO [SAVEPOINT]` (GORM's
  failed nested transaction) does not end the transaction; `... AND CHAIN` ends it and starts the next
  (REVIEW-SINGLE-WRITER-1 F3). **Every epoch move the poller sees flushes every entry**, whether or not a
  tracked commit explains it (F4): a write that passed the fence with a copied tag can share a poll window
  with one of the server's own commits, and the database cannot say which transaction moved the epoch
  without a write log per fenced statement. This is the original hit rule's `entry.epoch >= knownEpoch`,
  applied as a flush. The cost is one extra miss per entry after the server's own fenced writes. The
  unattributed-bump canary stays as an alarm only (it undercounts a foreign move that shares a window with
  an own commit). Not seen by the tracker, stated: pgx batches (only the audit pipeline, which writes no
  fenced table) and SQL-level `PREPARE` / `EXECUTE` (unused); a write either of them made would be caught
  by the epoch flush within one poll. A cascading FK from an unfenced parent into a fenced table is
  forbidden by `TestFencedTables_NoCascadeFromUnfencedParent`.
- **Authoritative caches (PR 3) are one memo, not four cache changes.** On a warm machine-token
  secret read the only confirming statement is the folded credential statement (credential, identity
  state, node stamp, the machine's roles at the node's scope, the role->permission generation,
  schedule/versions). While the guard vouches for it (`swstate`: authoritative, lease fresh, no fenced
  write in flight or finished since the fill), the store serves that statement's last answer for the
  same text and binds (`local_folded_credential_memo.go`). Every decision is still made by the same
  code on the same rows. Revocation, expiry against the request's clock, identity state, node stamp,
  roles and the schedule window are all judged per request. The middleware and core are unchanged. Every
  table the statement reads is fenced (`TestFoldedCredentialSQL_ReadsOnlyFencedTables`). The cold and
  first-hit paths (slow-path validation, the plain credential re-check before a (machine, secret) pair is
  folded) are not memoized: steady state is what is measured. Sessions and PATs are untouched.
- **PgBouncer**: `storage.database.pooler: pgbouncer-transaction` (#3254) is refused at config
  validation; `pgbouncer-session` is allowed. The Helm `fail` guard is a follow-up.

## 0. What the request path pays today, and what the mode removes

A machine-token `GET /api/v1/secrets/{id}?include_value=true` on a warm cache (Postgres) runs:

1. **One confirming statement** (the PERF-LEVER2 fold, `store/local_folded_credential.go` +
   `local_readpath_prefetch.go`, on the native pool since #3248). It reads the credential and the
   identity state (INV-MW-02), the node `cache_epoch` stamp and trigger proof, the machine's role ids at
   the node's scope (live by design, `role_permission_cache.go` header), the `role_permissions_generation`
   row, and (when asked) the schedule row and the versions generation.
2. The throttled `last_used_at` touch (usually a no-op), the `max_reads` conditional UPDATE (only for
   secrets that set it), and the audit write (2 flights, durable).

The mode skips (1) entirely on a cache hit: **0 request-path statements apart from audit**. Expected: about
−0.3 ms per read at c=1 and +8-12 % throughput at c=50 (one statement and its database CPU fewer per
read); go/no-go targets in §5. Nothing about audit changes.

### Premises in the brief that the code does not support (checked)

- **The CLI has no local/embedded mode.** ADR-108 Decision A removed it. `cli/` is a separate module
  with no dependency on the main module, and `cli/internal/depguard/depguard_test.go` fails if it ever
  imports `internal/storage`, `internal/core` or `server/`. Every CLI write is an API call, so it's a
  server-path write. The only binary that opens the database directly is `keyorix-server` itself:
  `serve` and the `admin` subcommands (plus `examples/`, which are not shipped).
- **There is no "emergency lockdown" feature** (no route, command or table; grep over
  server/internal/cli/docs). Break-glass revoke is the HTTP route
  `POST /projects/{id}/break-glass/{activationId}/revoke`, so it's a server-path write.
- **The Helm chart already runs exactly one server replica with `strategy: Recreate`**
  (`deploy/helm/keyorix/templates/server-deployment.yaml:20-22`). So the default chart deployment
  is the target topology, not a special case.
- **Admin commands already refuse to run next to a live server** (`serverguard.AcquireExclusive`
  via `server/admin/admin.go:acquireDatabaseLock`), except under `--force`.

## 1. Mechanism

### 1.1 Setting

`storage.database.single_writer: true` (default false; Helm `externalDatabase.singleWriter`).
Decided (2026-10-15): this name, valid only with the write fence. Without the fence the honest name
would be `insecure_single_writer_cache` under the ADR-112 opt-out rule, which is why the server refuses
to start when the fence cannot be installed and verified.

Config validation **refuses** the setting when any of these holds:
- the backend is SQLite or remote (v1 is Postgres only; SQLite's request path is in-process, so the
  saving is CPU only and there is no session-lock primitive for the fence);
- `storage.database.pooler: pgbouncer-transaction` (#3254). Both the holder lock and the
  per-connection writer tag (§1.3) are session-scoped. `pgbouncer-session` is allowed: a client
  session keeps one backend, and `DISCARD ALL` on release clears the tag;
- `auth.rate_limit_fallback.replicas > 1`. The operator has declared more than one replica;
- Helm: `server.replicas > 1` or `strategy != Recreate` together with `singleWriter` (template `fail`).

### 1.2 Refusing a second writer (three layers, all in the database)

**(a) Holder lock K1.** At boot, after `serverguard.AcquirePresence` and before migrations, the server opens
a dedicated connection (its own pool, like the named-lock pool, INV-STORE-named-lock-own-pool) and runs
`pg_try_advisory_lock(K1)`, with K1 = `0x4B455941_534F4C45` ("KEYASOLE", following the KEYA-tag convention
from `secret_node_cache_epoch.go:36-53`). If the lock is held elsewhere, the server retries with backoff for up
to 120 s and then exits non-zero with: "another Keyorix server holds the single-writer lock (backend pid N);
single_writer allows exactly one server". The bounded wait covers a Recreate rollout whose old pod's backend
has not yet noticed the client is gone. On that connection the server also sets `tcp_keepalives_idle=10`,
`tcp_keepalives_interval=5`, `tcp_keepalives_count=3` and `client_connection_check_interval=5s`, so
Postgres drops a dead holder within ~25 s instead of the 2 h default.

**(b) Presence census.** While it holds K1, the server reads `pg_locks` for the serverguard presence key
(`serverPresenceLockKey`, shared mode). It refuses to continue if any other backend holds presence, which
would be a normal-mode replica already running. The other direction: a server with `single_writer: false`
checks K1 at boot and refuses to start while a live holder exists ("a single_writer server is running
against this database"). Admin commands: `acquireDatabaseLock` refuses `--force` outright when K1 is
held. `--force` can never write next to a single-writer server.

**(c) Write fence (the part that makes this safe for revocation).** Every fenced table (§1.4) gets a
`BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ... FOR EACH STATEMENT` trigger, installed `ENABLE ALWAYS`
so it also fires under `session_replication_role = replica`, which pg_restore and logical
replication use. Its function:
- **allows** the statement if the session's `keyorix.sole_writer_nonce` GUC hashes (`sha256`) to
  `keyorix_sole_writer.nonce_hash`. This cheap check comes first, so the server's own writes never touch
  `pg_locks`;
- otherwise **allows** it if no live holder exists (`keyorix_sole_writer.holder_pid` has no granted K1
  row in `pg_locks`). This covers a stopped or crashed server, admin commands and normal mode;
- otherwise **raises**: `keyorix single_writer: server (backend pid N, since T) is the only permitted
  writer of <table>; write through its API, or stop it (see docs/single-writer.md "Emergency SQL")`.

The server generates a 256-bit nonce per boot. It writes its hash and its holder pid into the one-row
`keyorix_sole_writer` table after taking K1. Every pool's AfterConnect sets the GUC with
`SET keyorix.sole_writer_nonce = ...`, not a startup parameter, because PgBouncer drops those (#3254
inventory). The pools are request, audit, lock, migration and serverguard; the native pool is read-only by
INV-STORE-native-read-pool, but it is set there too. If the server forgets the tag on some pool, its own
writes fail loudly. That is fail-closed and the tests catch it at once.

Result: **while the server lives, no out-of-band write to a security table can commit.** A delayed
revocation turns into a refused write. What remains is deliberate bypass by a role that can disable
triggers or read the server's session (§2, rows 11-12).

### 1.3 write_epoch (backstop and bug canary)

One row `keyorix_write_epoch(id=1, incarnation uuid, n bigint)`. An `AFTER ... FOR EACH STATEMENT`
trigger (`ENABLE ALWAYS`) on every fenced table runs `UPDATE keyorix_write_epoch SET n = n + 1`. It runs
for **every** writer, the server included. A row in the same transaction, not a sequence: the new value
becomes visible atomically with the data at commit, so a statement that reads data and epoch together
gets a consistent pair. A sequence is non-transactional; it would show the bump before the commit and
let a refill tag old data with the new epoch. Fenced writes are rare, so the row lock serializing
them doesn't matter (read-path bookkeeping columns are excluded, §1.4). `incarnation` is regenerated
whenever the triggers are (re)installed, so a restored database whose counter happens to match is still
a mismatch.

The installer follows `EnsureSecretNodeCacheEpoch`: one definition for production and tests, idempotent,
never drops a correct trigger, convergence checked by body text. Downgrade-safe: an older binary has no
nonce, but with no live holder the fence allows its writes. The epoch trigger only costs one row update.

### 1.4 Fenced tables (v1 = the machine-token read path)

Derived from the confirming statement plus the machine authorization path (`AuthorizeSecretPrincipal`:
machines are role-only, no ACL/share terms):

| table | fence/epoch filter |
|---|---|
| machine_identity_credentials | all writes except an UPDATE that changes only `last_used_at` (row-level `WHEN (to_jsonb(OLD) - 'last_used_at' IS DISTINCT FROM to_jsonb(NEW) - 'last_used_at')`, a **deny-list**, so a future column is fenced by default) |
| machine_identities, machine_identity_roles, roles, role_permissions, permissions | all writes |
| projects, environments | all writes (soft delete removes role scope) |
| secret_nodes, secret_versions, secret_access_schedules | all writes; `read_count` changes included (max_reads state is cached, read-path-caching.md PR-1) |
| system_metadata | only `key = 'role_permissions_generation'` (row-level WHEN) |
| keyorix_sole_writer, keyorix_write_epoch | fence only (server-owned) |

A **derive-and-check guard** parses the FROM/JOIN table names of every statement whose result can be served
authoritatively (`foldedCredentialSQL`, `readPathPrefetchSQL`, the fill statements of the caches in §1.5) and
fails if one is not in the fenced set. A new join cannot silently add an unfenced dependency.

Sessions, PATs, users, groups and ACLs are **not** in v1. Those paths keep today's confirming reads
(INV-MW-01/03/04 unchanged). So v1 speeds up machine reads only. The CLI path (PAT) doesn't benefit until a
phase 2, which would need session idle-timeout and MFA-step state in the cache.

### 1.5 Which caches become authoritative

When the mode state is `authoritative` (§1.6):
- **auth token cache, machine entries** (`server/middleware/auth.go` `serveAuthCacheHit`):
  `CurrentMachineTokenRestriction` and the fold are skipped. The cached credential snapshot is judged with
  the same code. **Every time predicate is still evaluated per request** against the cached row:
  `expires_at` and the CIDR allowlist (INV-MW-06). Schedule windows below are evaluated likewise;
- **secret metadata cache** (`secret_metadata_cache.go`): node, latest version, schedule served without
  the stamp/generation read;
- **role→permission cache**: served without the generation read;
- **new: machine role-ids-at-scope cache**, key (machine, project, env). This is the one cache that
  doesn't exist today. Role membership is deliberately live in normal mode. It exists only in
  authoritative mode and is dropped on the first transition out of it.

Entry tag = `(incarnation, epoch at fill, localGen at fill)`. The **fill statement reads the epoch row in the
same statement** as the data (one READ COMMITTED snapshot), so the tag is exact.

### 1.6 State machine and hit rule

States: `off` (setting false) → `settling` → `authoritative` ⇄ `confirming`. Only `authoritative` serves
unconfirmed hits. `confirming` is today's code path byte for byte.

**Hit rule** (all atomics, ~ns): state == authoritative ∧ lease valid ∧ `inflight == 0` ∧
`entry.localGen == localGen` ∧ `entry.incarnation == incarnation` ∧ `entry.epoch >= knownEpoch`.
Otherwise the request takes today's confirming path. A confirming result may refill the entry, but only if
`localGen` and `inflight == 0` were the same before and after the fill statement.

**Poller** (on the K1 connection, every **250 ms**): one statement returning `pg_backend_pid()`, the
`pg_locks` proof that this backend holds K1, the epoch row, and the trigger census (every fenced table has
both triggers, `tgenabled = 'A'`, function body hash as installed). On success it extends the **lease to 1 s**.
The lease is checked against both the monotonic and the wall clock, so a paused VM or a SIGSTOP expires it
on resume. If the epoch changed it sets `knownEpoch` (which invalidates older entries).

**Synchronous invalidation of in-process writes, without trusting per-site eviction calls.** Today
`InvalidateTokenCacheByHash` and friends are "a latency optimization, not the source of correctness"
(read-path-caching.md §4). They missed sites before (gRPC revoke discarding the hash, INV-MW-08; #2518).
In this mode they'd become load-bearing, so the design doesn't rely on them. A **generated wrapper over
`storage.Storage`**, built by the same generator approach as `internal/faultstorage`, classifies every
method:
- read methods: untouched;
- **fenced writes**: `inflight++` before the call; `localGen++` then `inflight--` after it returns,
  commit or error. Inside `WithTransaction`, the first fenced call marks the transaction and the bump
  happens at transaction end;
- **unfenced writes** (audit, last_used touch, scheduler lease, notifications...): untouched. Unknown
  defaults to fenced, which only costs a flush.

Between write start and commit, every request uses the confirming path. After the commit, every entry
filled before it is stale (localGen), and no fill that overlapped it was stored. **A revocation through
the server is effective for every request that starts after the revoking call returns: zero window.**
The existing per-site evictions stay as they are.

The classification is checked against the database: the **trigger is the oracle** (§5 T9). Every storage
write method, run with the mode on: if the epoch moved, the wrapper must have bumped localGen. A
misclassified method is a test failure. If one slips through to production, the poller still catches it:
an epoch advance with no local fenced commit since the last poll is an **unattributed bump**. That means
ERROR log, metric `keyorix_single_writer_unattributed_bumps_total`, and a full flush. Fatal in tests.
Worst case for a classification bug is ≤ 1 s staleness, never unbounded.

**Boot (`settling`)**: K1 → census (b) → write `keyorix_sole_writer` (nonce hash, pid) → migrations and
boot writes (ADR-112 markers, posture snapshot) → **fence settle**: take `pg_current_snapshot()` and wait
until every xid in its `xip` list is finished (`pg_xact_status`, no extra privilege). That closes the race
of a non-server transaction whose fenced statement ran before the holder row existed and commits after →
first successful poll → `authoritative`. Settle times out after 30 s; the server then stays `confirming`
and reports why.

## 2. Write paths and revocation latency under the mode

"Immediate" = effective for every request that starts after the write's call returns (today's #G18
semantics).

| # | write path | goes through | latency under the mode | notes |
|---|---|---|---|---|
| 1 | HTTP API (revoke token, suspend/revoke machine, remove role, delete project/env, role-permission edit, schedule, rotate/delete secret) | in-process core → storage wrapper | **immediate** | localGen + inflight, §1.6 |
| 2 | gRPC (same operations) | same core + storage | **immediate** | gRPC has no auth cache (interceptors/auth.go:406); the storage caches are shared and invalidated by the same wrapper |
| 3 | CLI | HTTP API | **immediate** | no local mode exists (ADR-108 A, depguard) |
| 4 | Break-glass activate/revoke/review | HTTP route → core | **immediate** | |
| 5 | Emergency lockdown | does not exist | n/a | if built later, it must be a server-path write (it would then be immediate) |
| 6 | SCIM provisioning/deprovisioning, OIDC/SAML group sync at login | HTTP routes → core | **immediate** | in-process |
| 7 | Schedulers (JIT expiry, retention, auto-rotate, purge, recertify, break-glass review...) | `startSchedulers`, in-process | **immediate** | single process, so the scheduler locks are uncontended |
| 8 | Migrations at boot | in-process, before `authoritative` | n/a (caches cold) | |
| 9 | `admin` commands (restore, recover-admin, clear-login-lockout, migrate, encryption rotate/upgrade-aad...) | separate process | **refused while the server runs** (serverguard exclusive; `--force` refused under the mode; fence refuses any write regardless) | with the server stopped they run normally and the next boot starts cold |
| 10 | Direct SQL by a DBA / scripts / pg_restore into the live DB / a misconfigured second replica / an older binary | Postgres session without the nonce | **refused** (fence error naming the holder) | an operational change: see "Emergency SQL" below |
| 11 | Direct SQL after deliberately bypassing the fence (owner/superuser `ALTER TABLE ... DISABLE TRIGGER`, also toggled off and back on inside one transaction; dropping or re-creating a trigger or function; a child table; copying the nonce from the server's statement log) | — | **≤ 1 s**: the census on the next poll (≤ 250 ms) sees the catalog change (row `xmin` included) and drops to `confirming` for good; a copied-nonce write moves the epoch and every epoch move flushes the caches at that poll | not a boundary against the DB owner/superuser. Superuser writes **below SQL** (native code, data directory) are not detectable: up to the memo TTL; posture deviation when the server's role can do it |
| 12 | Writes after the holder lock is lost (pg_terminate_backend, network partition, PG restart) | — | **≤ 1 s** (lease) after the last successful poll | §4 |
| 13 | Backup restore: `admin restore` | admin path | refused while the server runs | |
| 14 | Backup restore: volume snapshot / PITR / `pg_restore` from outside | needs PG restart or a new cluster → the holder connection dies | row 12, then a restart with cold caches; the incarnation check rejects old entries | |

**Emergency SQL runbook** (docs/single-writer.md): either stop the server (preferred), or run
`SELECT pg_terminate_backend(holder_pid) FROM keyorix_sole_writer`. The fence opens at once. The server
loses its lease within ≤ 1 s, drops to `confirming` and **does not re-enter** `authoritative` until a
restart. A revoking UPDATE issued after the terminate is therefore effective on the server's very next
request once the lease is gone (≤ 1 s). The trade-off for operators: the "psql UPDATE ... SET
revoked=true" emergency path still works, but it takes two statements instead of one, and the first
attempt fails with an error that names the fix. **No security-critical path is silently delayed**:
rows 1-8 are immediate, 9/10/13 are refused, and only deliberate bypass (11) or lock loss (12) has a
window, ≤ 1 s.

## 3. The immediate-revocation invariant (#G18, ADR-112)

### 3.1 What changes, plainly

Today, every replica re-reads the revocation state on every request, so a revocation **by any writer**,
direct SQL included, takes effect on the next request. Under the mode:
- through the server (API, gRPC, CLI, SCIM, schedulers, break-glass): **unchanged, immediate**;
- a direct database write while the server runs: **refused** instead of immediately effective;
- a direct write after the fence was deliberately bypassed or the holder lock was lost: effective
  within **1 second**, not on the next request.

So #G18 holds for every write that can commit, except two bounded cases that need a DB superuser or
owner acting against the fence, or an infrastructure failure, and one unbounded-by-the-poll case: a
superuser changing data below SQL (row 11, posture deviation). The opt-in exists because the cost is real.

### 3.2 Proposed wording

ADR-112 baseline line (amendment, coordinator-owned; I did not touch the ADR):
> Revocation takes effect immediately (#G18). With `storage.database.single_writer` (opt-in,
> single-server PostgreSQL only) this holds for every change made through the server; direct
> database writes are refused while the server runs, and a change made after the database-side
> fence has been bypassed in SQL or the server's lock lost takes effect within 1 second. A database
> superuser changing data below SQL is not detected (reported by the posture check when the
> server's own role has that power).

docs/CONFIGURATION.md entry:
> `storage.database.single_writer` (default `false`, PostgreSQL only). Declares this server the only
> writer of its database. The server then trusts its own caches for machine-token reads and skips one
> confirming database statement per read (about 0.3 ms at low load, about 10 % more throughput at high
> load). A second server, an admin command with `--force`, or any SQL session that writes to a
> security table is refused while it runs. Revocations made through the server stay immediate.
> Not compatible with more than one replica or with PgBouncer transaction pooling.

### 3.3 Visibility (the mode must never be silent)

- **Start-up line** (log, always):
  `single_writer: authoritative (lock KEYASOLE held by backend pid 4711; write fence on 13 tables; epoch poll 250ms, lease 1s). Direct database writes to security tables are refused while this server runs.`
  On every state change: `single_writer: confirming (reason: lease expired / trigger census mismatch / lock lost / settle timeout)`.
- **`GET /system/info`**: `storage.single_writer: {enabled, state, reason, holder_pid, fenced_tables, epoch, last_poll_age_ms, unattributed_bumps}`
  (same handler as fast audit mode, `system_fast_audit_mode_test.go` pattern).
- **`admin validate --posture`** and the posture report: always a line `single_writer: on (authoritative)`.
  It is a **posture deviation** when enabled and the state is `confirming` for any reason other than boot,
  or any fenced table lacks an `ENABLE ALWAYS` trigger, or `unattributed_bumps > 0`.
  Whether "enabled and healthy" also counts as a deviation depends on the naming decision. With the fence:
  informational. Without the fence: `insecure_` prefix, deviation, start-up warning, audited (registry
  `internal/config/insecure_settings_registry.go`).
- **Audit**: toggling the setting appears in the start-to-start settings diff
  (`ReconcileSecurityPostureSnapshot`). Every transition to `confirming` writes an audit event
  `single_writer_degraded`.
- **Metrics**: state gauge, authoritative hit ratio, polls, unattributed bumps, fence refusals (as far as
  the server can see them: a refusal happens in another session, so it shows only in Postgres logs and in
  the census, not here; documented).

## 4. Failure modes

| failure | detection | behaviour |
|---|---|---|
| Holder lock lost (backend killed, PG restart, partition, PgBouncer server-conn drop) | next poll fails or `pg_backend_pid()`/K1 proof changes; at the latest lease expiry | `confirming` within ≤ 1 s of the last good poll; **no re-entry until restart** (a terminate can be an operator's emergency action, §2); audit + deviation. Requests stay correct (today's path). |
| Poll statement fails, same session | poll error | lease runs out → `confirming`. Re-entry is allowed only if a later poll succeeds **on the same backend pid** (same session ⇒ the lock was never released), followed by a full flush and a re-read of the epoch. A different pid means lock lost (row above). |
| Poll goroutine stalls (GC, CPU starvation), clock jump, VM pause/SIGSTOP | lease checked against monotonic AND wall clock on every hit | expires → `confirming` until a fresh poll succeeds; no hit is ever served on an old lease |
| Trigger census mismatch (dropped, disabled, `tgenabled != 'A'`, body changed) | poll | `confirming` until restart; deviation; the boot installer reinstalls the triggers on the next start |
| Unattributed epoch bump | poll | full flush (as for every epoch move), ERROR, metric, deviation (the first stays authoritative: the flush already made it correct; the second → `confirming` until restart) |
| Crash / kill -9 | Postgres drops the session (≤ ~25 s with the keepalive settings, at once on a clean TCP close) | caches die with the process; the fence opens once K1 is released; the next boot starts cold, settles, then becomes authoritative. Until Postgres notices the dead client, out-of-band writes are refused (loudly), not lost. |
| Recreate rollout overlap | new pod can't get K1 | bounded wait (120 s), then exit non-zero, so the orchestrator retries |
| Fence settle can't complete (a long-open transaction) | 30 s timeout | stays `confirming` and says which xid/age |
| Upgrade (mode-less binary → mode) | — | installer adds tables and triggers idempotently; settle; authoritative |
| Downgrade (→ binary without the mode) | — | triggers stay. With no live holder the fence allows every write; the epoch trigger costs one row update per fenced write statement. To remove them cleanly: `admin single-writer uninstall` (exclusive lock), or the next mode-aware boot with the setting off leaves them installed, harmless |
| Mode on → off between starts | settings diff | audited; the server never takes K1 and never writes `keyorix_sole_writer`, so the fence stays open |
| Database restored under a running server | the restore kills the holder session, or the incarnation changes | row 1, plus incarnation mismatch ⇒ every entry invalid |
| Wrapper bug: the server's own write not classified fenced | trigger oracle test; in production the unattributed-bump canary | ≤ 1 s staleness worst case, never unbounded |
| Cache fill races a write | fill stored only if localGen/inflight unchanged; epoch read in the same snapshot as the data | no stale entry survives a commit |

## 5. Test plan

All pg-gated tests use `kpg`-style DSNs and two independent `*gorm.DB`/pgx pools per "process" (CLAUDE.md:
a test named "cross-replica" must not share one LocalStorage). Each guard gets a red-proof.

- **T1 refusal**: second server with the mode → refused (K1); a normal-mode server next to a holder →
  refused; a holder next to an existing normal-mode presence → refused; `admin ... --force` while held →
  refused; config: SQLite / remote / `pgbouncer-transaction` / `replicas > 1` → validation error; Helm
  template `fail` for replicas 2 / RollingUpdate.
- **T2 server-path revocation is immediate**, the `credential_gone_cache_hit_test.go` table extended to
  every end-of-access path (revoke token, delete credential, suspend/revoke identity, remove role,
  delete project/env, remove permission from role, set closed schedule, delete secret, rotate) × {HTTP,
  gRPC}: warm the cache, revoke, **the very next request** is denied. Red-proof: delete the wrapper's
  `localGen++` → stale success. Plus a concurrent variant: revoke in flight while 50 readers hammer;
  no read that starts after the revoke returns succeeds.
- **T3 direct SQL is refused while live**: a plain session (no nonce) runs UPDATE/DELETE/INSERT/TRUNCATE on
  every fenced table → error naming the holder, row unchanged; again under `session_replication_role =
  replica`. Red-proof: install the fence `ENABLE` instead of `ENABLE ALWAYS` → the replica-role write
  commits → red. The `last_used_at`-only UPDATE is allowed and bumps nothing.
- **T4 the brief's out-of-band window test**: (a) `pg_terminate_backend(holder)` then SQL revoke → denied
  within ≤ 1 s, measured (assert < 1.0 s, log the actual); (b) superuser disables only the fence trigger,
  SQL revoke → the census flips the state to `confirming` and the next request is denied within ≤ 1 s;
  (c) both triggers disabled → same via the census. Red-proof: stop the poller → still served after 2 s
  → red. Paired with T2 in one test file, so the immediate and windowed cases sit next to each other.
- **T5 lease**: fault-inject poll errors / a stalled poller / a wall-clock jump (injected clock) → no
  authoritative hit after lease expiry; same-pid recovery re-enters, a different pid doesn't.
- **T6 settle**: open a transaction in another session that writes a fenced row while no holder exists,
  boot the server, assert it stays `settling` until that commit, then serves the committed revocation.
- **T7 fill race**: deterministic hooks between the fill statement and the store; a fenced commit in
  between → the entry is not stored.
- **T8 derive-and-check**: every table referenced by an authoritative fill statement is fenced; every fenced
  table has both triggers `ENABLE ALWAYS` after migration (checked at boot and by the poller; red-proof by
  adding an unfenced join in a test copy of the SQL).
- **T9 classification oracle**: drive every `storage.Storage` write method with the mode on; epoch moved
  ⇒ localGen moved. Also: no wrapper-unfenced method moves the epoch (protects the hot path from flush
  storms). Unattributed-bump detector fatal across the server test suite with the mode on.
- **T10 differential/fuzz**: `FuzzAuthCacheDifferential` and `FuzzCrossReplicaInvariants` (single-replica
  seeds) run with the mode on: the authoritative and confirming decisions must agree for every op
  sequence; `server/faultops` fault fuzzer with the mode on (oracle (c), fail closed).
- **T11 upgrade/downgrade**: old binary against a DB with triggers and no holder → all writes OK; mode
  toggled across restarts → settings-diff audit event; incarnation change → all entries invalid.
- **T12 journey (definition of done)**: on the e2e VM, server with `single_writer: true`: CLI revokes a
  machine token → next read 401; `psql` UPDATE → refused with the documented message; runbook terminate +
  SQL revoke → 401 within 1 s; `/system/info` and `admin validate --posture` show the mode;
  posture golden files for on/healthy and on/degraded.

### A/B plan (bench VM, PVE-BENCH-LOCK, PERF-6 harness, same pinning)

- Arms: **A** default · **B** `single_writer` · **C** AUDIT-1FLIGHT-1 · **D** B+C. W1 (machine token, KV
  read include_value), c = 1, 10, 50; ABAB interleaved, 3 × 60 s per cell after warm-up, one sitting.
- Record: p50/p99, rps, PG CPU per read, backend CPU per read, `pg_stat_statements` calls per read (B must show
  0 request-path statements apart from audit/touch), authoritative hit ratio (must be ≈ 1), polls/s.
- Churn arm: B with one fenced admin write per second (token mint/revoke) → measure the flush cost and
  check that p99 doesn't regress.
- Go criteria: B vs A c=1 p50 ≤ −0.25 ms **and** c=50 rps ≥ +6 %, with no p99 regression > 5 % in the churn arm.
  ≥ 10 interleaved repetitions per cell. If it misses, no-go: the complexity isn't justified by less.
- Harness hygiene (REVIEW-SINGLE-WRITER-1): set `anomaly_alerts.schedule` to the same value in every arm, or
  `anomaly_alerts.enabled: false` in all of them, so no arm samples `pg_stat_statements` during an
  anomaly-detection pass the others don't run. Record pgss `mean_exec_time` and `total_plan_time` per
  statement, not only calls. The churn arm also measures the flush on every epoch move (F4 fix).
- The magnitude is rig-specific. The first A/B measured ≈ 0.68 ms of PostgreSQL CPU per confirming statement on
  the bench VM, against ≈ 0.045 ms above `SELECT 1` locally and the ≈ 0.2 ms this design assumed. The direction
  is trustworthy (same image, every rep); quote no percentage externally until a second rig reproduces it.

## 6. Recommendation

**Go with restrictions**, in this order, each gated:
1. **Only with the write fence.** Trigger + poll alone (the brief's minimum) turns every out-of-band
   revocation into a ≤ 1 s window. That's a real weakening of #G18, would need the `insecure_` name
   under ADR-112, and I would not ship it. With the fence, every write that can commit is either
   server-path (immediate) or refused. The windows that remain need deliberate superuser bypass or lock loss and
   are bounded at 1 s and reported.
2. **v1 scope = machine-token read path, Postgres, one replica, no PgBouncer transaction mode.**
   Sessions/PATs stay confirming.
3. **Implementation order**: (i) the triggers, census and fence with no cache change at all, shipped
   dark (mode reports `confirming` always), so T3/T6/T8 and the downgrade story are proven first;
   (ii) the generated storage wrapper + T9 oracle, still with no authoritative hits; (iii) authoritative hits +
   T2/T4/T5/T7/T10 + A/B. Do AUDIT-1FLIGHT-1 and SQLITE-SYNC-1 first if the budget is tight: they buy
   similar c=1 gains with no security-model change.
4. Effort: M-H (≈ 3 PRs, ~1.5-2 sessions plus the A/B). Risk sits in the wrapper classification, and the
   trigger oracle plus the unattributed-bump canary turn that risk into ≤ 1 s rather than unbounded.

Reason: the gain is modest (≈ 7 % at c=1, ≈ 10 % at c=50). It is only worth having if revocation
semantics stay intact for every path an operator actually uses. The fence makes that achievable
with Postgres primitives the codebase already relies on (session advisory locks, `ENABLE ALWAYS` triggers,
the KEYA-tagged keys, the `cache_epoch` installer pattern). The operational cost is that emergency SQL
needs the two-step runbook.

