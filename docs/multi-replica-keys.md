# Encryption keys with more than one server replica

Status: implemented (`storage.encryption.key_dir_lock: database`), HA-READY-1.
Live Kubernetes verification is pending (see the end of this page).
Operator summary: [SELF_HOSTING.md, "Running more than one replica"](SELF_HOSTING.md#running-more-than-one-replica).

## The problem

Until this change a server took an exclusive `flock(2)` on `<key dir>/dek.lock` before it
generated or loaded keys, and held it for its whole lifetime (`server/main.go`,
`initializeEncryption`; INV-ENCRYPTION-01/02). That lock does two jobs on one host:

1. First boot: two processes racing a fresh key directory cannot both generate a DEK.
2. Lifetime: `keyorix-server admin encryption rotate` (a separate process) cannot replace
   `dek.key` while a server still has the old DEK in memory (#92).

Two replicas that share one key directory, which is what the Helm chart's
`server.replicas > 1` asks for (a ReadWriteMany keys volume, #3305), then depend on how
the filesystem implements `flock`:

| Filesystem behaviour | Result with the flock |
|---|---|
| flock enforced across clients (NFSv4 on Linux, CephFS, EFS, most CSI RWX drivers) | The second replica cannot take the exclusive lock and **refuses to start**, on any node. Only one replica ever runs. |
| flock local to each node (NFS mounted `local_lock=flock`, some FUSE drivers) | Both start, but the lock protects nothing across nodes: two first boots can each generate a DEK, and a rotation on node A ignores a live server on node B. |
| No lock support (`ENOLCK`) | No replica starts. |

None of these is a working HA mode. `TestKeyDirLock_Flock_SecondReplicaOnSharedKeyDirRefuses`
reproduces the first row on one host.

## What lives in the key directory

Paths are the Helm chart's (`/app/keys`); the names follow `storage.encryption.dek_path` and
`salt_path`.

| File | Content | Written by | Read by | Needed at start-up | At rotation |
|---|---|---|---|---|---|
| `data.key` (`dek_path`) | DEK wrapped by the KEK (AES-GCM) | first boot; `admin encryption rotate`, `rotate-kek`, `migrate-provider` (temp file + rename) | every server at start-up; admin commands | yes, by every replica, and it must be the same file everywhere | replaced; every replica must restart onto the new one |
| `kek.salt` (`salt_path`) | PBKDF2 salt, `password` provider only | first boot; `rotate-kek` | every server at start-up | yes, the same everywhere (with the same master password) | replaced by `rotate-kek` only |
| wrapped KEK (`key_provider.wrapped_key_path`) | KMS/TPM-wrapped KEK (`aws-kms`, `gcp-kms`, `azure-kms`, `tpm`) | first boot; `migrate-provider` | every server at start-up | yes | replaced by `migrate-provider` |
| `data.key.pending` | staged DEK during a rotation | rotate / rewrap / rotate-kek | crash recovery at start-up | only if a rotation crashed; recovery promotes or deletes it | transient |
| `data.key.backup.*`, `data.key.migrate-backup.*` | old wrapped DEKs | rotate, migrate-provider | operator only | no | left behind |
| `dek.lock` | empty; `flock` handle | server (lifetime, exclusive), admin commands | — | flock mode only | — |
| `data.key.lock` (`<dek_path>.lock`) | empty; `flock` handle for key-file rewrites (#195, #2602) | rotate, rewrap, rotate-kek (exclusive); live `admin backup` (shared) | — | no | taken by the rewriting command |

Nothing else is written there. The evidence-signing, audit-checkpoint and backup-manifest
keys are derived from the KEK in memory (`keymanager_lifecycle.go`), so they are not files.
The `file`/`env`/`exec`/`shamir` KEK providers read their material from outside the key
directory.

So a replica needs **read-only** access to `data.key`, plus `kek.salt` or the wrapped KEK,
at start-up and never writes them while running. Writes happen only at first boot, during
crash recovery, and in admin commands. With the flock, the server also wrote `dek.lock`.

## Design: `storage.encryption.key_dir_lock: database`

An opt-in mode, PostgreSQL only (config validation refuses it with SQLite or remote storage).
The default `flock` mode, SQLite and single-replica deployments are unchanged.

Every exclusion the flock gave is moved onto a PostgreSQL advisory lock. Advisory locks are
per database, are released when the holding connection ends (a crashed replica leaves no
stale lock), and work through a transaction pooler as transaction-scoped locks held in a
pinned transaction (`internal/serverguard`).

| Exclusion | flock mode | database mode |
|---|---|---|
| Two first boots on a fresh directory | exclusive `dek.lock`, loser refused | key-initialisation lock `872343` (`serverguard.WithKeyInitLock`): the loser **waits** (up to 2 min), then finds the files and loads them |
| Crash recovery (promote/discard `data.key.pending`) | under `dek.lock` | under the same key-initialisation lock |
| Rotation/restore while a server runs (#92) | server's lifetime `dek.lock` (and the presence lock) | the presence lock `872342` alone: every replica holds it **shared** for its lifetime, key-changing admin commands need it **exclusive** (already true on main) |
| Admin `--force` past a held presence lock | still stopped by `dek.lock` | **refused**: `--force` cannot override in this mode (`server/admin/admin.go`) |
| Live `admin backup` vs a rotation | `data.key.lock` shared vs exclusive | additionally holds the presence lock **shared** for the whole backup, so a rotation cannot start meanwhile |
| Admin command vs admin command | `data.key.lock` | the presence lock exclusive (unchanged) |

One more check, which the flock made unnecessary: **first-boot generation is refused when the
database already holds secret versions or a recorded DEK epoch**. With the flock, a replica that got
its own empty key directory (a per-pod volume, or a Secret that failed to mount) could not start
next to a sibling on the shared directory. Without the flock it could, and it would generate a
second DEK. Now it exits with "refusing to generate a new DEK", before it writes any key file. The
check looks at the `dek.epoch` row in `system_metadata` (written by the first replica's boot, so it
also covers a fresh database with no secret yet) and at `secret_versions`, including soft-deleted
rows. Two replicas with separate empty key directories that boot at the very same instant, before
the first has recorded its epoch, can both generate a DEK; the DEK epoch
([#3344](https://github.com/keyorixhq/keyorix/pull/3344)) then refuses the loser at start-up, but
it has already written its own key files, which an operator removes.

A server in this mode also records `key_dir_lock.mode = database` in `system_metadata`. `admin`
commands read it: `--force` cannot override a held lock when the database says its replicas run
this mode, even if the admin command's own config does not set `key_dir_lock`. The row is never
removed automatically; if you go back to `flock`, delete it
(`DELETE FROM system_metadata WHERE key = 'key_dir_lock.mode'`) or `--force` stays refused.

The server no longer writes to the key directory after first boot, so in this mode it can be:

- **a shared ReadWriteMany volume**, whatever its flock semantics. The first replica generates
  the keys; the others wait and load them. Rotation runs as an admin command (a Job) on the
  same volume while every replica is stopped.
- **read-only key material per replica**, e.g. a Kubernetes Secret (or CSI secret-store volume)
  holding `data.key` plus `kek.salt` or the wrapped KEK. Generate the key set once
  (`keyorix-server admin encryption init`, or a first boot against a writable directory), store
  it in the Secret, and mount it read-only. `TestKeyDirLock_Database_ReadOnlyKeyDir` boots from
  a directory the server cannot write to. To rotate: scale to 0, run the rotation in a Job on a
  writable copy, update the Secret, then scale up. A replica still holding the old key set is
  refused by #3344's DEK epoch, so update the Secret before scaling up.

What a replica needs, by phase:

| Phase | Needs |
|---|---|
| First boot (fresh install) | write access to the key directory for the one replica that wins the key-initialisation lock; the others need only read access |
| Every later start | read access to the same key set; the presence lock (shared); the key-initialisation lock for a moment |
| Running | nothing from the key directory (the DEK is in memory) |
| DEK/KEK rotation, provider migration, restore | every replica stopped (the admin command needs the presence lock exclusively); write access for the admin command only; every replica then restarts onto the new key set |

### Limits, stated

- Read-only admin commands (`admin encryption status`, `validate`) still take a shared flock on
  `dek.lock`. On a filesystem without lock support they fail. They change nothing, so run them
  from a pod with a local copy.
- The admin commands that rewrite key files still take `data.key.lock`. They already hold the
  presence lock exclusively, so the flock is redundant there; where flock fails with `ENOLCK`
  they fail closed.
- The presence lock is cooperative. A binary older than the presence guard, or one started
  with a different database, is not seen. Every replica must run a version with this setting
  and the same configuration.
- Losing the presence lock while running (a pooler or a `pg_terminate_backend`) is STORAGE-3
  item 2 (POOLER-LOCKLOSS-SESSION), which waits for #3299. Until that lands, a replica whose
  presence connection was killed keeps serving without the lock. #3344's runtime epoch poll
  fences its writes during a rotation.

## Not chosen

- **Keep the flock, take it shared in the server.** That still needs working flock on the RWX
  volume (the `ENOLCK` and per-node rows above), and it loses the first-boot exclusion.
- **Wrapped DEK in the database** (`system_metadata`), so that no key volume is needed at all and
  only the KEK comes from a Secret or KMS. This is the cleanest end state for HA. It changes the
  backup format (keys are archived next to the database today), rotation crash consistency
  (temp file + rename + redo marker) and restore, so it is a separate design.
  **NEEDS ANDREI**: recommended as a follow-up; #3344 (merged) already puts a DEK
  fingerprint in `system_metadata`.

## Helm (#3305)

The chart change belongs to the open PROD-HELM-1 PRs (deploy/helm is theirs). For
`server.replicas > 1` the chart should render `storage.encryption.key_dir_lock: database`.
That is enough for a ReadWriteMany volume. The ReadWriteMany requirement could then be
relaxed to "ReadWriteMany, or `server.keysSecret` mounted read-only". Until the chart renders
the setting, `replicas > 1` on an RWX volume whose flock is enforced runs one replica, and
the others crash-loop on the key lock.

## Verification

- Native, kpg PostgreSQL: the `server/key_dir_lock_postgres_test.go` tests, the
  `internal/serverguard/keyinit_postgres_test.go` tests, and
  `server/admin/backup_key_dir_lock_postgres_test.go` (pg-gated), plus
  `TestAcquireDatabaseLock_ForceRefusedWithDatabaseKeyDirLock` and `TestValidate_KeyDirLock`
  (default CI). Red runs are recorded in the PR.
- **Pending e2e VM:** `scripts/k8s-e2e/multi-replica.sh`, two replicas on an RWX volume in kind,
  with the server `server.replicas=2` + `key_dir_lock: database`.
