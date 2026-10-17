# Disaster drills

`scripts/drills/disaster.sh` rehearses three failures on throwaway instances with real
binaries (shared helpers and environment: [upgrade drill](drill-upgrade.md)). The rule it
checks: the server either recovers or fails closed with a clear message, and nothing it
acknowledged is lost.

```sh
scripts/drills/disaster.sh                                   # SQLite: kill9 + diskfull
DRILL_BACKEND=postgres DRILL_PG_DSN_FILE=a.txt DRILL_PG_DSN_FILE2=b.txt \
  scripts/drills/disaster.sh                                 # PostgreSQL: kill9 + pgdown
DRILL_SCENARIOS=kill9 scripts/drills/disaster.sh             # pick scenarios
```
(Each PostgreSQL scenario needs its own EMPTY database; the URL files hold
`postgres://user:password@host:port/db`.)

## kill9: SIGKILL under write load

Four writers create secrets in a loop; the server is killed with `kill -9`; three rounds.
After every kill: the restart needs no `--force` (no stale lock to clear), every write the
server acknowledged is present, a write that was in flight is either whole or absent, the
seeded data still decrypts, MFA login and machine tokens work, and `admin verify-audit` is
VALID. What to expect in production: just start the server again. An acknowledged write is
committed; the client that saw a connection error should retry (a retried create can then
report a name clash if the first attempt did land).

SQLite note: after a stop, committed data may still sit in `keyorix.db-wal`, and the main
file can look tiny. Never copy `keyorix.db` alone as a backup or for `verify-audit --db`:
copy the `-wal` and `-shm` files with it, or use `admin backup`.

## pgdown: PostgreSQL goes away and comes back

The drill cannot restart a shared database, so it puts a TCP forwarder
(`scripts/drills/tools/tcpproxy.go`) between the server and PostgreSQL and takes it down
(open connections reset, new ones refused) and up again, which is what a PostgreSQL restart
looks like from the server. During the outage: reads and writes are refused (a valid machine
token gets a retryable `503` with `Retry-After`, never `401`), nothing hangs, the server
does not crash. After it: the same server process serves again within seconds with no
restart, the write refused during the outage left nothing behind, nothing acknowledged is
lost, the audit chain verifies. (The `401` that older builds returned during an outage, and
cached afterwards, was a bug this drill found: fixed by the credential-lookup change in the
same release. Alert on a rise in `503`, not on `401`.)

## diskfull: the data directory fills up

A full filesystem cannot be made without a privileged mount, so the server runs under
`ulimit -f` just above the SQLite file size: growing a file past it fails like `ENOSPC` on
the write. Expect: writes are refused with an error (log: `Storage operation failed: disk
I/O error`), the server stays up and keeps serving what it can, and a secret read whose
audit row cannot be written is refused (`SECURITY: audit write failed for secret read ...
failing closed, value NOT returned`): the drill checks that every value handed out has its
audit row. Free space (or raise the limit) and restart: all accepted writes are there, new
writes work, `verify-audit` is VALID. Check disk space and `df` alerts before it gets here:
once audit writes fail, reads fail too.

## Not covered (pending a run on the e2e VM)

A real `docker restart postgres`, a really full filesystem or volume, PostgreSQL's own disk
full, and the Compose / Helm / Kubernetes variants of these failures.
