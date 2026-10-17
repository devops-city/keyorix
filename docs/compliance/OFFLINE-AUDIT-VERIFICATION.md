# Offline Audit-Chain Verification (`keyorix-server admin verify-audit`)

> See [`README.md`](./README.md) for the positioning disclaimer. This page
> documents a shipped CLI capability, not a certification.

`GET /api/v1/audit/verify` (documented in
[`AUDIT-LOG-PROVISIONS.md`](./AUDIT-LOG-PROVISIONS.md#dora-oriented-audit-log-checklist),
checklist item 11) asks the **running server** to check its own audit hash
chain. For many buyer security reviews and audits, "the vendor's server says
its own log is fine" is not independent evidence — an auditor needs a check
they can run **themselves**, against a database artifact **they** hold, that
does not depend on the Keyorix server process being honest or even running.

`keyorix-server admin verify-audit` is that check. It re-derives the ADR-029
tamper-evidence hash chain directly from a SQLite file or a PostgreSQL
connection, using its own independent implementation
(`internal/auditverify` — deliberately not the same code that wrote the
chain; see that package's own design note in
[`../design-b4-offline-audit-verify.md`](../design-b4-offline-audit-verify.md)
§4).

## Quick start

```sh
# Against a detached copy of a SQLite deployment (never touches a running server).
# Copy keyorix.db together with its -wal and -shm files (committed rows can still be in
# the -wal after a stop; the main file alone may be nearly empty), or use an `admin backup`:

keyorix-server admin verify-audit --db /path/to/keyorix.db

# Against a Postgres deployment directly:
keyorix-server admin verify-audit --pg-dsn "host=... user=... dbname=... sslmode=require"

# Against THIS host's own configured, live database (see "Locking" below):
keyorix-server admin verify-audit --config /etc/keyorix/keyorix.yaml

# With the checkpoint signing key, to additionally catch tail-truncation
# and genesis re-seed (see "What each input adds" below):
keyorix-server admin verify-audit --db keyorix.db --checkpoint-key-file ./checkpoint.key

# Closing the "host admin holds everything" gap: an externally-held anchor
# and/or a third-party TSA root bundle constrain even an admin who holds
# the checkpoint key (see the trust-model table below):
keyorix-server admin verify-audit --db keyorix.db \
  --anchor /secure/path/checkpoint-2026-09-01.json \
  --tsa-roots /etc/ssl/tsa-roots.pem

# Machine-readable output, for a compliance evidence pack or a CI gate:
keyorix-server admin verify-audit --db keyorix.db --json
```

Run `keyorix-server admin verify-audit --help` for the full flag reference —
the command's own `--help` text restates the "what this does and does not
prove" section below, so it travels with the binary, not just this page.

## What each input adds

| Input | What it additionally proves | What it still does not prove |
|---|---|---|
| *(none — bare re-walk)* | Any modification, deletion, insertion, or reordering of a row **still present** in the table. | Tail-truncation or a genesis re-seed (a shorter, self-consistent chain still verifies — this is documented in ADR-029 itself, not a gap specific to this tool). |
| `--checkpoint-key-file` | The above, plus tail-truncation / genesis re-seed, by authenticating the in-database signed checkpoint and anti-rollback high-water mark. | A host admin who holds **both** this database **and** the checkpoint signing key can fabricate a fully self-consistent, validly-checkpointed alternate history. |
| `--anchor` | Truncation or re-seed **even if** the local checkpoint/high-water rows were themselves deleted or forged — because the anchor's ground truth was captured **outside this host**, beforehand. | Anything before the anchor was captured. |
| `--tsa-roots` | Independently re-verifies an RFC 3161 timestamp token (on the in-DB checkpoint or on an `--anchor` bundle) against a third-party time-stamping authority — the **one check that needs no shared secret at all** (no key file, no trust in this host). | The chain's content itself — pair with a bare re-walk or `--checkpoint-key-file`, it does not replace them. |

**The bottom line stated by every report, human or JSON:** this proves a
**DB-only actor** (someone with read/write access to the database file or
connection, but not the checkpoint signing key and not control of an
external TSA) cannot tamper undetectably. It does **not** prove a host admin
with full access can never fabricate history — only an anchor genuinely held
outside that host's blast radius constrains that stronger adversary, and
only from the moment the anchor was taken.

## Locking

- `--db` / `--pg-dsn` point at an **explicit artifact** — a detached copy, or
  a Postgres connection the operator supplies directly. This never touches
  the path a running server might be attached to, so it takes **no lock**.
- With neither flag, `verify-audit` reads the **configured, live** database
  and acquires the same exclusive lock every other `keyorix-server admin`
  command does (`internal/serverguard`) for its entire run, refusing (unless
  `--force`) if a server or another admin command already holds it.

## PostgreSQL: minimum read-only role

A read-only role is sufficient for verification — `verify-audit` issues only
`SELECT` statements. Auditors will ask for the exact grant; this is it:

```sql
CREATE ROLE keyorix_audit_verify WITH LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE keyorix TO keyorix_audit_verify;
GRANT USAGE ON SCHEMA public TO keyorix_audit_verify;
GRANT SELECT ON audit_events, audit_checkpoints, system_metadata TO keyorix_audit_verify;
```

Adjust the schema name if your deployment does not use `public`. No other
tables are read; no writes are ever issued.

## Exit codes

| Code | Verdict | Meaning |
|---|---|---|
| `0` | `VALID` | The chain re-walked cleanly and every check this run could perform (given its inputs) passed. |
| `1` | `BROKEN` | Tamper evidence found — a modified row, a broken linkage, a certified checkpoint/high-water regression, or an anchor that fails to authenticate. |
| `2` | `INDETERMINATE` | The chain re-walks consistently from a given point forward, but this run could not authenticate something it needed to rule out tampering — most notably an unauthenticated retention gap (a real, sanctioned purge left behind a gap, but no key was supplied to confirm it). Never conflated with `BROKEN` (that would false-alarm on every purged deployment) or with `VALID` (that would silently trust an unauthenticated gap). |
| `3` | — | Usage or input error: an unreadable `--db`/`--anchor` file, a malformed `--pg-dsn`, a checkpoint key that is neither valid hex nor base64, or the database's lock being held by another process. |

A CI gate or cron job can treat exit code `0` as the only "safe to ignore"
result; `1` and `2` both need a human to look, for different reasons.

## Sample JSON output

```json
{
  "verdict": "VALID",
  "range": {"from_id": 1, "to_id": 48213, "from_time": "2025-01-01T00:00:00Z", "to_time": "2026-09-24T06:00:00Z"},
  "chained_events": 48213,
  "unchained_legacy_events": 0,
  "checkpoint": {"present": true, "authenticated": true, "key_version": "v1", "chained_events_certified": 48213},
  "retention_gap": {"present": false, "authenticated": false, "sanctioned": false},
  "anchor": {"present": false, "verified": false},
  "external_anchor": {"supplied": false, "authenticated": false},
  "not_proven": [
    "a host admin holding both this database and its checkpoint signing key can fabricate a fully self-consistent, validly-checkpointed history; this verification proves only that a DB-only actor (without that key) could not have tampered undetectably"
  ],
  "generated_at": "2026-09-24T07:00:00Z",
  "verifier_version": "auditverify/v1"
}
```

The `not_proven` array is always present, even on a clean `VALID` run — a
compliance tool that only states its limits in `--help` and drops them from
the machine-readable report overstates what it proves. Paste the whole
object into an evidence pack; do not summarize it down to just `"verdict"`.

## Relation to `GET /api/v1/audit/verify`

Keep using the online endpoint (surfaced in the UI, and via `keyorix audit
verify` — see [`AUDIT-LOG-PROVISIONS.md`](./AUDIT-LOG-PROVISIONS.md)) as the
fast, always-available health check. Use `verify-audit` as the independent,
out-of-band check for an auditor who should not have to trust the running
server process. Both share the same underlying result shape, so a
compliance pack or dashboard can render either source with one renderer.

Full design and trust-model rationale:
[`../design-b4-offline-audit-verify.md`](../design-b4-offline-audit-verify.md).
