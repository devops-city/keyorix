# Design: offline audit-chain verification (ADR-108 §B4)

**Status:** Draft for review
**Scope:** `keyorix-server admin verify-audit` — verify the tamper-evident audit
hash chain (ADR-029) directly from a database artifact, without trusting or
needing a running server. Plugs into the `server/admin` framework landed in
PR 11 (`internal/serverguard.AcquireExclusive`).

## 1. Why this exists, and what it is not

`GET /api/v1/audit/verify` (`internal/core/audit_retention.go:167`) asks the
live server to check its own chain. For a regulated customer, "the vendor's
server says its log is fine" is not evidence — an auditor needs a check they
can run themselves, against an artifact they hold, that does not depend on the
server process being honest or even running. Per
`docs/cli-split-inventory.md` §6 GAP-2 / §7, this capability does not exist
in any form today. It is new work, not a reclassification of `audit verify`.

## 2. Trust model — what this proves, against whom

The chain (ADR-029) is `entry_hash = SHA256(canonical(fields) ‖ prev_hash)`.
Re-walking it detects any **modification, deletion, insertion, or reordering
of a row that is still present** in the table. That property holds for an
offline verifier exactly as it holds for the online one — it needs nothing
but the rows themselves.

Two things a bare re-walk cannot catch, spelled out in ADR-029's own
"Consequences" section: **tail-truncation** (delete the newest N rows) and
**genesis re-seed** (wipe the table, start a new self-consistent chain from
scratch). A shorter chain still verifies perfectly. Closing this needs an
anchor **external to the artifact being checked**:

- the in-DB signed checkpoint (`audit_checkpoints`, HMAC-SHA256 keyed by a
  KEK-derived secret the server holds in memory — `audit_checkpoint.go:33`),
  or
- an RFC 3161 timestamp token anchoring that checkpoint to a third-party TSA
  (`internal/notary`), or
- a copy of a prior verification result / export held somewhere the actor
  being audited does not control.

**The adversary this actually constrains: a database-only actor** — someone
with read/write access to the DB file or a Postgres connection, but not the
KEK/signing key and not control of the external TSA. Against that adversary,
an offline verifier with the DB artifact alone proves the linkage property
above, and — if given the checkpoint signing key or an externally-held
RFC 3161 anchor — also proves no truncation happened since the last
checkpoint/anchor.

**What it explicitly does not prove, stated because ADR-029 and this repo's
own conventions require a mechanism to say what it silently skips**: if the
checkpoint HMAC key lives on the same host as the database (the common case —
`storage.encryption.enabled`'s KEK, whether passphrase-derived or from a local
file), then **a host admin with both the DB and the key is unconstrained**.
They can rebuild an entirely self-consistent, validly-checkpointed chain
reflecting any history they choose, because they hold every secret this
verifier would check against. Running this tool against artifacts taken from
that same host, by that same admin, proves nothing about what that admin did.
The property this design closes is "a DBA with data access alone cannot
tamper undetectably" (already what ADR-029 delivers online) plus "an auditor
does not have to trust the running server process to check it" (new). It is
**not** "a host admin can never fabricate history" — only an anchor genuinely
held outside the host's blast radius (a third-party TSA, or the auditor's own
periodic pull of a signed export) constrains that stronger adversary, and
even then only from the moment the anchor was taken.

This must be stated in the tool's own `--help` and in its report output, not
just in this doc — a compliance tool that overstates what it proves is worse
than one that says nothing (`CLAUDE.md`: "a check that always fails is as
useless as one that always passes… worse, because it teaches people to
[trust it]").

## 3. Inputs

| Flag | Purpose |
|---|---|
| `--db <path>` | SQLite file, opened **read-only** (`file:<path>?mode=ro`, immutable if the file isn't being written concurrently) |
| `--pg-dsn <dsn>` | Postgres DSN, alternative to `--db`. Document a suggested read-only role (`GRANT SELECT ON audit_events, audit_checkpoints, system_metadata`) |
| `--checkpoint-key-file <path>` | Optional. The KEK-derived checkpoint signing key, if the operator chooses to make it available to this run. Without it, checkpoint/high-water/retention-anchor rows are read and reported, but their **signatures are not checked** — the report must say so explicitly (see §6), never silently treat an unauthenticated row as valid. |
| `--anchor <path>` | Optional. A JSON bundle (checkpoint fields + RFC 3161 token) held externally by the operator/auditor — e.g. from a prior `verify-audit --emit-checkpoint` run archived off-box, or from `keyorix audit export`. Used to cross-check the DB's own checkpoint rows against a copy the host cannot have altered after the fact. |
| `--tsa-roots <path>` | PEM bundle of trusted TSA root certs, to independently verify an RFC 3161 anchor token. **This is the one check that needs no shared secret at all** — RFC 3161 is a public-key proof-of-existence, so an auditor with only the TSA's public root and the anchor token (no key file, no `--checkpoint-key-file`) can independently confirm a checkpoint existed at a given time, even with zero trust in this host. This is the strongest leg of the trust model and should be the one compliance documentation leads with. |
| `--from-id` / `--json` / `--out` | Range bounding (see §4) and machine-readable output. |

**What an auditor can do with only a DB copy and public material** (no key
file, no `--anchor`): the linkage re-walk (detects tamper on present rows),
plus RFC 3161 anchor verification if a token and TSA roots are available.
What they cannot do without the key or an externally-held anchor: detect
truncation/re-seed, or authenticate a post-purge retention re-anchor (§5).

## 4. Independence — what this may share with the server

A verifier that reuses the server's own storage layer (GORM models, the
`storage.Storage` interface, `core.KeyorixCore`) proves less: a bug or
backdoor in the code that *wrote* the chain is invisible to a check that
walks it through the *same* code. Recommend a new, minimal, separately
reviewed package — `internal/auditverify` — with:

- **Its own DB access**, `database/sql` against `modernc.org/sqlite` /
  `lib/pq`/`pgx` directly. Plain `SELECT id, event_type, …, prev_hash,
  entry_hash FROM audit_events WHERE id > ? ORDER BY id ASC LIMIT ?` —
  no GORM, no `storage.Storage`. This also means it degrades gracefully
  against a hostile or corrupted SQLite file (a fuzz target target, §8),
  which the server's own GORM path has never needed to handle.
- **Its own copy of `computeAuditEntryHash`**, not an import of
  `internal/storage/store`'s. Deliberate duplication, guarded by a
  differential test that runs both implementations over the same fixture
  rows and asserts byte-identical output — so drift is caught immediately
  rather than silently accepted as "the independent one." Same treatment for
  `ComputeAuditEntryHashPre1452` (the frozen legacy encoder — un-migrated
  installs are the common case, not a corner case; see `local_audit_chain.go:576`).
- **Reuse `internal/notary.VerifyReceipt`** as-is. It is already a small,
  self-contained, independently fuzzed leaf package with no dependency on
  core or storage — sharing it is "generate/derive," not "trust the same
  code twice," and re-implementing RFC 3161 ASN.1 parsing would be pure risk
  for no independence gain.
- The HMAC checkpoint/high-water/retention-anchor verification logic
  (`checkpointCanonical`, `auditHighWaterValue`, `auditRetentionAnchorCanonical`
  — all pure functions over public byte layouts) is small enough to
  reimplement in the new package rather than import `internal/core`, for the
  same reason as the hash function.
- `server/admin/audit_verify.go` becomes a thin cobra command that opens the
  configured DB (or takes `--db`/`--pg-dsn` directly, so it also runs against
  a **detached artifact** the running server never touches — this is what
  "does not need the running server" means concretely: no `serverguard`
  acquisition is required when pointed at an offline copy, only when pointed
  at the live config-referenced database) and calls into `auditverify`.

This is the one place in this design that costs real engineering effort
without an immediate feature behind it (duplicated hash/HMAC code, a second
DB-access path) — justified here because "the verifier proves less if it
shares the server's code" is exactly the property regulated customers are
paying for; everywhere else in this codebase the default is the opposite
(derive, don't duplicate).

## 5. Retention gaps

> **Purged count (#3257).** Since #3257 the anchor (layout `v2`,
> `retanchor-v2` canonical bytes) also carries the cumulative number of
> chained events removed by sanctioned purges, covered by its HMAC.
> Checkpoints certify chained + purged, and the checkpoint, high-water and
> external `--anchor` comparisons use `chained_events + purged_events`. Only an
> anchor that authenticates under the supplied key contributes a count
> (`purged_events` in the report); without the key, or with a TSA-only
> `--anchor`, no purge credit is given and a purge after the anchor was taken
> still reads BROKEN for that bundle (fail closed). A `v1` anchor is read as 0.

A retention purge (`PurgeAuditLogs`) that reaches into the chained region
persists a signed re-anchor (`audit_retention_anchor.go`) recording the new
earliest surviving row. The online walk trusts it once its HMAC verifies
under the current key. The offline verifier has the same two paths:

1. **Key available** (`--checkpoint-key-file` or a verifying `--anchor`):
   authenticate the anchor exactly as the server does, seed the walk from
   there, report the gap as **sanctioned** (with the purge cutoff and
   deleted-row count if available from the accompanying `system.audit_purge`
   event).
2. **Key unavailable**: the current online code, if simply reused unmodified,
   would report this as a **broken chain** ("prev_hash does not link") —
   which is the wrong finding. It is not tamper evidence, it is an
   unverifiable-but-plausible retention gap. Mirroring the existing
   pre-#1452-encoding distinction (`local_audit_chain.go:576`, "this is an
   un-migrated upgrade, NOT evidence of tampering"), the offline verifier
   must detect the shape (`earliest chained row's prev_hash != genesis`) and
   report a **distinct verdict** — `INDETERMINATE: retention gap present,
   unauthenticated` — never conflate it with `BROKEN`. Reporting a legitimate
   purge as "tampered" is exactly the false-alarm failure mode ADR-029's own
   pre-#1452 fix exists to avoid, and a compliance tool that cries wolf on
   every purged deployment will get its verdicts ignored.

No signing key configured at all (`storage.encryption.enabled: false`) means
no anchor was ever written; a purge on such a deployment permanently
un-anchors everything before it. The verifier reports this state plainly —
"no checkpoint signing was ever configured; chain verifiable only from the
last purge forward" — rather than a bare BROKEN at row 1.

## 6. Output

**Human report** (default): pass/fail banner, range verified (id + time
bounds), chained/unchained/gap-affected row counts, checkpoint status
(checked / key unavailable / valid / invalid, with key version), anchor
status (RFC 3161 token present/verified/against which root), and — on
failure — the first broken row id and reason, in the same three-way framing
the online code already uses (tampered / un-migrated encoding / unverifiable
retention gap).

**`--json`** — a single structured document, stable enough to be pasted into
a compliance evidence pack:

```json
{
  "verdict": "VALID | BROKEN | INDETERMINATE",
  "reason": "",
  "range": {"from_id": 1, "to_id": 48213, "from_time": "...", "to_time": "..."},
  "chained_events": 48213,
  "unchained_legacy_events": 0,
  "first_broken_id": null,
  "checkpoint": {"present": true, "authenticated": true, "key_version": "v2", "chained_events_certified": 48200},
  "retention_gap": {"present": false},
  "anchor": {"present": true, "verified": true, "provider": "rfc3161:...", "anchored_at": "..."},
  "generated_at": "...",
  "verifier_version": "..."
}
```

**Exit codes**: `0` VALID, `1` BROKEN (tamper detected), `2` INDETERMINATE
(could not fully verify — missing key/anchor for a real gap; distinct from
both, so a CI/compliance script doesn't have to string-match to avoid
treating "we couldn't check the last bit" as "everything's fine").
`3` usage/input error (bad DSN, unreadable file). Never exit `0` when a gap
was silently ignored — that is the single most important behavior of this
whole command, and it should have its own test asserting it (see §8).

## 7. Relation to the online `audit verify` and compliance evidence

Keep both. `GET /api/v1/audit/verify` stays the fast, always-available health
check surfaced in the UI; this is the independent, out-of-band check for
auditors. **Share the JSON shape** (§6 already mirrors
`storage.AuditChainVerification`'s fields) so a compliance pack or dashboard
can render either source with one renderer, and so a future
`compliance verify` fix (the AUD-009 filename-binding gap tracked as GAP-2 —
`export` never signs/names its pack, `verify`'s request has no `filename`
field — cli-split-inventory.md §6/§8 Finding S16) can reuse the same report
struct rather than inventing a third shape. Fixing that export/verify
round-trip bug is explicitly **out of scope** here; it's an independent,
already-filed gap.

## 8. Performance

Measured via a throwaway spike (raw `modernc.org/sqlite`, keyset-paginated
`SELECT` in 1000-row batches + per-row SHA256 recompute — the same shape
`VerifyAuditChain` already uses, `auditChainVerifyBatch = 1000`): **~900k
rows/sec** re-walking a freshly-seeded 2M-row / 410 MB local SQLite table on
this dev machine. That is comfortably CPU-light (SHA-256 over a few hundred
bytes is microseconds); the real-world bottleneck will be **disk I/O for a
cold multi-GB file** or, for `--pg-dsn`, **network round-trips per batch**
(mitigated by the same 1000-row batching, not per-row queries). Treat the
measured number as an upper bound for local SQLite, not a Postgres or
cold-cache estimate — a follow-up spike against a real Postgres connection
over a WAN-like link before this ships would firm up the DSN-mode number.
Streaming via keyset pagination (never `OFFSET`, never a full-table load) is
already the existing pattern to keep; a multi-GB audit table must never be
read into memory at once.

## 9. Test and fuzz plan

- Golden-path: freshly seeded chain of N rows, `VALID`, count matches.
- Tampered row (field mutated after write): `BROKEN`, correct `first_broken_id`.
- Reordered rows (swap two ids' content): `BROKEN` (linkage break).
- Deleted middle row: `BROKEN`.
- Truncated tail, **no key/anchor supplied**: `VALID` (this is the exact gap
  ADR-029 documents — the online code has the same limit; the offline tool
  must not overclaim what a bare re-walk can catch). This test exists
  precisely to keep that limitation honest and visible, not to pass.
- Truncated tail, **checkpoint key supplied**: `BROKEN` via checkpoint
  enforcement (`checkpointTruncation`'s len/head-hash comparison).
- Forged checkpoint (flipped signature byte): `BROKEN`, "fails its signature."
- Retention gap, key available: `VALID`, gap reported as sanctioned.
- Retention gap, key unavailable: `INDETERMINATE`, **not** `BROKEN` — the
  test this design most wants to exist, given §5's whole point.
- Differential test: `auditverify`'s hash/HMAC functions vs.
  `internal/storage/store`'s, over shared fixtures — catches silent drift
  between the two intentionally-duplicated implementations.
- **Fuzz target** over the row decoder: feed `FuzzAuditChainRowDecode`
  arbitrary bytes shaped like a SQLite page / row tuple and assert no panic,
  mirroring this repo's existing `backend_differential_fuzz_test.go`
  pattern — this is the one genuinely new attack surface (a corrupted or
  adversarially crafted DB file handed to a tool that must not crash or,
  worse, silently report `VALID` on malformed input).

## 10. Open questions for Andrei

1. **Should `--checkpoint-key-file` accept the raw KEK-derived key, or should
   the tool derive it itself from the same passphrase/KMS config the server
   uses?** Recommend: accept the *derived* checkpoint key directly (a
   32-byte hex/base64 blob the operator extracts once, out of band), not the
   KEK or passphrase — narrows what this tool needs to touch and keeps it
   from replicating the server's KEK-unwrap logic (another independence win,
   same reasoning as §4).
2. **Does `verify-audit` acquire `serverguard`'s shared/exclusive lock?**
   Recommend: only when it opens the config-referenced live database path
   (same DB a running server might attach to); when pointed at an explicit
   `--db`/`--pg-dsn` copy, it never touches the live path and the guard is
   irrelevant. State this distinction in `--help`.
3. **Should `--emit-checkpoint` (write a fresh signed checkpoint from this
   offline run, for later archiving) be in scope for the first version?**
   Recommend: no — writing requires the DB to be writable and the *current*
   key, which cuts against "does not need the running server" for the read
   path; ship read-only verification first, consider a separate
   `admin checkpoint` command later if operators want offline archival.
4. **Minimum Postgres access this needs**: a read-only role is sufficient
   for verification proper; should the design also *document* the exact
   `GRANT` statements as a first-class deliverable (auditors will ask)?
   Recommend: yes, ship a `docs/` snippet alongside the command's `--help`.

5. **Should the offline anchor source (a checkpoint export read from a file on
   write-once media) be a CLI-only flag, or also config-driven?** Decided
   (2026-09-25): **both**, with `--anchor` taking precedence when set. Added
   `audit.offline_anchor_path` (`internal/config`, documented in
   `docs/CONFIGURATION.md`) as the default `verify-audit --anchor` source when
   the flag is not passed — lets an operator on an air-gapped host configure the
   anchor's location once (in the same config file already governing storage)
   instead of remembering the flag on every verification run. Resolution order
   lives in `resolveOfflineAnchorPath` (`server/admin/audit_verify.go`):
   explicit `--anchor` always wins; otherwise the config value, if any; neither
   set means no anchor, same pre-existing behavior (an already-reported
   limitation via `Result.NotProven`, never a failure). Config loading for this
   purpose is deliberately best-effort: `--db`/`--pg-dsn` mode (Q2) works with
   no config file present at all, so a missing/unparseable config must not
   block verification when the operator never relied on it — it only costs the
   config-derived default in that case. Once a path IS resolved (from either
   source), reading it is NOT best-effort: a missing or unreadable file at
   that path is a hard, exit-3 error (`buildVerifyAuditOptions` wraps
   `os.ReadFile`'s error), never a silent "no anchor" — a configured-but-broken
   anchor must never be indistinguishable from "nothing configured" (§2's
   fail-closed framing applies to resolution, not just to signature checking).

   **No new Go interface.** `ExternalAnchorBundle` + `Options.ExternalAnchor`
   (§4, `internal/auditverify/anchor_bundle.go`) already fully generalizes "an
   anchor bundle from somewhere external" — the offline-file case just supplies
   one by reading a path, the same shape `--anchor` already consumed before
   this change. Introducing a formal `AnchorSource` interface for a single
   concrete implementation would be exactly the premature abstraction
   `CLAUDE.md`'s engineering practices section warns against ("does this fact
   exist in more than one place, or will someone rely on the claim?" — today,
   no). If a second offline-anchor *source* shape ever materializes (e.g.
   pulling the export from a fixed removable-media mount point that changes
   across reboots, rather than a static path), that is the point to introduce
   one, not before.

   **Convergence with the DECOUPLE program's `TimestampNotary` port**
   (`internal/core/ports.TimestampNotary`, ADR-109): that port is orthogonal to
   this one, not a duplicate. `TimestampNotary` abstracts *creating* a new RFC
   3161 anchor at checkpoint-write time (server-side, online, `internal/notary`
   as today's only implementation); this offline anchor source is about
   *consuming* an already-signed checkpoint export at verify time (CLI-side,
   deliberately independent of any running server or live network — see §4's
   independence rationale). Neither needs the other. If a future step wants a
   single abstraction spanning both anchor lifecycles (create-time and
   verify-time), the natural seam is `resolveOfflineAnchorPath`'s return value
   (a resolved bundle) versus `TimestampNotary.Anchor`'s return value (a fresh
   receipt) — but that unification is speculative and explicitly out of scope
   here; this change does not touch `internal/core/ports` or any
   `TimestampNotary` wiring.

   **Test coverage**: the bundle-level authentication logic (tampered
   signature, wrong verifier key, truncation-after-export, genesis re-seed)
   is covered by `internal/auditverify`'s own differential tests
   (`TestDifferential_ExternalAnchor_*`, `anchor_bundle_test.go`) against the
   exact `crossCheckExternalAnchor` this command calls into — unchanged by
   this step, so not re-tested at the CLI layer to avoid duplication. New for
   this step, in `server/admin/audit_offline_anchor_test.go`: the config
   resolution itself — a full `export-checkpoint` → config-anchored
   `verify-audit` round trip (`ConfigDefault_RoundTrip`), a configured-but-
   missing file surfacing a clear exit-3 error rather than silently verifying
   without an anchor (`MissingConfiguredFile_ClearError`), and `--anchor`'s
   precedence over a simultaneously-configured (and deliberately unwritten)
   config path (`ExplicitFlagOverridesConfig`).

   **Addendum (review of #2084, 2026-09-25): "no config file" and "config file
   present but unloadable" are different states and must not collapse into
   the same silent outcome.** The first cut of `buildVerifyAuditOptions` took
   a bare `*config.Config`, already `nil` in both cases — so an operator who
   genuinely set `audit.offline_anchor_path`, but whose config later developed
   a typo, bad permissions, or any other load failure, got a **silent**
   downgrade to a bare re-walk with no anchor and no indication why. Fixed via
   `configLoadState` (`server/admin/audit_verify.go`): an independent
   `os.Stat` on the resolved config path (mirroring `runAdminAudit`'s own
   resolution) tags the `loadConfig()` result as `fileMissing` or not.
   `resolveOfflineAnchor` then only tolerates a load failure when the file
   was genuinely absent (§10 Q2's case); a present-but-broken config with no
   `--anchor` passed is now a hard exit-3 error naming the load failure,
   never a silent "none." An explicit `--anchor` still resolves regardless,
   since it never depended on config. `Result` also gained `AnchorSource`
   (`"flag"` / `"config (audit.offline_anchor_path)"` / `"none"`), reported in
   both the human report and `--json`, so a run discloses which source
   actually served its anchor rather than leaving that implicit. Tests:
   `TestVerifyAudit_OfflineAnchor_ConfigPresentButUnloadable_NoAnchorFlag_FailsClosed`,
   its `_ExplicitAnchorFlag_StillVerifies` counterpart (proving the fix
   doesn't overcorrect), and `TestVerifyAudit_AnchorSourceReported`'s three
   subtests (flag/config/none).

## Effort estimate

- `internal/auditverify` package (DB access, duplicated hash/HMAC + parity
  tests, retention-gap classification): **3–4 days**.
- `server/admin/audit_verify.go` cobra command + `--db`/`--pg-dsn`/
  `--checkpoint-key-file`/`--anchor`/`--tsa-roots`/`--json` wiring: **1 day**.
- Fuzz target + corrupted-file handling hardening: **1–2 days**.
- Test plan (§9), including the retention-gap and truncation-without-key
  cases that are the whole point of this design: **2 days**.
- Docs (operator guide, `GRANT` snippet, compliance-evidence framing): **1 day**.

**Total: ~8–10 engineer-days**, plus review time given the security-sensitive
nature of a tool whose entire purpose is being trusted by an auditor.
