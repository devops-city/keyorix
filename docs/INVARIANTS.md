# Package invariants index

Every core package has an `INVARIANTS.md` next to its code: the rules a change there must
keep, each linked to the automated check that enforces it, or marked `UNGUARDED` with a
follow-up issue (label `unguarded-invariant`). **Read the relevant file(s) before changing
code in any of these packages.** See the root `CLAUDE.md`'s "Spec first, independent tests,
package invariants" convention for when this is required.

These are not invented — every entry traces to an ADR, an existing test/fuzzer/static guard,
`docs/security-closures.d/`, `docs/adr-conformance-enforced.tsv`, or a documented review
finding. If you discover or add an invariant while working in a package, add it to that
package's file in the same PR; if a change would have to break one, stop and ask rather than
silently removing it.

| Package | File | Invariants | Guarded | UNGUARDED |
|---|---|---|---|---|
| `internal/core` | [internal/core/INVARIANTS.md](../internal/core/INVARIANTS.md) | 40 | 35 | 5 |
| `internal/storage` | [internal/storage/INVARIANTS.md](../internal/storage/INVARIANTS.md) | 35 | 29 | 6 |
| `internal/storage/store` | [internal/storage/store/INVARIANTS.md](../internal/storage/store/INVARIANTS.md) | 20 | 16 | 4 |
| `internal/storage` | [internal/storage/INVARIANTS.md](../internal/storage/INVARIANTS.md) | 35 | 28 | 7 |
| `internal/storage/store` | [internal/storage/store/INVARIANTS.md](../internal/storage/store/INVARIANTS.md) | 21 | 17 | 4 |
| `internal/encryption` | [internal/encryption/INVARIANTS.md](../internal/encryption/INVARIANTS.md) | 27 | 24 | 3 |
| `internal/encryption` | [internal/encryption/INVARIANTS.md](../internal/encryption/INVARIANTS.md) | 28 | 25 | 3 |
| `internal/auditverify` | [internal/auditverify/INVARIANTS.md](../internal/auditverify/INVARIANTS.md) | 15 | 12 | 3 |
| `server/middleware` | [server/middleware/INVARIANTS.md](../server/middleware/INVARIANTS.md) | 22 | 20 | 2 |
| `server/http` (+ `handlers`) | [server/http/INVARIANTS.md](../server/http/INVARIANTS.md) | 19 | 19 | 0 |
| `server/grpc` (+ `interceptors`) | [server/grpc/INVARIANTS.md](../server/grpc/INVARIANTS.md) | 13 | 9 | 4 |
| `server/grpc/services` | [server/grpc/services/INVARIANTS.md](../server/grpc/services/INVARIANTS.md) | 8 | 8 | 0 |
| `cli` | [cli/INVARIANTS.md](../cli/INVARIANTS.md) | 13 | 10 | 3 |
| `web/src` | [web/src/INVARIANTS.md](../web/src/INVARIANTS.md) | 7 | 2 | 5 |
| `internal/solewriter` | [internal/solewriter/INVARIANTS.md](../internal/solewriter/INVARIANTS.md) | 8 | 8 | 0 |
| **Total** | | **219** | **184** | **35** |
| **Total** | | **220** | **184** | **36** |

## Highest-priority UNGUARDED gaps

A few UNGUARDED items are flagged as materially more important than the rest — worth reading
even if you skip everything else:

- **`cli/cmd/run.go`'s reserved-environment-variable filter has zero test coverage**
  (`cli/INVARIANTS.md` INV-CLI-11) — this is the fix for the exact bug class (#1816, a secret
  named `LD_PRELOAD` getting code-exec) the CLI-server split (ADR-108) was rebuilt to prevent.
- **ADR-103's Postgres RLS tenancy layer is a ratified design with zero implementation and
  zero tests** (`internal/storage/INVARIANTS.md` INV-STORAGE-31/32) — confirmed by direct grep,
  no `ROW LEVEL SECURITY`/`app.current_tenant` reference anywhere in `internal/storage`.
- **No structural completeness guard exists for "every best-effort post-commit call recovers a
  panic"** in `internal/core` (INV-CORE-34) or for "every key-shaped byte slice gets
  `wipeBytes`" in `internal/encryption` (INV-ENCRYPTION-25) — both are point-fixes after live
  fuzz findings, the same recurring shape, in two different packages.
- **`web/src/types` drift check covers only the schema'd wire types, and does not run on
  an `openapi.yaml`-only PR** (`web/src/INVARIANTS.md` INV-WEB-05) — guarded by
  `openapiDrift.test.ts`, but `web-ci.yml` is path-filtered to `web/**`.

## Ledger gaps (informational, not filed as issues)

`docs/adr-conformance-enforced.tsv` has zero rows for `server/middleware`, `server/grpc`,
`server/grpc/interceptors`, or `cli`, despite real, currently-passing tests enforcing several
properties documented in those packages' files. Seeding rows for these is a low-effort
follow-up distinct from the UNGUARDED gaps above (those have no test at all; these have a test
but no ledger entry).

## Maintaining this index

- Package-count and guarded/unguarded totals above are a snapshot as of this writing
  (2026-10-03). They will drift as invariants are added, closed, or re-guarded — re-derive by
  counting `- **INV-<PKG>-NN` bullets per file, and per bullet whether its own text contains
  `UNGUARDED`. **Do not `grep -c UNGUARDED` the whole file** — every file's own intro line
  ("Format: `INV-<PKG>-NN ... UNGUARDED (#issue)`") contains the literal word and will inflate
  a naive count by one per file (this is exactly what happened on the first draft of this
  table: a raw `grep -c` gave 50 UNGUARDED/169 guarded; the bullet-boundary-aware count caught
  that, then a second pass found INV-STORAGE-34 was already resolved by a guard discovered in
  a different package's research — `cli/internal/depguard` — moving it from UNGUARDED to
  guarded. Both corrections landed before any issue was filed against a wrong number; final:
  36 UNGUARDED / 183 guarded).
- When a package not yet covered here gets its first `INVARIANTS.md`, add a row.
