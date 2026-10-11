# ADR-108: Split Keyorix into a thin network CLI and a server with offline `admin` subcommands

**Status:** Implemented (conformance pass 2026-09-28 — see table below; two known gaps tracked, neither blocking). It builds on ADR-083 (remote storage is a client mode only) and ADR-107 (CLI over the human-facing API, Proposed). **Companion ADR:** server-side decoupling of `internal/core` from connectors and backends is a separate decision in `ADR-109 (`docs/adr-109-core-depends-on-interfaces.md`)`. It is not a prerequisite for this ADR, and this ADR is not a prerequisite for it. Both are sequenced in (Keyorix planning notes, claude/2026-09-23-refactor-program-plan-cli-server-split.md).

## Conformance (2026-09-28)

Each decision below is checked against the code and test that prove it today, not
re-derived from the plan. Method: `go list -deps` dependency-graph checks (not source
grep, so an indirect import can't hide), the tests actually run, and live PR/issue
history for anything claimed "decided" or "tracked."

| Decision | Code | Test | Status |
|---|---|---|---|
| A1. Thin CLI is its own Go module; cannot import core/storage/config/SDKs | `cli/go.mod` (no dependency on the main module); `cli/internal/depguard` | `TestNoServerOrCloudSDKDependencies` — walks the real `go list -deps` graph, not a source grep | **Implemented** |
| A2. REST-only transport, generated request/response types | `cli/internal/apiclient/{types,client}.gen.go`, generated from `server/http/handlers/openapi.yaml` (`cli/Makefile`'s `client` target); zero `google.golang.org/grpc` in the module's dependency graph | `cli/internal/depguard` (transitively — a gRPC import would need a route through one of the guarded prefixes or a direct add, neither present); `go list -deps` verified grpc-free | **Implemented** |
| A3. No local database mode | `internal/storage` is a forbidden import prefix in `depguard`; `go list -deps` shows no gorm/sqlite/pq driver in the module | Same `TestNoServerOrCloudSDKDependencies` | **Implemented** |
| B1. `admin` subcommands for a server that can't start (diagnose, repair, migrate) | `server/admin/diagnose.go` (diagnose), `server/admin/validate.go --fix` + `init.go --overwrite-existing` (repair — no single subcommand literally named "repair"; the capability is split across these two), `server/admin/migrate.go` (migrate, reuses the server's own boot-time migration code) | Package test suite (`server/admin/*_test.go`) | **Implemented** (repair realized as two flags/subcommands, not one — a documented mapping, not a gap) |
| B2. `recover-admin` for a fully-locked-out install | `server/admin/recover_admin.go`, `recover_admin_logic.go` | `recover_admin_test.go`, incl. `TestPerformRecoverAdmin_OTPActuallyLogsIn` — the proving test for a real found-and-fixed defect (`recover-admin-empty-hash-lockout-001`, `docs/security-closures.d/`): the empty-password-hash recovery path could never actually log back in | **Implemented, with 1 known gap** (see below) |
| Decision 2. recover-admin requires a recovery key by default; keyless mode is explicit opt-in; every use is audited and notifies admins | `internal/recoverykey`, `server/admin/recovery_key.go` (`admin recovery-key rotate`), `security.recover_admin.keyless_mode` config field, `server/main.go`'s startup WARNING + `admin.keyless_mode_enabled_at_startup` audit event on every boot with keyless mode on | `TestAdminRecoveryKey_GenerateThenRotate_SQLite`/`_Postgres`, `TestAdminRecoveryKey_ConcurrentRotateRefusesWhileLockHeld` | **Implemented, with 1 known gap**: `docs/design-b2-recover-admin.md`'s own §"Shown once, at install" specifies the key is "generated during first-run bootstrap, same moment `GenerateBootstrapToken` already exists" — the shipped implementation instead requires an explicit, separate `admin recovery-key rotate` run (its own doc even calls out "an install that predates this feature" as a normal case, not an edge case). Until this PR, that manual step also wasn't documented anywhere in `docs/SELF_HOSTING.md` — a real install could go into production with `recover-admin` permanently non-functional (no key ever generated) with no signal. Fixed the documentation gap in this PR (SELF_HOSTING.md §2 now calls out the step explicitly). **NEEDS ANDREI**: whether to also change server bootstrap to auto-generate the key (matching the original design) — recommend keeping it a manual, now-documented step, since auto-printing a security-critical one-time secret during an unattended `docker compose up -d` risks it being lost with no attached TTY to read it from; a docs-first fix is lower-risk than a startup-behavior change. |
| B3. Consistent offline backup/restore, version-skipping upgrades, SQLite→PostgreSQL move, KEK re-encryption sweep | `server/admin/backup.go`/`restore.go` (v1, SQLite-only, `VACUUM INTO`, #2099, merged); `server/admin/encryption.go`'s `rotate-kek` (KEK re-encryption); GORM `AutoMigrate`'s purely-additive schema design makes "version-skipping" implicit, not a separate feature (`docs/SELF_HOSTING.md` §6) | `backup_restore_test.go`, `backup_restore_integration_test.go`, `backup_restore_fuzz_test.go` | **Implemented for backup/restore (SQLite) and KEK re-encryption. SQLite→PostgreSQL move not yet implemented** — `docs/design-b3-backup-v2.md` (PR #2100, merged, Status: Decided) is the complete, already-decided design for a backend-neutral archive format that closes this exact gap ("by construction, the SQLite → Postgres move ADR-108 already named as a sibling requirement — not a separate feature, the same mechanism"); implementation hasn't started (only a related security fix, PR #2233, is in flight). Not a product-decision gap — the design is already decided — but a real, not-yet-built feature. Sizing (HMAC-authenticated manifests, a Postgres `REPEATABLE READ` snapshot mechanism, a new archive format) puts it well beyond this conformance pass's scope; tracked via its own design doc, needs its own implementation PR(s). |
| B4. Offline audit-chain verification, no running server or trust in it | `server/admin/audit_verify.go` (`admin verify-audit`), `internal/auditverify` package (independent hash-chain re-derivation, direct DB access) | `internal/auditverify`: `differential_test.go`, `tamper_exhaustive_test.go`, `rowdecode_fuzz_test.go`, `postgres_test.go`, `anchor_bundle_test.go`/`_fuzz_test.go`, `dependency_guard_test.go` (proves independence from `internal/storage/store`) | **Implemented** |
| C. Remove the `/system` storage-proxy tier and `RemoteStorage` | `internal/storage/store/remote_*.go` fully deleted; zero `/system` proxy handlers remain in `server/http/handlers` | `TestNoNewRemoteStorageImportersOutsideAllowlist` (`internal/storage/store`, empty allowlist) | **Implemented** — see SESSION-D item D2 for the accompanying stale-comment sweep |
| Decision 1. REST only for the CLI transport | Same as A2 | Same as A2 | **Implemented** |
| Decision 3. Tiered CLI/server version skew (same major: warn; newer CLI/missing route: clear error; different major or below floor: refuse) | `cli/internal/skew/skew.go` | `cli/internal/skew`'s test suite (26 cases) | **Implemented** |

## Context (measured 2026-09-23 on main)

| Binary | Size | Links `internal/core` | Cloud-SDK packages linked |
|---|---|---|---|
| `keyorix` (CLI, repo root `main`) | 65 MB | yes | 90 |
| `server` | 97 MB | yes | 99 |
| `keyorix-mcp`, `keyorix-k8s-sync` | small | no | 0 |

- The CLI embeds the whole server stack: core, storage, and every AWS/Azure/GCP SDK. 45 CLI files import core. It works in two modes:
  - **local:** it opens the SQLite DB itself, which makes it a second server that bypasses the API's authorization, audit and rate limits;
  - **remote:** it calls `RemoteStorage`, which uses the `/system` storage-proxy tier on the server.
- The `/system` proxy tier has to re-implement the authorization of each human-facing route. It is where the 2026-09-21/23 authority findings came from (11 proxy routes, F5/F6). Per ADR-102, `system.write` reaches 148 routes.
- Coupling finding (already fixed by #2004): `internal/config` imported `internal/connect` only for the list of connector type names, which pulled every cloud SDK into config, into i18n, and into everything that translates an error. The list is now in a leaf package, and a guard test keeps it that way. The CLI still links core directly, and core imports the connectors, so the client stays heavy until this split.

## Decision (proposed)

**A. Thin network CLI (`keyorix`).**
- It lives in its own Go module (its own `go.mod`), so it cannot import core, storage, `internal/config` server code or any SDK. The compiler enforces the boundary.
- It talks to the server only through the public REST API (or gRPC). Its request and response types are generated from the OpenAPI/proto definitions (ADR-106).
- It has no local database mode.

**B. `keyorix-server admin …` subcommands for operations that must not, or cannot, go through the network API.** These need shell access on the server host plus the DB and key files; owning the host is the authority.
1. Server cannot start: migration failure, broken config, KEK unavailable, crash-corrupted DB. Covers diagnose, repair and migrate.
2. Everyone locked out: recover an admin account (lost password or MFA, last admin deactivated). This must never be a network endpoint, because that would be a built-in auth bypass. Every use is written to the audit chain, and the command prints what it did.
3. Operations that need the database to themselves: consistent offline backup and restore, version-skipping upgrades (air-gapped customers), the SQLite → PostgreSQL move, a full KEK re-encryption sweep.
4. Independent audit verification: check the tamper-evident audit chain from the DB file, without trusting the running server. This is a compliance deliverable for regulated customers.

These are subcommands of the server binary rather than a third binary, because the server binary already links core and storage. Keycloak's `kc.sh export/import` and GitLab's host-side rake tasks use the same pattern.

**C. Remove the `/system` storage-proxy tier and `RemoteStorage`** once nothing calls them. This is ADR-083's deferred work and ADR-107's goal. It also settles most of ADR-102's `system.write` question by removing the surface.

**Out of scope:** server-side decoupling (core depending on interfaces instead of connector SDKs, lean build tags). That is the companion ADR. This ADR removes the SDKs from the *client*; the companion ADR removes them from builds of the *server* that don't need them.

## Why

- **Security:** it removes the proxy tier, a whole bug class and a large authorization surface. The CLI cannot bypass the API. Break-glass needs host access and is audited.
- **Air-gapped and regulated environments:**
  - offline backup, restore, upgrade and recovery without a running API;
  - offline audit-chain verification for auditors;
  - a smaller client to ship and certify, with an SBOM that lists no cloud SDKs.
- **Size:** CLI from 65 MB to an estimated 10–15 MB (not measured). Server size is the companion ADR's concern.
- **Maintainability and fuzzing:** the local-vs-remote conformance suites, the `/system` handlers and the parity fuzzers that exist only because of them all go away. The CLI's request/response parsing becomes a small, fast fuzz target.

## Consequences and risks

- **Breaking change:** "CLI opens the DB directly" is removed, and those operations move to `keyorix-server admin`. Acceptable at prototype stage; release notes and migration docs are needed.
- **API gaps:** any CLI command with no REST equivalent needs one first. The inventory decides the order.
- **Two modules in one repo:** CI must build and test both, and version skew between CLI and server needs a compatibility rule (the CLI checks the server's API version and warns or refuses).

## Order of work (separate PRs, one program)

1. Inventory: every CLI command → the REST route it would call, the gaps, and the operations for B.
2. New CLI module with a dependency guard in CI. Move commands group by group: secrets, projects, users, then the rest.
3. `keyorix-server admin` subcommands for B1–B4. Each gets its own tests; recover-admin gets an adversarial review.
4. Delete the `/system` proxy tier and `RemoteStorage`, plus their tests and parity fuzzers. Update the ledger and closures.
5. Then the companion decoupling ADR (see the program plan).

## Decisions on the open questions (Andrei, 2026-09-23)

1. **Transport: REST only for the CLI.** The human-facing REST API carries the full authorization model, audit and rate limiting. One transport means one test surface and no CLI-level REST↔gRPC parity problem, and plain HTTPS works through enterprise proxies and TLS inspection. gRPC stays for machine clients (SDKs, k8s-sync, services). The CLI's client is generated from the canonical API definition (ADR-106), so it cannot drift.
2. **recover-admin requires a recovery key by default.**
   - Generated at install and shown once. Split M-of-N (Shamir) is a later enterprise option.
   - Every use writes to the audit chain and notifies all admins.
   - A keyless host-only mode exists only when explicitly configured, for labs and demos.
   - Rationale: separation of duties. Host root should not automatically become Keyorix admin (an insider-threat control for NIS2/DORA). This matters most when the KEK is in a KMS or HSM; if the KEK file sits on the host, root already has everything, and the docs say so plainly.
3. **CLI/server version skew is tiered.** The server advertises its API version and a minimum supported CLI version.
   - Same major version: allowed. An older CLI warns ("upgrade available"). A newer CLI calling an endpoint the server doesn't have gets a clear "server too old for this command" error, not a 404.
   - Different major version, or a CLI below the server's minimum: refused. The minimum lets us force upgrades after a CLI-side security fix.
