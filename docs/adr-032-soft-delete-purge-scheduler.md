# ADR-032: Soft-delete retention + purge scheduler

**Status:** Accepted
**Date:** 2026-06-10
**Context:** The config has carried dormant `SoftDeleteConfig{Enabled,
RetentionDays}` and `PurgeConfig{Enabled, Schedule}` blocks that nothing reads.
Users, projects, and environments already soft-delete (GORM `DeletedAt`) with
restore endpoints, so soft-deleted rows accumulate forever with no lifecycle.

## Context

Soft delete is a safety net (a restore window after an accidental delete), but
without a purge step the rows live indefinitely. That is both a storage-hygiene
problem and a compliance one: GDPR/NIS2 erasure expects that a deleted record is
*actually* removed after a bounded grace period, not retained forever. Three
entities already soft-delete via `DeletedAt`: `users`, `projects`,
`environments`. (Secrets currently hard-delete and use a `Status` field, not
`DeletedAt` — giving secrets a `DeletedAt` soft-delete is a separate, larger
change that touches every secret query; it is a tracked follow-up, and the purge
scheduler will cover it for free once it lands.)

## Decision

Wire the dormant config into a **purge scheduler**: a background job that
hard-deletes soft-deleted rows whose `deleted_at` is older than the retention
window.

- **`SoftDeleteConfig.RetentionDays`** — the grace period; soft-deleted rows are
  purged once `deleted_at < now − RetentionDays`. Defaults to 30 days when unset.
- **`PurgeConfig.Enabled`** — opt-in. **Default off**: a hard delete is
  irreversible, so an operator must explicitly enable it. With it off the
  scheduler never runs and behaviour is unchanged (soft-deleted rows persist).
- **`PurgeConfig.Schedule`** — the run interval, parsed as a Go duration
  (e.g. `24h`, `6h`). Defaults to 24h.

A `KeyorixCore.PurgeExpiredSoftDeletes(ctx, before)` orchestrates per-entity
hard deletes (`PurgeDeletedUsersBefore` / `…ProjectsBefore` /
`…EnvironmentsBefore`, each `Unscoped().Where("deleted_at < ?").Delete`,
returning a count) and emits one **system-actored** `data.purged` audit event
with the counts. The scheduler goroutine in `main.go` mirrors the existing
anomaly-detection ticker (run-once-on-start + ticker + `ctx.Done()` shutdown),
guarded by `PurgeConfig.Enabled`.

Each entity is purged independently on its own `deleted_at` — no cascade logic
in the purge (a soft-deleted project's environments carry their own
`deleted_at` and are purged by their own query). This keeps the job simple and
idempotent.

## Consequences

- Operators get a real retention lifecycle: a configurable grace period, then
  permanent removal — the GDPR/NIS2 "erasure after grace" story, opt-in.
- Default-off means no behaviour change for anyone who doesn't enable it, and no
  surprise data loss.
- The purge is irreversible by design; the retention window is the only safety
  net, so the default (30 days, off) is conservative.
- Secrets soft-delete + restore (replacing the hard delete) is a follow-up; when
  it lands, adding `secret_nodes` to the purge is a one-line extension.

## Amendment (RETENTION-1): the purge date is exposed, frozen at deletion, and never undercut

A soft-deleted secret now carries `purge_at` (UTC): `deleted_at` + its per-secret
`retention_override_days`, else the `soft_delete.retention_days` in force when it was
deleted. It is returned as `purge_at` in `GET /projects/{id}/secrets/deleted`, as the
`Keyorix-Purge-At` header of the (still 204) `DELETE /secrets/{id}`, and as
`DeleteSecretResponse.purge_at` over gRPC; the CLI (`secret delete`, `secret trash`) and
the web Recycle bin show it. No `api_version` bump: every change is additive.

**Rule when the window changes after a deletion:** the date shown is the date used. The
purge honours the frozen `purge_at` and ignores the current `retention_days`, so shortening
the window never purges a secret earlier than the date an operator was told, and
lengthening it never defers that date. A changed window affects deletions made after the
change. Why not recompute from the live config (the previous behaviour): the date on screen
would change under the operator, and a shortening would silently remove a secret that the
UI had promised was restorable. Secrets deleted before this amendment have no frozen date
and keep the live-config rule (their shown date is `deleted_at` + the current window).
Invariant: `INV-STORE-secret-purge-never-before-shown-date`.

**Mixed-version rollout (ADR-101).** An epoch-1 binary does not know `purge_at`: its
`RestoreSecret`/`RestoreProject` do not clear it and its `DeleteSecret` does not re-stamp
it. On a shared database a restore + re-delete on an old replica would leave the first
deletion's date in place and the new purge job would hard-delete (irreversibly) before the
date shown for the second deletion. The column is therefore NOT additive-and-safe, and
`minCompatibleSchemaEpoch` is raised to 2 with this change: an epoch-1 binary refuses to
start against a migrated database (`TestCurrentSchemaEpoch_Is5_SeeADR101`). Consequence:
a rolling upgrade must not leave epoch-1 replicas running after the first epoch-2 replica
migrates (they exit at their next start, and a one-release rollback is no longer possible
without restoring the database). Secrets deleted before the upgrade have no `purge_at`
and follow the live window, so the UI states that date can still move.
