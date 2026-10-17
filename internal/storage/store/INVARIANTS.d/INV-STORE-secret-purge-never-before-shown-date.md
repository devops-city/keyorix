- **INV-STORE-secret-purge-never-before-shown-date** The purge job
  (`PurgeDeletedSecretsBefore`) never hard-deletes a soft-deleted secret before the
  `purge_at` that the trash listing and the delete response show for it, whatever
  `soft_delete.retention_days` is changed to afterwards. The date is frozen into
  `secret_nodes.purge_at` by the same transaction that soft-deletes the secret
  (`DeleteSecret`, the `deleteProjectCascade` secret sweep: `deleted_at` + the secret's
  own `retention_override_days`, else the window then configured, via
  `models.PurgeAtFor`), cleared by `RestoreSecret`/`RestoreProject`, and compared in Go,
  strictly after, by `secretPurgeCandidate.eligible` — which ignores the caller's
  config-derived `before` for a stamped row. Chosen rule for a window changed after
  deletion: it affects only later deletions, in both directions (a shortening never
  pulls a displayed date earlier, a lengthening never defers it); an operator who needs
  an earlier erasure sets the per-secret override before deleting. Rows soft-deleted
  before the column existed carry no `purge_at` and keep the legacy rule (the date shown
  is `deleted_at` + the CURRENT window, `models.SecretNode.EffectivePurgeAt`) - the one
  population for which a later config change can still move the date. Why: RETENTION-1 —
  the CLI printed "default 30 days" because the real date was not exposed, and the
  window was re-read at purge time, so shortening it purged secrets earlier than any
  date an operator could have been told. Guard: `local_purge_purgeat_test.go`
  (`TestSecretPurgeCandidate_Eligible_Boundary`, the 20k-case
  `TestSecretPurgeCandidate_NeverEligibleBeforeShownDate_Property`, and the
  `TestPurge_RetentionShortenedAfterDeletion_DoesNotPurgeEarlierThanShown` /
  `_RetentionLengthenedAfterDeletion_KeepsShownDate` / `_OverrideLongerThanGlobal_HoldsUntilItsOwnDate`
  integration tests through the real delete and purge). Limit: `SetSoftDeleteRetentionDays`
  is wired only by `storage.factory`; a store never told the window stamps nothing and
  falls back to the legacy rule (`TestPurge_UnstampedRowsKeepLegacyCutoffRule`).
  Mixed versions: an epoch-1 binary neither clears nor re-stamps `purge_at`, so the
  property holds only because `minCompatibleSchemaEpoch` is 2 (epoch-1 binaries refuse to
  start against a migrated database); guard `TestCurrentSchemaEpoch_Is3_SeeADR101`.
  Lowering the floor re-opens an irreversible early purge.
