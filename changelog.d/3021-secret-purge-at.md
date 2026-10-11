### Changed
- **Deleting a secret now shows its real purge date (the restore deadline)** in the CLI,
  REST and gRPC responses and in the trash listing. The date is frozen when the secret is
  soft-deleted, so a later change to `soft_delete.retention_days` can neither pull a purge
  earlier than the date already shown nor silently push it out. New nullable column
  `secret_nodes.purge_at`, added automatically on upgrade (schema epoch 2). **The
  compatibility floor rises to 2: binaries from before this release refuse to start against
  an upgraded database** (they would not clear or re-stamp `purge_at` on restore/re-delete,
  and a stale date could purge a secret earlier than shown), so upgrade every replica
  before relying on a rollback. Secrets soft-deleted before the upgrade keep following the
  current window until purged, and the settings page says so.
