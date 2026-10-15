- **INV-SW-census-sees-undone-tampering** The census fingerprint changes on any change to a fence
  trigger or function, even one undone before the next poll (toggled off and back on in one
  transaction or across two, dropped and re-created identically, replaced with the same body), and
  on any table inheriting from a fenced table; InstallFence refuses to start when one already
  inherits. It does so by including the pg_trigger and pg_proc rows' `xmin` and the `pg_inherits`
  children. Routine catalog maintenance (VACUUM FULL / FREEZE, ANALYZE, CREATE INDEX) does not change
  it. Superuser access below SQL is the stated residual, reported by the posture check. Why:
  REVIEW-SINGLE-WRITER-1 F1. Guard: `TestPoll_FenceTamperingLeavesAuthoritativeForGood` (the
  undone-tampering cases red without `xmin`, the child case red without `pg_inherits`),
  `TestInstallFence_RefusesAFencedTableWithAChild`, `TestPoll_CatalogMaintenanceKeepsAuthoritative`,
  `TestInspectFence_ReportsARoleThatReachesBelowSQL`.
