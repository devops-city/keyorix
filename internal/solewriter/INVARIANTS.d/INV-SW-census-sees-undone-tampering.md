- **INV-SW-census-sees-undone-tampering** The census fingerprint changes on any change to a fence
  trigger or function, even one undone before the next poll (toggled off and back on in one
  transaction or across two, dropped and re-created identically, replaced with the same body or
  settings), on any inheritance or partition link with a fenced (or the holder/epoch) table on either
  side, and on any change to such a table's columns (ALTER COLUMN TYPE ... USING, RENAME COLUMN);
  InstallFence refuses to start when such a link already exists. It does so by including the
  pg_trigger, pg_proc and pg_attribute rows' `xmin`, the functions' `proconfig` and the `pg_inherits`
  links. Routine maintenance (VACUUM FREEZE of the catalogs, ANALYZE, CREATE INDEX, VACUUM FULL and
  CLUSTER of a fenced table; VACUUM FULL of the catalogs checked by hand) does not change it. Superuser access below SQL is the stated residual, reported by the posture check. Why:
  REVIEW-SINGLE-WRITER-1 F1, REVIEW-SINGLE-WRITER-2 N2. Guard: `TestPoll_FenceTamperingLeavesAuthoritativeForGood` (the
  undone-tampering cases red without `xmin`, the child case red without `pg_inherits`),
  `TestFence_FencedTableAsAChild` (the "becomes a child/partition" cases red without both the
  `inhrelid` direction and `pg_attribute`, the column cases red without `pg_attribute`),
  `TestInstallFence_RefusesAFencedTableWithAChild`, `TestInstallFence_RefusesAFencedTableThatIsAChild`, `TestPoll_CatalogMaintenanceKeepsAuthoritative`,
  `TestInspectFence_ReportsARoleThatReachesBelowSQL`.
