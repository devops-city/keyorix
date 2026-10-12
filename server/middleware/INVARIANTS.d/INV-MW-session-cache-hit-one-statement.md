- **INV-MW-session-cache-hit-one-statement** An interactive session's cache hit
  (`serveAuthCacheHit`, default branch) re-reads the owning account and the session row with
  ONE storage statement (`core.SessionCacheHitLiveness` -> `GetSessionAuthLiveness`) and acts
  on the two halves exactly as it acted on `AccountUsabilityAndState` and
  `SessionLiveForToken`, in the same order: account read ok and unusable -> deny and evict;
  account read ok -> refresh AccountState/Restricted from it; account read failed -> keep the
  cached snapshot; then session checked, read ok and not live -> deny and evict; session read
  failed or no session id on the entry -> no session verdict (INV-MW-05's two halves
  unchanged). Token-cache invalidation by core is unchanged. Why: PERF-FIX-7 (collapse C6).
  Guard: `server/http` `TestSessionCacheHitLiveCheck_Equivalence` (23 account/session cases on
  replica A after a change through replica B, SQLite and Postgres; passes unchanged on the
  code before this change), `_Invalidation` (same changes through the cache-owning replica),
  `_CrossReplicaRace` (two Postgres pools: revoke / suspend / session delete racing a request
  loop; every request started after the write returned is refused), `_OneStatement`
  (red before: 2 statements on users/sessions per cache hit); `cache_hit_transient_degrade_test.go`.
