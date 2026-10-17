- **INV-MW-session-cache-hit-one-statement** An interactive session's cache hit
  (`serveAuthCacheHit`, default branch) re-reads the owning account and the session row with
  ONE storage statement (`core.SessionCacheHitLiveness` -> `GetSessionAuthLiveness`) and acts
  on the two halves with the verdicts of `AccountUsabilityAndState` and
  `SessionLiveForToken`: definitive verdicts first (account row gone, account read ok and
  unusable, or session checked, read ok and not live -> deny and evict); then any failed read
  (account, or session when checked) -> refuse 503 (INV-MW-cache-hit-recheck-fails-closed;
  until CACHE-FAILCLOSED-1 a failed read kept the cached snapshot); otherwise refresh
  AccountState/Restricted from the account read. No session id on the entry -> no session
  verdict. Token-cache invalidation by core is unchanged. Why: PERF-FIX-7 (collapse C6).
  Guard: `server/http` `TestSessionCacheHitLiveCheck_Equivalence` (23 account/session cases on
  replica A after a change through replica B, SQLite and Postgres; passes unchanged on the
  code before this change), `_Invalidation` (same changes through the cache-owning replica),
  `_CrossReplicaRace` (two Postgres pools: revoke / suspend / session delete racing a request
  loop; every request started after the write returned is refused), `_OneStatement`
  (red before: 2 statements on users/sessions per cache hit); `cache_hit_transient_refused_test.go`,
  `cache_hit_fail_closed_test.go`.
