- **INV-CORE-session-cache-hit-one-read** `SessionCacheHitLiveness(user, session, token)`
  answers what `AccountUsabilityAndState(user)` and `SessionLiveForToken(session, token)`
  answer, verdicts and error contract alike, from ONE storage call
  (`GetSessionAuthLiveness`): usable = active and not login-blocked (`accountUsableFromRow`,
  shared with `AccountUsabilityAndState`); the account read's error is reported as the
  account error (the caller denies on a missing row and refuses 503 on any other error,
  INV-MW-cache-hit-recheck-fails-closed; it used to keep its cached snapshot); live = the row's hash is the presented
  token's, not rotated, inside idle and absolute expiry (`sessionRowLiveForToken`, shared with
  `SessionLiveForToken`); a missing session row is the DEFINITIVE "not live", any other session
  read error is indeterminate. A failure of the combined read is indeterminate on both halves,
  never a verdict. Without a session id it is `AccountUsabilityAndState` alone. A Storage
  wrapper that embeds a store and overrides `GetUser` or `GetSessionByID` (a test injecting a
  fault) must also override `GetSessionAuthLiveness`, forwarding it to
  `storage.ComposeSessionAuthLiveness` over itself. Why: PERF-FIX-7 (collapse C6). Guard:
  `TestSessionCacheHitLiveness_MatchesTheTwoChecks` (200 combinations against the two methods),
  `_CombinedReadFailureIsIndeterminateOnBothHalves`;
  `TestSessionAuthReadWrappersForwardTheCombinedRead` (`internal/core/guards`; AST scan, with calibration);
  `server/http` `TestSessionCacheHitLiveCheck_*` (end to end, below).
