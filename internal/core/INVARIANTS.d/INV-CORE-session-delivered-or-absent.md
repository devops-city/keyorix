- **INV-CORE-session-delivered-or-absent** An operation that writes a session either hands
  that session's token to the client or leaves no live row for it. Concretely: (1) every
  fallible-and-reported read a login needs (the response identity) runs BEFORE the session
  insert (`resolveLoginIdentityBeforeMint`; `LoginWithIdentity(Pending)` for the password login, the
  MFA and WebAuthn logins since #2841); (2) everything after the insert is panic-safe
  best-effort (`besteffort.Run`, never a bare `_ =`, which drops an error but not a panic);
  (3) a session write that reports an error is read back by its token
  (`createSession`, `sessionWriteLanded` in `session_undelivered.go`): a row that landed is
  delivered, an absent one keeps the error, a lookup that fails keeps the error and is audited
  `auth.undelivered_session_unresolved`; a write that panics has its row deleted
  (`auth.undelivered_session_revoked`) before the panic continues. Session inserts go through
  `createSession` (mintSession's seven callers, StartImpersonation); RefreshSession applies (3)
  to `RotateSession`. Handler-side, `completeLogin` (ConsumeSetup only) revokes on a panic as
  well as an error. Why: #2844 — a reported-failure login left a live session the owner could
  see and a revocation sweep had to find (identity-read panic on /auth/login, step-up grant
  panic on WebAuthn finish, CreateSession/RotateSession effect-then-error on every
  session-issuing op). Guard: `server/faultops` oracle (f) `checkNoUndeliveredSession`
  (every fuzz input), `TestUndeliveredSessionSweep` (every fired method x nth 1-3 x kind on
  every session-issuing op), `TestUndeliveredSession_PinnedTuplesLeaveNoSession`;
  `login_undelivered_session_test.go` here and in `server/http/handlers` (ConsumeSetup).
  **Not covered**: the passwordless WebAuthn finish and setup consume are not in opCatalog
  (covered by the core/handler tests above, not by the sweep).
