- **INV-CORE-setup-consume-all-or-nothing** A setup-link consume (account_setup,
  password_reset_link) has its full effect or none. `completePasswordSetup` commits every
  write in ONE transaction: the token marked consumed (a conditional update, so of two
  concurrent consumes exactly one commits), the password hash and account state, the
  revocation of every PAT, and the session (or, with a second factor enrolled, the MFA
  challenge holding the transport's login slot). Everything fallible that is not a write
  runs before it: the account read, the policy/history check, the response identity
  (`resolveLoginIdentityBeforeMint`, returned in the result so the transport reads nothing
  after the commit). A transaction that reports an error is read back by the one row it
  built (`setupConsumeLanded`: the session by its token, the challenge by its hash) and
  delivered if it committed. After the commit only best-effort, self-recovering work runs
  (cache eviction, password history, the session cap, the purge of other sessions, audit).
  So a failure or panic leaves the token active, the old password, every PAT live and no
  session: the same link works again. A failure after the token was validated is
  `ErrSetupPostVerdict`: answered exactly like a dead link (the generic 400), the per-IP slot
  kept, audited `setup_token.consume_error`; a lookup that evaluated nothing
  (`ErrSetupNotEvaluated`, including its panic) hands the slot back, audited
  `auth.login_error`. Deliberate difference from ChangePassword: PAT revocation is inside
  the transaction, so a reset whose revocation fails is refused whole rather than completed
  with a thief's PAT alive. Not covered: invitation_accept (`completeInvitationAccept`, a
  reviewed saga with compensations, class S in docs/atomicity-exempt.tsv). Why: #3298
  (FIX-3277's sweep: 25 oracle findings, the token spent and the password changed behind a
  reported failure). Guard: `server/faultops` ops `REST POST /auth/setup/consume` and
  `... (second factor)` (every fuzz input; exhaustive with `TestOpFaultSweep`), their
  `oracle_a_by_design_entry_setup_consume_*` rows (answered like a dead link, slot kept,
  audited, checked per run), `internal/core/TestCompleteSetup_FaultAtAnyWriteLeavesNothingAndTheLinkStillWorks`,
  `server/http/handlers/TestConsumeSetup_FailedConsumeLeavesTheLinkUsable`.
