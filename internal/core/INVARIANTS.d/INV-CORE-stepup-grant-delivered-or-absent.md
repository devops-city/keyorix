- **INV-CORE-stepup-grant-delivered-or-absent** An MFA step-up either reports
  success with the grant it wrote, or leaves no live grant from that call. A
  grant write that fails after the code matched (an error, a lost
  acknowledgement, or a panic before or after the commit) is refused like a
  wrong code (counted, `mfa.error`, the wrong-code answer), and
  `createStepUpGrant` then consumes the grant if it landed
  (`revokeUndeliveredStepUpGrant`: our ID was assigned, or a live
  restricted-secret-read grant was created after the write started),
  auditing `mfa.undelivered_stepup_grant_revoked`, or
  `mfa.undelivered_stepup_grant_unresolved` when that cannot be done. A live
  grant from an earlier, delivered step-up survives an honest failure. Why:
  #3277 follow-up — the grant write's effect-then-error left a live
  restricted-secret-read grant behind a step-up the caller was told had failed,
  and its panic answered the Recovery 500 a wrong code never gets. Guard:
  `TestVerifyMFAStepUp_GrantWriteFailureLeavesNoElevation` (five failure
  modes), `TestVerifyMFAStepUp_HonestGrantFailureKeepsAnEarlierGrant`
  (calibration), `server/http/handlers/TestMFAStepUp_PostVerdictFaultIsIdenticalToAWrongCode`
  (panic cases through `middleware.Recovery`, no live grant), and
  `server/faultops/TestPostVerdictWritePanic_AnsweredLikeItsError`.
  **Not covered**: there is no delete-by-ID, so when ours landed the
  revocation also ends any older live restricted-read grant of that user
  (fail-closed: the user steps up again).
