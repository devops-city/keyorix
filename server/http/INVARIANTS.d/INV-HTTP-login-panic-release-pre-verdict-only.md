- **INV-HTTP-login-panic-release-pre-verdict-only** A login handler that reserved the per-IP
  login-attempt slot hands it back on a PANIC from core only if the panic landed before the
  credential was evaluated. `verifyMFALoginReleasingOnPanic` (mfa.go) and
  `finishWebAuthnLoginReleasingOnPanic` (webauthn.go) read `core.LoginVerdict`. Core marks it
  in `VerifyMFACredentials` (the TOTP code matched, or the input was evaluated with no
  storage error) and in `FinishWebAuthnLoginPending` (right after `ValidateLogin`), before
  the first storage call that follows the evaluation. After the verdict the request was a
  real attempt (correct or wrong), so it keeps its slot exactly as the same fault returned
  as an error does (#2880, #2894). Releasing it would make a faulted correct credential
  cheaper than a wrong one. The panic is always re-raised with its original value. Why:
  #3048 (the wrappers from #2565/CR3 released on any panic). Guard:
  `server/http/handlers/login_post_verdict_panic_slot_test.go`
  (`TestVerifyMFA_PanicKeepsTheSlotOnlyAfterTheVerdict` and
  `TestFinishWebAuthnLogin_PanicKeepsTheSlotOnlyAfterTheVerdict`: both sides of the verdict per
  endpoint; `TestLoginPanic_AfterAWrongCredentialKeepsTheSlot`: a wrong credential, then a
  panic while recording it). Each of core's three markers was removed in turn, and each
  removal turned a different subtest red.
