- **INV-CORE-login-lockout-clear-only-after-delivery** A login's failed-login
  counter is cleared ONLY once that login has actually been delivered to its
  caller, and any failure after the credential matched is COUNTED as an attempt
  — so the account's lockout state after a post-verdict storage fault is
  identical to its state after a wrong credential, not merely the HTTP response
  (INV-CORE-24's sibling property for #2888's response-shape rule). Concretely,
  with the threshold at N and the counter at N−1: a wrong credential goes to N
  and locks; a correct credential plus an injected fault in the TOCTOU lock
  recheck (`recheckLockAfterCredentialMatched`, #2894 review), the
  password-expiry gate, the session mint, the step-up-grant write, or the
  transport's identity read also goes to N and locks; only a login the client actually received
  resets to 0. Why: #2894 — `checkLockAndClearLoginFailures` cleared the counter
  on its way past the TOCTOU re-check, which put the clear BEFORE every
  remaining fallible step of every login path (`internal/core/auth.go`,
  `mfa.go`, `webauthn.go` ×2, `mfa_stepup.go`), and the `completeLogin` failure
  branches recorded nothing, so a CORRECT guess was strictly cheaper
  lockout-wise than a wrong one and whether the account locked was an oracle for
  password correctness — through the one channel #2888 had not equalised.
  **Why "count the failure" alone is not sufficient**, and why the clear had to
  move as well: clear-then-count leaves the account at 1, not at N, so at
  threshold−1 a correct guess still buys the attacker N−1 attempts a wrong guess
  does not. Both halves are required; `LoginCompletion` is the type that makes
  them inseparable. The two cases stay distinguishable in the AUDIT trail only
  (`auth.login_error` vs `auth.login_failed`, `ErrLoginPostVerdict`), which is
  an operator-only channel. The rule is stated per PATH, and that matters:
  "counted" means **matching that path's own wrong-credential cost**, not
  "always incremented". Two paths deliberately charge nothing, because their
  wrong-credential branch charges nothing either, and charging a post-verdict
  fault there would make the CORRECT credential the more expensive one — the
  same oracle inverted. **Passwordless WebAuthn**: a failed discoverable
  assertion never identifies a user (the handle comes out of the assertion), so
  there is nobody to charge and charging would let an attacker lock an arbitrary
  victim; the fix there is purely that the counter is no longer CLEARED on the
  way to a denial, which used to wipe a victim's accumulated lockout progress.
  **SSO** (`sso.go`): an IdP-rejected assertion never reaches this counter, so
  the same reasoning applies; it follows the clear-after-mint ordering and counts
  nothing. `LoginCompletion` carries which of the two a path is
  (`newLoginCompletion` vs `newLoginCompletionNotCounted`) so the transport's
  single commit point stays uniform. Guard:
  `login_lockout_clear_site_guard_test.go:TestClearLoginFailures_HasNoCallerBeforeAFallibleStep`
  (structural — every `clearLoginFailures` / `recheckLoginLockFailClosed` call
  site is allowlisted with its reason, so a new login path cannot quietly
  reintroduce the ordering), plus the behavioural
  `server/http/handlers/login_lockout_no_oracle_test.go` family
  (`TestLogin_PostVerdictFaultCostsTheSameAsAWrongPassword`,
  `TestLogin_CreateMFAChallengeFaultCostsTheSameAsAWrongPassword`,
  `TestVerifyMFA_PostVerdictFaultCostsTheSameAsAWrongCode` — each comparing
  status, body bytes, headers, the lockout columns AND the per-IP
  login-attempt rows against the wrong-credential run) and
  `internal/core/login_lockout_post_verdict_parity_test.go` for the paths whose
  post-verdict window is entirely in core (`FinishWebAuthnLogin`,
  `FinishWebAuthnPasswordlessLogin`, `FinishWebAuthnReauth`,
  `VerifyMFAStepUp`), which the handlers package cannot drive because only
  `internal/core` has a cryptographically valid WebAuthn assertion fixture;
  `internal/core/login_lockout_recheck_fault_parity_test.go` for the recheck
  fault on every path; `mfa_totp_recovery_lookup_parity_test.go` for the TOTP
  second factor, where a six-digit code is evaluated by the TOTP path ALONE
  (`isTOTPShaped`) so a recovery-code lookup fault cannot turn a wrong code into
  "unavailable" while a correct one stays "invalid code"; and
  `server/http/handlers/mfa_stepup_identical_response_test.go` for the step-up
  endpoint's response bytes.
<!-- section: Last-admin / lockout -->
