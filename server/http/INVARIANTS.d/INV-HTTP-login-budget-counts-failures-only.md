- **INV-HTTP-login-budget-counts-failures-only** The shared per-IP login budget counts
  failures, not logins. Every login-family endpoint still reserves its slot BEFORE the
  credential check (INV-HTTP-19 is unchanged), but a request that DELIVERS a session —
  `Login`, `VerifyMFA`, `FinishWebAuthnLogin`, `FinishWebAuthnPasswordlessLogin`,
  `RefreshToken`, `ConsumeSetup` — returns its own slot via `returnLoginSlot`, and only on
  that path. A wrong credential, a refused request and a post-verdict storage fault
  (#2880/#2894) keep the slot. A step that does not finish its flow keeps its slot while
  the flow is open (the password step of an MFA login, bound to the MFA challenge's
  `login_attempt_id`; `BeginWebAuthnLogin` and `BeginWebAuthnPasswordlessLogin`, bound to
  the ceremony row's `login_attempt_id`, because Begin neither consumes anything nor is
  otherwise bounded, G1 / #2956 review), and core's `LoginCompletion.Succeeded` hands those
  back only when the finishing step delivers a session — at most once, because both rows
  are single-use. So a delivered login flow costs no slot, and a failed, expired or
  abandoned one keeps every slot it took (#2936 item 4). The
  count is the persisted `login_attempts` table, so a restart does not reset it. Why: #2936
  (Andrei, 2026-10-10: "count failures only") — charging successes let a handful of ordinary
  MFA logins from one IP lock everybody behind it out for 15 minutes, surviving a restart.
  Guard: `login_budget_count_failures_test.go`
  (`TestLoginBudget_SuccessfulLoginsDoNotConsumeTheBudget`,
  `TestLoginBudget_DeliveredMFALoginConsumesNoSlot`,
  `TestLoginBudget_SuccessfulRefreshesDoNotConsumeTheBudget`, and the calibrations
  `TestLoginBudget_FailuresStillLockAtTheThreshold`,
  `TestLoginBudget_FailureCountSurvivesRestart`). Host-side override:
  `keyorix-server admin clear-login-lockout` (audited, `server/admin/login_lockout.go`).
  `login_budget_mfa_slot_release_test.go` covers the held slots over HTTP with the go-webauthn
  spec vector (a verifying assertion): `TestLoginBudget_SuccessfulMFALoginsNeverHitTheLimit`,
  `TestLoginBudget_FailedOrAbandonedMFAStillCounts`,
  `TestLoginBudget_ConsumedOrExpiredChallengeCannotReleaseASlot`,
  `TestLoginBudget_PasskeyMFALoginLeavesNoSlot`,
  `TestLoginBudget_WebAuthnBeginKeepsItsSlotUntilDelivered`,
  `TestLoginBudget_PasswordlessLoginLeavesNoSlot`.
