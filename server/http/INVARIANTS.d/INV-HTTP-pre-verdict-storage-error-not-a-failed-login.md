- **INV-HTTP-pre-verdict-storage-error-not-a-failed-login** A storage error that
  happens BEFORE any credential was checked (the username lookup on `/auth/login`;
  loading the user named by a passwordless passkey's handle; ActivateMFA's
  anti-replay write is the audit-only sibling) is not a failed login: it is audited
  as an error event (`auth.login_error`, `mfa.error`), never as `auth.login_failed`
  / `webauthn.failed` / `mfa.failed`, and the per-IP login-budget slot is handed
  back (the budget counts failed credential attempts only,
  INV-HTTP-login-budget-counts-failures-only). The client response is byte-for-byte
  the one the matching negative result gets (an unknown username, a handle naming no
  user, a wrong code), so the distinction adds no account-existence signal. A
  POST-verdict storage error is the opposite case and is unchanged: answered like a
  wrong credential AND counted (INV-CORE-login-lockout-clear-only-after-delivery).
  Why: #2744/#2745/#2746 (ported from #2846 by AUTH-AUDIT-1). Guard:
  `server/http/handlers/pre_verdict_storage_error_test.go` (control vs probe:
  status, body, headers, audit rows, login_attempts rows) and
  `internal/core/pre_verdict_storage_error_labelling_test.go` (the class split, plus
  the must-not-change halves: absent account == wrong password, replay stays
  `mfa.failed`, unchanged error texts).
