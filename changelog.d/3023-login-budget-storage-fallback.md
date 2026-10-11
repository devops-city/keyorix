### Security
- **The per-IP login budget no longer fails open on a database error.** It used
  to stop counting whenever its `login_attempts` storage failed, including when
  only the count query failed while inserts still worked. It now falls back to
  a bounded in-memory limiter with the same limit and window, per server
  process. Each fallback writes an `auth.rate_limit_error` audit event and
  increments `keyorix_login_budget_fallback_total`. Clients see the same 429.
  An MFA or passkey login whose slot came from that fallback completes as
  normal: the in-memory slot is never written to the challenge or ceremony row.
- **A storage error before any credential was checked is no longer recorded as
  a failed login.** The username lookup on `/auth/login` and the passwordless
  passkey's user lookup audit it as `auth.login_error` and hand the per-IP slot
  back; MFA activation's anti-replay write audits `mfa.error`. The client answer
  is unchanged.
