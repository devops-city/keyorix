### Security
- **No auth rate limit fails open on a database error any more.** The per-IP
  login, password-reset and SSO/SAML-begin budgets, and the per-account lockout,
  used to stop counting whenever their storage failed, including when only the
  count query failed while inserts still worked. While the database (or
  just its rate-limit table) was failing, brute-force and email-bombing limits
  were off. The per-account lockout is the only bound on MFA step-up and
  recovery-code guessing. Now each budget falls back to a bounded in-memory
  limiter with the same limits, per server process. Each fallback writes an
  `auth.rate_limit_error` audit event and increments
  `keyorix_auth_rate_limit_fallback_total{budget}`, so alert on that metric.
  `/health` also reports `"auth_rate_limit": "degraded"` while a fallback is in use.
  During the outage, password reset is tighter: half the per-IP limit, and a cap on
  reset emails per account. In HA, set the new
  `security.auth_rate_limit_fallback.replicas` to your replica count so each
  replica enforces its share. Clients see the same responses as before.
