### Security
- **A crafted passkey user handle no longer counts as a storage error.** On a
  passwordless login, a user handle above the largest possible user id made
  Postgres return an error that was taken for a database failure, so the
  request was audited `auth.login_error` and gave its per-IP login-budget slot
  back: unlimited attempts, each one recorded as an outage. Such handles (and a
  zero handle) are now refused before the lookup, audited `webauthn.failed` and
  counted. The client answer is unchanged.
