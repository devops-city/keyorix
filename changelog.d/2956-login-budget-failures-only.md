### Security
- **Successful logins no longer use up the per-IP login budget** (#2936). The
  budget (10 attempts per 15 minutes per IP, shared by the password, TOTP,
  passkey and token-refresh endpoints) was charged for every request, success
  or not, so a few ordinary MFA logins from one demo laptop, booth or office
  network locked everyone behind it out with a 429 for 15 minutes, and a
  restart did not help. A request that delivers a session now returns its slot,
  and so does every earlier step of the same login (the password step of an MFA
  login, a passkey `begin`), so a successful MFA or passkey login costs nothing;
  a failed, expired or abandoned one keeps every slot it took. Failures count
  exactly as before, including storage faults after a correct credential
  (#2880), and the slot is still reserved before the credential check, so a
  concurrent burst cannot outrun the budget. The count still survives a
  restart. New audited host-side command
  `keyorix-server admin clear-login-lockout --ip ADDR | --user ID` clears an
  IP's budget and/or an account's login lockout (docs/SELF_HOSTING.md).
