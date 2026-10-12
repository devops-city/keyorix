### Security
- **`keyorix-server admin clear-login-lockout` now writes its audit event before it
  clears anything** (#2956 follow-up). It used to clear the IP budget / account
  lockout first and audit afterwards, so a fault in the audit write left a lifted
  lockout with no record. Now a failed audit write clears nothing and fails the
  command, and a clear that faults after the audit event was written appends an
  `admin.login_lockout_clear_failed` event so the chain never claims a lift that
  did not happen. The per-run counts ("cleared N attempts") are printed to the
  operator and no longer part of the audit text.
