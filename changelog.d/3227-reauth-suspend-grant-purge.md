### Security
- **Suspending a user revokes their re-auth step-up grants.** A user suspended right after re-authenticating
  (passkey re-auth mints a grant, not a session) kept a short-lived elevated grant. Suspend, deactivate,
  delete and SCIM deprovision now delete the user's step-up grants right after the account change commits, and spending a grant re-checks that the account is still active, so a grant created between a
  suspension's check and its insert is refused with the same generic "invalid code or password" as an
  absent grant.
