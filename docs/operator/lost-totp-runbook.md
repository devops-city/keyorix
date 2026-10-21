# Lost TOTP runbook: a user cannot produce a second factor

A user can sign in with a password but not with their authenticator code: a lost phone, a
wiped app, a clock that drifts. This runbook picks the recovery path that exists in the code
today for each kind of account, and says plainly where there is none. For an admin who is
locked out entirely (password, MFA or lockout), the full procedure is
[j5-lost-admin.md](j5-lost-admin.md); this page is the decision tree in front of it.

Do **not** set `security.require_mfa: false` to get someone in. It is not needed for any path
below and it weakens every account on the install.

## 1. Decide which case you are in

| The user | Path |
|---|---|
| Still has an **unused recovery code** | Section 2: self-service, no operator needed. |
| Is a **global admin**, no recovery code, you have shell access to the server host | Section 3: `recover-admin`. |
| Signs in through **SSO** | Their identity provider owns the second factor. Fix it there. Keyorix cannot reset it (`user reissue-one-time-password` also refuses SSO users). |
| Is a **non-admin with local credentials**, no recovery code | Section 4: there is no supported reset today. |
| Is **locked out** after failed codes (the code is right, the account is refused) | Section 5. |

## 2. Self-service with a recovery code

Ten single-use recovery codes are printed once, when MFA is activated. The login and step-up
prompts for the authenticator code also accept an unused recovery code:

```
$ keyorix login --server https://localhost:8080 --ca-file certs/server.crt --username alice
Password:
Authenticator code (or an unused recovery code):
Logged in to https://localhost:8080 as alice.
```

Then, in the same session, replace the lost factor before the codes run out. The `keyorix`
CLI has `mfa enroll`, `mfa activate` and `mfa stepup` only, so these two go through the web UI
or the API (all require a bearer session):

- `GET /api/v1/auth/mfa/recovery-codes` returns `{remaining, total}`.
- `POST /api/v1/auth/mfa/recovery-codes/regenerate` issues ten new codes and invalidates every old
  one, used or not; it needs a current code **or the account password**.
- `POST /api/v1/auth/mfa/disable` (`{"code": ...}` or `{"password": ...}`) clears the secret and
  all recovery codes, and ends the user's other sessions. The user then enrols a new device:

  ```bash
  keyorix mfa enroll        # scan the otpauth:// URI or type the base32 secret into the new app
  keyorix mfa activate      # prompts for a code from the app and the account password
  ```

  `mfa activate` prints the new recovery codes once. Store them offline.

## 3. A global admin, with host access

`recover-admin` resets exactly one account and refuses an account that does not hold a
global-admin role. It needs the host **and** the recovery key
([j5-lost-admin.md](j5-lost-admin.md) §0 generates it ahead of time; the key is read from stdin
only):

```bash
# stop keyorix-server first: admin commands need the database to themselves
printf '%s' "$RECOVERY_KEY" | keyorix-server admin recover-admin --user admin@example.com --recovery-key - --config ./keyorix.yaml
```

It reactivates the account if needed, sets a one-time password (printed once, expires after
`security.recovery_one_time_password_ttl`, default 24h), **clears MFA enrolment, recovery codes
and every WebAuthn credential**, clears the login lockout and revokes every session of that
account. Nothing else is touched. Every run writes `admin.recover_admin` to the audit trail
(naming the host user who ran it) and notifies every current admin. The user then signs in with
the one-time password and, on a `require_mfa` install, gets a setup-only session of at most 15
minutes in which to set a new password and enrol a new factor
([j5-lost-admin.md](j5-lost-admin.md) §3-§5 has the exact prompts).

If no recovery key was ever generated, the command stops and tells you to run
`keyorix-server admin recovery-key rotate` first. On an install that has no key yet, `rotate`
generates the first one and prints it once (`--recipient` / `--output` have it age-encrypted
instead of printed). Mind the terminal scrollback, and note that this makes the host plus the
master passphrase enough to recover an admin: that is the existing trust model.

`security.recover_admin.insecure_keyless_admin_recovery` skips the key. It exists for labs and demos;
do not turn it on for a pilot.

## 4. A non-admin with no recovery code: no supported path

Facts, all from the current source:

- `recover-admin` refuses a non-admin account (it "is specifically for restoring ADMIN accounts").
- `keyorix user reissue-one-time-password <user>` resets the **password**, not the second factor:
  "an enrolled second factor is left alone: stripping it would let a users.write holder take over
  an MFA-protected account" (`internal/core/reissue_otp.go`).
- There is no admin-initiated MFA-reset route in the OpenAPI document, and `mfa/disable` needs
  the user's own code or password on a signed-in session, which a user without a factor cannot
  reach on a `require_mfa` install.

So nothing here, run by an administrator, gets a non-admin without a recovery code past the second
factor. This is a gap, listed in section 6. Do not work around it by editing `mfa_secrets` or
`users` rows in the database: that skips the audit trail for an authentication change and is not
a path the product supports. Ask the user to look for a saved recovery code first (a password
manager, the codes printed at activation). Pending a product fix, escalate to the maintainers.

## 5. Refused despite a correct code: lockout, not MFA

Repeated failures lock an account or an address (HTTP 429 "Too many login attempts" for the
address budget). Clearing it touches nothing else: no password, MFA enrolment, session or role.
With the server stopped (or `--force` if you are certain it is safe):

```bash
keyorix-server admin clear-login-lockout --user alice@example.com --config ./keyorix.yaml
keyorix-server admin clear-login-lockout --ip 203.0.113.7 --config ./keyorix.yaml
```

At least one of `--user` / `--ip` is required; the run is audited as `admin.login_lockout_cleared`.
Also check the clock: a TOTP code is time-based, and a server or phone that is several minutes
off fails every code.

## 6. Verify and gaps

After any path: `keyorix audit logs --limit 20` shows the sequence (`mfa.disabled` or
`admin.recover_admin`, `mfa.enrolled`, `mfa.activated`, `auth.password_changed`).

Gaps:

- No administrator-run MFA reset for a non-admin user with local credentials and no recovery
  code (section 4).
- The CLI has no `mfa disable`, `mfa recovery-codes` or `mfa regenerate-recovery-codes`; they are
  web UI / API only (section 2).
