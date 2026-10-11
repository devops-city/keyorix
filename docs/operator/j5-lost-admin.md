# Recovering a locked-out admin

What to do when every admin account is locked out, password-lost, or MFA-lost, and you
still have shell access to the host running the server. Every command below was run for
real against a fresh SQLite install with the shipped config (`security.require_mfa: true`,
the default) while writing this page (#3024, 2026-10-10).

## 0. Before you're locked out: generate a recovery key

Do this once, ahead of time, and store the printed key somewhere offline (a password
manager, a sealed envelope) — **not** in this terminal's scrollback or a log file. It is
shown exactly once.

```bash
export KEYORIX_MASTER_PASSWORD='your-existing-passphrase'
keyorix-server admin recovery-key rotate --config ./keyorix.yaml
```

Expected:

```
Recovery key generated (generation 1).

=====================================================================
  RECORD THIS KEY NOW -- it is shown exactly once and cannot be
  recovered later. Store it offline (password manager, sealed
  envelope) -- NOT in this terminal's scrollback or a log file.

  3LPS9-HWETE-XULZS-SDNYS-XQ5K9-VDY89-3YVQ8-SU8AP-EP7JG-PJFWU-FH
=====================================================================
```

On a local-KEK-file install, this key does not protect your secrets from host root — it
protects your admin account from anyone who is not you. Running this command again
replaces the key; the old one stops working immediately.

## 1. When locked out: stop the server

`recover-admin` needs exclusive access to the database, the same as any other `admin`
command.

```bash
# stop the running keyorix-server process first
```

## 2. Recover the account

```bash
printf '%s' '3LPS9-HWETE-XULZS-SDNYS-XQ5K9-VDY89-3YVQ8-SU8AP-EP7JG-PJFWU-FH' | \
  keyorix-server admin recover-admin --user admin@example.com --recovery-key - --config ./keyorix.yaml
```

`--recovery-key` must be exactly `-` — the key is always read from stdin, never a
command-line argument, so it never ends up in shell history or `ps` output.

Expected:

```
Recovered admin account: admin (user id 1).
Reset: account state, password, MFA enrollment,
  0 WebAuthn credential(s), login-lockout state, 1 active session(s).

One-time password (shown once — copy it now, it cannot be retrieved again):
  Qx-Wz+p^+LgF!3sPw33a
Log in as "admin" with this password. That session lasts at most 15 minutes and can only set a new
password (keyorix change-password) and enrol a second factor (keyorix mfa enroll + activate), in either
order. When both are done it ends; log in again with the new password and a code.
```

This reactivates the account if it was deactivated, sets a one-time password (printed
above, shown exactly once — copy it now), clears MFA/WebAuthn enrollment and the old
recovery codes (forcing re-enrollment), clears any lockout, and revokes every session
belonging to that account. It touches nothing else — no other user, role, project, or
secret. Every use is written to the audit trail (`admin.recover_admin`, naming the host
user who ran the command) and notifies every current admin, whether or not the server
happens to be running when you do this.

## 3. Restart the server, then log in with the one-time password

```bash
KEYORIX_CONFIG_PATH=./keyorix.yaml keyorix-server     # the server has no --config flag
keyorix login --server http://localhost:8080 --username admin --password 'Qx-Wz+p^+LgF!3sPw33a'
```

Expected: `Logged in to http://localhost:8080 as admin.` This is a **setup session**: it
lasts at most 15 minutes (refreshing does not extend it) and can do exactly two things —
set a new password and enrol a second factor. Everything else is refused:

```
$ keyorix secret list
Error: failed to list secrets: HTTP 403
```

Over the API the refusal names what is still owed:
`{"error":"PasswordChangeRequired", ..., "pending_steps":["change_password","enroll_mfa"]}`.
If the 15 minutes run out, log in again with the same one-time password.

## 4. Enrol a second factor and set a real password (either order)

Enrol TOTP (or, in the web UI, a passkey). The password `mfa activate` asks for is the
one-time password until you have changed it:

```bash
keyorix mfa enroll        # scan the otpauth:// URI or type the base32 secret into your app
keyorix mfa activate      # prompts for a code from the app and the account password
```

Expected: `MFA enabled. ...` followed by ten recovery codes — save them now, they are
shown once. The session stays signed in because the password change is still owed.

```bash
keyorix change-password   # prompts for the current (one-time) password and the new one
```

Expected:

```
Password changed. Account setup is complete and this session has ended:
run "keyorix login" with the new password and a code from your authenticator app.
```

Changing the password first and enrolling second works the same way; whichever step is
last ends the session (`mfa activate` then says `Account setup is complete ...`). Omit the
flags to be prompted (no terminal echo); passing `--current-password`/`--new-password`/
`--code`/`--password` on the command line works but leaves them in shell history.

## 5. Log in normally, with the second factor

```
$ keyorix secret list
Error: failed to list secrets: HTTP 401          # the setup session is gone
$ keyorix login --server http://localhost:8080 --username admin --password '<new password>'
Error: this account requires a second factor and there is no terminal to prompt on: pass --mfa-code ...
$ keyorix login --server http://localhost:8080 --username admin --password '<new password>' --mfa-code 123456
Logged in to http://localhost:8080 as admin.
$ keyorix secret list
Secrets List
...
```

(At a terminal, `keyorix login` prompts for the code instead.) The one-time password no
longer works (`401`). The audit trail shows the whole recovery:

```
$ keyorix audit logs --limit 8
EVENT                        DESCRIPTION
auth.login                   User admin logged in
mfa.login_verified           user admin passed MFA
auth.account_setup_completed user 1 finished account setup in a setup-only session (both setup steps are done); ...
auth.password_changed        user 1 changed their own password
mfa.activated                user admin activated MFA
mfa.reauth_verified          user admin completed MFA re-authentication ...
mfa.enrolled                 user admin began MFA enrolment
auth.login                   User admin logged in
```

and, further back, the `admin.recover_admin` event with the host user who ran step 2.

Do **not** set `security.require_mfa: false` to get through this: it is not needed, and it
weakens every account on the install. The same setup session is what a one-time-password
user (`keyorix user create --one-time-password`), a user an admin forced to reset
(`keyorix user force-password-reset`) or a user whose password expired gets on a
`require_mfa` install when they have no second factor yet. With `require_mfa: false` the
one-time-password login is only confined to `change-password`, and the session continues
after it.
