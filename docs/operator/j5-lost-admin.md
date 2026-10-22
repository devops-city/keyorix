# Recovering a locked-out admin

What to do when every admin account is locked out, password-lost, or MFA-lost, and you
still have shell access to the host running the server. The output below is illustrative
(user ids, the key, the one-time password and times differ on your install); it assumes the
shipped config (`security.require_mfa: true`, the default) and a server that serves TLS
with the certificate `admin init` generated, so the CLI needs `--ca-file certs/server.crt`
(or `keyorix config set ca_file`).

A user who has only lost their authenticator code, and is not locked out of everything, may not
need this page: see [lost-totp-runbook.md](lost-totp-runbook.md) for the decision tree.

## 0. Before you're locked out: generate a recovery key

Do this once, ahead of time, and store the printed key somewhere offline (a password
manager, a sealed envelope) — **not** in this terminal's scrollback or a log file. It is
shown exactly once.

```bash
export KEYORIX_MASTER_PASSWORD_FILE=./secrets/master_password   # or KEYORIX_MASTER_PASSWORD, --passphrase-file, --passphrase-stdin
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
Expires: 2026-10-11T09:30:12Z (UTC). After that, login with it is refused like a wrong password; run recover-admin again for a new one.
Log in as "admin" with this password. That session lasts at most 15 minutes and can only set a new
password (keyorix change-password) and enrol a second factor (keyorix mfa enroll + activate), in either
order. When both are done it ends; log in again with the new password and a code.
```

This reactivates the account if it was deactivated, sets a one-time password (printed
above, shown exactly once — copy it now), clears MFA/WebAuthn enrollment and the old
recovery codes (forcing re-enrollment), clears any lockout, and revokes every session
belonging to that account. The one-time password **expires**: 24 hours after the run by
default (`security.recovery_one_time_password_ttl`, e.g. `4h`), at the UTC time printed
on the `Expires:` line. Log in and change it before then; an expired password is refused
exactly like a wrong one (same `401`, no hint that it was merely late; the server audits
`auth.one_time_password_expired`, and each refused attempt counts toward the account
lockout). If it expires unused, run `recover-admin` again — it issues a fresh password
and a fresh expiry. It touches nothing else — no other user, role, project, or
secret. Every use is written to the audit trail (`admin.recover_admin`, naming the host
user who ran the command) and notifies every current admin, whether or not the server
happens to be running when you do this.

## 3. Restart the server, then log in with the one-time password

```bash
KEYORIX_CONFIG_PATH=./keyorix.yaml keyorix-server     # the server has no --config flag
keyorix login --server https://localhost:8080 --ca-file certs/server.crt --username admin   # paste the one-time password at the hidden prompt
```

Expected: `Logged in to https://localhost:8080 as admin.` This is a **setup session**: it
lasts at most 15 minutes (refreshing does not extend it) and can do exactly two things —
set a new password and enrol a second factor. Everything else is refused:

```
$ keyorix secret list
Error: failed to list secrets: Finish account setup before continuing: change your password and enrol a second factor (MFA), in either order. (HTTP 403) Next step: you do not have permission for this; ask a project admin, or request access with `keyorix request access`.
```

(The "Next step" text is the CLI's generic hint for any 403; it does not apply here. What is owed
is in the message before it.)

Over the API the refusal names what is still owed:
`{"error":"PasswordChangeRequired", ..., "pending_steps":["change_password","enroll_mfa"]}`.
If the 15 minutes run out, log in again with the same one-time password — as long as it
has not expired (step 2 printed when); once it has, go back to step 2.

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
Error: failed to list secrets: Account setup is complete. Sign in again with your new password and second factor. (HTTP 401) Next step: run `keyorix login` to sign in again (the session may have expired or been revoked).
$ keyorix login --server https://localhost:8080 --ca-file certs/server.crt --username admin
Password:                                        # the new password, no echo
Authenticator code (or an unused recovery code):
Logged in to https://localhost:8080 as admin.
$ keyorix secret list
Secrets List
...
```

(Without a terminal there is nothing to prompt on, and `keyorix login` stops with an error naming the flag to use for the code; prefer a terminal for a recovery.) The one-time password no
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

**Not locked out yourself?** `recover-admin` is for the *last* way back into your own account.
If it is a colleague whose one-time password expired or got lost and you can still log in, you
do not need the host or the recovery key: any administrator with `users.write` (and rank over
that account) can run `keyorix user reissue-one-time-password <user id or email>`. It prints a
new one-time password once, ends the user's sessions and puts them through the same
change-password / enrol-MFA setup session described here. It refuses your *own* account (that
is what this runbook is for) and SSO-only users. See
[CONFIGURATION.md](../CONFIGURATION.md#security) ("Reissuing a one-time password").

Do **not** set `security.require_mfa: false` to get through this: it is not needed, and it
weakens every account on the install. The same setup session is what a one-time-password
user (`keyorix user create --one-time-password`, which also prints an `Expires:` time,
72 hours by default, `security.one_time_password_ttl`), a user an admin forced to reset
(`keyorix user force-password-reset`) or a user whose password expired gets on a
`require_mfa` install when they have no second factor yet. With `require_mfa: false` the
one-time-password login is only confined to `change-password`, and the session continues
after it.
