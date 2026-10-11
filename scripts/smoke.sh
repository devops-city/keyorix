#!/usr/bin/env bash
# scripts/smoke.sh -- the CI + release gate for the SHIPPED $(BINARY_CLI) binary
# (Phase 5, ADR-108). Executes QUICK_START.md's flow, step for step, against real
# built binaries, in an isolated HOME/cwd. Keep this file's steps in exact
# correspondence with QUICK_START.md -- if you change one, change the other.
#
# This is the executing counterpart to cli/cmd/quickstart_commands_test.go and
# server/admin/quickstart_commands_test.go, which only prove every command QUICK_START.md
# documents resolves to a real command with real flags -- their own header says they
# "do not run them." This script runs the flow for real, including the exact
# `secret export --project --env --format json` call
# integrations/github-action/entrypoint.sh makes, so a break in that contract is
# caught here too. Neither mechanism is sufficient alone: one proves the commands
# exist, this one proves they work.
#
# The new CLI is REST-only -- there is no embedded/local mode to smoke test here.
# The old CLI's embedded-mode flow (internal/cli, scripts/smoke-legacy.sh) was
# deleted in Phase 6 (ADR-108 Decision C) along with internal/cli itself.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI_BIN="$REPO_ROOT/bin/keyorix"
SERVER_BIN="$REPO_ROOT/bin/keyorix-server"
SERVER_PORT=18089
SERVER_URL="http://127.0.0.1:$SERVER_PORT"

fail() {
    echo "" >&2
    echo "SMOKE TEST FAILED: $1" >&2
    exit 1
}

if [ ! -x "$CLI_BIN" ]; then
    echo "==> bin/keyorix not found, building it"
    (cd "$REPO_ROOT/cli" && GOWORK=off go build -o "$CLI_BIN" .) || fail "go build did not produce $CLI_BIN"
fi
if [ ! -x "$SERVER_BIN" ]; then
    echo "==> bin/keyorix-server not found, building it"
    (cd "$REPO_ROOT" && go build -o "$SERVER_BIN" ./server) || fail "go build did not produce $SERVER_BIN"
fi

SMOKE_DIR="$(mktemp -d)"
SERVER_PID=""
cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    rm -rf "$SMOKE_DIR"
}
trap cleanup EXIT

echo "==> Isolated smoke test dir: $SMOKE_DIR"

# HOME isolation: a real ~/.keyorix/ credential file must never be visible to this
# run, and must never be overwritten by it. REAL_HOME is kept aside so the
# scripts/totpgen `go run` call below (needs the real module cache, not a
# throwaway one under this ephemeral dir -- `go run` under the isolated HOME
# re-resolves GOPATH/GOMODCACHE there and re-downloads the entire module
# graph on every run) can still find Go's real toolchain state.
REAL_HOME="$HOME"
export HOME="$SMOKE_DIR"
export KEYORIX_MASTER_PASSWORD="smoke-test-master-password-$$-${RANDOM}"
BOOTSTRAP_TOKEN="smoke-test-bootstrap-token-$$-${RANDOM}"
# Must satisfy internal/core/rules.DefaultPasswordPolicy: >=16 chars, upper,
# lower, digit, and special, and must not contain the account's username/
# email/display name -- the plain lowercase/digit/hyphen form this used to be
# failed "password must contain an uppercase letter" against a real bootstrap
# call (only exercised once this script became the actual release gate; a
# mocked/unit test never validates a real password against the policy), and
# "Admin" in the password collided with --admin-username admin below.
ADMIN_PASSWORD="Smoke-Test-Op3rator-Passw0rd!-$$-${RANDOM}"

cd "$SMOKE_DIR"
# admin init refuses an absolute --config path (securefiles.SecureWriteFileSync
# requires a path relative to its base dir) -- relative, from this cwd, like the
# old smoke.sh's equivalent step.
CONFIG_PATH="./keyorix.yaml"

echo "==> keyorix-server admin init"
"$SERVER_BIN" admin init --config "$CONFIG_PATH" || fail "admin init exited non-zero"
[ -f "$CONFIG_PATH" ] || fail "admin init did not create $CONFIG_PATH"
# admin init's generated config always listens on the default port -- point this
# run's server at an isolated one so it never collides with a real dev server or
# scripts/cli-parity-check.sh's own instance.
sed -i.bak -E "s/port: \"8080\"/port: \"$SERVER_PORT\"/" "$CONFIG_PATH"
rm -f "$CONFIG_PATH.bak"

echo "==> keyorix-server admin encryption init"
"$SERVER_BIN" admin encryption init --config "$CONFIG_PATH" || fail "admin encryption init exited non-zero"

echo "==> keyorix-server admin migrate"
"$SERVER_BIN" admin migrate --config "$CONFIG_PATH" || fail "admin migrate exited non-zero"

echo "==> starting keyorix-server"
KEYORIX_CONFIG_PATH="$CONFIG_PATH" KEYORIX_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" "$SERVER_BIN" \
    > "$SMOKE_DIR/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 30); do
    if curl -fs "$SERVER_URL/health" >/dev/null 2>&1; then break; fi
    sleep 0.5
done
if ! curl -fs "$SERVER_URL/health" >/dev/null 2>&1; then
    echo "server never became healthy -- see $SMOKE_DIR/server.log" >&2
    cat "$SMOKE_DIR/server.log" >&2
    fail "keyorix-server did not start"
fi

echo "==> keyorix system init --server (bootstrap admin + default workspace)"
"$CLI_BIN" system init --server "$SERVER_URL" --admin-username admin \
    --admin-password "$ADMIN_PASSWORD" --admin-email admin@smoke-test.local \
    --bootstrap-token "$BOOTSTRAP_TOKEN" || fail "system init --server exited non-zero"

echo "==> keyorix login"
"$CLI_BIN" login --server "$SERVER_URL" --username admin --password "$ADMIN_PASSWORD" \
    || fail "login exited non-zero"

# ADR-112 item 1: security.require_mfa defaults on, so admin init's generated
# config enforces it from this run's first boot. The bootstrap admin has no
# MFA enrolled yet, so EnforceAccountSetup confines this session to the
# enrolment endpoints until it enrols -- every OTHER authenticated call below
# (starting with project create) would otherwise fail closed with
# "This deployment requires multi-factor authentication." Enrol for real,
# the way an operator would: `mfa enroll` returns a fresh TOTP secret,
# scripts/totpgen computes a code from it the way an authenticator app
# would (there is no human here to read one off a phone), and `mfa activate`
# confirms enrolment with that code plus the account password.
echo "==> keyorix mfa enroll"
ENROLL_OUT="$("$CLI_BIN" mfa enroll)" || fail "mfa enroll exited non-zero"
MFA_SECRET="$(echo "$ENROLL_OUT" | grep -E '^  [A-Z2-7]+$' | tr -d '[:space:]')"
[ -n "$MFA_SECRET" ] || fail "could not parse MFA secret from:
$ENROLL_OUT"

echo "==> keyorix mfa activate"
MFA_CODE="$(cd "$REPO_ROOT" && HOME="$REAL_HOME" GOWORK=off go run scripts/totpgen/main.go "$MFA_SECRET")" \
    || fail "totpgen exited non-zero"
"$CLI_BIN" mfa activate --code "$MFA_CODE" --password "$ADMIN_PASSWORD" \
    || fail "mfa activate exited non-zero"

# ActivateMFA invalidates every OTHER session for this user (the calling session
# is kept, #2978), so a pre-MFA session elsewhere cannot outlive the upgrade.
# Log in again anyway, to exercise the MFA login path: the account now has MFA
# enabled, so this second attempt gets mfa_required instead of a token
# directly -- exercises the exact two-step login path (`--mfa-code`,
# completing POST /auth/mfa/verify) a real operator's SECOND-and-later
# login goes through from now on.
echo "==> keyorix login (again, now MFA-enabled)"
# +30s step offset: ActivateMFA just marked the CURRENT step's code used
# (anti-replay) -- without the offset this would very likely compute the
# identical code (same 30s window) and get rejected as a replay.
MFA_LOGIN_CODE="$(cd "$REPO_ROOT" && HOME="$REAL_HOME" GOWORK=off go run scripts/totpgen/main.go "$MFA_SECRET" 30)" \
    || fail "totpgen exited non-zero"
"$CLI_BIN" login --server "$SERVER_URL" --username admin --password "$ADMIN_PASSWORD" \
    --mfa-code "$MFA_LOGIN_CODE" || fail "login (MFA-enabled) exited non-zero"

echo "==> keyorix project create"
"$CLI_BIN" project create --name smoke-project || fail "project create exited non-zero"

echo "==> keyorix secret create"
SECRET_VALUE="smoke-value-$$-${RANDOM}"
"$CLI_BIN" secret create --name smoke-secret --value "$SECRET_VALUE" \
    --project 1 --environment 1 || fail "secret create exited non-zero"

echo "==> keyorix secret get (value round-trip)"
GET_OUT="$("$CLI_BIN" secret get --id 1 --show-value)" || fail "secret get exited non-zero"
echo "$GET_OUT" | grep -qF "$SECRET_VALUE" || fail \
    "secret get did not return the value that was stored -- got:
$GET_OUT"

echo "==> keyorix secret export (the exact call integrations/github-action/entrypoint.sh makes)"
EXPORT_OUT="$("$CLI_BIN" secret export --project 1 --env 1 --format json)" || fail "secret export exited non-zero"
echo "$EXPORT_OUT" | grep -qF "$SECRET_VALUE" || fail \
    "secret export did not include the value that was stored -- got:
$EXPORT_OUT"

# Sharing (QUICK_START.md "Sharing" section): holding the global admin role from
# bootstrap is NOT enough to share a secret -- both the owner and the recipient need
# an explicit project role first, or share create 403s with no explanation. This was
# a real, newcomer-blocking bug found live (see docs/operator/demo.md); keep this
# step in exact correspondence with QUICK_START.md's Sharing section, like every
# other step in this file.
echo "==> keyorix user create (share recipient)"
"$CLI_BIN" user create --username alice --email alice@smoke-test.local --one-time-password \
    || fail "user create exited non-zero"

echo "==> keyorix rbac assign-role (owner + recipient, both required before sharing)"
"$CLI_BIN" rbac assign-role --user admin@smoke-test.local --role project_admin --project default \
    || fail "rbac assign-role (owner) exited non-zero"
"$CLI_BIN" rbac assign-role --user alice@smoke-test.local --role project_viewer --project default \
    || fail "rbac assign-role (recipient) exited non-zero"

echo "==> keyorix share create + share list"
"$CLI_BIN" share create --secret-id 1 --recipient-id 2 --permission read \
    || fail "share create exited non-zero -- did the rbac assign-role steps above stop matching QUICK_START.md's Sharing section?"
SHARE_LIST_OUT="$("$CLI_BIN" share list --secret-id 1)" || fail "share list exited non-zero"
# share list identifies the recipient by ID (2, alice), not by name.
echo "$SHARE_LIST_OUT" | grep -qE '^1[[:space:]]+1[[:space:]]+1[[:space:]]+2[[:space:]]' || fail \
    "share list did not show alice (recipient id 2) as the share recipient -- got:
$SHARE_LIST_OUT"

# Machine identity access (QUICK_START.md "Giving a machine access" section):
# issue a token, confirm it's denied until granted a project role, grant it via
# `machine grant-role`, confirm the token can now read the secret, revoke the
# role via `machine revoke-role`, confirm the token is denied again.
echo "==> keyorix machine create + token issue"
# The secret created above lives in project 1 (--project 1, "default") -- the
# machine identity must be created there too, not in "smoke-project" (project
# 2), or its role grant scopes to the wrong project and the read stays denied.
"$CLI_BIN" machine create --name smoke-ci-app --project default --type ci \
    || fail "machine create exited non-zero"
TOKEN_OUT="$("$CLI_BIN" machine token issue smoke-ci-app --name smoke-token-1 \
    --project default --expires-in-days 30)" || fail "machine token issue exited non-zero"
APP_TOKEN="$(echo "$TOKEN_OUT" | grep '^Token:' | awk '{print $2}')"
[ -n "$APP_TOKEN" ] || fail "could not parse machine token from:
$TOKEN_OUT"

echo "==> machine token denied before grant-role"
DENIED_CODE="$(curl -s -o /dev/null -w '%{http_code}' "$SERVER_URL/api/v1/secrets/1?include_value=true" \
    -H "Authorization: Bearer $APP_TOKEN")"
[ "$DENIED_CODE" = "403" ] || fail "expected 403 before grant-role, got $DENIED_CODE"

echo "==> keyorix machine grant-role"
"$CLI_BIN" machine grant-role smoke-ci-app --project default --role project_viewer \
    || fail "machine grant-role exited non-zero"

echo "==> machine token reads the secret after grant-role"
READ_OUT="$(curl -s "$SERVER_URL/api/v1/secrets/1?include_value=true" \
    -H "Authorization: Bearer $APP_TOKEN")"
echo "$READ_OUT" | grep -qF "$SECRET_VALUE" || fail \
    "machine token did not read the secret value after grant-role -- got:
$READ_OUT"

echo "==> keyorix machine revoke-role"
"$CLI_BIN" machine revoke-role smoke-ci-app --project default --role project_viewer \
    || fail "machine revoke-role exited non-zero"

echo "==> machine token denied again after revoke-role"
REVOKED_CODE="$(curl -s -o /dev/null -w '%{http_code}' "$SERVER_URL/api/v1/secrets/1?include_value=true" \
    -H "Authorization: Bearer $APP_TOKEN")"
[ "$REVOKED_CODE" = "403" ] || fail "expected 403 after revoke-role, got $REVOKED_CODE"

echo ""
echo "SMOKE TEST PASSED"
