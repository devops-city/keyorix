#!/usr/bin/env bash
# scripts/release-qa/scenario1.sh -- RELEASE-QA scenario 1 (fresh install -> admin
# init -> start -> login -> project -> secret create/get/export -> machine identity
# token -> app read -> revoke -> denied), against real built binaries.
#
# Extends scripts/smoke.sh's golden path (init/login/project/secret) with the
# machine-identity token issue/read/revoke/deny leg the RELEASE-QA track's scenario
# 1 requires. Storage backend is sqlite by default; set KEYORIX_QA_STORAGE=postgres
# plus KEYORIX_QA_PG_DSN to run against Postgres instead (see docs/CONFIGURATION.md's
# storage.database.dsn form).
#
# Usage: scenario1.sh <server-bin> <cli-bin> [work-dir]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER_BIN="$1"
CLI_BIN="$2"
WORK_DIR="${3:-$(mktemp -d)}"
SERVER_PORT="${KEYORIX_QA_PORT:-18089}"
SERVER_URL="http://127.0.0.1:$SERVER_PORT"
STORAGE="${KEYORIX_QA_STORAGE:-sqlite}"

fail() { echo "" >&2; echo "SCENARIO1 FAILED: $1" >&2; exit 1; }
pass() { echo "==> $1"; }

[ -x "$SERVER_BIN" ] || fail "server binary not found/executable: $SERVER_BIN"
[ -x "$CLI_BIN" ] || fail "cli binary not found/executable: $CLI_BIN"

mkdir -p "$WORK_DIR"
SERVER_PID=""
cleanup() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT

REAL_HOME="$HOME"
export HOME="$WORK_DIR"
export KEYORIX_MASTER_PASSWORD="qa-master-password-$$-${RANDOM}"
BOOTSTRAP_TOKEN="qa-bootstrap-token-$$-${RANDOM}"
ADMIN_PASSWORD="Qa-Test-Op3rator-Passw0rd!-$$-${RANDOM}"

cd "$WORK_DIR"
CONFIG_PATH="./keyorix.yaml"

pass "keyorix-server admin init (storage=$STORAGE)"
# This harness drives plain HTTP. A binary with --dev (SECURE-DEFAULT-1) writes the
# secure baseline (TLS) by default, so ask for the DEV-ONLY config; an older
# release binary has no --dev and already writes the relaxed config.
INIT_DEV=""
"$SERVER_BIN" admin init --help 2>&1 | grep -q -- '--dev' && INIT_DEV="--dev"
"$SERVER_BIN" admin init $INIT_DEV --config "$CONFIG_PATH" || fail "admin init exited non-zero"
[ -f "$CONFIG_PATH" ] || fail "admin init did not create $CONFIG_PATH"
sed -i.bak -E "s/port: \"8080\"/port: \"$SERVER_PORT\"/" "$CONFIG_PATH"

if [ "$STORAGE" = "postgres" ]; then
    [ -n "${KEYORIX_QA_PG_DSN:-}" ] || fail "KEYORIX_QA_PG_DSN required when KEYORIX_QA_STORAGE=postgres"
    python3 - "$CONFIG_PATH" "$KEYORIX_QA_PG_DSN" <<'PYEOF' || fail "failed to rewrite storage block for postgres"
import re, sys
path, dsn = sys.argv[1], sys.argv[2]
with open(path) as f:
    text = f.read()
text = text.replace('type: sqlite  # options: sqlite, postgres', 'type: postgres  # options: sqlite, postgres')
text = re.sub(r'(  database:\n)(    # SQLite.*\n    path: "keyorix\.db"\n)',
              r'\1    dsn: "%s"\n' % dsn, text)
with open(path, 'w') as f:
    f.write(text)
PYEOF
fi
rm -f "$CONFIG_PATH.bak"

pass "keyorix-server admin encryption init"
"$SERVER_BIN" admin encryption init --config "$CONFIG_PATH" || fail "admin encryption init exited non-zero"

pass "keyorix-server admin migrate"
"$SERVER_BIN" admin migrate --config "$CONFIG_PATH" || fail "admin migrate exited non-zero"

pass "starting keyorix-server"
KEYORIX_CONFIG_PATH="$CONFIG_PATH" KEYORIX_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" "$SERVER_BIN" \
    > "$WORK_DIR/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 60); do
    if curl -fs "$SERVER_URL/health" >/dev/null 2>&1; then break; fi
    sleep 0.5
done
if ! curl -fs "$SERVER_URL/health" >/dev/null 2>&1; then
    echo "server never became healthy -- see $WORK_DIR/server.log" >&2
    cat "$WORK_DIR/server.log" >&2
    fail "keyorix-server did not start"
fi

pass "keyorix system init --server (bootstrap admin)"
"$CLI_BIN" system init --server "$SERVER_URL" --admin-username admin \
    --admin-password "$ADMIN_PASSWORD" --admin-email admin@release-qa.local \
    --bootstrap-token "$BOOTSTRAP_TOKEN" || fail "system init --server exited non-zero"

pass "keyorix login"
"$CLI_BIN" login --server "$SERVER_URL" --username admin --password "$ADMIN_PASSWORD" \
    || fail "login exited non-zero"

# ADR-112 item 1: security.require_mfa defaults on -- enrol for real (see
# scripts/smoke.sh's identical block for the full rationale), then log in
# again since ActivateMFA invalidates the pre-enrolment session.
pass "keyorix mfa enroll"
ENROLL_OUT="$("$CLI_BIN" mfa enroll)" || fail "mfa enroll exited non-zero"
MFA_SECRET="$(echo "$ENROLL_OUT" | grep -E '^  [A-Z2-7]+$' | tr -d '[:space:]')"
[ -n "$MFA_SECRET" ] || fail "could not parse MFA secret from:
$ENROLL_OUT"

pass "keyorix mfa activate"
MFA_CODE="$(cd "$REPO_ROOT" && HOME="$REAL_HOME" GOWORK=off go run scripts/totpgen/main.go "$MFA_SECRET")" \
    || fail "totpgen exited non-zero"
"$CLI_BIN" mfa activate --code "$MFA_CODE" --password "$ADMIN_PASSWORD" \
    || fail "mfa activate exited non-zero"

pass "keyorix login (again, now MFA-enabled)"
MFA_LOGIN_CODE="$(cd "$REPO_ROOT" && HOME="$REAL_HOME" GOWORK=off go run scripts/totpgen/main.go "$MFA_SECRET" 30)" \
    || fail "totpgen exited non-zero"
"$CLI_BIN" login --server "$SERVER_URL" --username admin --password "$ADMIN_PASSWORD" \
    --mfa-code "$MFA_LOGIN_CODE" || fail "login (MFA-enabled) exited non-zero"

pass "keyorix project create"
"$CLI_BIN" project create --name qa-project || fail "project create exited non-zero"

pass "keyorix secret create"
SECRET_VALUE="qa-value-$$-${RANDOM}"
"$CLI_BIN" secret create --name qa-secret --value "$SECRET_VALUE" \
    --project 1 --environment 1 || fail "secret create exited non-zero"

pass "keyorix secret get (value round-trip)"
GET_OUT="$("$CLI_BIN" secret get --id 1 --show-value)" || fail "secret get exited non-zero"
echo "$GET_OUT" | grep -qF "$SECRET_VALUE" || fail "secret get did not return the stored value -- got:
$GET_OUT"

pass "keyorix secret export"
EXPORT_OUT="$("$CLI_BIN" secret export --project 1 --env 1 --format json)" || fail "secret export exited non-zero"
echo "$EXPORT_OUT" | grep -qF "$SECRET_VALUE" || fail "secret export did not include the stored value -- got:
$EXPORT_OUT"

pass "keyorix machine create (app identity, same project as the secret: default/id=1)"
"$CLI_BIN" machine create --name qa-app --project default --type service \
    || fail "machine create exited non-zero"

pass "keyorix machine token issue"
TOKEN_OUT="$("$CLI_BIN" machine token issue qa-app --project default --name qa-app-token)" \
    || fail "machine token issue exited non-zero"
MACHINE_TOKEN="$(echo "$TOKEN_OUT" | grep -oE '[A-Za-z0-9_.\-]{24,}' | tail -1)"
[ -n "$MACHINE_TOKEN" ] || fail "could not extract machine token from issue output:
$TOKEN_OUT"

pass "keyorix machine grant-role (project_viewer)"
"$CLI_BIN" machine grant-role qa-app --project default --role project_viewer \
    || fail "machine grant-role exited non-zero"

pass "app read: machine token can read the secret"
APP_GET_OUT="$(KEYORIX_SERVER="$SERVER_URL" KEYORIX_TOKEN="$MACHINE_TOKEN" "$CLI_BIN" \
    secret get --id 1 --show-value)" || fail "app read (machine token) exited non-zero -- token auth broken:
$APP_GET_OUT"
echo "$APP_GET_OUT" | grep -qF "$SECRET_VALUE" || fail "app read via machine token did not return the stored value -- got:
$APP_GET_OUT"

pass "keyorix machine revoke"
"$CLI_BIN" machine revoke qa-app --project default --force || fail "machine revoke exited non-zero"

pass "denied: revoked machine token must be rejected"
if KEYORIX_SERVER="$SERVER_URL" KEYORIX_TOKEN="$MACHINE_TOKEN" "$CLI_BIN" \
    secret get --id 1 --show-value >"$WORK_DIR/denied.out" 2>&1; then
    fail "revoked machine token was still able to read the secret (should have been denied) -- output:
$(cat "$WORK_DIR/denied.out")"
fi
pass "confirmed: revoked token denied ($(cat "$WORK_DIR/denied.out" | head -1))"

echo ""
echo "SCENARIO1 PASSED"
