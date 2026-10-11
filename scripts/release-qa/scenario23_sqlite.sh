#!/usr/bin/env bash
# scripts/release-qa/scenario23_sqlite.sh -- RELEASE-QA scenarios 2 (restart
# survives) and 3 (backup -> wipe -> restore -> verify-audit -> secrets readable),
# SQLite only ('admin backup'/'admin restore' are sqlite-only; Postgres uses
# pg_dump per docs/SELF_HOSTING.md -- see scenario23_postgres.sh for that path).
#
# Usage: scenario23_sqlite.sh <server-bin> <cli-bin> [work-dir]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER_BIN="$1"
CLI_BIN="$2"
WORK_DIR="${3:-$(mktemp -d)}"
SERVER_PORT="${KEYORIX_QA_PORT:-18091}"
SERVER_URL="http://127.0.0.1:$SERVER_PORT"

fail() { echo "" >&2; echo "SCENARIO23 FAILED: $1" >&2; exit 1; }
pass() { echo "==> $1"; }

start_server() {
    KEYORIX_CONFIG_PATH="$CONFIG_PATH" "$SERVER_BIN" > "$WORK_DIR/server-$1.log" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 60); do
        if curl -fs "$SERVER_URL/health" >/dev/null 2>&1; then return 0; fi
        sleep 0.5
    done
    cat "$WORK_DIR/server-$1.log" >&2
    fail "keyorix-server ($1) did not become healthy"
}
stop_server() {
    kill "$SERVER_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do
        kill -0 "$SERVER_PID" 2>/dev/null || return 0
        sleep 0.25
    done
}

mkdir -p "$WORK_DIR"
SERVER_PID=""
cleanup() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT

REAL_HOME="$HOME"
export HOME="$WORK_DIR"
export KEYORIX_MASTER_PASSWORD="qa23-master-password-$$-${RANDOM}"
BOOTSTRAP_TOKEN="qa23-bootstrap-token-$$-${RANDOM}"
ADMIN_PASSWORD="Qa23-Test-Op3rator-Passw0rd!-$$-${RANDOM}"

cd "$WORK_DIR"
CONFIG_PATH="./keyorix.yaml"

pass "fresh install"
# Plain-HTTP harness: --dev where the binary has it (see scenario1.sh).
INIT_DEV=""
"$SERVER_BIN" admin init --help 2>&1 | grep -q -- '--dev' && INIT_DEV="--dev"
"$SERVER_BIN" admin init $INIT_DEV --config "$CONFIG_PATH" || fail "admin init exited non-zero"
sed -i.bak -E "s/port: \"8080\"/port: \"$SERVER_PORT\"/" "$CONFIG_PATH"
"$SERVER_BIN" admin encryption init --config "$CONFIG_PATH" || fail "admin encryption init exited non-zero"
"$SERVER_BIN" admin migrate --config "$CONFIG_PATH" || fail "admin migrate exited non-zero"

pass "start #1, bootstrap admin, create a secret"
KEYORIX_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" start_server "boot1"
"$CLI_BIN" system init --server "$SERVER_URL" --admin-username admin \
    --admin-password "$ADMIN_PASSWORD" --admin-email admin@release-qa.local \
    --bootstrap-token "$BOOTSTRAP_TOKEN" || fail "system init --server exited non-zero"
"$CLI_BIN" login --server "$SERVER_URL" --username admin --password "$ADMIN_PASSWORD" \
    || fail "login exited non-zero"

# ADR-112 item 1: security.require_mfa defaults on -- enrol for real (see
# scripts/smoke.sh's identical block for the full rationale), then log in
# again since ActivateMFA invalidates the pre-enrolment session. Done once,
# here, before everything else this scenario exercises (restart, backup,
# wipe, restore all operate on an already-MFA-enabled admin from this point on).
ENROLL_OUT="$("$CLI_BIN" mfa enroll)" || fail "mfa enroll exited non-zero"
MFA_SECRET="$(echo "$ENROLL_OUT" | grep -E '^  [A-Z2-7]+$' | tr -d '[:space:]')"
[ -n "$MFA_SECRET" ] || fail "could not parse MFA secret from:
$ENROLL_OUT"
MFA_CODE="$(cd "$REPO_ROOT" && HOME="$REAL_HOME" GOWORK=off go run scripts/totpgen/main.go "$MFA_SECRET")" \
    || fail "totpgen exited non-zero"
"$CLI_BIN" mfa activate --code "$MFA_CODE" --password "$ADMIN_PASSWORD" \
    || fail "mfa activate exited non-zero"
MFA_LOGIN_CODE="$(cd "$REPO_ROOT" && HOME="$REAL_HOME" GOWORK=off go run scripts/totpgen/main.go "$MFA_SECRET" 30)" \
    || fail "totpgen exited non-zero"
"$CLI_BIN" login --server "$SERVER_URL" --username admin --password "$ADMIN_PASSWORD" \
    --mfa-code "$MFA_LOGIN_CODE" || fail "login (MFA-enabled) exited non-zero"

SECRET_VALUE="qa23-value-$$-${RANDOM}"
"$CLI_BIN" secret create --name qa23-secret --value "$SECRET_VALUE" \
    --project 1 --environment 1 || fail "secret create exited non-zero"

pass "SCENARIO 2: restart survives"
stop_server
start_server "restart"
RESTART_GET="$("$CLI_BIN" secret get --id 1 --show-value)" || fail "secret get after restart exited non-zero"
echo "$RESTART_GET" | grep -qF "$SECRET_VALUE" || fail "secret value did not survive restart -- got:
$RESTART_GET"
# Session behaviour after restart: the CLI's stored token should still work (session
# persisted in the database, not in server memory) -- document what actually happens
# rather than assuming.
"$CLI_BIN" status || fail "'keyorix status' exited non-zero after restart"
pass "SCENARIO 2 PASSED: data + session both survived a full server restart"

pass "SCENARIO 3: backup -> wipe -> restore -> verify-audit -> secrets readable"
stop_server
BACKUP_ARCHIVE="./keyorix-backup.tar.gz.enc"
[ -f "$BACKUP_ARCHIVE" ] && fail "backup archive already exists (should not, --output must not pre-exist)"
"$SERVER_BIN" admin backup --config "$CONFIG_PATH" --output "$BACKUP_ARCHIVE" \
    || fail "admin backup exited non-zero"
[ -f "$BACKUP_ARCHIVE" ] || fail "admin backup did not create $BACKUP_ARCHIVE"

pass "wiping the live database + key material (simulating disaster)"
DB_PATH="$(grep -A3 '^  database:' "$CONFIG_PATH" | grep 'path:' | head -1 | sed -E 's/.*path: *"([^"]+)".*/\1/')"
[ -n "$DB_PATH" ] || fail "could not determine sqlite db path from config"
mv "$DB_PATH" "${DB_PATH}.wiped-aside"
[ -d "./keys" ] && mv "./keys" "./keys.wiped-aside"

pass "restore from backup"
"$SERVER_BIN" admin restore --config "$CONFIG_PATH" --input "$BACKUP_ARCHIVE" \
    || fail "admin restore exited non-zero (this also runs verify-audit internally and fails on a BROKEN chain)"

pass "verify-audit (explicit, standalone re-check)"
"$SERVER_BIN" admin verify-audit --config "$CONFIG_PATH" \
    || fail "admin verify-audit exited non-zero after restore -- audit chain not VALID"

pass "start #2 (post-restore), confirm secret is readable again"
start_server "postrestore"
RESTORE_GET="$("$CLI_BIN" secret get --id 1 --show-value)" || fail "secret get after restore exited non-zero"
echo "$RESTORE_GET" | grep -qF "$SECRET_VALUE" || fail "secret value did not survive backup/restore -- got:
$RESTORE_GET"

echo ""
echo "SCENARIO23 PASSED"
