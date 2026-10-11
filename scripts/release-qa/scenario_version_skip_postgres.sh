#!/usr/bin/env bash
# scripts/release-qa/scenario_version_skip_postgres.sh -- design-b3-backup-v2.md
# §11.1/H6's version-skipping upgrade proof: `admin backup` with a REAL OLD
# release binary (sqlite), then HEAD gets that data into a REAL, separate
# Postgres database, then prove secrets decrypt identically, the audit chain
# verifies, and authz answers (allowed AND denied) match what the old binary
# computed for the identical stored grants.
#
# The OLD binary writes the v1 (physical, sqlite-only) archive format --
# v1 archives can ONLY restore into sqlite, by design (design §3.6 decision
# 3, server/admin/restore.go's own explicit isPostgresStorage refusal for
# v1 -- there is no "raw sqlite file bytes" equivalent on Postgres, so this
# is a real, permanent constraint, not a gap to route around). The
# documented real-world path this script proves end-to-end: HEAD restores
# the v1 archive into an intermediate sqlite database (still proving a real
# old-binary archive restores on HEAD, same as H5's dedicated test but as
# part of the full operator procedure here), HEAD takes a fresh v2 backup OF
# that now-current-schema sqlite database, and THAT v2 archive is what
# restores into the Postgres target -- the actual sqlite->postgres leg.
#
# Usage: scenario_version_skip_postgres.sh <old-server-bin> <old-cli-bin> \
#          <new-server-bin> <new-cli-bin> <postgres-dsn> [work-dir]
#
# <postgres-dsn> must point at an EMPTY, dedicated Postgres database --
# restore refuses a non-empty target by design (refuseNonEmptyPostgresTarget).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OLD_SERVER_BIN="$1"
OLD_CLI_BIN="$2"
NEW_SERVER_BIN="$3"
NEW_CLI_BIN="$4"
PG_DSN="$5"
WORK_DIR="${6:-$(mktemp -d)}"
SERVER_PORT="${KEYORIX_QA_PORT:-18095}"
SERVER_URL="http://127.0.0.1:$SERVER_PORT"

fail() { echo "" >&2; echo "VERSION-SKIP PROOF FAILED: $1" >&2; exit 1; }
pass() { echo "==> $1"; }

for bin in "$OLD_SERVER_BIN" "$OLD_CLI_BIN" "$NEW_SERVER_BIN" "$NEW_CLI_BIN"; do
    [ -x "$bin" ] || fail "binary not found/executable: $bin"
done
[ -n "$PG_DSN" ] || fail "postgres-dsn argument is required"

mkdir -p "$WORK_DIR"
SERVER_PID=""
cleanup() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT

start_server() {
    local bin="$1" cfg="$2" label="$3"
    KEYORIX_CONFIG_PATH="$cfg" "$bin" > "$WORK_DIR/server-$label.log" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 60); do
        if curl -fs "$SERVER_URL/health" >/dev/null 2>&1; then return 0; fi
        sleep 0.5
    done
    cat "$WORK_DIR/server-$label.log" >&2
    fail "keyorix-server ($label) did not become healthy"
}
stop_server() {
    kill "$SERVER_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do
        kill -0 "$SERVER_PID" 2>/dev/null || return 0
        sleep 0.25
    done
    SERVER_PID=""
}

REAL_HOME="$HOME"
export HOME="$WORK_DIR"
export KEYORIX_MASTER_PASSWORD="qavs-master-password-$$-${RANDOM}"
BOOTSTRAP_TOKEN="qavs-bootstrap-token-$$-${RANDOM}"
ADMIN_PASSWORD="Qavs-Test-Op3rator-Passw0rd!-$$-${RANDOM}"

# The CLI caches its session token in $HOME's OS config dir
# (~/Library/Application Support/keyorix/credentials.yaml on macOS),
# keyed by server_url -- and this script deliberately reuses the SAME
# SERVER_PORT (and therefore the same server_url) for phase 1's OLD
# server and phase 2's HEAD server, since it's simulating one host
# upgrading in place. A stale token cached under that URL from phase 1's
# login breaks the new CLI's phase-2 login against the same URL (found
# live: a direct curl POST to /auth/login succeeded with 200, but the
# HEAD CLI's own `login` command failed with 401 against the identical
# server/credentials -- isolated to this cached-credentials file, not a
# restore or auth-path defect). clear_cli_credentials is called before
# each phase's login for exactly this reason.
clear_cli_credentials() {
    rm -rf "$HOME/Library/Application Support/keyorix" "$HOME/.config/keyorix" "$HOME/.keyorix" 2>/dev/null || true
}

OLD_DIR="$WORK_DIR/old"
mkdir -p "$OLD_DIR"
cd "$OLD_DIR"
OLD_CONFIG="./keyorix.yaml"

echo "============================================================"
echo " PHASE 1: OLD binary ($OLD_SERVER_BIN) -- fresh sqlite install"
echo "============================================================"

pass "old: admin init / encryption init / migrate (sqlite)"
"$OLD_SERVER_BIN" admin init --config "$OLD_CONFIG" || fail "old admin init exited non-zero"
sed -i.bak -E "s/port: \"8080\"/port: \"$SERVER_PORT\"/" "$OLD_CONFIG"
rm -f "$OLD_CONFIG.bak"
"$OLD_SERVER_BIN" admin encryption init --config "$OLD_CONFIG" || fail "old admin encryption init exited non-zero"
"$OLD_SERVER_BIN" admin migrate --config "$OLD_CONFIG" || fail "old admin migrate exited non-zero"

pass "old: start, bootstrap admin, login"
KEYORIX_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" start_server "$OLD_SERVER_BIN" "$OLD_CONFIG" "old"
clear_cli_credentials
"$OLD_CLI_BIN" system init --server "$SERVER_URL" --admin-username admin \
    --admin-password "$ADMIN_PASSWORD" --admin-email admin@release-qa.local \
    --bootstrap-token "$BOOTSTRAP_TOKEN" || fail "old system init --server exited non-zero"
"$OLD_CLI_BIN" login --server "$SERVER_URL" --username admin --password "$ADMIN_PASSWORD" \
    || fail "old login exited non-zero"

pass "old: create project + secret"
"$OLD_CLI_BIN" project create --name qavs-project || fail "old project create exited non-zero"
SECRET_VALUE="qavs-secret-value-$$-${RANDOM}"
"$OLD_CLI_BIN" secret create --name qavs-secret --value "$SECRET_VALUE" \
    --project 1 --environment 1 || fail "old secret create exited non-zero"

pass "old: machine identity granted project_viewer -- PROBE A (must be ALLOWED)"
"$OLD_CLI_BIN" machine create --name qavs-app-allowed --project default --type service \
    || fail "old machine create (allowed) exited non-zero"
ALLOWED_TOKEN_OUT="$("$OLD_CLI_BIN" machine token issue qavs-app-allowed --project default --name qavs-allowed-token)" \
    || fail "old machine token issue (allowed) exited non-zero"
ALLOWED_TOKEN="$(echo "$ALLOWED_TOKEN_OUT" | grep -oE '[A-Za-z0-9_.\-]{24,}' | tail -1)"
[ -n "$ALLOWED_TOKEN" ] || fail "could not extract allowed machine token from:
$ALLOWED_TOKEN_OUT"
"$OLD_CLI_BIN" machine grant-role qavs-app-allowed --project default --role project_viewer \
    || fail "old machine grant-role exited non-zero"
PROBE_A_BEFORE_OUT="$(KEYORIX_SERVER="$SERVER_URL" KEYORIX_TOKEN="$ALLOWED_TOKEN" "$OLD_CLI_BIN" \
    secret get --id 1 --show-value)" || fail "PROBE A (before, should be allowed) failed:
$PROBE_A_BEFORE_OUT"
echo "$PROBE_A_BEFORE_OUT" | grep -qF "$SECRET_VALUE" \
    || fail "PROBE A (before): granted token did not read the correct value -- got:
$PROBE_A_BEFORE_OUT"
pass "PROBE A (before, old binary): granted machine token ALLOWED to read secret -- confirmed"

pass "old: machine identity with NO role -- PROBE B (must be DENIED)"
"$OLD_CLI_BIN" machine create --name qavs-app-denied --project default --type service \
    || fail "old machine create (denied) exited non-zero"
DENIED_TOKEN_OUT="$("$OLD_CLI_BIN" machine token issue qavs-app-denied --project default --name qavs-denied-token)" \
    || fail "old machine token issue (denied) exited non-zero"
DENIED_TOKEN="$(echo "$DENIED_TOKEN_OUT" | grep -oE '[A-Za-z0-9_.\-]{24,}' | tail -1)"
[ -n "$DENIED_TOKEN" ] || fail "could not extract denied machine token from:
$DENIED_TOKEN_OUT"
PROBE_B_BEFORE_STATUS=0
PROBE_B_BEFORE_OUT="$(KEYORIX_SERVER="$SERVER_URL" KEYORIX_TOKEN="$DENIED_TOKEN" "$OLD_CLI_BIN" \
    secret get --id 1 --show-value 2>&1)" || PROBE_B_BEFORE_STATUS=$?
[ "$PROBE_B_BEFORE_STATUS" -ne 0 ] || fail "PROBE B (before): unrole'd token was able to read the secret (should have been denied) -- output:
$PROBE_B_BEFORE_OUT"
pass "PROBE B (before, old binary): role-less machine token DENIED -- confirmed ($PROBE_B_BEFORE_OUT)"

pass "old: stop server, admin backup"
stop_server
OLD_ARCHIVE="$OLD_DIR/version-skip-backup.tar.gz"
"$OLD_SERVER_BIN" admin backup --config "$OLD_CONFIG" --output "$OLD_ARCHIVE" \
    || fail "old admin backup exited non-zero"
[ -f "$OLD_ARCHIVE" ] || fail "old admin backup did not create $OLD_ARCHIVE"
pass "old: backup archive written: $OLD_ARCHIVE"

echo ""
echo "============================================================"
echo " PHASE 2a: HEAD binary ($NEW_SERVER_BIN) -- restore v1 archive into an"
echo "           intermediate sqlite database (v1 archives are sqlite-only"
echo "           by design; this IS the real upgrade path's first hop)"
echo "============================================================"

MID_DIR="$WORK_DIR/mid"
mkdir -p "$MID_DIR"
cd "$MID_DIR"
MID_CONFIG="./keyorix.yaml"
MID_DB="$MID_DIR/keyorix.db"
cat > "$MID_CONFIG" <<EOF
storage:
  type: sqlite
  database:
    path: "$MID_DB"
  encryption:
    enabled: true
    dek_path: "keys/dek.key"
    salt_path: "keys/kek.salt"
server:
  http:
    enabled: true
    port: "$SERVER_PORT"
    protocol_versions: ["1.1"]
    tls:
      enabled: false
EOF

pass "mid: admin restore (old-binary v1 archive -> HEAD/sqlite intermediate)"
"$NEW_SERVER_BIN" admin restore --config "$MID_CONFIG" --input "$OLD_ARCHIVE" \
    || fail "mid admin restore (v1->sqlite) exited non-zero"

pass "mid: admin verify-audit (explicit, standalone re-check)"
"$NEW_SERVER_BIN" admin verify-audit --config "$MID_CONFIG" \
    || fail "mid admin verify-audit exited non-zero -- audit chain not VALID after the v1->sqlite hop"

pass "mid: fresh v2 backup of the intermediate sqlite database"
MID_ARCHIVE="$MID_DIR/version-skip-v2-backup.tar.gz"
"$NEW_SERVER_BIN" admin backup --config "$MID_CONFIG" --output "$MID_ARCHIVE" \
    || fail "mid admin backup (v2) exited non-zero"
[ -f "$MID_ARCHIVE" ] || fail "mid admin backup did not create $MID_ARCHIVE"

echo ""
echo "============================================================"
echo " PHASE 2b: HEAD binary -- restore the v2 archive into Postgres"
echo "============================================================"

NEW_DIR="$WORK_DIR/new"
mkdir -p "$NEW_DIR"
cd "$NEW_DIR"
NEW_CONFIG="./keyorix.yaml"

pass "new: writing Postgres target config (key paths must match the intermediate's own template)"
cat > "$NEW_CONFIG" <<EOF
storage:
  type: postgres
  database:
    dsn: "$PG_DSN"
  encryption:
    enabled: true
    dek_path: "keys/dek.key"
    salt_path: "keys/kek.salt"
server:
  http:
    enabled: true
    port: "$SERVER_PORT"
    protocol_versions: ["1.1"]
    tls:
      enabled: false
EOF

pass "new: admin restore (v2 archive -> HEAD/postgres target)"
"$NEW_SERVER_BIN" admin restore --config "$NEW_CONFIG" --input "$MID_ARCHIVE" \
    || fail "new admin restore (v2->postgres) exited non-zero (this also runs verify-audit internally and fails on a BROKEN chain)"

pass "new: admin verify-audit (explicit, standalone re-check)"
"$NEW_SERVER_BIN" admin verify-audit --config "$NEW_CONFIG" \
    || fail "new admin verify-audit exited non-zero after restore -- audit chain not VALID"

pass "new: start HEAD server against restored Postgres database"
start_server "$NEW_SERVER_BIN" "$NEW_CONFIG" "new"

pass "new: login"
clear_cli_credentials
"$NEW_CLI_BIN" login --server "$SERVER_URL" --username admin --password "$ADMIN_PASSWORD" \
    || fail "new login exited non-zero"

# ADR-112 item 1: security.require_mfa defaults on for the HEAD binary --
# the restored admin account predates MFA entirely (old binary, old
# schema default), so this login succeeds as a plain session but is
# confined to the enrolment endpoints (EnforceAccountSetup) until it
# enrols. Enrol for real (see scripts/smoke.sh's identical block for the
# full rationale), then log in again since ActivateMFA invalidates the
# pre-enrolment session.
pass "new: mfa enroll"
ENROLL_OUT="$("$NEW_CLI_BIN" mfa enroll)" || fail "new mfa enroll exited non-zero"
MFA_SECRET="$(echo "$ENROLL_OUT" | grep -E '^  [A-Z2-7]+$' | tr -d '[:space:]')"
[ -n "$MFA_SECRET" ] || fail "could not parse MFA secret from:
$ENROLL_OUT"

pass "new: mfa activate"
MFA_CODE="$(cd "$REPO_ROOT" && HOME="$REAL_HOME" GOWORK=off go run scripts/totpgen/main.go "$MFA_SECRET")" \
    || fail "totpgen exited non-zero"
"$NEW_CLI_BIN" mfa activate --code "$MFA_CODE" --password "$ADMIN_PASSWORD" \
    || fail "new mfa activate exited non-zero"

pass "new: login (again, now MFA-enabled)"
MFA_LOGIN_CODE="$(cd "$REPO_ROOT" && HOME="$REAL_HOME" GOWORK=off go run scripts/totpgen/main.go "$MFA_SECRET" 30)" \
    || fail "totpgen exited non-zero"
"$NEW_CLI_BIN" login --server "$SERVER_URL" --username admin --password "$ADMIN_PASSWORD" \
    --mfa-code "$MFA_LOGIN_CODE" || fail "new login (MFA-enabled) exited non-zero"

pass "new: secret decrypts identically"
NEW_GET_OUT="$("$NEW_CLI_BIN" secret get --id 1 --show-value)" || fail "new secret get exited non-zero:
$NEW_GET_OUT"
echo "$NEW_GET_OUT" | grep -qF "$SECRET_VALUE" \
    || fail "secret did NOT decrypt identically after version-skip upgrade -- expected to find %q in:
$NEW_GET_OUT" "$SECRET_VALUE"
pass "confirmed: secret value byte-identical to what the OLD binary encrypted"

pass "new: PROBE A re-run (must still be ALLOWED -- same grant, HEAD's authz engine)"
PROBE_A_AFTER_OUT="$(KEYORIX_SERVER="$SERVER_URL" KEYORIX_TOKEN="$ALLOWED_TOKEN" "$NEW_CLI_BIN" \
    secret get --id 1 --show-value)" || fail "PROBE A (after) failed -- authz answer changed across the version skip:
$PROBE_A_AFTER_OUT"
echo "$PROBE_A_AFTER_OUT" | grep -qF "$SECRET_VALUE" \
    || fail "PROBE A (after): granted token did not read the correct value -- got:
$PROBE_A_AFTER_OUT"
pass "PROBE A (after, HEAD binary): still ALLOWED -- authz answer matches the old binary's"

pass "new: PROBE B re-run (must still be DENIED)"
PROBE_B_AFTER_STATUS=0
PROBE_B_AFTER_OUT="$(KEYORIX_SERVER="$SERVER_URL" KEYORIX_TOKEN="$DENIED_TOKEN" "$NEW_CLI_BIN" \
    secret get --id 1 --show-value 2>&1)" || PROBE_B_AFTER_STATUS=$?
[ "$PROBE_B_AFTER_STATUS" -ne 0 ] || fail "PROBE B (after): role-less token was able to read the secret -- authz answer changed across the version skip:
$PROBE_B_AFTER_OUT"
pass "PROBE B (after, HEAD binary): still DENIED -- authz answer matches the old binary's ($PROBE_B_AFTER_OUT)"

echo ""
echo "VERSION-SKIP UPGRADE PROOF PASSED"
echo "  secret value:      byte-identical before/after"
echo "  audit chain:       VALID (restore's own verify-audit + standalone re-check)"
echo "  authz PROBE A:     ALLOWED before, ALLOWED after (unchanged)"
echo "  authz PROBE B:     DENIED before, DENIED after (unchanged)"
