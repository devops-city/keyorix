#!/usr/bin/env bash
# scripts/demo/seed-demo.sh STATE_DIR — seed a RUNNING, freshly initialised Keyorix server with
# the calm demo org. Called by scripts/demo/native-up.sh, and usable on its own by any kit that
# starts the server itself (e.g. a hosted demo's --seed-script).
#
# Contract
#   * Non-interactive; the only argument is STATE_DIR (created 0700 if missing).
#   * The server URL comes from $KEYORIX_SERVER, else STATE_DIR/server.url, else
#     http://127.0.0.1:${KEYORIX_DEMO_PORT:-18490}.
#   * The server's bootstrap token is read from STATE_DIR/bootstrap-token (0600). Whoever starts
#     the server must start it with KEYORIX_BOOTSTRAP_TOKEN set to that file's content; if the
#     file is missing this script creates it (`openssl rand -hex 32`) and the server must be
#     started with it BEFORE seeding. It is never a fixed value and never on a command line.
#   * MFA stays ON. The script enrols TOTP for the demo admin itself, through the real API, and
#     writes the setup key, the otpauth URI and the recovery codes to STATE_DIR/admin-mfa (0600).
#     Nothing secret goes to stdout or argv, so the presenter adds the key to an authenticator
#     once, from that file.
#   * Idempotent. With STATE_DIR/state.env present and the admin able to log in with the stored
#     TOTP key, it does nothing and exits 0. It never re-enrols an enrolled admin, so the key in
#     admin-mfa stays valid across runs while the data persists.
#     Limit: the server generates the TOTP secret at enrolment (the API takes none), so a demo
#     whose database was wiped and re-seeded gets a NEW key, written over admin-mfa.
#   * Writes STATE_DIR/state.env (0600): logins + TOTP keys of the three seeded accounts and the
#     CI machine token, read by the scenario scripts (scripts/demo/scn-lib.sh).
#   * Ends after the detector's first pass has been settled (the low "first observed" alerts the
#     seed itself caused are acknowledged), so the dashboard starts with zero open anomalies.
#
# Optional environment: KEYORIX_DEMO_PG_DSN / KEYORIX_DEMO_OIDC_PORT / KEYORIX_DEMO_PORT are only
# recorded in state.env for the scenario scripts; DEMO_SERVER_LOG (default STATE_DIR/server.log)
# is where the settle step reads the detector's first-pass delay.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
STATE_DIR="${1:?usage: seed-demo.sh STATE_DIR}"
mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
STATE_DIR="$(cd "$STATE_DIR" && pwd)"
cd "$REPO_ROOT"

SERVER_URL="${KEYORIX_SERVER:-}"
[ -n "$SERVER_URL" ] || { [ -s "$STATE_DIR/server.url" ] && SERVER_URL="$(cat "$STATE_DIR/server.url")"; } || true
[ -n "$SERVER_URL" ] || SERVER_URL="http://127.0.0.1:${KEYORIX_DEMO_PORT:-18490}"
PORT="${SERVER_URL##*:}"; PORT="${PORT%%/*}"

BIN="$REPO_ROOT/bin"; CLI_BIN="$BIN/keyorix"; TOTPGEN_BIN="$BIN/totpgen"
CLI_HOME="$STATE_DIR/cli-home"; STATE_ENV="$STATE_DIR/state.env"; MFA_FILE="$STATE_DIR/admin-mfa"
BOOTSTRAP_TOKEN_FILE="$STATE_DIR/bootstrap-token"
export DEMO_SERVER_LOG="${DEMO_SERVER_LOG:-$STATE_DIR/server.log}"

ADMIN_USER="admin"; ADMIN_EMAIL="admin@keyorix.demo"
ADMIN_PASSWORD="Correct-Horse-Battery-2026"
ALICE_PASSWORD="Nebula-Quartz-Flagstone-2026"
SECOFFICER_PASSWORD="Granite-Meadow-Lantern-2026"

CYAN='\033[0;36m'; BLUE='\033[0;34m'; GREEN='\033[0;32m'; NC='\033[0m'
step() { echo -e "${CYAN}==>${NC} $1"; }
info() { echo -e "${BLUE}  i${NC} $1"; }
ok()   { echo -e "${GREEN}  ok${NC} $1"; }

# shellcheck source=scripts/demo/lib.sh
. "$SCRIPT_DIR/lib.sh"
# shellcheck source=scripts/demo/seed.sh
. "$SCRIPT_DIR/seed.sh"

command -v python3 >/dev/null 2>&1 || { echo "python3 is required (JSON handling in scripts/demo/lib.sh)" >&2; exit 1; }
mkdir -p "$BIN" "$CLI_HOME"
if [ ! -x "$CLI_BIN" ]; then step "Building the CLI"; ( cd cli && GOWORK=off go build -o "$CLI_BIN" . ); fi
if [ ! -x "$TOTPGEN_BIN" ]; then step "Building the TOTP helper"; GOWORK=off go build -o "$TOTPGEN_BIN" ./scripts/totpgen/main.go; fi
if [ ! -s "$BOOTSTRAP_TOKEN_FILE" ]; then
  command -v openssl >/dev/null 2>&1 || { echo "openssl is required to generate the bootstrap token" >&2; exit 1; }
  ( umask 077; openssl rand -hex 32 > "$BOOTSTRAP_TOKEN_FILE" )
  info "generated $BOOTSTRAP_TOKEN_FILE - the server must have been started with this bootstrap token"
fi

export HOME="$CLI_HOME" DEMO_STEP_DIR="$CLI_HOME"
curl -s -o /dev/null --max-time 5 "$SERVER_URL/health" || { echo "server not reachable at $SERVER_URL" >&2; exit 1; }

# ── Idempotent re-run ─────────────────────────────────────────────────────
if [ -f "$STATE_ENV" ]; then
  # shellcheck disable=SC1090
  . "$STATE_ENV"
  if demo_login_mfa "$SERVER_URL" "$ADMIN_USER" "$DEMO_ADMIN_PASSWORD" "$DEMO_ADMIN_TOTP" 2>/dev/null; then
    info "already seeded ($STATE_ENV present and the admin can log in) - nothing to do"
    exit 0
  fi
  echo "state file present but the admin cannot log in with the stored TOTP key: this server was reset behind the state directory's back; delete $STATE_DIR (or at least $STATE_ENV) after wiping the demo and seed again" >&2
  exit 1
fi

step "Bootstrapping the admin account"
set +e
bootstrap_out="$(KEYORIX_ADMIN_PASSWORD="$ADMIN_PASSWORD" KEYORIX_BOOTSTRAP_TOKEN="$(cat "$BOOTSTRAP_TOKEN_FILE")" \
  "$CLI_BIN" system init --server "$SERVER_URL" --admin-username "$ADMIN_USER" --admin-email "$ADMIN_EMAIL" 2>&1)"
rc=$?
set -e
if [ "$rc" -ne 0 ] || printf '%s' "$bootstrap_out" | grep -qi 'already initialised'; then
  echo "the server is already initialised but this state directory has no seed: reset the demo's data first (the admin bootstrap is one-shot)" >&2
  printf '%s\n' "$bootstrap_out" | head -n 3 >&2
  exit 1
fi
ok "admin bootstrapped"

step "Enrolling TOTP for the admin (MFA stays required)"
demo_enroll_mfa "$SERVER_URL" "$ADMIN_USER" "$ADMIN_PASSWORD" || { echo "MFA enrolment failed" >&2; exit 1; }
ADMIN_TOTP="$DEMO_MFA_SECRET"
( umask 077
  {
    printf 'setup_key=%s\n' "$DEMO_MFA_SECRET"
    printf 'otpauth_uri=%s\n' "$DEMO_MFA_URI"
    printf 'recovery_codes=%s\n' "$DEMO_RECOVERY_CODES"
  } > "$MFA_FILE" )
ok "setup key, otpauth URI and recovery codes written to $MFA_FILE (0600)"
export KEYORIX_SERVER="$SERVER_URL" KEYORIX_TOKEN="$DEMO_TOKEN"

demo_seed_org

step "Writing $STATE_ENV (0600, demo logins for the scenario scripts)"
( umask 077
  {
    printf "DEMO_URL='%s'\n" "$SERVER_URL"
    printf "DEMO_PORT='%s'\n" "$PORT"
    printf "DEMO_ADMIN_PASSWORD='%s'\nDEMO_ADMIN_TOTP='%s'\n" "$ADMIN_PASSWORD" "$ADMIN_TOTP"
    printf "DEMO_ALICE_PASSWORD='%s'\nDEMO_ALICE_TOTP='%s'\n" "$ALICE_PASSWORD" "$ALICE_MFA_SECRET"
    printf "DEMO_OFFICER_PASSWORD='%s'\nDEMO_OFFICER_TOTP='%s'\n" "$SECOFFICER_PASSWORD" "$SECOFFICER_MFA_SECRET"
    printf "DEMO_MACHINE_TOKEN='%s'\n" "$MACHINE_TOKEN"
    printf "DEMO_STORAGE='%s'\n" "$([ -n "${KEYORIX_DEMO_PG_DSN:-}" ] && echo postgres || echo sqlite)"
    printf "DEMO_DB_FILE='%s'\n" "$STATE_DIR/keyorix.db"
    printf "DEMO_PG_DSN='%s'\n" "${KEYORIX_DEMO_PG_DSN:-}"
    printf "DEMO_CONFIG='%s'\n" "$STATE_DIR/keyorix.yaml"
    printf "DEMO_OIDC_PORT='%s'\n" "${KEYORIX_DEMO_OIDC_PORT:-18520}"
  } > "$STATE_ENV" )

step "Waiting for the first detection pass, then acknowledging what the seed itself caused"
demo_settle_anomalies "$SERVER_URL" "$KEYORIX_TOKEN"
ok "seeded: $SERVER_URL (state: $STATE_ENV)"
