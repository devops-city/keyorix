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
# Hosted-kit hooks (all optional; with none of them set the behaviour above is unchanged)
#   KEYORIX_DEMO_ADMIN_PASSWORD_FILE   file (not readable by "other", normally 0600/0640) holding the
#                                      admin's password instead of the built-in demo one. The value is
#                                      never printed, logged or copied into state.env (which then
#                                      records the file path); it does travel to the CLI through the
#                                      environment exactly as the built-in password does.
#   (admin already exists)             when the admin can already log in with that password (a hosted
#                                      entrypoint bootstraps it) `system init` is skipped instead of
#                                      failing "already initialised"; MFA is still enrolled.
#   admin-mfa already in STATE_DIR     with the password file, an admin that already has TOTP and
#                                      accepts the key in STATE_DIR/admin-mfa keeps that enrolment
#                                      (adopted, not re-enrolled): the hosted reset copies the
#                                      encrypted TOTP rows across the wipe so the presenter's
#                                      authenticator survives it.
#   KEYORIX_DEMO_BOOTSTRAP_TOKEN_FILE  overrides STATE_DIR/bootstrap-token (only read if the admin
#                                      has to be created here).
#   KEYORIX_DEMO_GENERATE_PASSWORDS=1  alice and security-officer get a random password per run,
#                                      written to STATE_DIR/demo-passwords (0600), never printed.
#                                      Implied by KEYORIX_DEMO_ADMIN_PASSWORD_FILE: a hosted VM never
#                                      carries the fixed demo passwords from the repository.
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
BOOTSTRAP_TOKEN_FILE="${KEYORIX_DEMO_BOOTSTRAP_TOKEN_FILE:-$STATE_DIR/bootstrap-token}"
export DEMO_SERVER_LOG="${DEMO_SERVER_LOG:-$STATE_DIR/server.log}"

ADMIN_USER="admin"; ADMIN_EMAIL="admin@keyorix.demo"
ADMIN_PASSWORD="Correct-Horse-Battery-2026"
ALICE_PASSWORD="Nebula-Quartz-Flagstone-2026"
SECOFFICER_PASSWORD="Granite-Meadow-Lantern-2026"
ADMIN_PASSWORD_FILE="${KEYORIX_DEMO_ADMIN_PASSWORD_FILE:-}"
PASSWORDS_FILE="$STATE_DIR/demo-passwords"
GENERATE_PASSWORDS=0
{ [ "${KEYORIX_DEMO_GENERATE_PASSWORDS:-0}" = 1 ] || [ -n "$ADMIN_PASSWORD_FILE" ]; } && GENERATE_PASSWORDS=1

CYAN='\033[0;36m'; BLUE='\033[0;34m'; GREEN='\033[0;32m'; NC='\033[0m'
step() { echo -e "${CYAN}==>${NC} $1"; }
info() { echo -e "${BLUE}  i${NC} $1"; }
ok()   { echo -e "${GREEN}  ok${NC} $1"; }

# shellcheck source=scripts/demo/lib.sh
. "$SCRIPT_DIR/lib.sh"
# shellcheck source=scripts/demo/seed.sh
. "$SCRIPT_DIR/seed.sh"

# gen_password: 28 characters meeting the default policy (upper, lower, digit, special, >=16).
gen_password() { printf 'Dm%s-Q7' "$(openssl rand -hex 12)"; }

command -v python3 >/dev/null 2>&1 || { echo "python3 is required (JSON handling in scripts/demo/lib.sh)" >&2; exit 1; }
if [ -n "$ADMIN_PASSWORD_FILE" ]; then
  [ -f "$ADMIN_PASSWORD_FILE" ] && [ -r "$ADMIN_PASSWORD_FILE" ] || { echo "KEYORIX_DEMO_ADMIN_PASSWORD_FILE is not a readable file: $ADMIN_PASSWORD_FILE" >&2; exit 1; }
  python3 -I -c 'import os,stat,sys; sys.exit(1 if os.stat(sys.argv[1]).st_mode & stat.S_IRWXO else 0)' "$ADMIN_PASSWORD_FILE" \
    || { echo "KEYORIX_DEMO_ADMIN_PASSWORD_FILE must not be accessible to other users (chmod 0600): $ADMIN_PASSWORD_FILE" >&2; exit 1; }
  ADMIN_PASSWORD="$(tr -d '\r\n' < "$ADMIN_PASSWORD_FILE")"
  [ -n "$ADMIN_PASSWORD" ] || { echo "KEYORIX_DEMO_ADMIN_PASSWORD_FILE is empty: $ADMIN_PASSWORD_FILE" >&2; exit 1; }
  info "admin password read from $ADMIN_PASSWORD_FILE (value not shown)"
fi

mkdir -p "$BIN" "$CLI_HOME"
if { [ ! -x "$CLI_BIN" ] || [ ! -x "$TOTPGEN_BIN" ]; } && ! command -v go >/dev/null 2>&1; then
  echo "bin/keyorix and bin/totpgen are needed and go is not installed here: build them where Go is available ((cd cli && GOWORK=off go build -o ../bin/keyorix .) and GOWORK=off go build -o bin/totpgen ./scripts/totpgen/main.go) and copy them to $BIN" >&2
  exit 1
fi
if [ ! -x "$CLI_BIN" ]; then step "Building the CLI"; ( cd cli && GOWORK=off go build -o "$CLI_BIN" . ); fi
if [ ! -x "$TOTPGEN_BIN" ]; then step "Building the TOTP helper"; GOWORK=off go build -o "$TOTPGEN_BIN" ./scripts/totpgen/main.go; fi
ensure_bootstrap_token() {
  [ -s "$BOOTSTRAP_TOKEN_FILE" ] && return 0
  command -v openssl >/dev/null 2>&1 || { echo "openssl is required to generate the bootstrap token" >&2; exit 1; }
  ( umask 077; openssl rand -hex 32 > "$BOOTSTRAP_TOKEN_FILE" )
  info "generated $BOOTSTRAP_TOKEN_FILE - the server must have been started with this bootstrap token"
}
[ -n "$ADMIN_PASSWORD_FILE" ] || ensure_bootstrap_token # hosted mode needs it only if `system init` really runs
command -v openssl >/dev/null 2>&1 || { [ "$GENERATE_PASSWORDS" = 0 ] || { echo "openssl is required to generate passwords" >&2; exit 1; }; }

export HOME="$CLI_HOME" DEMO_STEP_DIR="$CLI_HOME"
curl -s -o /dev/null --max-time 5 "$SERVER_URL/health" || { echo "server not reachable at $SERVER_URL" >&2; exit 1; }

# ── Idempotent re-run ─────────────────────────────────────────────────────
if [ -f "$STATE_ENV" ]; then
  # shellcheck disable=SC1090
  . "$STATE_ENV"
  [ -z "${DEMO_ADMIN_PASSWORD_FILE:-}" ] || DEMO_ADMIN_PASSWORD="$ADMIN_PASSWORD"
  if demo_login_mfa "$SERVER_URL" "$ADMIN_USER" "$DEMO_ADMIN_PASSWORD" "$DEMO_ADMIN_TOTP" 2>/dev/null; then
    info "already seeded ($STATE_ENV present and the admin can log in) - nothing to do"
    exit 0
  fi
  echo "state file present but the admin cannot log in with the stored TOTP key: this server was reset behind the state directory's back; delete $STATE_DIR (or at least $STATE_ENV) after wiping the demo and seed again" >&2
  exit 1
fi

# Hosted mode (password file): the entrypoint bootstraps the admin, so `system init` is skipped
# when the admin already exists. A fresh admin has no second factor yet (ADMIN_MFA=new: enrol
# below). An admin whose TOTP enrolment survived a reset (the reset copies the encrypted rows,
# see deploy/demo-hosted/democtl.sh) logs in with the key kept in $MFA_FILE (ADMIN_MFA=kept: it
# is adopted, never re-enrolled, so the presenter's authenticator keeps working).
ADMIN_MFA=""; ADMIN_TOTP=""
if [ -n "$ADMIN_PASSWORD_FILE" ]; then
  _try=0
  while :; do
    if demo_login_mfa "$SERVER_URL" "$ADMIN_USER" "$ADMIN_PASSWORD" >/dev/null 2>&1; then ADMIN_MFA=new; break; fi
    if [ -s "$MFA_FILE" ]; then
      _key="$(sed -n 's/^setup_key=//p' "$MFA_FILE" | head -n 1)"
      if [ -n "$_key" ] && demo_login_mfa "$SERVER_URL" "$ADMIN_USER" "$ADMIN_PASSWORD" "$_key" >/dev/null 2>&1; then ADMIN_MFA=kept; ADMIN_TOTP="$_key"; break; fi
    fi
    _try=$((_try + 1)); [ "$_try" -lt 10 ] || break
    info "waiting for the bootstrapped admin to accept the password file ($_try/10)"
    sleep 3
  done
  unset _key
fi

if [ -n "$ADMIN_MFA" ]; then
  step "Admin already exists and accepts the password file - skipping system init"
else
  step "Bootstrapping the admin account"
  ensure_bootstrap_token
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
fi

if [ "$GENERATE_PASSWORDS" = 1 ]; then
  ALICE_PASSWORD="$(gen_password)"; SECOFFICER_PASSWORD="$(gen_password)"
  ( umask 077
    {
      printf 'alice_password=%s\n' "$ALICE_PASSWORD"
      printf 'security_officer_password=%s\n' "$SECOFFICER_PASSWORD"
    } > "$PASSWORDS_FILE" )
  ok "alice and security-officer passwords generated into $PASSWORDS_FILE (0600, not shown)"
fi

if [ "$ADMIN_MFA" = kept ]; then
  step "Admin TOTP enrolment kept across the reset - adopting the key in $MFA_FILE (not shown)"
else
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
fi
export KEYORIX_SERVER="$SERVER_URL" KEYORIX_TOKEN="$DEMO_TOKEN"

demo_seed_org

step "Writing $STATE_ENV (0600, demo logins for the scenario scripts)"
( umask 077
  {
    printf "DEMO_URL='%s'\n" "$SERVER_URL"
    printf "DEMO_PORT='%s'\n" "$PORT"
    if [ -n "$ADMIN_PASSWORD_FILE" ]; then
      printf "DEMO_ADMIN_PASSWORD_FILE='%s'\nDEMO_ADMIN_TOTP='%s'\n" "$ADMIN_PASSWORD_FILE" "$ADMIN_TOTP"
    else
      printf "DEMO_ADMIN_PASSWORD='%s'\nDEMO_ADMIN_TOTP='%s'\n" "$ADMIN_PASSWORD" "$ADMIN_TOTP"
    fi
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
