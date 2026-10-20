#!/usr/bin/env bash
# scripts/demo/native-up.sh — the same calm demo as scripts/demo/up.sh, but on host
# binaries: no Docker. Builds the server, CLI and TOTP helper with `go build`, runs the
# server in the background against SQLite (default) or PostgreSQL, and seeds the org via
# scripts/demo/seed.sh (shared with up.sh).
#
#   scripts/demo/native-up.sh                 # SQLite, http://127.0.0.1:18480
#   KEYORIX_DEMO_PG_DSN=<dsn> scripts/demo/native-up.sh   # PostgreSQL (the DSN is read
#                                              # from the environment, never argv)
#
# Everything lives in .demo-native/ (gitignored): config, keys, SQLite file, server.log,
# cli-home, state.env (0600: demo logins + TOTP keys, read by scenario scripts). Idempotent:
# re-running with the demo already up and seeded just reprints it; with the server stopped
# but the data present it restarts the server without reseeding. native-down.sh [--wipe]
# stops it (and with --wipe deletes .demo-native/).
#
# Demo thresholds: the detector pass runs every 15 s (anomaly_alerts.schedule) so a
# triggered anomaly shows within about 20 s instead of up to an hour; loopback is a trusted
# proxy so scripts/demo/trigger-anomaly.sh can present a different client IP via
# X-Forwarded-For. Both are DEMO-ONLY settings written to the demo's own config file.
#
# Not covered here (pending e2e VM): the container image path (up.sh) and the Playwright UI walk.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

PORT="${KEYORIX_DEMO_PORT:-18490}"
WORK="${KEYORIX_DEMO_DIR:-$REPO_ROOT/.demo-native}"
BIN="$REPO_ROOT/bin"
SERVER_BIN="$BIN/keyorix-server"
CLI_BIN="$BIN/keyorix"
TOTPGEN_BIN="$BIN/totpgen"
CLI_HOME="$WORK/cli-home"
STATE_ENV="$WORK/state.env"
SERVER_URL="http://127.0.0.1:${PORT}"
DEMO_SERVER_LOG="$WORK/server.log"
PID_FILE="$WORK/server.pid"

BOOTSTRAP_TOKEN_FILE="$WORK/bootstrap-token"   # generated per demo (openssl rand -hex 32), 0600
MASTER_PASSWORD="keyorix-demo-master-passphrase-2026"

CYAN='\033[0;36m'; BLUE='\033[0;34m'; GREEN='\033[0;32m'; NC='\033[0m'
step() { echo -e "${CYAN}==>${NC} $1"; }
info() { echo -e "${BLUE}  i${NC} $1"; }
ok()   { echo -e "${GREEN}  ok${NC} $1"; }

# shellcheck source=scripts/demo/lib.sh
. "$SCRIPT_DIR/lib.sh"
# shellcheck source=scripts/demo/seed.sh
. "$SCRIPT_DIR/seed.sh"

command -v python3 >/dev/null 2>&1 || { echo "python3 is required (JSON handling in scripts/demo/lib.sh)" >&2; exit 1; }
command -v go >/dev/null 2>&1 || { echo "go is required" >&2; exit 1; }

healthy() { curl -s -o /dev/null --max-time 3 "$SERVER_URL/health"; }

start_server() {
  # `;` not `&&` before the background job: `a && b &` backgrounds the whole list, and
  # $! would then be the subshell, not the server.
  ( cd "$WORK"
    export KEYORIX_MASTER_PASSWORD="$MASTER_PASSWORD" KEYORIX_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" KEYORIX_CONFIG_PATH=keyorix.yaml
    nohup "$SERVER_BIN" >> "$DEMO_SERVER_LOG" 2>&1 &
    echo $! > "$PID_FILE" )
  local _
  for _ in $(seq 1 40); do
    healthy && return 0
    sleep 1
  done
  tail -20 "$DEMO_SERVER_LOG" >&2
  echo "server did not become healthy (log tail above)" >&2
  return 1
}

# ── Idempotent re-run ──────────────────────────────────────────────────────
if [ -f "$STATE_ENV" ] && healthy; then
  info "Demo already running and seeded — reprinting"
  # shellcheck disable=SC1090
  . "$STATE_ENV"; echo "URL: $DEMO_URL   (admin / $DEMO_ADMIN_PASSWORD; TOTP setup key in $WORK/admin-mfa)"
  exit 0
fi

# ── Build ──────────────────────────────────────────────────────────────────
mkdir -p "$BIN" "$WORK" "$CLI_HOME"
# The bootstrap token is never a fixed value: the server refuses a pinned one shorter than
# 32 characters. Generated once per demo, kept 0600, read from the file (never on argv).
if [ ! -s "$BOOTSTRAP_TOKEN_FILE" ]; then
  command -v openssl >/dev/null 2>&1 || { echo "openssl is required to generate the bootstrap token" >&2; exit 1; }
  ( umask 077; openssl rand -hex 32 > "$BOOTSTRAP_TOKEN_FILE" )
fi
BOOTSTRAP_TOKEN="$(cat "$BOOTSTRAP_TOKEN_FILE")"
if [ ! -x "$SERVER_BIN" ]; then
  step "Building the server"
  go build -o "$SERVER_BIN" ./server
fi
if [ ! -x "$BIN/demo-dbexec" ]; then
  step "Building the demo DB helper (scenario scripts: tamper / dynamic credentials)"
  go build -o "$BIN/demo-dbexec" ./scripts/demo/dbexec
fi
if [ ! -x "$CLI_BIN" ]; then
  step "Building the CLI"
  ( cd cli && GOWORK=off go build -o "$CLI_BIN" . )
fi
if [ ! -x "$TOTPGEN_BIN" ]; then
  step "Building the TOTP helper (stands in for an authenticator app)"
  GOWORK=off go build -o "$TOTPGEN_BIN" ./scripts/totpgen/main.go
fi

# ── Resume: data present, server stopped ───────────────────────────────────
if [ -f "$STATE_ENV" ]; then
  step "Data present, server stopped — restarting it (no reseed)"
  start_server
  # shellcheck disable=SC1090
  . "$STATE_ENV"; echo "URL: $DEMO_URL   (admin / $DEMO_ADMIN_PASSWORD; TOTP setup key in $WORK/admin-mfa)"
  exit 0
fi

# ── Fresh: nothing half-seeded survives a failure ──────────────────────────
SEEDING=true
on_exit() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ "$SEEDING" = true ]; then
    echo "Demo setup failed (exit $rc); removing the unfinished state so the next run starts clean." >&2
    [ -f "$PID_FILE" ] && kill "$(cat "$PID_FILE")" 2>/dev/null || true
    rm -rf "$WORK"
  fi
}
trap on_exit EXIT

STORAGE_ARGS=()
if [ -n "${KEYORIX_DEMO_PG_DSN:-}" ]; then
  STORAGE_ARGS=(--storage-type postgres)
  info "Storage: PostgreSQL (DSN from KEYORIX_DEMO_PG_DSN)"
else
  info "Storage: SQLite ($WORK/keyorix.db)"
fi

step "Initialising config, keys and schema in $WORK"
export KEYORIX_MASTER_PASSWORD="$MASTER_PASSWORD"
# For PostgreSQL the first init only writes the config and exits non-zero until the DSN is
# set (below); the second init then finishes the job.
( cd "$WORK" && "$SERVER_BIN" admin init --dev --config keyorix.yaml ${STORAGE_ARGS[@]+"${STORAGE_ARGS[@]}"} >/dev/null 2>&1 ) \
  || [ -n "${KEYORIX_DEMO_PG_DSN:-}" ] || { echo "admin init failed" >&2; exit 1; }
# DEMO-ONLY edits: port, loopback trusted proxy (X-Forwarded-For for trigger-anomaly.sh),
# the Postgres DSN when given, break-glass on, and a 15 s detection cadence.
KEYORIX_DEMO_PORT_E="$PORT" KEYORIX_DEMO_OIDC_PORT="${KEYORIX_DEMO_OIDC_PORT:-18520}" python3 - "$WORK/keyorix.yaml" <<'PY'
import os, re, sys
p = sys.argv[1]
s = open(p).read()
port = os.environ["KEYORIX_DEMO_PORT_E"]
s = s.replace('    port: "8080"\n', '    port: "%s"\n    trusted_proxies: ["127.0.0.1/32"]\n' % port, 1)
dsn = os.environ.get("KEYORIX_DEMO_PG_DSN", "")
if dsn:
    s = re.sub(r'^(\s*)# dsn: .*$', lambda m: '%sdsn: "%s"' % (m.group(1), dsn.replace('"', '\\"')), s, count=1, flags=re.M)
oidc_port = os.environ.get("KEYORIX_DEMO_OIDC_PORT", "18520")
s += """
break_glass:
  enabled: true
  emergency_role: project_developer
  default_ttl: 4h
  max_ttl: 24h
anomaly_alerts:
  enabled: true
  schedule: 15s
# DEMO-ONLY, for scripts/demo/scenario-oidc-federation.sh: trust the local stand-in CI issuer
# (scripts/demo/oidcissuer, loopback http is allowed for loopback hosts only).
oidc:
  enabled: true
  issuers:
    - name: demo-ci-platform
      issuer: http://127.0.0.1:%s
      jwks_uri: http://127.0.0.1:%s/jwks.json
      audiences: ["keyorix-demo"]
# DEMO-ONLY, for scripts/demo/scenario-dynamic-credentials.sh: sweep expired leases every 10 s
# and allow a database on this machine as the target.
dynamic_secrets:
  sweep_enabled: true
  sweep_interval: 10s
  insecure_allow_private_network_dynamic_secret_targets: true
""" % (oidc_port, oidc_port)
open(p, "w").write(s)
PY
chmod 600 "$WORK/keyorix.yaml"
if [ -n "${KEYORIX_DEMO_PG_DSN:-}" ]; then
  ( cd "$WORK" && "$SERVER_BIN" admin init --dev --config keyorix.yaml >/dev/null 2>&1 ) || { echo "admin init (postgres, second pass) failed" >&2; exit 1; }
fi
( cd "$WORK" && "$SERVER_BIN" admin encryption init --config keyorix.yaml >/dev/null 2>&1 \
  && "$SERVER_BIN" admin migrate --config keyorix.yaml >/dev/null 2>&1 )
ok "initialised"

step "Starting the server on $SERVER_URL"
start_server
ok "server healthy (pid $(cat "$PID_FILE"), log $DEMO_SERVER_LOG)"

printf '%s' "$SERVER_URL" > "$WORK/server.url"
# Seeding is its own script (also usable by a kit that starts the server itself): it bootstraps
# the admin, enrols MFA, seeds the org, writes state.env and admin-mfa, and settles the detector.
KEYORIX_SERVER="$SERVER_URL" KEYORIX_DEMO_PORT="$PORT" "$SCRIPT_DIR/seed-demo.sh" "$WORK"
SEEDING=false

echo
echo "  Keyorix demo (native) is up: $SERVER_URL   [$([ -n "${KEYORIX_DEMO_PG_DSN:-}" ] && echo postgres || echo sqlite)]"
echo "  admin / Correct-Horse-Battery-2026  MFA is required: setup key + otpauth URI are in $WORK/admin-mfa (0600)"
if [ -t 1 ] && [ -s "$WORK/admin-mfa" ]; then
  # Interactive terminal only: show the setup key once so the presenter can type it in. Never
  # when stdout is a pipe or a log.
  sed -n 's/^setup_key=/  authenticator setup key: /p' "$WORK/admin-mfa"
fi
echo "  state for scripts: $STATE_ENV      stop: scripts/demo/native-down.sh [--wipe]"

# KEYORIX_DEMO_FOREGROUND=1: stay attached and stop the server when this script is stopped
# (Ctrl-C, or a harness that cannot signal a detached process later).
if [ "${KEYORIX_DEMO_FOREGROUND:-}" = "1" ]; then
  trap 'kill "$(cat "$PID_FILE")" 2>/dev/null || true' EXIT INT TERM
  while kill -0 "$(cat "$PID_FILE")" 2>/dev/null; do sleep 2; done
fi
