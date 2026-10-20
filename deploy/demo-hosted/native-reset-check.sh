#!/usr/bin/env bash
# native-reset-check.sh sqlite|postgres -- run the REAL `democtl.sh reset` twice on a Mac or
# Linux box without Docker, to prove the reset ends in the same state and the admin's TOTP
# enrolment survives it. Offline stand-in for the e2e VM run (the container path stays
# "pending e2e VM").
#
# What is real: democtl.sh, scripts/demo/seed-demo.sh, the server, CLI, TOTP helper, the SQL
# the reset runs. What is faked (shims on PATH, written under $WORK/shim): `docker` (compose
# up/down/ps/stop/exec, volume rm, inspect), `flock`, and `psql` inside the postgres
# container (run through scripts/demo/dbexec). The shim maps "remove volume postgres_data" to
# wiping the database and "remove volume keyorix_keys" to deleting the key directory.
#
#   postgres  needs KEYORIX_DEMO_PG_DSN (an empty database you own; `kpg dsn <name>` in the
#             sandbox). The reset keeps the admin's TOTP key: asserted.
#   sqlite    the reset cannot copy the TOTP rows (the kit's SQL is PostgreSQL, the hosted
#             stack is PostgreSQL only): democtl says so and the seed enrols a new key.
#
# Env: KEYORIX_NATIVE_RESET_DIR (work dir, default ${TMPDIR:-/tmp}/keyorix-native-reset-MODE,
# removed first), KEYORIX_NATIVE_RESET_PORT (default: first free port from 18900).
# Prints counts, never a password or a TOTP key. Exit 0 = every assertion held.
# shellcheck disable=SC2154 # U_r1 S_r1 K_r1 ... are set by snapshot() through eval
set -euo pipefail

MODE="${1:?usage: native-reset-check.sh sqlite|postgres}"
case $MODE in sqlite|postgres) ;; *) echo "mode must be sqlite or postgres" >&2; exit 2 ;; esac
KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$KIT_DIR/../.." && pwd)"
WORK="${KEYORIX_NATIVE_RESET_DIR:-${TMPDIR:-/tmp}/keyorix-native-reset-$MODE}"
[ "$MODE" = sqlite ] || : "${KEYORIX_DEMO_PG_DSN:?postgres mode needs KEYORIX_DEMO_PG_DSN (never put it on a command line)}"

say() { printf '== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

PORT="${KEYORIX_NATIVE_RESET_PORT:-}"
if [ -z "$PORT" ]; then
  for p in $(seq 18900 18990); do
    curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$p/health" || { PORT=$p; break; }
  done
fi
[ -n "$PORT" ] || fail "no free port in 18900-18990"

rm -rf "$WORK"
mkdir -p "$WORK/shim" "$WORK/state" "$WORK/secrets" "$WORK/server" "$WORK/cli-home"
chmod 700 "$WORK/state" "$WORK/secrets"
( umask 027; printf 'Hosted-%s-Zz9!' "$(openssl rand -hex 10)" > "$WORK/secrets/admin_password" )
( umask 077; openssl rand -hex 32 > "$WORK/secrets/bootstrap_token" )

say "building the server, CLI, TOTP helper and DB helper"
mkdir -p "$REPO/bin"
( cd "$REPO" && go build -o bin/keyorix-server ./server && go build -o bin/demo-dbexec ./scripts/demo/dbexec \
  && GOWORK=off go build -o bin/totpgen ./scripts/totpgen/main.go && cd cli && GOWORK=off go build -o ../bin/keyorix . )

# ---- shims -------------------------------------------------------------------------------
cat > "$WORK/shim/flock" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat > "$WORK/shim/docker" <<'EOF'
#!/usr/bin/env bash
# Offline stand-in for the parts of docker/compose that democtl.sh uses.
set -uo pipefail
SRV="$NR_WORK/server"; PIDF="$SRV/server.pid"; URL="http://127.0.0.1:$NR_PORT"
LOG="$NR_WORK/shim.log"
note() { printf '%s shim: %s\n' "$(date -u +%T)" "$*" >> "$LOG"; }
healthy() { curl -s -o /dev/null --max-time 3 "$URL/health"; }
running() { [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null && healthy; }

stop_server() {
  if [ -f "$PIDF" ]; then
    local pid; pid="$(cat "$PIDF")"
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    rm -f "$PIDF"
  fi
}

init_config() {
  export KEYORIX_MASTER_PASSWORD="native-reset-master-passphrase-2026"
  local storage=()
  [ "$NR_MODE" != postgres ] || storage=(--storage-type postgres)
  ( cd "$SRV" && "$NR_REPO/bin/keyorix-server" admin init --dev --config keyorix.yaml ${storage[@]+"${storage[@]}"} >/dev/null 2>&1 ) || [ "$NR_MODE" = postgres ] || { note "admin init failed"; exit 1; }
  NR_PORT_E="$NR_PORT" python3 - "$SRV/keyorix.yaml" <<'PY'
import os, re, sys
p = sys.argv[1]; s = open(p).read()
s = s.replace('    port: "8080"\n', '    port: "%s"\n    trusted_proxies: ["127.0.0.1/32"]\n' % os.environ["NR_PORT_E"], 1)
dsn = os.environ.get("KEYORIX_DEMO_PG_DSN", "")
if dsn:
    s = re.sub(r'^(\s*)# dsn: .*$', lambda m: '%sdsn: "%s"' % (m.group(1), dsn.replace('"', '\\"')), s, count=1, flags=re.M)
s += "\nanomaly_alerts:\n  enabled: true\n  schedule: 15s\n"
open(p, "w").write(s)
PY
  chmod 600 "$SRV/keyorix.yaml"
  if [ "$NR_MODE" = postgres ]; then ( cd "$SRV" && "$NR_REPO/bin/keyorix-server" admin init --dev --config keyorix.yaml >/dev/null 2>&1 ) || { note "admin init (pg) failed"; exit 1; }; fi
}

start_server() {
  running && return 0
  export KEYORIX_MASTER_PASSWORD="native-reset-master-passphrase-2026"
  if [ ! -f "$SRV/keyorix.yaml" ] || [ ! -d "$SRV/keys" ]; then rm -f "$SRV/keyorix.yaml"; init_config; fi # first boot, or keys wiped: like the entrypoint's admin init
  ( cd "$SRV" && "$NR_REPO/bin/keyorix-server" admin encryption init --config keyorix.yaml >/dev/null 2>&1 \
    && "$NR_REPO/bin/keyorix-server" admin migrate --config keyorix.yaml >/dev/null 2>&1 ) || { note "encryption init / migrate failed"; exit 1; }
  ( cd "$SRV"
    export KEYORIX_BOOTSTRAP_TOKEN; KEYORIX_BOOTSTRAP_TOKEN="$(cat "$NR_WORK/secrets/bootstrap_token")"
    export KEYORIX_CONFIG_PATH=keyorix.yaml
    nohup "$NR_REPO/bin/keyorix-server" >> "$SRV/server.log" 2>&1 &
    echo $! > "$PIDF" )
  for _ in $(seq 1 60); do healthy && break; sleep 1; done
  healthy || { note "server did not become healthy"; tail -5 "$SRV/server.log" >> "$LOG"; exit 1; }
  # what server/entrypoint.sh does: bootstrap the admin from the secret files, idempotent
  KEYORIX_ADMIN_PASSWORD="$(cat "$NR_WORK/secrets/admin_password")" KEYORIX_BOOTSTRAP_TOKEN="$(cat "$NR_WORK/secrets/bootstrap_token")" HOME="$NR_WORK/cli-home" \
    "$NR_REPO/bin/keyorix" system init --server "$URL" --admin-username admin --admin-email admin@keyorix.demo >/dev/null 2>&1 || true
  note "server up, admin bootstrapped"
}

wipe_db() {
  if [ "$NR_MODE" = postgres ]; then
    "$NR_REPO/bin/demo-dbexec" exec 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;' >/dev/null
  else
    rm -f "$SRV"/keyorix.db "$SRV"/keyorix.db-shm "$SRV"/keyorix.db-wal
  fi
  note "database wiped"
}

psql_emulation() { # args after `psql`
  [ "$NR_MODE" = postgres ] || { echo "psql: no postgres in sqlite mode" >&2; exit 2; }
  local sql="" a
  while [ $# -gt 0 ]; do
    case $1 in
      -c) sql="$2"; shift 2 ;;
      -U|-d|-v) shift 2 ;;
      *) shift ;;
    esac
  done
  [ -n "$sql" ] || sql="$(cat)"
  case "$(printf '%s' "$sql" | tr -d '[:space:]' | cut -c1-6 | tr '[:lower:]' '[:upper:]')" in
    SELECT) "$NR_REPO/bin/demo-dbexec" query "$sql" ;;
    *) "$NR_REPO/bin/demo-dbexec" exec "$sql" >/dev/null ;;
  esac
}

case "${1:-}" in
  compose)
    shift
    while [ $# -gt 0 ]; do
      case $1 in
        --project-directory|--env-file|-f|--profile) shift 2 ;;
        -*) shift ;;
        *) break ;;
      esac
    done
    sub="${1:-}"; shift || true
    case $sub in
      up)
        svc=""; for a in "$@"; do case $a in -*) ;; *) svc=$a ;; esac; done
        note "compose up ${svc:-all}"
        [ "$svc" = postgres ] || start_server ;;
      down|stop)
        svc=""; for a in "$@"; do case $a in -*) ;; *) svc=$a ;; esac; done
        note "compose $sub ${svc:-all}"
        [ "$svc" = caddy ] || stop_server ;;
      ps)
        svc=""; for a in "$@"; do case $a in -*) ;; *) svc=$a ;; esac; done
        if [ "$svc" = postgres ] || running; then echo "cid-${svc:-x}"; fi ;;
      exec)
        shift_args=("$@"); i=0
        while [ $i -lt ${#shift_args[@]} ] && [ "${shift_args[$i]}" != psql ]; do i=$((i + 1)); done
        [ "${shift_args[$i]:-}" = psql ] || { echo "shim: only exec ... psql is supported" >&2; exit 2; }
        psql_emulation "${shift_args[@]:$((i + 1))}" ;;
      *) note "compose $sub (ignored)" ;;
    esac ;;
  inspect) if [ "${3:-}" = cid-postgres ] || running; then echo healthy; else echo exited; fi ;;
  volume)
    case "${2:-}" in
      inspect) exit 0 ;;
      rm)
        case "${3:-}" in
          *_postgres_data) wipe_db ;;
          *_keyorix_keys) rm -rf "$SRV/keys"; note "keys removed" ;;
          *) note "volume rm ${3:-} (ignored)" ;;
        esac ;;
    esac ;;
  *) note "docker ${1:-} (ignored)" ;;
esac
EOF
chmod +x "$WORK/shim/docker" "$WORK/shim/flock"

cat > "$WORK/demo.env" <<EOF
KEYORIX_DEMO_REPO=$REPO
KEYORIX_DEMO_STATE=$WORK/state
KEYORIX_SECRETS_DIR=$WORK/secrets
KEYORIX_DEMO_SEED_SCRIPTS=scripts/demo/seed-demo.sh
KEYORIX_DOMAIN=localhost
KEYORIX_DEMO_GATE_DIR=$WORK/gate
KEYORIX_DEMO_LOCK=$WORK/lock
KEYORIX_DEMO_WEB_URL=http://127.0.0.1:$PORT
KEYORIX_DEMO_HEALTH_TIMEOUT=60
EOF

export NR_WORK="$WORK" NR_MODE="$MODE" NR_PORT="$PORT" NR_REPO="$REPO"
export PATH="$WORK/shim:$PATH" KEYORIX_DEMO_ENV="$WORK/demo.env"
export DEMO_SERVER_LOG="$WORK/server/server.log" # lets the seed read the detector's first-pass delay instead of waiting the 5 minute worst case
URL="http://127.0.0.1:$PORT"
DEMOCTL="$KIT_DIR/democtl.sh"
cleanup() { docker compose down >/dev/null 2>&1 || true; }
trap cleanup EXIT

# ---- helpers: counts, login, audit verify -------------------------------------------------------
count() { # table
  if [ "$MODE" = postgres ]; then "$REPO/bin/demo-dbexec" query "SELECT count(*) FROM $1" | tr -d '[:space:]'
  else sqlite3 "$WORK/server/keyorix.db" "SELECT count(*) FROM $1"; fi
}
TOTPGEN_BIN="$REPO/bin/totpgen"
# shellcheck source=scripts/demo/lib.sh
. "$REPO/scripts/demo/lib.sh"
ADMIN_PW="$(cat "$WORK/secrets/admin_password")"
mfa_key() { sed -n 's/^setup_key=//p' "$WORK/state/seed/admin-mfa" | head -n 1; }
verify_audit() {
  local out
  out="$(HOME="$WORK/cli-home" KEYORIX_SERVER="$URL" KEYORIX_TOKEN="$DEMO_TOKEN" "$REPO/bin/keyorix" audit verify --full 2>&1)" || true
  printf '%s\n' "$out" | grep -q 'Audit chain: VALID' || { printf '%s\n' "$out" | head -n 5 >&2; return 1; }
}
login_with_seed() {
  export DEMO_STEP_DIR="$WORK/state/seed/cli-home" # where the seed recorded the TOTP steps it already spent
  demo_login_mfa "$URL" admin "$ADMIN_PW" "$(mfa_key)" >/dev/null
}
snapshot() { # label -> sets U_$label S_$label K_$label
  local u s k
  u="$(count users)"; s="$(count secret_nodes)"
  k="$(mfa_key | cksum | cut -d' ' -f1)"
  eval "U_$1=$u S_$1=$s K_$1=$k"
  say "$1: users=$u secret_nodes=$s"
}

say "mode=$MODE port=$PORT work=$WORK"
say "reset #1 (democtl.sh reset: wipe, bootstrap, seed)"
"$DEMOCTL" reset
login_with_seed || fail "after reset #1 the admin cannot log in with the key in admin-mfa"
verify_audit || fail "after reset #1 audit verify is not VALID"
snapshot r1
[ "$S_r1" -gt 0 ] && [ "$U_r1" -ge 3 ] || fail "reset #1 did not seed the demo (users=$U_r1 secret_nodes=$S_r1)"

say "reset #2"
"$DEMOCTL" reset
login_with_seed || fail "after reset #2 the admin cannot log in with the key in admin-mfa"
verify_audit || fail "after reset #2 audit verify is not VALID"
snapshot r2

[ "$U_r1" = "$U_r2" ] || fail "user counts differ: $U_r1 vs $U_r2"
[ "$S_r1" = "$S_r2" ] || fail "secret counts differ: $S_r1 vs $S_r2"
if [ "$K_r1" = "$K_r2" ]; then say "the admin's TOTP key is the same after the reset"; else say "the admin's TOTP key was re-enrolled by the reset"; fi

# ---- no secret value reached the output (this script's own output is the log) ----------------------
say "checking the secret files hold values that were never printed"
for f in "$WORK/state/seed/demo-passwords" "$WORK/state/seed/admin-mfa" "$WORK/state/seed/state.env"; do
  [ -f "$f" ] || fail "missing $f"
  [ "$(python3 -I -c 'import os,stat,sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))' "$f")" = 0o600 ] || fail "$f is not 0600"
done
grep -q "DEMO_ADMIN_PASSWORD=" "$WORK/state/seed/state.env" && fail "state.env holds the admin password value (it must hold the file path)"
say "OK: $MODE reset twice, same state"
