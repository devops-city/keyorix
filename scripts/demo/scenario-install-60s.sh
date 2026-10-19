#!/usr/bin/env bash
# scripts/demo/scenario-install-60s.sh — catalogue scenario 3: install in 60 seconds.
#
#   scenario-install-60s.sh            # native: single binary, init -> running, admin created
#   scenario-install-60s.sh --docker   # container one-liner (docker compose)      PENDING e2e VM
#   scenario-install-60s.sh --airgap   # air-gapped bundle install                 PENDING e2e VM
#
# Native path (verified): from the built server + CLI binaries to a healthy server with an
# admin account takes five commands - init, encryption init, migrate, start, bootstrap - and
# this script times them against a throwaway directory and port, asserting the whole thing is
# under 60 s. It does not time the build (an installed release ships the binary) and does not
# open the browser; with the web UI built and embedded the same server serves it at the URL.
#
# The container and air-gapped paths need Docker, which is not available where this script was
# written; they are written out below exactly as documented (README.md "Quick start",
# docs/AIRGAP_RUNBOOK.md, scripts/airgap-e2e.sh) and have NOT been run by this script.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

mode="${1:-native}"
case "$mode" in
  --docker)
    cat <<'EOF'
PENDING e2e VM (needs Docker) - the documented one-liner, not run here:
    git clone https://github.com/keyorixhq/keyorix && cd keyorix
    docker compose up -d            # then open http://localhost:8088
    (docs/SELF_HOSTING.md: init-secrets.sh generates the compose secrets first)
To time it on the e2e VM:  time docker compose up -d --wait
EOF
    exit 0 ;;
  --airgap)
    cat <<'EOF'
PENDING e2e VM (needs Docker) - the documented air-gapped path, not run here:
    scripts/demo/up.sh              # builds the air-gapped image once, then runs offline
    scripts/airgap-e2e.sh           # proof that nothing leaves the box (--network none)
    docs/AIRGAP_RUNBOOK.md          # bundle verification + import for updates (keyorix bundle)
EOF
    exit 0 ;;
  native|--native) ;;
  *) echo "usage: $0 [--native|--docker|--airgap]" >&2; exit 2 ;;
esac

SERVER="$REPO_ROOT/bin/keyorix-server"; CLI="$REPO_ROOT/bin/keyorix"
[ -x "$SERVER" ] && [ -x "$CLI" ] || { echo "build first: go build -o bin/keyorix-server ./server && GOWORK=off go -C cli build -o ../bin/keyorix ." >&2; exit 1; }
PORT="${KEYORIX_INSTALL_PORT:-18560}"
DIR="$REPO_ROOT/.demo-install-60s"
rm -rf "$DIR"; mkdir -p "$DIR"
( umask 077; openssl rand -hex 32 > "$DIR/bootstrap-token"; printf 'install-60s-%s' "$(openssl rand -hex 12)" > "$DIR/master-passphrase"; printf 'Correct-Horse-%s9' "$(openssl rand -hex 4)" > "$DIR/admin-password" )
SRV_PID=""
trap '[ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true; rm -rf "$DIR"' EXIT

step() { printf '\033[0;36m==>\033[0m %s\n' "$1"; }
T0=$SECONDS
export KEYORIX_MASTER_PASSWORD; KEYORIX_MASTER_PASSWORD="$(cat "$DIR/master-passphrase")"

step "1/5 init (secure baseline config, --dev: no TLS for this local run)"
( cd "$DIR" && "$SERVER" admin init --dev --config keyorix.yaml >/dev/null 2>&1 )
python3 -I - "$DIR/keyorix.yaml" "$PORT" <<'PY'
import sys
p, port = sys.argv[1], sys.argv[2]
s = open(p).read().replace('    port: "8080"\n', '    port: "%s"\n' % port, 1)
open(p, "w").write(s)
PY
step "2/5 encryption init"
( cd "$DIR" && "$SERVER" admin encryption init --config keyorix.yaml >/dev/null 2>&1 )
step "3/5 migrate"
( cd "$DIR" && "$SERVER" admin migrate --config keyorix.yaml >/dev/null 2>&1 )
step "4/5 start the server"
( cd "$DIR"
  export KEYORIX_CONFIG_PATH=keyorix.yaml KEYORIX_BOOTSTRAP_TOKEN
  KEYORIX_BOOTSTRAP_TOKEN="$(cat bootstrap-token)"
  nohup "$SERVER" > server.log 2>&1 &
  echo $! > server.pid )
SRV_PID="$(cat "$DIR/server.pid")"
for _ in $(seq 1 60); do curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/health" && break; sleep 0.5; done
curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/health" || { tail -5 "$DIR/server.log" >&2; echo "server not healthy" >&2; exit 1; }
step "5/5 bootstrap the admin account (bootstrap token and password come from 0600 files / env, not argv)"
KEYORIX_ADMIN_PASSWORD="$(cat "$DIR/admin-password")" KEYORIX_BOOTSTRAP_TOKEN="$(cat "$DIR/bootstrap-token")" \
  HOME="$DIR" "$CLI" system init --server "http://127.0.0.1:$PORT" --admin-username admin --admin-email admin@keyorix.demo >/dev/null
ELAPSED=$((SECONDS - T0))
ui="$(curl -s --max-time 3 "http://127.0.0.1:$PORT/" | head -c 2000)"
# The built dashboard's index.html loads hashed bundles from /assets/; the committed placeholder does not.
case "$ui" in *"/assets/"*) uimsg="the web UI is embedded and served at /" ;; *) uimsg="no web UI embedded in this build (API only; build it with: make build-ui)" ;; esac
printf '\n  healthy server + admin account in %s s (limit 60 s); %s\n' "$ELAPSED" "$uimsg"
[ "$ELAPSED" -lt 60 ] || { echo "FAIL: took ${ELAPSED}s" >&2; exit 1; }
echo "  OK"
