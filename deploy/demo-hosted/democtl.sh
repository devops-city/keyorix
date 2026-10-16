#!/usr/bin/env bash
# democtl.sh -- day-2 control of the hosted demo VM (DEMO-HOSTED-1).
# install.sh copies it to /usr/local/sbin/keyorix-demo. Run as root.
#
#   keyorix-demo up                 start the stack (idempotent)
#   keyorix-demo down               stop the stack, keep every volume
#   keyorix-demo status             what is running, last reset, gate, idle settings
#   keyorix-demo reset              FULL reset back to the demo seed (nightly timer + on demand)
#   keyorix-demo seed               run only the seed/scenario hook against the running stack
#   keyorix-demo idle-check         stop/power off when nobody used the demo (5-minute timer)
#   keyorix-demo destroy --yes      remove the stack, its data, secrets and units (not the VM)
#   keyorix-demo compose <args...>  docker compose with this install's files and env
#
# Configuration is /etc/keyorix-demo/demo.env (KEY=VALUE, no secrets in it; secrets
# are files under KEYORIX_SECRETS_DIR). Nothing here prints a secret value.
set -euo pipefail

ENV_FILE="${KEYORIX_DEMO_ENV:-/etc/keyorix-demo/demo.env}"
[ -r "$ENV_FILE" ] || { echo "keyorix-demo: cannot read $ENV_FILE (run deploy/demo-hosted/install.sh first)" >&2; exit 1; }
set -a
# shellcheck source=/dev/null
. "$ENV_FILE"
set +a

REPO="${KEYORIX_DEMO_REPO:?KEYORIX_DEMO_REPO missing in $ENV_FILE}"
STATE="${KEYORIX_DEMO_STATE:?KEYORIX_DEMO_STATE missing in $ENV_FILE}"
SECRETS="${KEYORIX_SECRETS_DIR:?KEYORIX_SECRETS_DIR missing in $ENV_FILE}"
PROJECT="keyorix-demo" # the `name:` in docker-compose.demo.yml
LOCK="${KEYORIX_DEMO_LOCK:-/run/lock/keyorix-demo.lock}"
WEB_URL="http://127.0.0.1:8088" # web published on the loopback by the overlay
HEALTH_TIMEOUT="${KEYORIX_DEMO_HEALTH_TIMEOUT:-300}"

log() { printf '%s keyorix-demo: %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

compose() {
  docker compose --project-directory "$REPO" --env-file "$ENV_FILE" \
    -f "$REPO/docker-compose.yml" -f "$REPO/deploy/demo-hosted/docker-compose.demo.yml" \
    --profile tls "$@"
}

# One mutating command at a time (reset vs idle-check vs boot). idle-check never
# waits: it just skips a round while something else is running.
take_lock() { # [-n]
  mkdir -p "$(dirname "$LOCK")"
  exec 9>"$LOCK"
  flock "$@" 9
}

wait_healthy() { # service
  local svc=$1 deadline cid status
  deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
  while :; do
    cid=$(compose ps -q "$svc" 2>/dev/null || true)
    if [ -n "$cid" ]; then
      status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)
      case $status in healthy|running) return 0 ;; esac
    fi
    [ "$(date +%s)" -lt "$deadline" ] || die "$svc did not become healthy within ${HEALTH_TIMEOUT}s"
    sleep 3
  done
}

stamp() { date -u +%FT%TZ > "$STATE/$1"; }

cmd_up() {
  take_lock
  compose up -d
  wait_healthy backend
  wait_healthy web
  stamp last-up
  log "stack is up"
}

cmd_down() {
  take_lock
  compose down --remove-orphans # never -v: the volumes are removed explicitly by reset/destroy
  log "stack is down (volumes kept)"
}

# The seed/scenario hook. DEMO-LOCAL-2 owns the demo seed and scenario scripts and this
# kit never edits or copies them: KEYORIX_DEMO_SEED_SCRIPTS lists repo-relative paths
# that are run in order, each as its own process, with this environment (paths and
# names only; a secret is a FILE the script reads, never a value on argv or in env):
#   KEYORIX_DEMO_URL                       http://127.0.0.1:8088 (web, proxies /api to the backend)
#   KEYORIX_DEMO_ADMIN_USERNAME            first admin (default admin)
#   KEYORIX_DEMO_ADMIN_PASSWORD_FILE       0640 file with the generated admin password
#   KEYORIX_DEMO_BOOTSTRAP_TOKEN_FILE      0600 file with the bootstrap token
# While that list is empty (DEMO-LOCAL-2 not merged at the time of writing) this is a
# PLACEHOLDER: it says so loudly and leaves the instance with the bootstrap admin only.
# KEYORIX_DEMO_REQUIRE_SEED=1 turns the placeholder into a failure.
run_seed_hook() {
  local rel path
  if [ -z "${KEYORIX_DEMO_SEED_SCRIPTS:-}" ]; then
    log "WARNING: seed hook is a PLACEHOLDER (KEYORIX_DEMO_SEED_SCRIPTS is empty): the demo has the bootstrap admin only, no seeded data"
    if [ "${KEYORIX_DEMO_REQUIRE_SEED:-0}" = 1 ]; then
      die "KEYORIX_DEMO_REQUIRE_SEED=1 but no seed script is configured"
    fi
    return 0
  fi
  for rel in $KEYORIX_DEMO_SEED_SCRIPTS; do
    case $rel in /*|*..*) die "seed script path must be repo-relative without '..': $rel" ;; esac
    path="$REPO/$rel"
    [ -x "$path" ] || die "seed script $rel is not an executable file in $REPO"
    log "seed: running $rel"
    KEYORIX_DEMO_URL="$WEB_URL" \
    KEYORIX_DEMO_ADMIN_USERNAME="${KEYORIX_ADMIN_USERNAME:-admin}" \
    KEYORIX_DEMO_ADMIN_PASSWORD_FILE="$SECRETS/admin_password" \
    KEYORIX_DEMO_BOOTSTRAP_TOKEN_FILE="$SECRETS/bootstrap_token" \
      "$path" || die "seed script $rel failed"
  done
}

cmd_seed() {
  take_lock
  run_seed_hook
}

remove_volume() { # short name, e.g. postgres_data
  local vol="${PROJECT}_$1"
  if docker volume inspect "$vol" >/dev/null 2>&1; then
    docker volume rm "$vol" >/dev/null # a failure here must stop the reset, not be skipped
    log "removed volume $vol"
  fi
}

# Full reset: database and encryption keys are wiped, the stack starts empty, the
# bootstrap admin is created again from the same secret files, then the seed hook runs.
# caddy_data (the issued certificate) is kept on purpose: a nightly reset must not
# request a new certificate every time (Let's Encrypt rate limits).
# Fail closed: if anything after the wipe fails, the public entry (caddy) is stopped so
# nobody meets a half-seeded demo; `status` and the log say why.
RESETTING=0
reset_exit_guard() { # EXIT trap: any failure (set -e, die) after the wipe stops caddy
  local rc=$?
  if [ "$RESETTING" = 1 ] && [ "$rc" -ne 0 ]; then
    compose stop caddy >/dev/null 2>&1 || true
    log "reset FAILED (exit $rc); caddy is stopped so the demo is not served half-seeded. See the lines above."
  fi
}

cmd_reset() {
  take_lock
  trap reset_exit_guard EXIT
  log "reset: start"
  compose down --remove-orphans
  RESETTING=1
  remove_volume postgres_data
  remove_volume keyorix_keys
  rm -f "$STATE/last-reset"
  compose up -d
  wait_healthy backend
  wait_healthy web
  run_seed_hook
  RESETTING=0
  stamp last-reset
  stamp last-up
  log "reset: done"
}

# Idle = no successful (2xx/3xx) request through Caddy for KEYORIX_DEMO_IDLE_MINUTES,
# ignoring /health. 401/403 from the gate or scanners do not count as use. A freshly
# started or reset stack gets KEYORIX_DEMO_GRACE_MINUTES before it can be judged idle,
# so starting the VM a few minutes before a call is safe.
cmd_idle_check() {
  take_lock -n || { log "idle-check: another command is running, skipping"; return 0; }
  local idle=${KEYORIX_DEMO_IDLE_MINUTES:-45} grace=${KEYORIX_DEMO_GRACE_MINUTES:-30}
  local action=${KEYORIX_DEMO_IDLE_ACTION:-poweroff} up_s age_min n
  [ "$action" = none ] && { log "idle-check: disabled (KEYORIX_DEMO_IDLE_ACTION=none)"; return 0; }
  up_s=$(cut -d. -f1 /proc/uptime)
  if [ "$up_s" -lt $(( grace * 60 )) ]; then
    log "idle-check: host up ${up_s}s, inside the ${grace} minute grace"; return 0
  fi
  if [ -f "$STATE/last-up" ]; then
    age_min=$(( ( $(date +%s) - $(date -r "$STATE/last-up" +%s) ) / 60 ))
    if [ "$age_min" -lt "$grace" ]; then
      log "idle-check: stack (re)started ${age_min} minutes ago, inside the ${grace} minute grace"; return 0
    fi
  fi
  if [ -z "$(compose ps -q caddy 2>/dev/null || true)" ]; then
    log "idle-check: caddy is not running; nothing to stop"; return 0
  fi
  n=$(compose logs --since "${idle}m" --no-log-prefix caddy 2>/dev/null \
      | grep -F 'http.log.access' | grep -E '"status":[23][0-9][0-9]' | grep -vc -F '"uri":"/health"' || true)
  if [ "${n:-0}" -gt 0 ]; then
    log "idle-check: $n successful request(s) in the last ${idle} minutes, staying up"; return 0
  fi
  log "idle-check: no use for ${idle} minutes, action=$action"
  case $action in
    stop) compose stop ;;
    poweroff) systemctl poweroff ;;
    *) die "KEYORIX_DEMO_IDLE_ACTION must be stop, poweroff or none (got $action)" ;;
  esac
}

cmd_status() {
  compose ps || true
  echo
  echo "host:        $KEYORIX_DOMAIN"
  echo "last up:     $(cat "$STATE/last-up" 2>/dev/null || echo never)"
  echo "last reset:  $(cat "$STATE/last-reset" 2>/dev/null || echo 'none since the last wipe')"
  echo "idle:        ${KEYORIX_DEMO_IDLE_ACTION:-poweroff} after ${KEYORIX_DEMO_IDLE_MINUTES:-45} min (grace ${KEYORIX_DEMO_GRACE_MINUTES:-30} min)"
  echo "seed hook:   ${KEYORIX_DEMO_SEED_SCRIPTS:-PLACEHOLDER (none configured)}"
  echo "gate file:   $KEYORIX_DEMO_GATE_DIR/gate.caddy"
  echo "secrets:     $SECRETS (admin_password, bootstrap_token, gate_password under $STATE)"
}

safe_rm_dir() { # absolute path with at least two components
  case $1 in
    /?*/?*) rm -rf -- "$1" ;;
    *) die "refusing to remove '$1'" ;;
  esac
}

cmd_destroy() {
  [ "${1:-}" = --yes ] || die "destroy removes the stack, ALL demo data, the secrets and the generated units; re-run with --yes"
  take_lock
  log "destroy: removing the stack and every volume (including the issued certificate)"
  compose down -v --remove-orphans || true
  systemctl disable --now keyorix-demo-reset.timer keyorix-demo-idle.timer keyorix-demo.service 2>/dev/null || true
  rm -f /etc/systemd/system/keyorix-demo.service /etc/systemd/system/keyorix-demo-reset.service \
        /etc/systemd/system/keyorix-demo-reset.timer /etc/systemd/system/keyorix-demo-idle.service \
        /etc/systemd/system/keyorix-demo-idle.timer
  rm -rf /etc/systemd/system/keyorix-demo-reset.timer.d
  systemctl daemon-reload || true
  safe_rm_dir "$STATE"
  safe_rm_dir "$(dirname "$ENV_FILE")"
  log "destroy: done. The VM, its disk, the DNS record and the firewall rules are still yours to delete at the provider."
  log "destroy: this script (/usr/local/sbin/keyorix-demo) and the repository checkout are left in place."
}

case "${1:-}" in
  up) cmd_up ;;
  down) cmd_down ;;
  status) cmd_status ;;
  reset) cmd_reset ;;
  seed) cmd_seed ;;
  idle-check) cmd_idle_check ;;
  destroy) shift; cmd_destroy "$@" ;;
  compose) shift; compose "$@" ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
