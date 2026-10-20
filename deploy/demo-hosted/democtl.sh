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
WEB_URL="${KEYORIX_DEMO_WEB_URL:-http://127.0.0.1:8088}" # web published on the loopback by the overlay (override: offline tests only)
SEED_STATE="$STATE/seed" # STATE_DIR of the seed script: state.env, the admin's TOTP key (admin-mfa), generated passwords
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

# The seed/scenario hook. KEYORIX_DEMO_SEED_SCRIPTS lists repo-relative paths (install.sh
# defaults it to the demo seed, which this kit never edits or copies) that are run in order,
# each as its own process with the seed state directory as its only argument ($STATE/seed,
# 0700) and this environment (paths and names only; a secret is a FILE the script reads,
# never a value on argv or in env):
#   KEYORIX_SERVER                         http://127.0.0.1:8088 (web, proxies /api, /auth, /system to the backend)
#   KEYORIX_DEMO_URL                       the same URL, for scripts that name it this way
#   KEYORIX_DEMO_ADMIN_USERNAME            first admin (default admin)
#   KEYORIX_DEMO_ADMIN_PASSWORD_FILE       0640 file with the generated admin password
#   KEYORIX_DEMO_BOOTSTRAP_TOKEN_FILE      0600 file with the bootstrap token
# There is no placeholder: a reset without a seed script fails (fail closed, caddy stays off).
run_seed_hook() {
  local rel path
  [ -n "${KEYORIX_DEMO_SEED_SCRIPTS:-}" ] || die "no seed script configured (KEYORIX_DEMO_SEED_SCRIPTS is empty in $ENV_FILE): re-run install.sh"
  mkdir -p "$SEED_STATE"; chmod 700 "$SEED_STATE"
  for rel in $KEYORIX_DEMO_SEED_SCRIPTS; do
    case $rel in /*|*..*) die "seed script path must be repo-relative without '..': $rel" ;; esac
    path="$REPO/$rel"
    [ -x "$path" ] || die "seed script $rel is not an executable file in $REPO"
    log "seed: running $rel"
    KEYORIX_SERVER="$WEB_URL" \
    KEYORIX_DEMO_URL="$WEB_URL" \
    KEYORIX_DEMO_ADMIN_USERNAME="${KEYORIX_ADMIN_USERNAME:-admin}" \
    KEYORIX_DEMO_ADMIN_PASSWORD_FILE="$SECRETS/admin_password" \
    KEYORIX_DEMO_BOOTSTRAP_TOKEN_FILE="$SECRETS/bootstrap_token" \
      "$path" "$SEED_STATE" || die "seed script $rel failed"
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

# --- the admin's TOTP enrolment survives the reset (HOSTED-RESET-TOTP) -----------------------------
# MFA stays required, and the server generates the TOTP key at enrolment (the API takes none), so
# a wiped admin means the presenter enrols again every morning. The smaller fix is to carry the
# admin's own rows across the wipe instead of importing a key: the encrypted TOTP secret
# (mfa_secrets) and the hashed recovery codes (mfa_recovery_codes), as JSON, in $KEPT_MFA (0600,
# ciphertext only: the key is meaningless without the keyorix_keys volume, which a reset therefore
# keeps). After the fresh admin is bootstrapped they are inserted for that admin and users.mfa_enabled
# is set; the seed then finds the key in $SEED_STATE/admin-mfa still valid and adopts it (it never
# re-enrols). Nothing here prints a row or the key. Any failure only costs the presenter one
# re-enrolment: the stale key file is removed so the seed enrols a new key.
KEPT_MFA="$STATE/admin-mfa-rows"
ADMIN_USER="${KEYORIX_ADMIN_USERNAME:-admin}"

pg_sql() { compose exec -T postgres psql -U keyorix -d keyorix -qAtX -v ON_ERROR_STOP=1 "$@"; }

capture_admin_mfa() {
  local tmp
  rm -f "$KEPT_MFA"
  [[ $ADMIN_USER =~ ^[A-Za-z0-9._-]+$ ]] || { log "reset: admin user name has unusual characters; its TOTP is not kept"; rm -f "$SEED_STATE/admin-mfa"; return 0; }
  if [ ! -s "$SEED_STATE/admin-mfa" ]; then
    log "reset: no admin TOTP key from an earlier seed; the seed will enrol one"
    return 0
  fi
  tmp=$(umask 077; mktemp "$STATE/.admin-mfa-rows.XXXXXX")
  if compose up -d postgres >/dev/null 2>&1 && ( wait_healthy postgres ) \
     && pg_sql -c "SELECT 'S ' || row_to_json(m) FROM mfa_secrets m JOIN users u ON u.id = m.user_id WHERE u.username = '$ADMIN_USER' AND m.activated
                   UNION ALL
                   SELECT 'C ' || row_to_json(c) FROM mfa_recovery_codes c JOIN users u ON u.id = c.user_id WHERE u.username = '$ADMIN_USER'" >"$tmp" \
     && grep -q '^S ' "$tmp"; then
    mv "$tmp" "$KEPT_MFA"
    log "reset: the admin's TOTP enrolment is kept ($(grep -c . "$KEPT_MFA") row(s), not shown)"
  else
    rm -f "$tmp"
    rm -f "$SEED_STATE/admin-mfa"
    log "WARNING: could not read the admin's TOTP enrolment; it is NOT kept and the presenter must enrol again after this reset"
  fi
}

# The entrypoint bootstraps the admin once the backend is healthy; wait for that row.
restore_admin_mfa() {
  local i n line sql
  [ -s "$KEPT_MFA" ] || return 0
  for i in $(seq 1 30); do
    n=$(pg_sql -c "SELECT count(*) FROM users WHERE username = '$ADMIN_USER'" 2>/dev/null || true)
    [ "${n:-0}" = 1 ] && break
    [ "$i" -lt 30 ] || { log "WARNING: the bootstrapped admin did not appear; its TOTP is NOT restored"; rm -f "$SEED_STATE/admin-mfa"; return 0; }
    sleep 2
  done
  sql="BEGIN;
DELETE FROM mfa_recovery_codes WHERE user_id = (SELECT id FROM users WHERE username = '$ADMIN_USER');
DELETE FROM mfa_secrets WHERE user_id = (SELECT id FROM users WHERE username = '$ADMIN_USER');"
  while IFS= read -r line; do
    case $line in
      "S "*) sql="$sql
INSERT INTO mfa_secrets SELECT (json_populate_record(NULL::mfa_secrets, (\$kx\$${line#S }\$kx\$::jsonb || jsonb_build_object('id', nextval(pg_get_serial_sequence('mfa_secrets','id')), 'user_id', (SELECT id FROM users WHERE username = '$ADMIN_USER')))::json)).*;" ;;
      "C "*) sql="$sql
INSERT INTO mfa_recovery_codes SELECT (json_populate_record(NULL::mfa_recovery_codes, (\$kx\$${line#C }\$kx\$::jsonb || jsonb_build_object('id', nextval(pg_get_serial_sequence('mfa_recovery_codes','id')), 'user_id', (SELECT id FROM users WHERE username = '$ADMIN_USER')))::json)).*;" ;;
    esac
  done <"$KEPT_MFA"
  sql="$sql
UPDATE users SET mfa_enabled = true WHERE username = '$ADMIN_USER';
COMMIT;"
  if printf '%s\n' "$sql" | pg_sql >/dev/null; then
    log "reset: the admin's TOTP enrolment is restored (the key in $SEED_STATE/admin-mfa stays valid)"
  else
    rm -f "$SEED_STATE/admin-mfa"
    log "WARNING: restoring the admin's TOTP failed; the seed enrols a new key, the presenter must enrol again"
  fi
}

# Full reset: the database is wiped, the stack starts empty, the bootstrap admin is created
# again from the same secret files (its TOTP enrolment is carried across, see above), then the
# seed hook runs. Kept on purpose: caddy_data (the issued certificate: a nightly reset must not
# request a new certificate every time, Let's Encrypt rate limits) and keyorix_keys (the kept
# TOTP secret is encrypted under them; the demo data is re-encrypted under the same keys).
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
  capture_admin_mfa
  compose down --remove-orphans
  RESETTING=1
  remove_volume postgres_data
  rm -f "$STATE/last-reset"
  # The seed state belongs to the data just wiped, except the admin's TOTP key file and the
  # step ledger of already-spent codes (cli-home) when the enrolment was kept.
  rm -f "$SEED_STATE/state.env" "$SEED_STATE/demo-passwords" "$SEED_STATE/server.url" "$SEED_STATE/bootstrap-token"
  compose up -d
  wait_healthy backend
  wait_healthy web
  restore_admin_mfa
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
  echo "seed hook:   ${KEYORIX_DEMO_SEED_SCRIPTS:-NONE (a reset will fail)}  (state: $SEED_STATE)"
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
