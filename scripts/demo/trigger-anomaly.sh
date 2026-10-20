#!/usr/bin/env bash
# scripts/demo/trigger-anomaly.sh — trigger a REAL anomaly on the running demo, live.
#
# The demo starts calm (zero open anomalies). Each scenario below performs ordinary,
# authorised API calls that one of the product's existing detectors
# (internal/core/anomaly.go) flags; the alert then appears under Anomalies / the dashboard
# Alerts tile within one detection pass (the demo runs a pass every 15 s). Nothing is
# faked or inserted: the alert, its audit trail and the notification are produced by the
# product itself.
#
#   trigger-anomaly.sh list
#   trigger-anomaly.sh bulk-read      # machine identity reads 13 secrets it never read
#   trigger-anomaly.sh read-burst     # one secret read 25 times in a minute
#   trigger-anomaly.sh off-hours      # a read inside the (temporarily moved) off-hours window
#   trigger-anomaly.sh new-source     # a read from a client address never seen before
#   trigger-anomaly.sh login-burst    # AUDIT-ONLY: failed-login burst -> account lockout
#   trigger-anomaly.sh probe          # AUDIT-ONLY: refused secret reads (probing)
#   trigger-anomaly.sh status         # open anomalies right now
#   trigger-anomaly.sh reset          # back to calm: ack alerts, restore config, revoke actors
#
# Detectors used and thresholds (defaults of internal/core/anomaly.go; the demo changes none
# of them except the pass cadence, anomaly_alerts.schedule=15s):
#   principal_breadth  >= 5 distinct secrets a principal never read before in one scan window
#                      (medium; >= 10 -> high)                            [bulk-read]
#   frequency_spike    >= 10 reads in the window AND > 3x the secret's hourly baseline
#                      (medium)                                           [read-burst]
#   cumulative_rate    > 20 reads in 24 h on a secret averaging < 1/day (medium) [read-burst]
#   off_hours          read inside the configured off-hours band (default UTC 22:00-06:00;
#                      the scenario moves the band over "now" and reset restores it) [off-hours]
#   new_ip / new_user  first access from an address / principal not in the 24h-quarantined
#                      baseline; LOW severity while a secret has no history, which is every
#                      secret in a fresh demo (high once the demo has history)  [new-source]
# NOT anomaly detectors (no alert exists for them today; both leave audit rows and the first
# also trips the per-account lockout): failed-login burst, refused-read probing.
#
# No secrets on argv: sessions come from the 0600 state file via scripts/demo/scn-lib.sh,
# tokens travel in header files.
#
# Repeatability: the product suppresses an equivalent alert (same secret, type, accessor and
# client address) for one hour, acknowledged or not. So every run uses a fresh actor
# (bulk-read mints its own machine identity) or a fresh secret / source address (the others
# rotate through ids 1,4..13), and 'reset' acknowledging alerts is permanent: the detector
# does not re-raise them (checked: calm stays calm across later passes).

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/demo/scn-lib.sh
. "$SCRIPT_DIR/scn-lib.sh"

WAIT_SECONDS="${KEYORIX_DEMO_ANOMALY_WAIT:-90}"
ACTORS_FILE=""   # set in main after scn_init: machine identities this script created
CFG_BACKUP=""

usage() { sed -n '2,12p;13,16p' "$0" | sed 's/^# \{0,1\}//'; }

# new_machine_token NAME — create a machine identity with project_viewer on default and
# print its token to stdout (never to the terminal by the caller).
new_machine_token() {
  local name="$1" out
  scn_cli_as admin machine create --name "$name" --project default --type ci --classification internal >/dev/null
  scn_cli_as admin machine grant-role "$name" --project default --role project_viewer >/dev/null
  out="$(scn_cli_as admin machine token issue "$name" --name "${name}-token" --project default --classification internal)"
  printf '%s\n' "$name" >> "$ACTORS_FILE"
  printf '%s\n' "$out" | grep -oE 'kx_machine_[A-Za-z0-9_-]+' | head -1
}

# next_target — sets TARGET_ID to the next secret the CI identity (viewer on the default
# project) may read, rotating through ids 1,4..13. The product de-duplicates an alert per
# (secret, type, accessor, ip) for an hour even after it is acknowledged, so a repeat run
# aimed at the same secret would stay silent; a fresh secret per run keeps every run live.
next_target() {
  local ids=(1 4 5 6 7 8 9 10 11 12 13) n=0 f="$SCN_CLI_HOME/.scn-anomaly-target"
  [ -f "$f" ] && n="$(cat "$f")"
  case "$n" in ''|*[!0-9]*) n=0 ;; esac
  TARGET_ID="${ids[$((n % ${#ids[@]}))]}"
  printf '%s' $((n + 1)) > "$f"
}

# read_secret TOKEN ID [curl args...] — value read; prints the HTTP status.
read_secret() {
  local token="$1" id="$2"; shift 2
  scn_http_code "$token" "/api/v1/secrets/${id}?include_value=true" "$@"
}

expect_alert() { # TYPE WHO - only an alert raised after scn_mark_alerts, for that accessor
  local type="$1" who="$2" t0 hit
  t0=$(date +%s)
  scn_info "waiting for a '$type' alert (the detector runs every 15 s)..."
  if hit="$(scn_wait_anomaly "$type" "$WAIT_SECONDS" "$who")"; then
    scn_ok "ANOMALY RAISED after $(( $(date +%s) - t0 )) s:"
    printf '%s\n' "$hit" | while read -r id ty sev who sec; do
      printf '      #%s  %s  severity=%s  by=%s  secret=%s\n' "$id" "$ty" "$sev" "$who" "$sec"
    done
    scn_info "UI: Anomalies page / dashboard Alerts tile.  CLI: keyorix anomalies list --unacknowledged"
    scn_info "audit trail: keyorix audit logs   (the reads behind the alert)"
  else
    scn_fail "no '$type' alert within ${WAIT_SECONDS}s"
    return 1
  fi
}

do_bulk_read() {
  local name tok id bad=0
  name="exfil-bot-$(date +%H%M%S)"
  scn_mark_alerts
  scn_step "bulk-read: machine identity '$name' reads 13 secrets it has never read"
  tok="$(new_machine_token "$name")"
  [ -n "$tok" ] || { scn_fail "could not mint a machine token"; return 1; }
  for id in 1 2 3 4 5 6 7 8 9 10 11 12 13; do
    case "$(read_secret "$tok" "$id")" in
      200) ;;
      403|404) ;;                       # secrets outside the actor's grant are refused (audited)
      *) bad=$((bad + 1)) ;;
    esac
  done
  [ "$bad" -eq 0 ] || scn_info "$bad unexpected read response(s)"
  expect_alert principal_breadth "$name"
}

do_read_burst() {
  local i
  next_target
  scn_step "read-burst: the CI identity reads secret #$TARGET_ID 25 times in a few seconds"
  scn_mark_alerts
  for i in $(seq 1 25); do read_secret "$DEMO_MACHINE_TOKEN" "$TARGET_ID" >/dev/null; done
  expect_alert frequency_spike ""
}

do_new_source() {
  local ip
  next_target
  ip="203.0.113.$(( (RANDOM % 250) + 1 ))"
  scn_step "new-source: the CI identity reads secret #$TARGET_ID from $ip (documentation range), a client never seen before"
  scn_mark_alerts
  read_secret "$DEMO_MACHINE_TOKEN" "$TARGET_ID" -H "X-Forwarded-For: $ip" >/dev/null
  expect_alert new_ip ci-app
}

do_off_hours() {
  local h end body
  scn_step "off-hours: move the off-hours band over 'now', then read a secret"
  scn_token admin
  demo_api GET "$SCN_URL" /api/v1/admin/anomaly-config "$SCN_TOKEN"
  [ "$DEMO_HTTP_CODE" = "200" ] || { scn_fail "cannot read anomaly config ($DEMO_HTTP_CODE)"; return 1; }
  [ -f "$CFG_BACKUP" ] || ( umask 077; printf '%s' "$DEMO_BODY" > "$CFG_BACKUP" )
  h=$(date -u +%H); h=$((10#$h)); end=$(( (h + 2) % 24 ))
  body="$(DEMO_JSON="$DEMO_BODY" DEMO_H="$h" DEMO_E="$end" python3 -c '
import json, os
c = json.loads(os.environ["DEMO_JSON"])["data"]["config"]
for k in ("ID", "updated_at", "updated_by"):
    c.pop(k, None)
c.update(off_hours_enabled=True, off_hours_timezone="UTC", off_hours_start=int(os.environ["DEMO_H"]), off_hours_end=int(os.environ["DEMO_E"]))
print(json.dumps(c))')"
  demo_api PUT "$SCN_URL" /api/v1/admin/anomaly-config "$SCN_TOKEN" "$body"
  [ "$DEMO_HTTP_CODE" = "200" ] || { scn_fail "cannot update anomaly config ($DEMO_HTTP_CODE): $DEMO_BODY"; return 1; }
  scn_info "off-hours band is now ${h}:00-${end}:00 UTC (restored by 'reset')"
  next_target
  scn_mark_alerts
  read_secret "$DEMO_MACHINE_TOKEN" "$TARGET_ID" >/dev/null
  expect_alert off_hours ci-app
}

do_login_burst() {
  local name pw i code ip
  name="intern-$(date +%H%M%S)"
  scn_step "login-burst (AUDIT-ONLY): 6 wrong passwords against a throwaway account '$name'"
  command -v openssl >/dev/null 2>&1 || { scn_fail "openssl is required"; return 1; }
  pw="Kx-$(openssl rand -hex 16)-Z9"
  KEYORIX_INITIAL_PASSWORD="$pw" scn_cli_as admin user create --username "$name" --email "${name}@keyorix.demo" >/dev/null
  printf 'user:%s\n' "$name" >> "$ACTORS_FILE"
  # The attacker comes from its own address (X-Forwarded-For, loopback is a trusted proxy in
  # the demo): the per-IP login throttle then counts it separately from the presenter's logins.
  ip="198.51.100.$(( (RANDOM % 250) + 1 ))"
  for i in 1 2 3 4 5 6; do
    code="$(printf '{"username":"%s","password":"wrong-password-attempt"}' "$name" \
      | curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST -H 'Content-Type: application/json' -H "X-Forwarded-For: $ip" --data-binary @- "$SCN_URL/auth/login")"
    printf '      attempt %s -> HTTP %s\n' "$i" "$code"
  done
  scn_ok "no anomaly alert exists for this (see header): the evidence is the audit trail"
  scn_cli_as admin audit logs --limit 12 | grep -E 'auth.login_failed|account.locked' | head -n 8 || true
  scn_info "after the 5th failure the account is locked (lockout #1, about a minute); 'reset' deletes the throwaway account"
}

do_probe() {
  local id code n=0
  scn_step "probe (AUDIT-ONLY): alice (viewer on backend-api only) tries secrets outside her grant"
  scn_token alice
  for id in 1 4 5 6 7 8 9 10; do
    code="$(scn_http_code "$SCN_TOKEN" "/api/v1/secrets/${id}?include_value=true")"
    printf '      secret %s -> HTTP %s\n' "$id" "$code"
    case "$code" in 403|404) n=$((n + 1)) ;; esac
  done
  [ "$n" -gt 0 ] || { scn_fail "no refusals recorded"; return 1; }
  scn_ok "$n refused reads; each leaves an audit row (refused-read audit, #3274) - not an anomaly alert"
}

do_status() {
  local lines
  lines="$(scn_open_anomalies)"
  case "$lines" in ERROR*) scn_fail "$lines"; return 1 ;; esac
  if [ -z "$lines" ]; then scn_ok "calm: 0 open anomalies"; else printf 'open anomalies:\n%s\n' "$lines"; fi
}

do_reset() {
  local n name uid body
  scn_step "reset: back to calm"
  n="$(scn_ack_all)"
  scn_ok "acknowledged $n open alert(s) (they stay in history and in the audit trail)"
  if [ -f "$CFG_BACKUP" ]; then
    scn_token admin
    body="$(python3 -c '
import json, sys
c = json.loads(open(sys.argv[1]).read())["data"]["config"]
for k in ("ID", "updated_at", "updated_by"):
    c.pop(k, None)
print(json.dumps(c))' "$CFG_BACKUP")"
    demo_api PUT "$SCN_URL" /api/v1/admin/anomaly-config "$SCN_TOKEN" "$body"
    [ "$DEMO_HTTP_CODE" = "200" ] && { rm -f "$CFG_BACKUP"; scn_ok "off-hours band restored"; } || scn_fail "could not restore anomaly config ($DEMO_HTTP_CODE)"
  fi
  if [ -f "$ACTORS_FILE" ]; then
    while read -r name; do
      [ -n "$name" ] || continue
      case "$name" in
        user:*)
          uid="$(scn_cli_as admin user list | awk -v n="${name#user:}" '$2 == n {print $1}')"
          if [ -n "$uid" ] && scn_cli_as admin user delete --id "$uid" --by admin@keyorix.demo --force >/dev/null 2>&1; then
            scn_ok "deleted throwaway account ${name#user:}"
          else
            scn_info "could not delete ${name#user:} (already gone?)"
          fi
          continue ;;
      esac
      scn_cli_as admin machine revoke "$name" --project default --force >/dev/null 2>&1 && scn_ok "revoked machine identity $name" || scn_info "could not revoke $name (already revoked?)"
    done < "$ACTORS_FILE"
    rm -f "$ACTORS_FILE"
  fi
  scn_ok "final state: $(do_status 2>&1 | tail -n 1)"
}

cmd="${1:-}"
case "$cmd" in
  ""|-h|--help|help) usage; exit 0 ;;
esac
scn_init
ACTORS_FILE="$SCN_CLI_HOME/.scn-anomaly-actors"
CFG_BACKUP="$SCN_CLI_HOME/.scn-anomaly-config.orig"
case "$cmd" in
  list)        echo "bulk-read read-burst off-hours new-source login-burst probe status reset" ;;
  bulk-read)   do_bulk_read ;;
  read-burst)  do_read_burst ;;
  off-hours)   do_off_hours ;;
  new-source)  do_new_source ;;
  login-burst) do_login_burst ;;
  probe)       do_probe ;;
  status)      do_status ;;
  reset)       do_reset ;;
  *) echo "unknown scenario: $cmd" >&2; usage >&2; exit 2 ;;
esac
