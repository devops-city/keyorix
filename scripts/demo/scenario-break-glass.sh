#!/usr/bin/env bash
# scripts/demo/scenario-break-glass.sh — catalogue scenario 7: break-glass emergency access.
#
# alice is a read-only member (project_viewer) of backend-api. In an incident she needs to
# change a secret NOW: she activates break-glass with a written justification, gets the
# configured emergency role (project_developer) for a short, fixed window, does the work, and
# the grant expires on its own. The activation is audited loudly and the project admins are
# notified. A second administrator (security-officer) is the independent reviewer.
#
#   scenario-break-glass.sh            # 30 s grant, waits for the automatic expiry (~40 s)
#   KEYORIX_DEMO_BG_TTL=30s ...        # change the grant length
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/demo/scn-lib.sh
. "$SCRIPT_DIR/scn-lib.sh"
scn_init

TTL="${KEYORIX_DEMO_BG_TTL:-30s}"
PROJECT_ID=2                         # backend-api
NAME="incident-hotfix-$(date +%H%M%S)"
VALUE_FILE="$SCN_CLI_HOME/.bg-value"

write_attempt() { # prints the outcome of alice trying to create a secret
  ( umask 077; printf '%s' 'emergency-value' > "$VALUE_FILE" )
  cd "$SCN_REPO_ROOT"
  local rel="${VALUE_FILE#"$PWD"/}" out
  if out="$(scn_cli_as alice secret create --name "$1" --from-file "$rel" --project "$PROJECT_ID" 2>&1)"; then
    echo "ALLOWED id=$(printf '%s' "$out" | awk '/^ID:/ {print $2}')"
  else
    if printf '%s' "$out" | grep -qiE 'forbidden|denied|permission|not allowed|HTTP 403'; then
      echo "REFUSED: $(printf '%s' "$out" | grep -iE 'forbidden|denied|permission|not allowed|HTTP 403' | head -n 1 | cut -c1-110)"
    else
      echo "ERROR: $(printf '%s' "$out" | grep -m1 '^Error' | cut -c1-110)"
    fi
  fi
  rm -f "$VALUE_FILE"
}

scn_step "1/6 normal day: alice (read-only on backend-api) cannot write"
r="$(write_attempt "${NAME}-a")"; printf '   create secret -> %s\n' "$r"
case "$r" in REFUSED*) scn_ok "refused, as it should be" ;; *) scn_fail "expected a permission refusal, got: $r"; exit 1 ;; esac

scn_step "2/6 incident: alice activates break-glass with a justification (${TTL} window)"
scn_cli_as alice break-glass activate --project-id "$PROJECT_ID" --ttl "$TTL" \
  --justification "INC-4711 payments webhook failing; need to add a replacement secret now"
act_id="$(scn_cli_as alice break-glass list --project-id "$PROJECT_ID" | awk '$1 ~ /^[0-9]+$/ && $3 == "active" {print $1; exit}')"
[ -n "$act_id" ] || { scn_fail "no activation id found in 'break-glass list'"; exit 1; }
scn_ok "activation #$act_id active"
T_ACTIVATED=$SECONDS

scn_step "3/6 alice can now do the emergency change"
r="$(write_attempt "${NAME}-b")"; printf '   create secret -> %s\n' "$r"
CREATED_ID="${r##*id=}"
case "$r" in ALLOWED*) scn_ok "allowed during the window (secret #$CREATED_ID created)" ;; *) scn_fail "alice still refused during an active break-glass"; exit 1 ;; esac

scn_step "4/6 the trail is loud"
scn_cli_as admin audit logs --limit 25 | grep -iE 'break_glass|break-glass|ACTOR' | head -n 6 || true
scn_cli_as admin compliance controls | grep -A1 -E 'break-glass' | head -n 6 || true
scn_info "UI: Notifications (admins alerted on activation), Audit log, Compliance > break-glass control"

scn_step "5/6 automatic expiry: waiting out the ${TTL} window"
secs="${TTL%s}"; case "$secs" in *[!0-9]*) secs=60 ;; esac
# Activation happened ~$SECONDS-T0 ago; sleep out whatever is left of the window plus a margin.
left=$(( secs + 4 - (SECONDS - T_ACTIVATED) ))
[ "$left" -gt 0 ] && sleep "$left"
r="$(write_attempt "${NAME}-c")"
printf '   create secret -> %s\n' "$r"
case "$r" in REFUSED*) scn_ok "expired by itself - no one had to remember to take the access away" ;; *) scn_fail "access still allowed after the window"; exit 1 ;; esac
scn_step "6/6 the independent review (a second administrator; nobody reviews their own emergency access)"
scn_token officer
demo_api POST "$SCN_URL" "/api/v1/projects/${PROJECT_ID}/break-glass/${act_id}/review" "$SCN_TOKEN" \
  '{"note":"Reviewed: INC-4711 confirmed, change was within the incident scope"}'
[ "$DEMO_HTTP_CODE" = "200" ] || { scn_fail "review returned HTTP $DEMO_HTTP_CODE: $DEMO_BODY"; exit 1; }
scn_ok "activation #$act_id reviewed by security-officer (the control counts it as reviewed)"
scn_cli_as admin secret classify --id "$CREATED_ID" --level confidential >/dev/null
scn_info "the emergency secret (${NAME}-b, #$CREATED_ID, classified confidential) remains: it is the work product, visible in the audit trail"
