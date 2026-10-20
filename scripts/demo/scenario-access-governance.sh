#!/usr/bin/env bash
# scripts/demo/scenario-access-governance.sh — catalogue scenario 8: access request + approval,
# then an access-review (recertification) campaign that feeds the compliance posture.
#
#   1. alice has no access to the mobile-app project.
#   2. She files an access request with a reason; an administrator approves it, time-bound.
#   3. Later the periodic review campaign (ISO 27001 A.5.18; the same evidence maps to NIS2
#      Art. 21(2)(i) and DORA Art. 9) snapshots who has access; the independent reviewer
#      (security-officer - nobody reviews their own access) revokes alice's finished-project
#      grant and attests the rest; closing the campaign freezes it as audit evidence.
#   4. The posture control "Access recertification at planned intervals" stays PASS because the
#      cycle ran; alice is refused again.
#
#   scenario-access-governance.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/demo/scn-lib.sh
. "$SCRIPT_DIR/scn-lib.sh"
scn_init
PID=3   # mobile-app

alice_can_list() { scn_cli_as alice secret list --project mobile-app >/dev/null 2>&1 && echo yes || echo no; }

scn_step "1/5 alice has no access to mobile-app"
[ "$(alice_can_list)" = "no" ] || { scn_fail "alice already has access to mobile-app (previous run not cleaned up?)"; exit 1; }
scn_ok "refused"

scn_step "2/5 alice requests access; an administrator approves it for 4 hours"
scn_cli_as alice request access --project-id "$PID" --role project_viewer --reason "Q4 launch support: read-only look at mobile-app secrets"
rid="$(scn_cli_as admin request list --project-id "$PID" | awk '$1 ~ /^[0-9]+$/ && /pending/ {id=$1} END {print id}')"
[ -n "$rid" ] || { scn_fail "no pending access request found"; scn_cli_as admin request list --project-id "$PID" || true; exit 1; }
scn_cli_as admin request review --project-id "$PID" --id "$rid" --action approve --ttl 4h
[ "$(alice_can_list)" = "yes" ] || { scn_fail "alice cannot list after approval"; exit 1; }
scn_ok "request #$rid approved; alice now has time-bound read access"

scn_step "3/5 the periodic access review: the campaign snapshots who can reach mobile-app"
scn_token admin; admin_tok="$SCN_TOKEN"
scn_token officer; officer_tok="$SCN_TOKEN"
demo_api POST "$SCN_URL" "/api/v1/projects/${PID}/access-review/campaigns" "$admin_tok" '{"name":"Q4 access recertification"}'
[ "$DEMO_HTTP_CODE" = "200" ] || [ "$DEMO_HTTP_CODE" = "201" ] || { scn_fail "open campaign: $DEMO_HTTP_CODE $DEMO_BODY"; exit 1; }
cid="$(demo_json 'd["data"]["campaign"]["id"]' "$DEMO_BODY")"
demo_api GET "$SCN_URL" "/api/v1/projects/${PID}/access-review/campaigns/${cid}" "$admin_tok"
items="$(demo_json '"\n".join("%s|%s" % (i["id"], "alice" in json.dumps(i).lower()) for i in d["data"].get("items") or [])' "$DEMO_BODY")"
printf '   campaign #%s snapshot: %s item(s)\n' "$cid" "$(printf '%s\n' "$items" | grep -c .)"

scn_step "4/5 the independent reviewer decides every item (revoke alice's finished-project grant, attest the rest)"
revoked=0
while IFS='|' read -r item is_alice; do
  [ -n "$item" ] || continue
  if [ "$is_alice" = "True" ]; then
    body='{"action":"revoke","reason":"project work finished; temporary access no longer needed"}'; revoked=$((revoked + 1))
  else
    body='{"action":"attest","reason":"access still required"}'
  fi
  demo_api POST "$SCN_URL" "/api/v1/projects/${PID}/access-review/campaigns/${cid}/items/${item}/decide" "$officer_tok" "$body"
  [ "$DEMO_HTTP_CODE" = "200" ] || { scn_fail "decide item $item: $DEMO_HTTP_CODE $DEMO_BODY"; exit 1; }
done <<EOT
$items
EOT
demo_api POST "$SCN_URL" "/api/v1/projects/${PID}/access-review/campaigns/${cid}/close" "$admin_tok" '{"force":false}'
[ "$DEMO_HTTP_CODE" = "200" ] || { scn_fail "close campaign: $DEMO_HTTP_CODE $DEMO_BODY"; exit 1; }
scn_ok "campaign #$cid closed ($revoked grant revoked) - frozen as evidence"

scn_step "5/5 posture and effect"
scn_cli_as admin compliance controls | grep -A2 'Access recertification' | head -n 3
[ "$(alice_can_list)" = "no" ] || { scn_fail "alice still has access after the revoke decision"; exit 1; }
scn_ok "alice is refused again; the control maps to ISO A.5.18, SOC2 CC6.2/CC6.3, NIS2 Art.21(2)(i), DORA Art.9"
