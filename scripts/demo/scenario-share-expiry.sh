#!/usr/bin/env bash
# scripts/demo/scenario-share-expiry.sh — catalogue scenario 12: share with expiry + revoke.
#
# The owner of db-password (admin, project_admin on backend-api) lets alice - a read-only
# member - rotate that ONE secret by sharing it with write permission for a short time. The
# share expires by itself; a second share is revoked by hand and takes effect immediately.
# No role change, no ticket to remember to undo.
#
#   scenario-share-expiry.sh        # 25 s share, waits for the automatic expiry
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/demo/scn-lib.sh
. "$SCRIPT_DIR/scn-lib.sh"
scn_init

SECRET_ID=2        # db-password, backend-api / development
ALICE_ID=2         # alice
TTL=25

alice_rotate() { # prints ALLOWED or REFUSED: <why>
  local out
  if out="$(printf '%s\n' "demo-db-pass-$(date +%s)" | scn_cli_as alice secret rotate --id "$SECRET_ID" 2>&1)"; then
    echo ALLOWED
  elif printf '%s' "$out" | grep -qiE 'forbidden|denied|permission|HTTP 403|not found|expired'; then
    echo "REFUSED: $(printf '%s' "$out" | grep -iE 'forbidden|denied|permission|HTTP 403|not found|expired' | head -n 1 | cut -c1-100)"
  else
    echo "ERROR: $(printf '%s' "$out" | head -n 2 | tr '\n' ' ' | cut -c1-120)"
  fi
}
newest_share_id() { scn_cli_as admin share list --secret-id "$SECRET_ID" | awk '$1 ~ /^[0-9]+$/ {id=$1} END {print id}'; }

scn_step "1/5 alice (read-only on backend-api) cannot rotate db-password"
r="$(alice_rotate)"; printf '   alice rotate -> %s\n' "$r"
case "$r" in REFUSED*) scn_ok "refused" ;; *) scn_fail "expected a refusal, got: $r"; exit 1 ;; esac

scn_step "2/5 the owner shares that one secret with alice: write permission, ${TTL}-second lifetime"
scn_cli_as admin share create --secret-id "$SECRET_ID" --recipient-id "$ALICE_ID" --permission write --ttl "${TTL}s"
T0=$SECONDS
r="$(alice_rotate)"; printf '   alice rotate -> %s\n' "$r"
case "$r" in ALLOWED*) scn_ok "allowed while the share is live" ;; *) scn_fail "expected ALLOWED, got: $r"; exit 1 ;; esac

scn_step "3/5 expiry: nobody revokes anything"
left=$(( TTL + 3 - (SECONDS - T0) )); [ "$left" -gt 0 ] && sleep "$left"
r="$(alice_rotate)"; printf '   alice rotate -> %s\n' "$r"
case "$r" in REFUSED*) scn_ok "the share expired by itself" ;; *) scn_fail "still allowed after expiry: $r"; exit 1 ;; esac

scn_step "4/5 revoke on demand: a fresh 1-hour share, then taken back"
scn_cli_as admin share create --secret-id "$SECRET_ID" --recipient-id "$ALICE_ID" --permission write --ttl 1h
sid="$(newest_share_id)"
[ -n "$sid" ] || { scn_fail "no share id found"; exit 1; }
r="$(alice_rotate)"; printf '   alice rotate -> %s\n' "$r"
case "$r" in ALLOWED*) ;; *) scn_fail "expected ALLOWED, got: $r"; exit 1 ;; esac
scn_cli_as admin share revoke --share-id "$sid"
r="$(alice_rotate)"; printf '   alice rotate after revoke -> %s\n' "$r"
case "$r" in REFUSED*) scn_ok "revoked: effective immediately" ;; *) scn_fail "still allowed after revoke: $r"; exit 1 ;; esac

scn_step "5/5 who had access, when, and who changed it - all in the audit trail"
scn_cli_as admin audit logs --limit 20 | grep -iE 'share|ACTOR' | head -n 6 || true
