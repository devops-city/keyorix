#!/usr/bin/env bash
# scripts/demo/scenario-tamper-audit.sh — catalogue scenario 1: tamper-evident audit.
#
# Changes ONE audit row directly in the database (bypassing the product, as an insider with
# DB access would), then shows that `keyorix audit verify` pinpoints the exact row, that the
# posture control "Tamper-evident audit trail" turns to GAP, and restores the row so the chain
# is VALID again. The restore also runs on any failure or Ctrl-C.
#
#   scenario-tamper-audit.sh [ROW_ID]      # default row 5
#
# SQLite demo: edits the file with python3's sqlite3. PostgreSQL demo: bin/demo-dbexec
# (built by native-up.sh). Demo-only: this edits the demo's own database on purpose.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/demo/scn-lib.sh
. "$SCRIPT_DIR/scn-lib.sh"
scn_init

ROW="${1:-5}"
ORIG_FILE="$SCN_CLI_HOME/.tamper-original-$ROW"
TAMPERED=false

restore() {
  if [ "$TAMPERED" = true ] && [ -f "$ORIG_FILE" ]; then
    scn_db exec 'UPDATE audit_events SET description = $1 WHERE id = $2' "$(cat "$ORIG_FILE")" "$ROW" >/dev/null
    TAMPERED=false
  fi
}
trap restore EXIT

verify() { scn_cli_as admin audit verify --full 2>&1 || true; }

scn_step "1/5 baseline: the chain verifies"
out="$(verify)"
printf '%s\n' "$out" | sed -n '1,4p;/head id/p'
printf '%s\n' "$out" | grep -q 'Audit chain: VALID' || { scn_fail "baseline chain is not VALID - run scripts/demo/native-up.sh on a fresh demo"; exit 1; }
scn_ok "Audit chain: VALID"

scn_step "2/5 an insider edits audit row $ROW directly in the database"
scn_db query 'SELECT description FROM audit_events WHERE id = $1' "$ROW" > "$ORIG_FILE.tmp"
# strip the single trailing newline the query printer added
printf '%s' "$(cat "$ORIG_FILE.tmp")" > "$ORIG_FILE"; rm -f "$ORIG_FILE.tmp"
[ -s "$ORIG_FILE" ] || { scn_fail "audit row $ROW does not exist"; exit 1; }
scn_info "before: $(cut -c1-70 "$ORIG_FILE")"
TAMPERED=true
scn_db exec 'UPDATE audit_events SET description = $1 WHERE id = $2' "TAMPERED: nothing to see here" "$ROW" >/dev/null
scn_ok "row $ROW rewritten"

scn_step "3/5 verification pinpoints the row"
out="$(verify)"
printf '%s\n' "$out" | grep -E 'Audit chain:|first broken id|reason' || true
printf '%s\n' "$out" | grep -q 'Audit chain: BROKEN' || { scn_fail "tampering was NOT detected"; exit 1; }
printf '%s\n' "$out" | grep -q "first broken id:  $ROW" || { scn_fail "the broken row was not pinpointed as $ROW"; exit 1; }
scn_ok "BROKEN, first broken id: $ROW"

scn_step "4/5 the compliance posture breaks too"
ctrl="$(scn_cli_as admin compliance controls | grep -A1 'Tamper-evident audit trail' || true)"
printf '%s\n' "$ctrl"
printf '%s\n' "$ctrl" | grep -q '^\[GAP' || { scn_fail "the audit control did not turn to GAP"; exit 1; }
scn_ok "Tamper-evident audit trail: GAP (UI: Compliance page, Audit integrity tile)"

scn_step "5/5 restore the row; the chain is VALID again"
restore
out="$(verify)"
printf '%s\n' "$out" | grep -E 'Audit chain:' || true
printf '%s\n' "$out" | grep -q 'Audit chain: VALID' || { scn_fail "chain still not VALID after restore"; exit 1; }
scn_ok "restored; Audit chain: VALID"
rm -f "$ORIG_FILE"
