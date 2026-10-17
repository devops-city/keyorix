#!/usr/bin/env bash
# scripts/drills/rotation-under-load.sh -- DEK rotation with a load generator running (PROD-VERIFY-1 item 4).
#
# docs/operator/j6-key-rotation.md: `admin encryption rotate` needs EXCLUSIVE access to the
# database, so the supported procedure is stop the server, rotate, start it again. There is no
# online rewrap command. This drill runs that procedure while a load generator (load.sh) keeps
# reading, writing and deleting through it, and checks:
#   1. rotate --confirm beside the live, loaded server is REFUSED, and the load sees no failure
#      because of the attempt (the refusal must not disturb the server);
#   2. across stop -> rotate -> start, every failed request falls inside the window between the
#      stop and the server being healthy again; none before it, none after it;
#   3. afterwards every write the server acknowledged reads back with exactly that value (or is
#      gone, for a delete): nothing undecryptable, nothing lost; the seeded data is intact,
#      `encryption validate` passes and `admin verify-audit` is VALID.
# The multi-replica rotation fence (a second server on the same database) is not exercised here.
#
# Usage: [DRILL_BACKEND=postgres DRILL_PG_DSN_FILE=a.txt] [DRILL_SERVER_BIN=... DRILL_CLI_BIN=...] \
#        [LOAD_SECONDS=10] scripts/drills/rotation-under-load.sh
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=load.sh
source "$(dirname "${BASH_SOURCE[0]}")/load.sh"

drill_begin rotation-under-load
I=inst
P="$(drill_port 31)"
d="$DRILL_DIR/$I"
LOAD_SECONDS="${LOAD_SECONDS:-10}"

step "provision and seed"
inst_new "$I" "$P"
srv_start "$I" "$P"
seed_data "$I" "$P"

step "start the load generator (2 readers, 2 writers)"
load_start "$I" "$P"
sleep "$LOAD_SECONDS"
[ -s "$LOADLOG/read.1.log" ] && [ -s "$LOADLOG/write.1.log" ] || fail "the load generator produced no traffic"
if [ "$(load_count fail)" != "0" ]; then
    grep -h ' fail ' "$LOADLOG"/*.log | head -5 >&2
    fail "the load generator sees failures against a healthy server before any rotation"
fi
ok "baseline: $(load_count ok) requests ok, no failure"

# ---- 1. rotation beside the live, loaded server is refused ------------------------------
step "1. rotate --confirm beside the live, loaded server"
dek_before="$(shasum -a 256 "$d/keys/dek.key" | cut -d' ' -f1)"
t_try="$(now)"
if inst_admin "$I" encryption rotate --confirm >"$DRILL_DIR/rotate-live.log" 2>&1; then
    fail "DEK rotation ran beside a live, loaded server"
fi
ok "refused: $(grep -m1 -i 'error' "$DRILL_DIR/rotate-live.log" | cut -c1-140)"
[ "$(shasum -a 256 "$d/keys/dek.key" | cut -d' ' -f1)" = "$dek_before" ] || fail "the refused rotation changed the DEK file"
sleep 3
fails_try="$(awk -v t="$t_try" '$1 >= t && $3 == "fail"' "$LOADLOG"/*.log | wc -l | tr -d ' ')"
[ "$fails_try" = "0" ] || { awk -v t="$t_try" '$1 >= t && $3 == "fail"' "$LOADLOG"/*.log | head -5 >&2; fail "the refused rotation disturbed the load ($fails_try failures)"; }
ok "the refusal did not disturb the load (0 failures after it)"

# ---- 2. the documented procedure under load -------------------------------------------------
step "2. stop the server, rotate, start it (load keeps running)"
t_stop="$(now)"
srv_stop "$I"
t_stopped="$(now)"
out="$(inst_admin "$I" encryption rotate --confirm 2>&1)" || { echo "$out" >&2; fail "rotate --confirm failed"; }
echo "$out" | grep -q 'DEK rotated' || { echo "$out" >&2; fail "rotate did not report success"; }
t_rotated="$(now)"
[ "$(shasum -a 256 "$d/keys/dek.key" | cut -d' ' -f1)" != "$dek_before" ] || fail "DEK file unchanged after rotation"
srv_start "$I" "$P"
t_healthy="$(now)"
sleep "$LOAD_SECONDS"
load_stop
echo "$t_stop $t_healthy" >"$d/windows.txt"
ok "unavailability window (SIGTERM to healthy): $(awk -v a="$t_stop" -v b="$t_healthy" 'BEGIN{printf "%.1f", b-a}')s; stop took $(awk -v a="$t_stop" -v b="$t_stopped" 'BEGIN{printf "%.1f", b-a}')s, rotation $(awk -v a="$t_stopped" -v b="$t_rotated" 'BEGIN{printf "%.1f", b-a}')s"

outside="$(load_failures_outside "$d/windows.txt" | wc -l | tr -d ' ')"
total_fail="$(load_count fail)"
echo "    requests ok: $(load_count ok); failed in total: $total_fail; failed outside the window: $outside"
if [ "$outside" != "0" ]; then
    load_failures_outside "$d/windows.txt" | head -8 >&2
    fail "$outside requests failed outside the documented stop-to-healthy window"
fi
after_ok="$(awk -v b="$t_healthy" '$1 > b + 2 && $3 == "ok"' "$LOADLOG"/*.log | wc -l | tr -d ' ')"
[ "$after_ok" -gt 0 ] || fail "the load did not resume after the restart"
ok "load resumed after the restart ($after_ok successful requests), no failure outside the window"

# ---- 3. nothing lost, nothing undecryptable -------------------------------------------------
step "3. every acknowledged write reads back; nothing undecryptable; audit chain"
load_check_ledger
verify_seed "$I" "$P"
srv_stop "$I"
inst_admin "$I" encryption validate >"$DRILL_DIR/validate.log" 2>&1 || { cat "$DRILL_DIR/validate.log" >&2; fail "encryption validate failed after the rotation"; }
ok "encryption validate passes"
verify_audit "$I"
drill_end "ROTATION-UNDER-LOAD DRILL"
