#!/usr/bin/env bash
# scripts/demo/anomaly-check.sh — proof that the ANOMALY DEMO works on the running demo:
#   1. the freshly seeded demo is calm (zero open anomalies),
#   2. every anomaly scenario of scripts/demo/trigger-anomaly.sh makes its alert appear,
#   3. `reset` returns the demo to zero open anomalies after each one.
# Needs a demo started by scripts/demo/native-up.sh (the detector pass must be 15 s). Exit 0
# only if every check passes. Run it on a freshly seeded demo, or after a `reset`: it starts
# by requiring calm.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRIGGER="$SCRIPT_DIR/trigger-anomaly.sh"
# shellcheck source=scripts/demo/scn-lib.sh
. "$SCRIPT_DIR/scn-lib.sh"
scn_init || exit 1

fails=0
declare -a rows
record() { # NAME RESULT NOTE
  rows+=("$(printf '%-18s %-5s %s' "$1" "$2" "$3")")
  [ "$2" = PASS ] || fails=$((fails + 1))
}

n="$(scn_open_count)"
if [ "$n" = "0" ]; then record calm-seed PASS "0 open anomalies"; else
  record calm-seed FAIL "$n open anomalies at start: $(scn_open_anomalies | tr '\n' ';')"
  echo "start from a calm demo: scripts/demo/trigger-anomaly.sh reset (a FAIL here on a fresh seed is a seed bug)" >&2
fi

for sc in bulk-read read-burst off-hours new-source login-burst probe; do
  if "$TRIGGER" "$sc" >"$SCN_CLI_HOME/.anomaly-check-$sc.log" 2>&1; then
    record "$sc" PASS "scenario ran; expected evidence present"
  else
    record "$sc" FAIL "see $SCN_CLI_HOME/.anomaly-check-$sc.log"
  fi
  "$TRIGGER" reset >"$SCN_CLI_HOME/.anomaly-check-reset.log" 2>&1
  n="$(scn_open_count)"
  if [ "$n" = "0" ]; then record "reset-$sc" PASS "calm again"; else record "reset-$sc" FAIL "$n still open"; fi
done

printf '\n%-18s %-6s %s\n' CHECK RESULT NOTE
printf '%s\n' "${rows[@]}"
if [ "$fails" -eq 0 ]; then echo "ALL PASS"; else echo "$fails FAILED"; fi
[ "$fails" -eq 0 ]
