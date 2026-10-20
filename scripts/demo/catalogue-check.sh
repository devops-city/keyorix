#!/usr/bin/env bash
# scripts/demo/catalogue-check.sh — run every catalogue scenario against the running native
# demo and print one line each: PASS, FAIL, PENDING (needs Docker/kind, exit 3) or SKIPPED
# (a required input is missing, exit 2). Exit 0 only if nothing FAILED.
#   scripts/demo/catalogue-check.sh [scenario-name ...]     # default: all
# The dynamic-credentials scenario needs KEYORIX_DEMO_DYNAMIC_ADMIN_DSN (or a Postgres demo).
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${KEYORIX_DEMO_DIR:-$SCRIPT_DIR/../../.demo-native}/cli-home"
mkdir -p "$LOG_DIR"
if [ "$#" -gt 0 ]; then names=("$@"); else
  names=(tamper-audit vault-import install-60s run oidc-federation dynamic-credentials break-glass access-governance compliance-evidence mcp-readonly k8s-sync share-expiry)
fi
fails=0
printf '%-22s %-8s %s\n' SCENARIO RESULT LOG
for n in "${names[@]}"; do
  log="$LOG_DIR/.catalogue-$n.log"
  "$SCRIPT_DIR/scenario-$n.sh" > "$log" 2>&1; rc=$?
  case "$rc" in
    0) r=PASS ;;
    3) r=PENDING ;;
    2) r=SKIPPED ;;
    *) r=FAIL; fails=$((fails + 1)) ;;
  esac
  printf '%-22s %-8s %s\n' "$n" "$r" "$log"
done
[ "$fails" -eq 0 ]
