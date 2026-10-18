#!/usr/bin/env bash
# crash-soak.sh -- kill -9 soak for an unattended edge install (EDGE-1).
#
# Runs TestEdgeCrashSoak_SQLite (server/edge_crash_soak_integration_test.go):
# the real built keyorix-server on SQLite, mixed create/update/delete/read
# traffic, SIGKILL at random points, plain restart, then: healthy with no
# manual step, every acknowledged write present, `admin verify-audit` VALID,
# every acknowledged value disclosure has its audit row.
#
# SIGKILL stops the process, not the disk: this is the "server crash" row of
# docs/edge-deployment.md, not a power cut. A real power cut (dm-flakey) is a
# separate run on the e2e VM.
#
# Usage:
#   scripts/edge/crash-soak.sh                 # 25 cycles, 4 writers
#   scripts/edge/crash-soak.sh -n 100 -w 8     # bigger
#   scripts/edge/crash-soak.sh -s 12345        # replay a failing seed
#   scripts/edge/crash-soak.sh --lenient-mutation-audit
#       only log (do not fail) when an acknowledged create/update/delete lacks
#       its audit row. Strict is the default since the mutation audit joined the
#       mutation's transaction (also: KEYORIX_SOAK_STRICT_MUTATION_AUDIT=0)
set -euo pipefail

cycles=25
writers=4
seed=""
lenient_mutation=""

while [ $# -gt 0 ]; do
  case "$1" in
    -n|--cycles) cycles="$2"; shift 2 ;;
    -w|--writers) writers="$2"; shift 2 ;;
    -s|--seed) seed="$2"; shift 2 ;;
    --strict-mutation-audit) shift ;; # default now; accepted for old callers
    --lenient-mutation-audit) lenient_mutation=1; shift ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "crash-soak.sh: unknown argument: $1" >&2; exit 2 ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

export KEYORIX_SOAK_CYCLES="$cycles"
export KEYORIX_SOAK_WRITERS="$writers"
[ -n "$seed" ] && export KEYORIX_SOAK_SEED="$seed"
[ -n "$lenient_mutation" ] && export KEYORIX_SOAK_STRICT_MUTATION_AUDIT=0

# Generous timeout: each cycle is a kill, a restart and a verify.
exec go test ./server -run 'TestEdgeCrashSoak_SQLite$' -count=1 -v -timeout "$((cycles * 60 + 300))s"
