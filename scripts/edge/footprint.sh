#!/usr/bin/env bash
# footprint.sh -- the edge footprint guard (EDGE-1): binary size and idle peak RSS
# of the native server against scripts/edge/footprint-budget.tsv.
#
# Usage:
#   scripts/edge/footprint.sh                      # check the host platform against the budget
#   scripts/edge/footprint.sh --targets linux/amd64,linux/arm64
#                                                  # also cross-build and size-check those
#   scripts/edge/footprint.sh --print              # print current values as budget rows (no check)
#
# Binary size is checked for every target (cross-built, CGO_ENABLED=0). Idle RSS
# only for the host platform, because it needs a run; a platform with no RSS
# budget row is skipped with a message. See server/edge_footprint_test.go.
set -euo pipefail

targets=""
print=""
while [ $# -gt 0 ]; do
  case "$1" in
    --targets) targets="$2"; shift 2 ;;
    --print) print=1; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "footprint.sh: unknown argument: $1" >&2; exit 2 ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

[ -n "$targets" ] && export KEYORIX_FOOTPRINT_TARGETS="$targets"
[ -n "$print" ] && export KEYORIX_FOOTPRINT_PRINT=1

exec go test ./server -run 'TestEdgeFootprint_|TestFootprintBudgetFile_' -count=1 -v -timeout 40m
