#!/usr/bin/env bash
# scripts/ci/run-guards.sh -- every repo-wide guard test, whatever a merge group
# touches (CI-SELECT-1).
#
# The merge queue runs only the test-suite legs whose packages the group can
# affect (scripts/ci/select-affected.py). A guard that scans the whole tree can
# be broken by a change to a package it does not import, so selection must never
# decide whether a guard runs. ci.yml's repo-guards job runs this script on every
# selected merge-queue run; a full run gets the same tests through test-suite.
#
# What runs (the same two sets as the coordinator's preflight, widened from its
# fixed package list to the whole root module):
#   1. Named guards: Test*Guard / *Sweep / *Completeness / TestEvery* /
#      TestNoRaw* / TestPendingSeedsPromotedAfterFix, in every root-module
#      package and the packages in scripts/ci/global-guards.txt.
#   2. Static (source-scanning) guards: every Test func in a _test.go file that
#      imports go/parser, go/ast or go/packages, or walks the tree
#      (WalkDir( / filepath.Walk( ), in every root-module package plus the
#      global list (cli/cmd is a separate module: run with GOWORK=off).
# Without -race, without a Postgres DSN (pg-gated guards skip, as in preflight).
#
# Usage: scripts/ci/run-guards.sh   (from the repository root)
set -euo pipefail

NAME_RX='^Test[A-Za-z0-9_]*(Guard|Sweep|Completeness)|^TestEvery|^TestNoRaw|^TestPendingSeedsPromotedAfterFix'
NAME_GREP='func Test[A-Za-z0-9_]*(Guard|Sweep|Completeness|Every|NoRaw)'
STATIC_GREP='"go/(parser|ast|packages)"|WalkDir\(|filepath\.Walk\('

root=$(pwd)
global_list="scripts/ci/global-guards.txt"

# static_names DIR: the Test funcs of DIR's source-scanning test files.
static_names() {
  local d=$1 f
  for f in "$d"/*_test.go; do
    [ -f "$f" ] || continue
    grep -qE "$STATIC_GREP" "$f" || continue
    # A scanning file with only helpers/benchmarks has no Test funcs: not an error.
    { grep -oE '^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\)' "$f" || true; } | sed -E 's/^func (Test[A-Za-z0-9_]+).*/\1/'
  done
}

# module_of DIR: the directory of the go.mod that owns DIR.
module_of() {
  local m=$1
  while [ "$m" != "." ] && [ ! -f "$m/go.mod" ]; do m=$(dirname "$m"); done
  echo "$m"
}

echo "run-guards: listing root-module packages"
mapfile -t root_dirs < <(go list -f '{{.Dir}}' ./... | sed "s#^$root/##; s#^$root\$#.#")
mapfile -t extra_dirs < <(grep -vE '^[[:space:]]*(#|$)' "$global_list" | sed 's#^\./##')

declare -A pkgs_by_module=()
declare -A names_by_module=()
for d in "${root_dirs[@]}" "${extra_dirs[@]}"; do
  [ -d "$d" ] || { echo "run-guards: $d (from $global_list) does not exist" >&2; exit 1; }
  m=$(module_of "$d")
  picked=false
  if grep -lqE "$NAME_GREP" "$d"/*_test.go 2>/dev/null; then
    picked=true
  fi
  names=$(static_names "$d" | sort -u | paste -sd '|' -)
  if [ -n "$names" ]; then
    picked=true
    names_by_module[$m]="${names_by_module[$m]:+${names_by_module[$m]}|}$names"
  fi
  if [ "$picked" = true ]; then
    rel=${d#"$m"}; rel=".${rel:-}"; [ "$m" = "." ] && rel="./$d"
    case " ${pkgs_by_module[$m]:-} " in *" $rel "*) ;; *) pkgs_by_module[$m]="${pkgs_by_module[$m]:-} $rel" ;; esac
  fi
done

status=0
for m in "${!pkgs_by_module[@]}"; do
  read -r -a pkgs <<<"${pkgs_by_module[$m]}"
  rx="$NAME_RX"
  if [ -n "${names_by_module[$m]:-}" ]; then
    rx="$rx|^(${names_by_module[$m]})\$"
  fi
  nstatic=$(printf '%s' "${names_by_module[$m]:-}" | tr '|' '\n' | grep -c . || true)
  echo "run-guards: module $m: ${#pkgs[@]} package(s), named guards + $nstatic static guard test(s)"
  gw=${GOWORK:-}
  [ "$m" != "." ] && gw=off
  # shellcheck disable=SC2086
  if ! (cd "$m" && GOWORK=$gw go test -count=1 -timeout 1200s -run "$rx" "${pkgs[@]}"); then
    status=1
  fi
done
if [ "$status" -ne 0 ]; then
  echo "run-guards: FAILED -- a repo-wide guard is red; see the --- FAIL lines above" >&2
else
  echo "run-guards: every repo-wide guard passed"
fi
exit "$status"
