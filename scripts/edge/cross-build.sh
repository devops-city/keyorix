#!/usr/bin/env bash
# cross-build.sh -- build every shipped Keyorix component for the ARM Linux
# targets an edge device runs (EDGE-1), with the plain Go toolchain: no emulator,
# no container, no cgo.
#
# Targets:  linux/arm64            64-bit boards (Raspberry Pi 3/4/5 with a 64-bit OS)
#           linux/arm (GOARM=7)    32-bit boards (armv7, Raspberry Pi OS 32-bit)
#
# Components (each is its own build; the nested modules are built with GOWORK=off
# from their own directory, as the release does):
#   server           ./server                         full build
#   server-airgap    ./server  -tags noaws,noazure,nogcp   (cloud SDKs compiled out)
#   keyorix-k8s-sync ./cmd/keyorix-k8s-sync
#   keyorix-mcp      ./cmd/keyorix-mcp
#   keyorix (cli)    cli/        (separate module)
#   migrate          migrate/    (separate module)
#   operator         operator/cmd (separate module)
#
# All builds use CGO_ENABLED=0, which is also how the release builds: the SQLite
# driver is the pure-Go modernc.org/sqlite (ADR-048), so there is no C toolchain
# to cross-compile for. A package that needs cgo fails here, by design.
#
# This proves the code COMPILES and LINKS for the target. It does not run it: a
# run on real ARM hardware, or an emulated container, is pending the e2e VM.
#
# Usage: scripts/edge/cross-build.sh [--out DIR] [--targets linux/arm64,linux/arm]
# Exit status is non-zero if any build failed; every build is attempted.
set -uo pipefail

out=""
targets="linux/arm64,linux/arm"
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    --targets) targets="$2"; shift 2 ;;
    -h|--help) sed -n '2,29p' "$0"; exit 0 ;;
    *) echo "cross-build.sh: unknown argument: $1" >&2; exit 2 ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root" || exit 1
[ -n "$out" ] || out="$(mktemp -d)"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

# name | module dir (relative to the repo root) | package | extra go build args
components=(
  "server|.|./server|"
  "server-airgap|.|./server|-tags noaws,noazure,nogcp"
  "keyorix-k8s-sync|.|./cmd/keyorix-k8s-sync|"
  "keyorix-mcp|.|./cmd/keyorix-mcp|"
  "keyorix|cli|.|"
  "migrate|migrate|.|"
  "operator|operator|./cmd|"
)

# build_one DIR GOOS GOARCH EXTRA_FLAGS OUT PKG: one go build in its own subshell.
build_one() {
  local dir="$1" goos="$2" goarch="$3" extra="$4" bin="$5" pkg="$6"
  (
    cd "$dir" || exit 1
    export CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch"
    [ "$goarch" = arm ] && export GOARM=7
    [ "$dir" != . ] && export GOWORK=off
    # shellcheck disable=SC2086  # $extra is a deliberate word-split list of flags
    go build -trimpath -ldflags "-s -w" $extra -o "$bin" "$pkg"
  )
}

failed=0
printf '%-18s %-12s %-8s %s\n' component target result size_bytes
IFS=',' read -r -a target_list <<<"$targets"
for target in "${target_list[@]}"; do
  goos="${target%%/*}"
  goarch="${target##*/}"
  for c in "${components[@]}"; do
    IFS='|' read -r name dir pkg extra <<<"$c"
    bin="$out/${name}_${goos}_${goarch}"
    if build_one "$dir" "$goos" "$goarch" "$extra" "$bin" "$pkg" >"$bin.log" 2>&1; then
      size="$(wc -c <"$bin" | tr -d ' ')"
      printf '%-18s %-12s %-8s %s\n' "$name" "$target" ok "$size"
    else
      failed=1
      printf '%-18s %-12s %-8s %s\n' "$name" "$target" FAILED "-"
      sed 's/^/    /' "$bin.log" | head -30
    fi
  done
done
echo "binaries and logs in $out"
exit "$failed"
