#!/usr/bin/env bash
# Regenerate server/default.pgo, the profile `go build -pgo=auto` (Go's default)
# applies to ./server. See docs/pgo.md for when and how; run once per release.
#
#   scripts/pgo/refresh.sh hook             write the throwaway pprof listener into server/
#                                           (profiling build only; never commit it)
#   scripts/pgo/refresh.sh unhook           remove it again
#   scripts/pgo/refresh.sh capture URL SECS OUT.pprof
#                                           pull one CPU profile from a running profiling build
#   scripts/pgo/refresh.sh merge PROFILE... merge CPU profiles into server/default.pgo
#
# The load that runs while `capture` is recording is the bench kit's job (W1+W2 at
# c=10 and c=50 on Postgres, plus admin/list traffic); this script only handles the
# profile plumbing so the result is the same whoever runs it.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
hook_src="$root/scripts/pgo/capture_hook.go.txt"
hook_dst="$root/server/pgo_capture_local_only.go"
out="$root/server/default.pgo"

case "${1:-}" in
hook)
	cp "$hook_src" "$hook_dst"
	echo "wrote $hook_dst: build the profiling image, set KEYORIX_PGO_CAPTURE=1, then 'unhook'" >&2
	;;
unhook)
	rm -f "$hook_dst"
	;;
capture)
	[ $# -eq 4 ] || { echo "usage: $0 capture URL SECONDS OUT.pprof" >&2; exit 2; }
	curl -fsS -o "$4" "$2/debug/pprof/profile?seconds=$3"
	;;
merge)
	shift
	[ $# -ge 1 ] || { echo "usage: $0 merge PROFILE..." >&2; exit 2; }
	# Merging with pprof keeps every sample; -proto writes the format the compiler reads.
	go tool pprof -proto "$@" > "$out.tmp"
	mv "$out.tmp" "$out"
	go tool pprof -top -nodecount=15 "$out"
	echo "wrote $out ($(wc -c <"$out") bytes)" >&2
	;;
*)
	sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
	exit 2
	;;
esac
