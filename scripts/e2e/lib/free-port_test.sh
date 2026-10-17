#!/usr/bin/env bash
# Tests for lib/free-port.sh (#3174). Run: scripts/e2e/lib/free-port_test.sh
# Needs python3 (to hold listeners). Exits non-zero on the first failed assertion.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=free-port.sh
. "$HERE/free-port.sh"

PIDS=()
cleanup() {
    local p
    for p in "${PIDS[@]:-}"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null || true
    done
}
trap cleanup EXIT

fails=0
check() { # check DESC CONDITION-EXIT-CODE
    if [ "$2" = 0 ]; then
        echo "ok   - $1"
    else
        echo "FAIL - $1" >&2
        fails=$((fails + 1))
    fi
}

# listen FAMILY PORT: hold a listener in the background until cleanup.
listen() {
    python3 -I -c '
import socket, sys, time
fam = socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
s = socket.socket(fam, socket.SOCK_STREAM)
s.bind(("::1" if sys.argv[1] == "6" else "127.0.0.1", int(sys.argv[2])))
s.listen(8)
print("up", flush=True)
time.sleep(120)
' "$1" "$2" >"$TMPDIR_T/listen.$1.$2" 2>&1 &
    PIDS+=("$!")
    for _ in $(seq 1 50); do
        grep -q '^up' "$TMPDIR_T/listen.$1.$2" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

TMPDIR_T="$(mktemp -d)"
trap 'cleanup; rm -rf "$TMPDIR_T"' EXIT

# A base well away from anything else; tests pin it so they are deterministic.
BASE=41000
v6_ok=0
listen 6 $((BASE + 1)) || v6_ok=1

# 1. An IPv4-only listener is seen.
listen 4 $((BASE + 2))
rc=0; port_in_use $((BASE + 2)) || rc=$?
check "port_in_use sees a 127.0.0.1 listener" "$rc"

# 2. THE #3174 CASE: a listener on [::1] only (what Vite did) is seen.
if [ "$v6_ok" = 0 ]; then
    rc=0; port_in_use $((BASE + 1)) || rc=$?
    check "port_in_use sees a [::1]-only listener" "$rc"
else
    echo "skip - no IPv6 loopback on this host; [::1] cases not run"
fi

# 3. A port nobody holds is free.
rc=0; port_in_use $((BASE + 50)) && rc=1 || rc=0
check "port_in_use is false for an unused port" "$rc"

# 4. free_port skips both held ports and returns the first free one.
got="$(free_port $((BASE + 1)))"
want=$((BASE + 3))
if [ "$v6_ok" != 0 ]; then want=$((BASE + 1)); fi
rc=0; [ "$got" = "$want" ] || rc=1
check "free_port from BASE+1 skips held ports (got $got, want $want)" "$rc"

# 5. free_port honours the exclude list.
got="$(free_port $((BASE + 50)) $((BASE + 50)) $((BASE + 51)))"
rc=0; [ "$got" = "$((BASE + 52))" ] || rc=1
check "free_port skips excluded ports (got $got)" "$rc"

# 6. Override: valid, invalid, out of range.
got="$(KEYORIX_E2E_PORT_BASE=33000 pick_port_base)"
rc=0; [ "$got" = "33000" ] || rc=1
check "KEYORIX_E2E_PORT_BASE is honoured" "$rc"
rc=0; KEYORIX_E2E_PORT_BASE=abc pick_port_base 2>/dev/null && rc=1 || rc=0
check "non-numeric KEYORIX_E2E_PORT_BASE is rejected" "$rc"
rc=0; KEYORIX_E2E_PORT_BASE=80 pick_port_base 2>/dev/null && rc=1 || rc=0
check "privileged KEYORIX_E2E_PORT_BASE is rejected" "$rc"

# 7. The default base is random, high, and varies between calls.
seen=()
rc=0
for _ in 1 2 3 4 5 6 7 8; do
    b="$(pick_port_base)"
    if [ "$b" -lt 10000 ] || [ "$b" -gt 29999 ]; then rc=1; fi
    seen+=("$b")
done
check "default base is within 10000..29999" "$rc"
uniq_n="$(printf "%s\n" "${seen[@]}" | sort -u | wc -l | tr -d ' ')"
rc=0; [ "$uniq_n" -gt 1 ] || rc=1
check "default base varies between runs ($uniq_n distinct of 8)" "$rc"

# 8. #3353 self-check: no port a run can touch may be in an OS ephemeral range. Linux
# ephemeral starts at 32768, macOS/IANA at 49152; the highest port a run touches is
# BASE + 1000 (web) + 1000 (free_port scan) + the group number (groups are small; 100
# is generous). Checks the constants and a sample of real draws.
worst=$((PORT_BASE_MAX + 2000 + 100))
rc=0; [ "$worst" -lt "$EPHEMERAL_FLOOR" ] || rc=1
check "highest default port ($worst) is below the Linux ephemeral floor $EPHEMERAL_FLOOR" "$rc"
rc=0
for _ in $(seq 1 200); do
    b="$(pick_port_base)"
    [ $((b + 2100)) -lt "$EPHEMERAL_FLOOR" ] || rc=1
done
check "200 default bases all keep the whole run below 32768" "$rc"

[ "$fails" = 0 ] || { echo "$fails check(s) failed" >&2; exit 1; }
echo "all free-port checks passed"
