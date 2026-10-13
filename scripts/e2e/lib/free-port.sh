#!/usr/bin/env bash
# scripts/e2e/lib/free-port.sh -- port selection for scripts/e2e/web-real-smoke.sh
# (#3174). Sourced, not executed; unit-tested by scripts/e2e/lib/free-port_test.sh.
#
# Why this is not just "probe 127.0.0.1 from a fixed base":
#   - Vite (and Playwright's webServer check) bind/probe `localhost`, which can be
#     [::1]. A probe of 127.0.0.1 alone calls a port that another session's Vite holds
#     on [::1] free, and the next group fails with "http://localhost:NNNN is already
#     used". port_in_use therefore asks BOTH loopback families.
#   - Two sessions on one host that start from the same fixed base walk the same ports
#     in the same order and collide on the first one either has not bound yet. The base
#     is a random high port per run, and overridable (KEYORIX_E2E_PORT_BASE) for a
#     caller that wants a fixed, known range.
# A shell cannot bind and hold a port for a child process, so selection stays a probe;
# web-real-smoke.sh closes the remaining window by checking that the server process it
# started is the one answering (a lost race is a loud failure, not a silent stranger).

# port_in_use PORT: true if something accepts a TCP connection on PORT at 127.0.0.1
# or ::1. Uses bash's own /dev/tcp, so nothing extra needs installing. A family that
# is not configured on the host (no IPv6) simply refuses and counts as "not in use".
port_in_use() {
    local p=$1 host
    for host in 127.0.0.1 ::1; do
        if (exec 3<>"/dev/tcp/$host/$p") 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

# pick_port_base prints the base port for this run: KEYORIX_E2E_PORT_BASE if set
# (validated), else a random port in [20000, 58999].
pick_port_base() {
    if [ -n "${KEYORIX_E2E_PORT_BASE:-}" ]; then
        case "$KEYORIX_E2E_PORT_BASE" in
        '' | *[!0-9]*)
            echo "KEYORIX_E2E_PORT_BASE must be a number, got: $KEYORIX_E2E_PORT_BASE" >&2
            return 1
            ;;
        esac
        if [ "$KEYORIX_E2E_PORT_BASE" -lt 1024 ] || [ "$KEYORIX_E2E_PORT_BASE" -gt 63000 ]; then
            echo "KEYORIX_E2E_PORT_BASE must be in 1024..63000, got: $KEYORIX_E2E_PORT_BASE" >&2
            return 1
        fi
        echo "$KEYORIX_E2E_PORT_BASE"
        return 0
    fi
    echo $((20000 + (RANDOM * 32768 + RANDOM) % 39000))
}

# free_port START [EXCLUDE...]: prints the first port at or above START (scanning at
# most 1000 ports) that nothing listens on and that is not in EXCLUDE. Returns 1 with
# a message on stderr if none is found.
free_port() {
    local start=$1 p ex skip
    shift
    p=$start
    while [ "$p" -lt $((start + 1000)) ] && [ "$p" -lt 65000 ]; do
        skip=0
        for ex in "$@"; do
            [ "$p" = "$ex" ] && skip=1
        done
        if [ "$skip" = 0 ] && ! port_in_use "$p"; then
            echo "$p"
            return 0
        fi
        p=$((p + 1))
    done
    echo "no free TCP port found in $start..$((start + 999))" >&2
    return 1
}
