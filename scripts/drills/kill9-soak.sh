#!/usr/bin/env bash
# scripts/drills/kill9-soak.sh -- server kill -9 soak under load (PROD-VERIFY-1 item 2).
#
# The SQLite crash soak (scripts/edge/crash-soak.sh) is a Go test on the SQLite file. This is the
# same question for any backend, in particular PostgreSQL: the SERVER PROCESS is killed with
# SIGKILL at random points while a load generator (load.sh) reads, writes and deletes, and the
# plain restart must need no operator. It does NOT kill the database: a postmaster crash needs a
# disposable database container (see the report's "Needs coordinator").
#
# After every kill, on the database exactly as the kill left it:
#   - `admin verify-audit` is VALID;
#   - the server restarts with nothing but its config and environment and becomes healthy.
# Every 4th cycle the kill lands during start-up, before the server is healthy.
# At the end: every failed request lies inside a kill -> healthy window; every write the server
# acknowledged (create, update, delete) reads back (a secret whose update/delete was in flight at
# a kill is left out: it may hold either state); the seeded data is intact; verify-audit is VALID.
#
# Postgres: the script never drops or recreates the database (it holds only a DSN file, no admin
# role); each run needs a fresh EMPTY database from the caller (`kpg dsn`/`kpg drop`, or DROP/CREATE).
#
# Usage: [DRILL_BACKEND=postgres DRILL_PG_DSN_FILE=a.txt] [DRILL_SERVER_BIN=... DRILL_CLI_BIN=...] \
#        [SOAK_CYCLES=50] [SOAK_SEED=1] scripts/drills/kill9-soak.sh
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=load.sh
source "$(dirname "${BASH_SOURCE[0]}")/load.sh"

drill_begin kill9-soak
I=inst
P="$(drill_port 41)"
d="$DRILL_DIR/$I"
CYCLES="${SOAK_CYCLES:-50}"
SEED="${SOAK_SEED:-$(date +%s)}"
RANDOM="$SEED"
echo "==> kill -9 soak: cycles=$CYCLES seed=$SEED backend=$DRILL_BACKEND (replay: SOAK_SEED=$SEED)"

# rand_between <min> <max>: seconds with two decimals, from the seeded RANDOM.
rand_between() { awk -v r="$RANDOM" -v lo="$1" -v hi="$2" 'BEGIN{printf "%.2f", lo + r / 32768 * (hi - lo)}'; }

# srv_start_nowait <name>: launch the server and return at once (the caller kills it mid-start).
srv_start_nowait() {
    local dd="$DRILL_DIR/$1"
    [ -f "$dd/server.pid" ] && fail "$1 already has a server (pid file present)"
    (
        cd "$dd"
        if [ "$DRILL_BACKEND" = "postgres" ]; then export KEYORIX_DB_PASSWORD="$PG_PASS"; fi
        KEYORIX_CONFIG_PATH=./keyorix.yaml KEYORIX_BOOTSTRAP_TOKEN="$DRILL_BOOTSTRAP_TOKEN" \
            nohup "$DRILL_SERVER_BIN" >>"$dd/server.log" 2>&1 &
        echo $! >"$dd/server.pid"
    )
    DRILL_PIDS+=("$(cat "$dd/server.pid")")
}

step "provision and seed"
inst_new "$I" "$P"
if [ -n "${SOAK_AUDIT_DURABILITY:-}" ]; then
    sed -i.bak -E "s|^    ssl_mode: disable|    ssl_mode: disable\n    audit_durability: $SOAK_AUDIT_DURABILITY|" "$d/keyorix.yaml"
    rm -f "$d/keyorix.yaml.bak"
    grep -q "audit_durability: $SOAK_AUDIT_DURABILITY" "$d/keyorix.yaml" || fail "could not set audit_durability in the config"
fi
srv_start "$I" "$P"
grep -m1 -i 'audit durability' "$d/server.log" || echo "    (no 'audit durability' line in the server log)"
seed_data "$I" "$P"

step "start the load generator (2 readers, 2 writers)"
load_start "$I" "$P"
sleep 5
[ "$(load_count fail)" = "0" ] || fail "the load generator sees failures against a healthy server"
ok "baseline: $(load_count ok) requests ok"

: >"$d/windows.txt"
: >"$d/restart-times.txt"
step "$CYCLES kill -9 cycles"
for c in $(seq 1 "$CYCLES"); do
    sleep "$(rand_between 1.5 5)"
    t_kill="$(now)"
    if [ -n "${SOAK_DB_KILL_CMD:-}" ] && [ $((c % ${SOAK_DB_KILL_EVERY:-5})) -eq 0 ]; then
        # database kill cycle: the SERVER keeps running, the command kills and restarts the
        # database (e.g. `docker kill` + `docker start` of a disposable container). The server
        # must come back healthy by itself; if it does not, that is recorded, then it is killed
        # and restarted so the soak can go on.
        bash -c "$SOAK_DB_KILL_CMD" >"$d/db-kill.$c.log" 2>&1 || { cat "$d/db-kill.$c.log" >&2; fail "SOAK_DB_KILL_CMD failed in cycle $c"; }
        recovered=no
        for _ in $(seq 1 90); do
            if curl -fs --cacert "$d/certs/server.crt" "https://127.0.0.1:$P/health" >/dev/null 2>&1; then recovered=yes; break; fi
            sleep 1
        done
        if [ "$recovered" = "no" ]; then
            srv_kill9 "$I"
            srv_start "$I" "$P"
        fi
        t_healthy="$(now)"
        echo "$t_kill $t_healthy" >>"$d/windows.txt"
        echo "    cycle $c ok: DATABASE killed and restarted, server healthy again by itself: $recovered ($(awk -v a="$t_kill" -v b="$t_healthy" 'BEGIN{printf "%.1f", b-a}')s)"
        continue
    fi
    srv_kill9 "$I"
    verify_audit "$I" >/dev/null
    if [ $((c % 4)) -eq 0 ]; then
        # kill during start-up, before the server is healthy
        srv_start_nowait "$I"
        sleep "$(rand_between 0.1 0.9)"
        srv_kill9 "$I"
        verify_audit "$I" >/dev/null
        startup_kill=" (+ a kill during start-up)"
    else
        startup_kill=""
    fi
    t_restart="$(now)"
    srv_start "$I" "$P"
    t_healthy="$(now)"
    echo "$t_kill $t_healthy" >>"$d/windows.txt"
    awk -v a="$t_restart" -v b="$t_healthy" 'BEGIN{printf "%.2f\n", b-a}' >>"$d/restart-times.txt"
    echo "    cycle $c ok: killed, verify-audit VALID, restart healthy in $(tail -1 "$d/restart-times.txt")s$startup_kill"
done
sleep 5
load_stop

outside="$(load_failures_outside "$d/windows.txt" | wc -l | tr -d ' ')"
echo "    requests ok: $(load_count ok); failed in total: $(load_count fail); failed outside a kill->healthy window: $outside"
if [ "$outside" != "0" ]; then
    load_failures_outside "$d/windows.txt" | head -8 >&2
    fail "$outside requests failed outside a kill -> healthy window"
fi
ok "every failed request lies inside a kill -> healthy window"
echo "    restart-to-healthy seconds: min $(sort -n "$d/restart-times.txt" | head -1), max $(sort -n "$d/restart-times.txt" | tail -1) over $CYCLES cycles"

step "every acknowledged write, seeded data, audit chain"
load_check_ledger
verify_seed "$I" "$P"
srv_stop "$I"
verify_audit "$I"
drill_end "KILL -9 SOAK ($CYCLES cycles, seed $SEED, $DRILL_BACKEND)"
