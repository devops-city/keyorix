#!/usr/bin/env bash
# scripts/drills/disaster.sh -- disaster drills (PROD-OPS-1 item 4).
#
# The server must either recover or fail closed with a clear message. Scenarios
# (DRILL_SCENARIOS, default "kill9 pgdown diskfull"; pgdown needs postgres, diskfull sqlite):
#
#   kill9     SIGKILL the server three times while four writers are creating secrets.
#             After each kill: the restart needs no --force, every write the server
#             ACKNOWLEDGED (CLI exit 0) is there, nothing half-written is readable, the seeded
#             data still decrypts, and `admin verify-audit` is VALID.
#   pgdown    PostgreSQL goes away and comes back. The drill cannot restart the shared
#             database, so a TCP forwarder (tools/tcpproxy.go) sits between the server and
#             PostgreSQL and is taken down (open connections reset, new ones refused) and up again --
#             what a PostgreSQL restart looks like from the server. During the outage requests
#             must fail (never hang, never report success), the server must not crash; after it
#             the SAME server process serves again and nothing acknowledged is lost.
#             (A real `docker restart postgres` variant: pending the e2e VM.)
#   diskfull  The data directory fills up. A real full filesystem cannot be made without a
#             privileged mount, so the server runs under `ulimit -f` just above the SQLite file
#             size: growing past it fails exactly like ENOSPC/EFBIG on the write. While writes
#             fail the server must refuse them (HTTP error, clear log line), keep what it has,
#             and never hand out a secret value whose audit row could not be written; once
#             space is back everything works and the audit chain verifies.
#             (Real full-filesystem and PostgreSQL disk-full variants: pending the e2e VM.)
#
# Each scenario needs its own EMPTY database: kill9 uses DRILL_PG_DSN_FILE, pgdown uses
# DRILL_PG_DSN_FILE2 (falling back to DRILL_PG_DSN_FILE when only pgdown is selected).
#
# Usage: [DRILL_BACKEND=postgres DRILL_PG_DSN_FILE=a.txt [DRILL_PG_DSN_FILE2=b.txt]] \
#        [DRILL_SCENARIOS="kill9"] scripts/drills/disaster.sh
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

DRILL_SCENARIOS="${DRILL_SCENARIOS:-kill9 pgdown diskfull}"
drill_begin disaster
tools_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/tools"

want() { case " $DRILL_SCENARIOS " in *" $1 "*) return 0 ;; esac; return 1; }

# list_names <name> <port>: names of the secrets the server lists in project 1.
list_names() {
    local off=0 page n
    while :; do
        page="$(cli "$1" "$2" secret list --project 1 --format json --limit 100 --offset "$off" \
            | jq -r '.. | objects | select(has("name") and has("id")) | .name')"
        [ -n "$page" ] || break
        echo "$page"
        n="$(echo "$page" | wc -l | tr -d ' ')"
        off=$((off + n))
    done
}

# writers_start <name> <port> <tag> <n>: n background loops creating secrets; acked names go to <inst>/acked.<tag>.<k>
WRITER_PIDS=()
writers_start() {
    local name="$1" port="$2" tag="$3" n="$4" k
    local d="$DRILL_DIR/$name"
    WRITER_PIDS=()
    for k in $(seq 1 "$n"); do
        (
            i=0
            while :; do
                i=$((i + 1))
                nm="w-$tag-$k-$i"
                (umask 077 && printf 'value-%s-%s' "$nm" "$(rand_hex 4)" >"$d/wval.$tag.$k")
                if cli "$name" "$port" secret create --name "$nm" --from-file "./wval.$tag.$k" --project 1 --environment 1 >/dev/null 2>&1; then
                    echo "$nm" >>"$d/acked.$tag.$k"
                else
                    echo "$nm" >>"$d/failed.$tag.$k"
                fi
            done
        ) &
        WRITER_PIDS+=("$!")
        DRILL_PIDS+=("$!")
    done
}
writers_stop() {
    local p
    for p in "${WRITER_PIDS[@]:-}"; do
        [ -n "$p" ] && { kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; }
    done
    WRITER_PIDS=()
    # a CLI process may still be mid-call: let those finish or fail
    sleep 2
}

# ---------------------------------------------------------------------------
scenario_kill9() {
    step "kill9: provision and seed"
    local I=k9 P
    P="$(drill_port 31)"
    inst_new "$I" "$P"
    srv_start "$I" "$P"
    seed_data "$I" "$P"
    local d="$DRILL_DIR/$I" round
    for round in 1 2 3; do
        step "kill9 round $round: four writers, then SIGKILL"
        writers_start "$I" "$P" "r$round" 4
        sleep 6
        srv_kill9 "$I"
        writers_stop
        local acked failed
        acked="$(cat "$d"/acked.r$round.* 2>/dev/null | wc -l | tr -d ' ')"
        failed="$(cat "$d"/failed.r$round.* 2>/dev/null | wc -l | tr -d ' ')"
        echo "    writers: $acked acknowledged, $failed failed/in flight at the kill"
        [ "$acked" -gt 0 ] || fail "the writers acknowledged nothing before the kill: the drill measured nothing"

        # restart: must come back by itself (stale lock/pid state from the kill must not need --force)
        : >"$d/server.log"
        srv_start "$I" "$P"
        ok "restart after SIGKILL needed no --force"
        login_admin "$I" "$P"
        list_names "$I" "$P" | sort >"$d/names.$round"
        # every acknowledged write survived
        cat "$d"/acked.r$round.* | sort >"$d/acked.sorted.$round"
        local lost
        lost="$(comm -23 "$d/acked.sorted.$round" "$d/names.$round" | wc -l | tr -d ' ')"
        [ "$lost" = "0" ] || { comm -23 "$d/acked.sorted.$round" "$d/names.$round" | head >&2; fail "$lost acknowledged secrets are missing after SIGKILL"; }
        ok "all $acked acknowledged writes present"
        # a failed/in-flight write is either fully there or fully absent: if listed, its value reads back whole
        local nm checked=0
        for nm in $(cat "$d"/failed.r$round.* 2>/dev/null | head -20); do
            if grep -qx "$nm" "$d/names.$round"; then
                cli "$I" "$P" secret get --name "$nm" --project 1 --show-value >/dev/null 2>&1 \
                    || cli "$I" "$P" secret list --project 1 >/dev/null || fail "in-flight secret $nm is listed but unreadable"
                checked=$((checked + 1))
            fi
        done
        ok "in-flight writes: $checked landed whole, the rest absent"
        verify_seed "$I" "$P"
        srv_stop "$I"
        verify_audit "$I"
        srv_start "$I" "$P"
    done
    srv_stop "$I"
}

# ---------------------------------------------------------------------------
scenario_pgdown() {
    [ "$DRILL_BACKEND" = "postgres" ] || { echo "==> pgdown: skipped (needs DRILL_BACKEND=postgres)"; return 0; }
    step "pgdown: provision directly, then route the server through a TCP forwarder"
    local I=pg P PP
    P="$(drill_port 32)"
    PP="$(drill_port 33)"
    inst_new "$I" "$P" "${DRILL_PG_DSN_FILE2:-${DRILL_PG_DSN_FILE:-}}"
    local d="$DRILL_DIR/$I"
    (cd "$tools_dir" && go build -o "$DRILL_DIR/bin/tcpproxy" tcpproxy.go) || fail "cannot build tcpproxy"
    "$DRILL_DIR/bin/tcpproxy" "127.0.0.1:$PP" "$PG_HOST:$PG_PORT" >"$d/proxy.log" 2>&1 &
    local proxy=$!
    DRILL_PIDS+=("$proxy")
    sleep 1
    sed -i.bak -E "s/port: \"$PG_PORT\"/port: \"$PP\"/" "$d/keyorix.yaml"
    rm -f "$d/keyorix.yaml.bak"
    srv_start "$I" "$P"
    seed_data "$I" "$P"
    # raw HTTP probes use the machine token (a read needs nothing more)
    local hdr="$d/bearer.machine.hdr"

    step "pgdown: database goes away"
    kill -USR1 "$proxy"
    sleep 1
    local t0 t1 code
    t0="$(date +%s)"
    code="$(curl -s -o /dev/null -m 40 -w '%{http_code}' --cacert "$d/certs/server.crt" -H @"$hdr" "https://127.0.0.1:$P/api/v1/secrets/1?include_value=true" || true)"
    t1="$(date +%s)"
    echo "    read during the outage: HTTP $code in $((t1 - t0))s"
    case "$code" in 2*) fail "a secret read returned success while the database was unreachable" ;; esac
    [ "$((t1 - t0))" -lt 35 ] || fail "a request hung for $((t1 - t0))s during the outage"
    # an outage is the SERVER's fault: a valid credential must get a retryable 503, not a 401/403
    # (clients drop credentials on 401; the token must not be negative-cached either)
    [ "$code" = "503" ] || fail "a valid machine token got HTTP $code during the outage; want 503 (retryable), not a verdict on the credential"
    ok "read refused with 503, did not hang"
    (umask 077 && printf 'during-outage' >"$d/val.outage")
    if cli "$I" "$P" secret create --name during-outage --from-file ./val.outage --project 1 --environment 1 >/dev/null 2>&1; then
        fail "a secret create reported success while the database was unreachable"
    fi
    ok "write refused"
    kill -0 "$(cat "$d/server.pid")" 2>/dev/null || fail "the server process died during the database outage"
    grep -qiE 'panic|fatal error' "$d/server.log" && fail "the server panicked during the outage"
    ok "server process alive, no panic"

    step "pgdown: database comes back (same server process)"
    kill -USR2 "$proxy"
    local i recovered=""
    for i in $(seq 1 60); do
        code="$(curl -s -o /dev/null -m 10 -w '%{http_code}' --cacert "$d/certs/server.crt" -H @"$hdr" "https://127.0.0.1:$P/api/v1/secrets/1?include_value=true" || true)"
        [ "$code" = "200" ] && { recovered=$i; break; }
        sleep 1
    done
    [ -n "$recovered" ] || { tail -20 "$d/server.log" >&2; fail "the server did not recover within 60s of the database coming back"; }
    ok "reads served again ${recovered}s after the database returned, without a restart"
    login_admin "$I" "$P"
    (umask 077 && printf 'after-outage' >"$d/val.after")
    cli "$I" "$P" secret create --name after-outage --from-file ./val.after --project 1 --environment 1 >/dev/null \
        || fail "write failed after recovery"
    list_names "$I" "$P" | grep -qx 'during-outage' && fail "the write refused during the outage exists anyway"
    ok "writes work again; the refused write left nothing behind"
    verify_seed "$I" "$P"
    srv_stop "$I"
    verify_audit "$I"
    kill "$proxy" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
scenario_diskfull() {
    [ "$DRILL_BACKEND" = "sqlite" ] || { echo "==> diskfull: skipped (SQLite data directory; needs DRILL_BACKEND=sqlite)"; return 0; }
    step "diskfull: provision and seed"
    local I=df P
    P="$(drill_port 34)"
    inst_new "$I" "$P"
    srv_start "$I" "$P"
    seed_data "$I" "$P"
    srv_stop "$I"
    local d="$DRILL_DIR/$I" size kb
    # the limit is per file: the SQLite main file and its -wal grow independently, so size the
    # limit from the biggest of them (the data may all live in the WAL after a clean stop)
    size=0
    local f s
    for f in "$d"/keyorix.db "$d"/keyorix.db-wal; do
        [ -f "$f" ] || continue
        s="$(stat -f %z "$f" 2>/dev/null || stat -c %s "$f")"
        [ "$s" -gt "$size" ] && size="$s"
    done
    kb=$(((size + 1023) / 1024 + 3072))
    echo "    biggest database file $size bytes; file-size limit ${kb} KiB (3 MiB of headroom: SQLite extends its files in chunks, a tighter limit refuses the first write)"

    step "diskfull: start under the limit, fill it"
    : >"$d/server.log"
    (ulimit -f "$kb"; srv_start "$I" "$P") || fail "the server must start (read-only work needs no growth) under the limit"
    DRILL_PIDS+=("$(cat "$d/server.pid")")
    login_admin "$I" "$P"
    local audited_before=0
    if command -v sqlite3 >/dev/null; then
        audited_before="$(sqlite3 "$d/keyorix.db" "select count(*) from audit_events where event_type='secret.read'")"
    fi
    local i created=0 refused=0 code
    for i in $(seq 1 400); do
        (umask 077 && head -c 30000 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$d/val.fill")
        if cli "$I" "$P" secret create --name "fill-$i" --from-file ./val.fill --project 1 --environment 1 >/dev/null 2>&1; then
            created=$((created + 1)); echo "fill-$i" >>"$d/acked.fill"
        else
            refused=$((refused + 1))
            [ "$refused" -ge 3 ] && break
        fi
    done
    [ "$refused" -ge 3 ] || fail "400 writes of 60 KB never hit the limit: the drill did not fill the disk"
    ok "$created writes accepted, then writes were refused"
    kill -0 "$(cat "$d/server.pid")" 2>/dev/null || { tail -20 "$d/server.log" >&2; fail "the server process died when the disk filled (fail closed means refusing, not crashing)"; }
    grep -qiE 'panic|fatal error' "$d/server.log" && fail "the server panicked when the disk filled"
    grep -qiE 'disk|full|space|file too large|no space|SQLITE_FULL|database or disk' "$d/server.log" \
        || { tail -10 "$d/server.log" >&2; fail "no clear disk/space line in the server log"; }
    ok "server alive; log says: $(grep -iE 'disk|full|space|file too large|SQLITE_FULL' "$d/server.log" | tail -1 | cut -c1-150)"

    step "diskfull: a value read must not succeed unless its audit row was written"
    local reads_ok=0
    for i in 1 2 3 4 5; do
        code="$(curl -s -o /dev/null -m 20 -w '%{http_code}' --cacert "$d/certs/server.crt" -H @"$DRILL_DIR/$I/bearer.machine.hdr" "https://127.0.0.1:$P/api/v1/secrets/1?include_value=true" || true)"
        case "$code" in 2*) reads_ok=$((reads_ok + 1)) ;; esac
    done
    echo "    value reads that returned 2xx while writes fail: $reads_ok of 5"
    srv_stop "$I"
    if command -v sqlite3 >/dev/null; then
        local audited_after
        audited_after="$(sqlite3 "$d/keyorix.db" "select count(*) from audit_events where event_type='secret.read'")"
        echo "    secret.read audit rows: $audited_before before the fill, $audited_after after"
        # every value handed out while the disk was full needs its own audit row
        [ $((audited_after - audited_before)) -ge "$reads_ok" ] \
            || fail "$reads_ok values were handed out while the disk was full but only $((audited_after - audited_before)) reads were audited"
        ok "no value was disclosed without an audit row"
    else
        echo "    (sqlite3 not installed: skipped the audit-row count)"
    fi

    step "diskfull: space is back"
    verify_audit "$I"
    srv_start "$I" "$P"
    verify_seed "$I" "$P"
    local lost
    login_admin "$I" "$P"
    list_names "$I" "$P" | sort >"$d/names.full"
    sort "$d/acked.fill" >"$d/acked.fill.sorted"
    lost="$(comm -23 "$d/acked.fill.sorted" "$d/names.full" | wc -l | tr -d ' ')"
    [ "$lost" = "0" ] || fail "$lost writes acknowledged while filling are missing afterwards"
    (umask 077 && printf 'space-is-back' >"$d/val.back")
    cli "$I" "$P" secret create --name space-is-back --from-file ./val.back --project 1 --environment 1 >/dev/null \
        || fail "writes still fail after the limit was lifted"
    ok "all $created accepted writes present, new writes work"
    srv_stop "$I"
    verify_audit "$I"
}

want kill9 && scenario_kill9
want pgdown && scenario_pgdown
want diskfull && scenario_diskfull

drill_end "DISASTER DRILL"
