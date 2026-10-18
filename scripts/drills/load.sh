#!/usr/bin/env bash
# scripts/drills/load.sh -- a small read/write load generator for the drills (PROD-VERIFY-1).
#
# Sourced after lib.sh. Needs seed_data to have run (it reads the machine token and the expected
# seed values) and the instance to be logged in as admin (the writers use the shipped CLI).
#
#   load_start <inst> <port>   2 readers (the 3 seeded secrets via the machine token, value compared)
#                              and 2 writers (CLI: create a secret, then update it), in a loop
#   load_stop                  stop the loops and wait for in-flight requests
#   load_failures_outside <windows-file>
#                              prints the failed requests that fall outside every "<from> <to>"
#                              epoch window in the file (each widened by 1 s before, 2 s after)
#   load_check_ledger          every acknowledged create/update reads back with its last value
#
# Every request appends "<epoch> <kind> <ok|fail> <detail>" to its own log under $LOADLOG, so
# there are no shared appends. A write is "acknowledged" only when the CLI exited 0.

LOAD_INST=""
LOAD_PORT=""
LOADLOG=""
RUNFLAG=""

now() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }

load_reader() { # <id>
    local log="$LOADLOG/read.$1.log" i body d="$DRILL_DIR/$LOAD_INST"
    while [ -f "$RUNFLAG" ]; do
        for i in 1 2 3; do
            body="$(curl -s --max-time 5 --cacert "$d/certs/server.crt" -H @"$SEED_MACHINE_TOKEN_FILE" \
                "https://127.0.0.1:$LOAD_PORT/api/v1/secrets/$i?include_value=true" 2>/dev/null || true)"
            if grep -qF "$(cat "$d/expect.secret$i")" <<<"$body"; then
                echo "$(now) read ok $i" >>"$log"
            else
                echo "$(now) read fail $i $(echo "$body" | head -c 80 | tr '\n' ' ')" >>"$log"
            fi
        done
    done
}

load_writer() { # <id>
    local w="$1" n=0 name val out sid log="$LOADLOG/write.$1.log" d="$DRILL_DIR/$LOAD_INST"
    while [ -f "$RUNFLAG" ]; do
        n=$((n + 1))
        name="load-$w-$n"
        val="load-value-$w-$n-v1-$(rand_hex 6)"
        (umask 077 && printf '%s' "$val" >"$d/wval.$w")
        if out="$(cli "$LOAD_INST" "$LOAD_PORT" secret create --name "$name" --from-file "./wval.$w" --project 1 --environment 1 2>&1 </dev/null)"; then
            sid="$(echo "$out" | grep -oE '(ID|Id|id)[: ]+[0-9]+' | head -1 | grep -oE '[0-9]+' || true)"
            if [ -z "$sid" ]; then
                echo "$(now) write fail create-no-id $name $(echo "$out" | head -c 80 | tr '\n' ' ')" >>"$log"
                continue
            fi
            echo "$(now) write ok create $sid $val" >>"$log"
            val="load-value-$w-$n-v2-$(rand_hex 6)"
            (umask 077 && printf '%s' "$val" >"$d/wval.$w")
            if cli "$LOAD_INST" "$LOAD_PORT" secret update --id "$sid" --from-file "./wval.$w" >/dev/null 2>&1 </dev/null; then
                echo "$(now) write ok update $sid $val" >>"$log"
                if [ $((n % 3)) -eq 0 ]; then
                    if cli "$LOAD_INST" "$LOAD_PORT" secret delete --id "$sid" --force >/dev/null 2>&1 </dev/null; then
                        echo "$(now) write ok delete $sid -" >>"$log"
                    else
                        echo "$(now) write fail delete $sid" >>"$log"
                    fi
                fi
            else
                echo "$(now) write fail update $sid" >>"$log"
            fi
        else
            echo "$(now) write fail create $name $(echo "$out" | head -c 80 | tr '\n' ' ')" >>"$log"
        fi
    done
}

load_start() { # <inst> <port>
    LOAD_INST="$1"
    LOAD_PORT="$2"
    LOADLOG="$DRILL_DIR/$LOAD_INST/load"
    RUNFLAG="$DRILL_DIR/$LOAD_INST/load.run"
    mkdir -p "$LOADLOG"
    touch "$RUNFLAG"
    load_reader 1 &
    DRILL_PIDS+=("$!")
    load_reader 2 &
    DRILL_PIDS+=("$!")
    load_writer 1 &
    DRILL_PIDS+=("$!")
    load_writer 2 &
    DRILL_PIDS+=("$!")
}

load_stop() {
    rm -f "$RUNFLAG"
    sleep 6 # let in-flight requests finish
}

load_failures_outside() { # <windows-file>
    awk 'BEGIN { n = 0 } NR == FNR { a[n] = $1; b[n] = $2; n++; next }
         $3 == "fail" { ok = 0; for (i = 0; i < n; i++) if ($1 >= a[i] - 1 && $1 <= b[i] + 2) ok = 1; if (!ok) print }' \
        "$1" "$LOADLOG"/*.log
}

load_count() { # <ok|fail>
    cat "$LOADLOG"/*.log | awk -v k="$1" '$3 == k' | wc -l | tr -d ' '
}

load_check_ledger() {
    local d="$DRILL_DIR/$LOAD_INST" sid want got bad=0 n
    # the last acknowledged value of each secret id wins (an update comes after its create)
# A secret whose update or delete FAILED (not acknowledged, e.g. the server was killed mid-request)
    # may legitimately hold either value, or be gone: it is left out and counted.
    awk '$2 == "write" && $3 == "ok" {last[$5] = $6}
         $2 == "write" && $3 == "fail" && ($4 == "update" || $4 == "delete") {unsure[$5] = 1}
         END {for (k in last) if (!(k in unsure)) print k, last[k]; for (k in unsure) u++; print u + 0 > "/dev/stderr"}' \
        "$LOADLOG"/write.*.log >"$d/ledger.txt" 2>"$d/ledger.unsure" || true
    echo "    (left out: $(cat "$d/ledger.unsure") secrets with an unacknowledged update/delete in flight)"
    n="$(wc -l <"$d/ledger.txt" | tr -d ' ')"
    [ "$n" -gt 0 ] || fail "no acknowledged writes to check"
    login_admin "$LOAD_INST" "$LOAD_PORT"
    while read -r sid want; do
        if [ "$want" = "-" ]; then
            # acknowledged delete: the secret must be gone
            if cli "$LOAD_INST" "$LOAD_PORT" secret get --id "$sid" --show-value >/dev/null 2>&1 </dev/null; then
                echo "    secret $sid: acknowledged as deleted but still readable" >&2
                bad=$((bad + 1))
            fi
            continue
        fi
        got="$(cli "$LOAD_INST" "$LOAD_PORT" secret get --id "$sid" --show-value 2>&1 </dev/null || true)"
        grep -qF "$want" <<<"$got" || { echo "    secret $sid: want $want, got: $(echo "$got" | head -c 120 | tr '\n' ' ')" >&2; bad=$((bad + 1)); }
    done <"$d/ledger.txt"
    [ "$bad" = "0" ] || fail "$bad of $n acknowledged secrets do not read back with their last acknowledged value"
    ok "all $n acknowledged secrets read back with their last acknowledged state (value, or deleted)"
}
