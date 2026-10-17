#!/usr/bin/env bash
# nightly-cross-replica.sh — the nightly long run for the two-replica
# cross-replica invariant fuzzer (GUARD-5 item 4).
#
# WHY THIS IS NOT PART OF THE SHARED FUZZ RIG
#
# Every other Keyorix fuzz target runs under the external fuzz-harness runner
# (see README.md: one standardized runner across Keyorix/DashDiag/third-party
# rigs, crashers to the private corpus, never a public issue). This one cannot:
# FuzzCrossReplicaInvariants needs a real multi-connection PostgreSQL server,
# skips outright without KEYORIX_TEST_PG_DSN, and would therefore report a
# perfect clean run forever on the generic rig — the worst possible failure
# mode for a fuzz target. So it gets its own unit with its own throwaway
# Postgres, and everything else about it (private-corpus-only crashers, one
# ntfy line per NEW failure, no public disclosure) deliberately matches the
# shared rig's conventions rather than inventing new ones.
#
# WHAT IT RUNS, IN ORDER
#
#   1. the ordering SWEEP once (KEYORIX_INTERLEAVE_SWEEP=1): ~3 minutes, and
#      it is the only thing that runs the full 180-run interleaving
#      enumeration anywhere. Cheap relative to the fuzz budget, and it is the
#      discovery half of this rig — the per-issue regression tests in CI are
#      the guard half.
#   2. the fuzz target itself for $FUZZTIME.
#
# The sweep runs FIRST on purpose. If it fails, that is a specific, named,
# reproducible finding (a (pair, ordering) with no ledger row), which is worth
# alerting on immediately rather than after four hours of fuzzing.
#
# HOST COEXISTENCE
#
# pve01 is shared with the benchmark sessions, whose numbers a parallel CPU
# load silently corrupts. /root/PVE-BENCH-LOCK is the convention. This script
# is the polite party:
#   - it SKIPS (exit 0, no alert) if the lock exists when it starts. A skipped
#     night is not a failure and must not page anyone.
#   - it also WATCHES the lock while running and aborts cleanly if a benchmark
#     session claims it mid-run. Checking only at startup would be useless:
#     the run is four hours long and the benchmark sessions start whenever
#     their operator is awake.
#
# ALERTING
#
# One ntfy line per NEW failure, deduplicated by a marker file keyed on the
# failure's own fingerprint — so a crasher that reproduces every night for a
# week pages once, not seven times. A repeat is still recorded in the log.
# Same no-secrets-in-argv pattern as scripts/dast/lib-alert.sh and
# scripts/mutation-testing/notify-summary.sh: the topic URL goes into a
# `curl -K` config file, never into the command line, so it never appears in
# `ps`.
#
# EXIT CODES
#   0  clean run, or skipped because the host lock was held
#   1  a failure was found (sweep finding, or a fuzz crasher)
#   2  the rig itself is broken (no Postgres, no checkout, bad config)
set -euo pipefail

# --- configuration -----------------------------------------------------------
# Everything below is overridable from the systemd EnvironmentFile
# (/etc/keyorix-xreplica/config.env — see config.env.example).

# KEYORIX_REPO: the rig's own checkout, reset to origin/main before each run.
: "${KEYORIX_REPO:=/opt/keyorix-xreplica/keyorix}"
# STATE_DIR: logs and alert-dedup markers.
: "${STATE_DIR:=/opt/keyorix-xreplica/state}"
# KEYORIX_REF: the ref to test. origin/main is the only value the nightly
# should ever use -- the point of the rig is to tell you about main. It is a
# variable solely so an install can be smoke-tested against a branch before
# that branch merges (see docs/fuzzing/cross-replica-nightly.md). Without
# that, the first time anyone watches this script run would be the first
# night it mattered, and a guard nobody has watched fail is not a guard.
: "${KEYORIX_REF:=origin/main}"
# RUN_SWEEP / SWEEP_TIMEOUT: whether to run the ordering sweep before the fuzz
# run, and the `go test -timeout` budget for it. The sweep is ~175 forced
# interleavings and its wall-clock is dominated by Postgres round-trips, so it
# is minutes, not seconds. RUN_SWEEP=0 is for smoke-testing the rest of this
# script without paying for it -- not for routine use: the sweep is the only
# place the full interleaving enumeration runs anywhere, and turning it off
# permanently would leave this unit doing nothing CI does not already do.
: "${RUN_SWEEP:=1}"
: "${SWEEP_TIMEOUT:=90m}"
# FUZZTIME: the brief asks for a 4-hour run in a 01:00-05:00 window. 3h45m,
# not 4h, is deliberate: the window is four hours WIDE, and the run also has
# to pay for the container start, the schema migration, the ~3-minute ordering
# sweep, and the corpus push. A literal 4h fuzztime starting at 01:00 would
# end after 05:00 and collide with exactly the benchmark window this whole
# lock dance exists to protect. Raise it only if the timer moves earlier.
: "${FUZZTIME:=3h45m}"
# PG_CONTAINER / PG_IMAGE: the dedicated Postgres. Dedicated, not shared:
# the fuzzer creates an isolated schema per run but a shared server's other
# work would still contend for its connection slots and lock table, and a
# cross-replica race test is exactly the thing that mis-measures under that.
: "${PG_CONTAINER:=keyorix-xreplica-pg}"
: "${PG_IMAGE:=postgres:16}"
: "${PG_PASSWORD:=xreplica}"
# HOST_LOCK: the pve01 benchmark lock. Set to empty to disable the check
# (correct on a box that runs no benchmarks).
: "${HOST_LOCK:=/root/PVE-BENCH-LOCK}"
# LOCK_POLL_SECONDS: how often to re-check the host lock while running.
: "${LOCK_POLL_SECONDS:=60}"
# CORPUS_REPO: the PRIVATE corpus checkout new crashers are pushed to. Never
# a public repo — an unfixed own-code race must not be disclosed before its
# fix (README.md, REPORT_MODE=private).
: "${CORPUS_REPO:=/opt/keyorix-xreplica/fuzz-corpus}"
: "${CORPUS_SUBDIR:=corpus/internal-core/FuzzCrossReplicaInvariants}"
# NTFY_TOPIC: full topic URL. Unset = silent no-op (same as lib-alert.sh).
: "${NTFY_TOPIC:=}"
# KNOWN_OPEN_CLASSES: space-separated issue numbers whose invariant class is a
# KNOWN-OPEN bug on main. A crasher whose violation lines name only these is
# logged, kept, and NOT alerted on.
#
# This exists because of a real measurement, not in anticipation: the first
# smoke run of this script found #2649 by blind fuzzing in SEVEN SECONDS.
# Before #2768 fixed the fuzzer's world, that whole op family could not
# execute at all and the invariant was vacuous; now it is reachable
# immediately. With the fix stack (#2664..#2675) still open, an unsuppressed
# rig would spend every night re-reporting the same four known bugs and would
# never get far enough into the input space to find a new one -- and the
# recipient would learn to ignore the topic, which is how a real second
# finding gets missed.
#
# Same discipline as server/faultops' knownOpenTolerances (COMMON-RULES):
# scope it to the specific open issue, name the issue, and DELETE the entry in
# the PR that fixes it. A suppression that outlives its bug silences a
# regression forever. The sweep step is NOT suppressed -- only the fuzz step --
# because the sweep has its own per-(pair, ordering) ledger in-tree.
: "${KNOWN_OPEN_CLASSES:=}"

FUZZ_PKG="./internal/core/"
FUZZ_TARGET="FuzzCrossReplicaInvariants"
CORPUS_DIR_REL="internal/core/testdata/fuzz/${FUZZ_TARGET}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${STATE_DIR}/runs"
LOG="${LOG_DIR}/${RUN_ID}.log"

# --- plumbing ----------------------------------------------------------------

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }

die_rig() {
    log "RIG ERROR: $*"
    alert "cross-replica rig is broken: $*"
    exit 2
}

# alert pushes one ntfy line. Dedup is the CALLER's job (see alert_once).
alert() {
    local msg="$1"
    log "ALERT: $msg"
    [ -n "$NTFY_TOPIC" ] || return 0
    local cfg
    cfg="$(mktemp)"
    chmod 600 "$cfg"
    printf 'url = "%s"\n' "$NTFY_TOPIC" > "$cfg"
    curl -fsS -K "$cfg" -H "Title: Keyorix cross-replica fuzz" -H "Priority: high" \
        -H "Tags: rotating_light" -d "$msg" >/dev/null 2>&1 \
        || log "ALERT: (also) failed to push to ntfy"
    rm -f "$cfg"
}

# alert_once pushes only the first time a given fingerprint is seen. A crasher
# that keeps reproducing every night is the same finding, not a new one; paging
# nightly on it trains the recipient to mute the topic, which is how a real
# second finding gets missed.
alert_once() {
    local fingerprint="$1" msg="$2"
    local marker="${STATE_DIR}/alerted/${fingerprint}"
    mkdir -p "$(dirname "$marker")"
    if [ -e "$marker" ]; then
        log "repeat finding (already alerted $(cat "$marker")): $msg"
        return 0
    fi
    date -u +%FT%TZ > "$marker"
    alert "$msg"
}

# classify_crasher reads a fuzz log and echoes one of:
#   suppressed  — every "GLOBAL INVARIANT VIOLATED" line names a class listed
#                 in KNOWN_OPEN_CLASSES
#   alert       — at least one violation line names something else, or there
#                 are no violation lines to judge (fail loud, not quiet)
#
# Separated from the run flow so --self-test can drive it with synthetic logs.
# Relying on the fuzzer to produce each case on demand does not work: fuzzing
# is nondeterministic, and the one smoke run that was supposed to exercise the
# alert branch came back clean. A classifier that decides whether a human gets
# woken up is exactly the thing that must be checked in both directions
# (CLAUDE.md: "before adding a guard, confirm it is green on a known-good case
# as well as red on a known-bad one").
classify_crasher() {
    local logfile="$1"
    local lines
    lines="$(grep -F 'GLOBAL INVARIANT VIOLATED' "$logfile" 2>/dev/null || true)"
    if [ -z "$lines" ]; then
        echo alert
        return 0
    fi
    if [ -z "${KNOWN_OPEN_CLASSES:-}" ]; then
        echo alert
        return 0
    fi
    # A line is "known" only when EVERY issue number in its own class marker is
    # listed. Extracting the numbers and comparing them exactly is deliberate
    # rather than grepping for "#NNNN class": the fuzzer emits COMBINED markers
    # for invariants that cover a sibling pair — "(#2646/#2647 class)",
    # "(#2653/#2654 class)", "(#2657/#2659 class)" — and a matcher that only
    # knew the single form failed to suppress any of them. Found by
    # --self-test's "two violations, both known-open" case on the first run,
    # not by reading the code.
    local line nums n
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        nums="$(printf '%s\n' "$line" | grep -oE '#[0-9]+' | tr -d '#' || true)"
        if [ -z "$nums" ]; then
            # An unnumbered invariant (admin ceiling, audit chain, access
            # review) can never be attributed to a known-open issue, so it
            # always alerts.
            echo alert
            return 0
        fi
        for n in $nums; do
            case " ${KNOWN_OPEN_CLASSES} " in
                *" ${n} "*) ;;
                *) echo alert; return 0 ;;
            esac
        done
    done <<EOF
${lines}
EOF
    echo suppressed
}

# self_test exercises classify_crasher in both directions against synthetic
# logs. Run with --self-test; exits non-zero on the first mismatch.
self_test() {
    local tmp rc=0 got
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    check() {
        local name="$1" want="$2" classes="$3" body="$4"
        printf '%s\n' "$body" > "${tmp}/log"
        KNOWN_OPEN_CLASSES="$classes" got="$(classify_crasher "${tmp}/log")"
        if [ "$got" = "$want" ]; then
            printf 'ok    %-52s -> %s\n' "$name" "$got"
        else
            printf 'FAIL  %-52s -> %s (want %s)\n' "$name" "$got" "$want"
            rc=1
        fi
    }

    check "single known-open class"            suppressed "2649" \
        "GLOBAL INVARIANT VIOLATED (#2649 class): 1 ACL grant(s) exist on a soft-deleted secret"
    check "combined marker, all siblings listed" suppressed "2646 2647 2649" \
        "GLOBAL INVARIANT VIOLATED (#2646/#2647 class): 1 live share(s)
GLOBAL INVARIANT VIOLATED (#2649 class): 1 ACL grant(s)"
    # The sharp edge of combined markers, and the reason the classifier
    # extracts every number rather than matching one: a marker that names a
    # sibling NOT in the list must alert, because the sibling's own bug is
    # not the one that was accepted as known-open.
    check "combined marker, one sibling NOT listed" alert "2646 2649" \
        "GLOBAL INVARIANT VIOLATED (#2646/#2647 class): 1 live share(s)"
    check "one known-open, one NOT"            alert      "2649" \
        "GLOBAL INVARIANT VIOLATED (#2649 class): 1 ACL grant(s)
GLOBAL INVARIANT VIOLATED (#9999 class): something nobody has filed"
    check "class not in the list at all"       alert      "2646 2647" \
        "GLOBAL INVARIANT VIOLATED (#2649 class): 1 ACL grant(s)"
    check "no suppression configured"          alert      "" \
        "GLOBAL INVARIANT VIOLATED (#2649 class): 1 ACL grant(s)"
    check "no violation line at all (loud)"    alert      "2649" \
        "panic: runtime error: invalid memory address"
    # A substring near-miss must NOT suppress: "#264" must not match "#2649".
    check "prefix near-miss does not suppress" alert      "264" \
        "GLOBAL INVARIANT VIOLATED (#2649 class): 1 ACL grant(s)"
    # The unnumbered invariants (admin ceiling, audit chain, access review)
    # carry no "#NNNN class" marker and so can never be suppressed.
    check "unnumbered invariant is never suppressed" alert "2646 2647 2649 2650 2651 2652 2653 2654 2655 2656 2657 2659" \
        "GLOBAL INVARIANT VIOLATED: no live global admin remains (checked adminID=1 admin2ID=2)"

    return $rc
}

if [ "${1:-}" = "--self-test" ]; then
    self_test
    exit $?
fi

# host_lock_holder echoes the lock's contents, or nothing when it is free.
host_lock_holder() {
    [ -n "$HOST_LOCK" ] || return 0
    [ -e "$HOST_LOCK" ] || return 0
    cat "$HOST_LOCK" 2>/dev/null || echo "(unreadable)"
}

cleanup() {
    local rc=$?
    if [ -n "${LOCK_WATCHER_PID:-}" ]; then
        kill "$LOCK_WATCHER_PID" 2>/dev/null || true
        wait "$LOCK_WATCHER_PID" 2>/dev/null || true
    fi
    # Always remove the container. A leaked Postgres holding a port is the
    # thing that makes tomorrow night's run fail for an unrelated reason.
    if docker ps -aq --filter "name=^${PG_CONTAINER}$" | grep -q .; then
        log "removing ${PG_CONTAINER}"
        docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
    fi
    log "exit rc=${rc}"
    return $rc
}

# --- preflight ---------------------------------------------------------------

mkdir -p "$LOG_DIR" "${STATE_DIR}/alerted"
trap cleanup EXIT

log "cross-replica nightly run ${RUN_ID} starting"

holder="$(host_lock_holder)"
if [ -n "$holder" ]; then
    log "SKIP: ${HOST_LOCK} is held by: ${holder}"
    log "A skipped night is not a failure — no alert sent."
    exit 0
fi

command -v docker >/dev/null 2>&1 || die_rig "docker not found"
command -v go >/dev/null 2>&1 || die_rig "go not found"
[ -d "${KEYORIX_REPO}/.git" ] || die_rig "no git checkout at ${KEYORIX_REPO}"

log "updating ${KEYORIX_REPO} to ${KEYORIX_REF}"
git -C "$KEYORIX_REPO" fetch --quiet origin || die_rig "git fetch failed"
git -C "$KEYORIX_REPO" reset --hard --quiet "$KEYORIX_REF" || die_rig "git reset to ${KEYORIX_REF} failed"
# `git reset --hard` does NOT remove untracked files, and `go test -fuzz`
# writes every crasher it finds into the in-tree corpus directory as an
# untracked file. Without this clean, the FIRST crasher poisons every
# subsequent night: it is replayed in the seed phase, the run fails before
# exploring anything, no NEW corpus entry appears, and the "non-zero exit with
# no new entry" branch below reports "the rig is broken" — which is both
# wrong and the kind of wrong that gets a rig switched off. Observed on the
# second smoke run of this script, two minutes after the first one found a
# real crasher.
#
# Scoped to the corpus directory rather than `git clean -fdx` over the whole
# tree: the latter would also delete anything an operator deliberately left
# in the checkout, and there is no reason to reach beyond the one directory
# that is actually written to.
git -C "$KEYORIX_REPO" clean -fdq -- "$CORPUS_DIR_REL" || die_rig "git clean of the fuzz corpus failed"
HEAD_SHA="$(git -C "$KEYORIX_REPO" rev-parse --short HEAD)"
log "running against ${KEYORIX_REF} @ ${HEAD_SHA}"

# --- Postgres ----------------------------------------------------------------

docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
log "starting ${PG_IMAGE} as ${PG_CONTAINER}"
# The superuser password reaches the container through a 0600 --env-file, not `-e NAME=value`
# (an argv is visible in ps). The file only has to exist while `docker run` reads it.
PG_ENV_FILE="$(mktemp)"
printf 'POSTGRES_PASSWORD=%s\n' "$PG_PASSWORD" >"$PG_ENV_FILE"
docker run -d --name "$PG_CONTAINER" \
    --env-file "$PG_ENV_FILE" \
    -p 127.0.0.1::5432 \
    "$PG_IMAGE" >/dev/null || { rm -f "$PG_ENV_FILE"; die_rig "docker run failed"; }
rm -f "$PG_ENV_FILE"

PG_PORT="$(docker port "$PG_CONTAINER" 5432/tcp | head -1 | sed 's/.*://')"
[ -n "$PG_PORT" ] || die_rig "could not read the mapped Postgres port"
export KEYORIX_TEST_PG_DSN="postgres://postgres:${PG_PASSWORD}@127.0.0.1:${PG_PORT}/postgres?sslmode=disable"
log "Postgres on 127.0.0.1:${PG_PORT}"

# Wait for readiness rather than sleeping a guessed interval: a fuzz run that
# starts against a not-yet-accepting server fails with a connection error that
# looks nothing like a finding and wastes the whole night.
for _ in $(seq 1 60); do
    if docker exec "$PG_CONTAINER" pg_isready -q -U postgres 2>/dev/null; then break; fi
    sleep 1
done
docker exec "$PG_CONTAINER" pg_isready -q -U postgres 2>/dev/null \
    || die_rig "Postgres did not become ready within 60s"

# --- host-lock watcher -------------------------------------------------------
# Writes a flag file the moment a benchmark session claims the lock. The test
# runs below check it and stop; see the ABORT handling after each.
ABORT_FLAG="${STATE_DIR}/abort-${RUN_ID}"
(
    while :; do
        sleep "$LOCK_POLL_SECONDS"
        h="$(host_lock_holder)"
        if [ -n "$h" ]; then
            printf '%s\n' "$h" > "$ABORT_FLAG"
            exit 0
        fi
    done
) &
LOCK_WATCHER_PID=$!

aborted() { [ -e "$ABORT_FLAG" ]; }

# --- 1. the ordering sweep ---------------------------------------------------

SWEEP_LOG="${LOG_DIR}/${RUN_ID}.sweep.log"
sweep_rc=0
if [ "$RUN_SWEEP" = "1" ]; then
    log "ordering sweep (KEYORIX_INTERLEAVE_SWEEP=1, timeout ${SWEEP_TIMEOUT})"
    KEYORIX_INTERLEAVE_SWEEP=1 \
        go -C "$KEYORIX_REPO" test "$FUZZ_PKG" -run TestOrderingSweep -count=1 -v -timeout "$SWEEP_TIMEOUT" \
        > "$SWEEP_LOG" 2>&1 || sweep_rc=$?
else
    log "ordering sweep SKIPPED (RUN_SWEEP=${RUN_SWEEP})"
fi

if [ "$sweep_rc" -ne 0 ]; then
    if aborted; then
        log "sweep interrupted by the host lock ($(cat "$ABORT_FLAG")) — not treating this as a finding"
    else
        # Fingerprint on the set of unexplained (pair, ordering) keys, so a
        # second, different finding still pages even while the first is known.
        fp="sweep-$(grep -F 'UNEXPLAINED invariant break' "$SWEEP_LOG" | sort | sha256sum | cut -c1-16)"
        unexplained="$(grep -cF 'UNEXPLAINED invariant break' "$SWEEP_LOG" || true)"
        sequential="$(grep -cF 'SEQUENTIAL (not a race)' "$SWEEP_LOG" || true)"
        log "sweep FAILED: ${unexplained} unexplained, ${sequential} sequential — see ${SWEEP_LOG}"
        grep -F -A2 'invariant break' "$SWEEP_LOG" | head -40 | tee -a "$LOG"
        alert_once "$fp" "ordering sweep on ${KEYORIX_REF} @ ${HEAD_SHA}: ${unexplained} unexplained + ${sequential} sequential invariant break(s). Log: ${SWEEP_LOG}"
        exit 1
    fi
fi
if [ "$RUN_SWEEP" = "1" ]; then log "ordering sweep clean"; fi

if aborted; then
    log "host lock claimed by $(cat "$ABORT_FLAG") — stopping before the fuzz run"
    exit 0
fi

# --- 2. the fuzz run ---------------------------------------------------------

CORPUS_DIR="${KEYORIX_REPO}/${CORPUS_DIR_REL}"
before_list="$(mktemp)"
ls -1 "$CORPUS_DIR" 2>/dev/null | sort > "$before_list" || true

FUZZ_LOG="${LOG_DIR}/${RUN_ID}.fuzz.log"
log "fuzzing ${FUZZ_TARGET} for ${FUZZTIME}"
fuzz_rc=0
go -C "$KEYORIX_REPO" test "$FUZZ_PKG" -run "^${FUZZ_TARGET}\$" -fuzz "^${FUZZ_TARGET}\$" \
    -fuzztime "$FUZZTIME" -parallel 2 -timeout 0 \
    > "$FUZZ_LOG" 2>&1 || fuzz_rc=$?

if [ "$fuzz_rc" -eq 0 ]; then
    log "fuzz run clean (${FUZZTIME}, ${KEYORIX_REF} @ ${HEAD_SHA})"
    rm -f "$before_list"
    exit 0
fi

if aborted; then
    log "fuzz run interrupted by the host lock ($(cat "$ABORT_FLAG")) — not treating this as a finding"
    rm -f "$before_list"
    exit 0
fi

# A non-zero exit with no new corpus entry is a rig problem (build failure, the
# DSN went away, Postgres died), NOT a finding. Distinguishing them matters:
# alerting "a race was found" when the real story is "the container OOMed"
# sends the reader to the wrong place entirely.
after_list="$(mktemp)"
ls -1 "$CORPUS_DIR" 2>/dev/null | sort > "$after_list" || true
new_entries="$(comm -13 "$before_list" "$after_list" || true)"
rm -f "$before_list" "$after_list"

if [ -z "$new_entries" ]; then
    # Distinguish the two reasons for "failed but wrote nothing new":
    #  - an invariant DID break, on an input already in the committed corpus.
    #    That is a finding (a regression of a promoted seed), not a rig fault.
    #  - no invariant line at all: build failure, the DSN went away, Postgres
    #    died. Alerting "a race was found" for that sends the reader to
    #    entirely the wrong place.
    if grep -qF 'GLOBAL INVARIANT VIOLATED' "$FUZZ_LOG"; then
        log "fuzz exited ${fuzz_rc} with no NEW entry but a real invariant break — a committed corpus seed regressed"
        tail -40 "$FUZZ_LOG" | tee -a "$LOG"
        fp="seed-regression-$(grep -F 'GLOBAL INVARIANT VIOLATED' "$FUZZ_LOG" | sort -u | sha256sum | cut -c1-16)"
        alert_once "$fp" "committed corpus seed regressed on ${KEYORIX_REF} @ ${HEAD_SHA} — see ${FUZZ_LOG}"
        exit 1
    fi
    log "fuzz exited ${fuzz_rc} with no new corpus entry and no invariant break — treating as a rig failure"
    tail -40 "$FUZZ_LOG" | tee -a "$LOG"
    die_rig "fuzz run exited ${fuzz_rc} with no crasher (see ${FUZZ_LOG})"
fi

log "NEW crasher(s): ${new_entries}"
tail -40 "$FUZZ_LOG" | tee -a "$LOG"

# Classify the crasher against KNOWN_OPEN_CLASSES before deciding to alert.
# Every violation message the fuzzer emits carries its own issue class, e.g.
# "GLOBAL INVARIANT VIOLATED (#2649 class): ...", so this reads the fuzzer's
# own attribution rather than re-deriving it.
suppressed=0
if [ "$(classify_crasher "$FUZZ_LOG")" = "suppressed" ]; then
    suppressed=1
    log "SUPPRESSED: every violation names a known-open class (${KNOWN_OPEN_CLASSES}). Crasher kept, no alert."
else
    log "crasher is NOT covered by KNOWN_OPEN_CLASSES=\"${KNOWN_OPEN_CLASSES}\" — alerting"
fi

# Push the crasher to the PRIVATE corpus repo. Best-effort by design: losing
# the push must not lose the finding, so the alert fires either way and the
# crasher also stays in the rig's own checkout until someone collects it.
if [ -d "${CORPUS_REPO}/.git" ]; then
    dest="${CORPUS_REPO}/${CORPUS_SUBDIR}"
    mkdir -p "$dest"
    for f in $new_entries; do
        cp "${CORPUS_DIR}/${f}" "${dest}/${f}"
        log "copied ${f} to ${dest}"
    done
    if git -C "$CORPUS_REPO" add -- "$CORPUS_SUBDIR" \
        && git -C "$CORPUS_REPO" commit -q -m "corpus: ${FUZZ_TARGET} crasher(s) from ${RUN_ID} (${KEYORIX_REF} @ ${HEAD_SHA})" \
        && git -C "$CORPUS_REPO" push -q; then
        log "pushed to the private corpus repo"
    else
        log "WARNING: could not commit/push the private corpus — the crasher is still at ${CORPUS_DIR}"
    fi
else
    log "WARNING: no corpus checkout at ${CORPUS_REPO} — the crasher is only at ${CORPUS_DIR}"
fi

# Fingerprint on the crasher's own bytes, so the same input found again on a
# later night does not re-page.
if [ "$suppressed" = "1" ]; then
    # Exit 0: a known-open bug reproducing is the expected state of the world
    # until its fix lands, and a unit that is "failed" every morning for a
    # month is a unit whose status nobody reads.
    exit 0
fi

fp="crasher-$(for f in $new_entries; do sha256sum "${CORPUS_DIR}/${f}"; done | sort | sha256sum | cut -c1-16)"
alert_once "$fp" "NEW cross-replica invariant crasher on ${KEYORIX_REF} @ ${HEAD_SHA}: ${new_entries}. Private corpus + ${FUZZ_LOG}"
exit 1
