#!/bin/bash
# check-closures.sh — fails if any security closure claim lacks a proving test
# that actually runs and passes IN THE ENVIRONMENT ITS ROW CLAIMS.
#
# Caught missing: G01 was recorded in REMEDIATION-STATUS.md as "merged, fully
# addressed — 8 of 8 members" for three weeks. Five members had landed; the other
# three sat on an unmerged branch (112b64ff). An adversarial review later
# re-exploited the gap live, spending a full exploit build to learn what this
# check learns in one second.
#
# Three design rules, each from a failure:
#
#   1. Verify by test, not by commit. This repo squash-merges, so
#      `git merge-base --is-ancestor <branch> origin/main` returns false for
#      every correctly landed PR — a check that always fails is as useless as one
#      that always passes, and more corrosive, because it teaches people to
#      ignore it. The landed_commit column is informational only.
#
#   2. PASS is not "did not fail". `go test -run` over a name that matches
#      nothing EXITS ZERO, and a gated test with no DSN does not appear in output
#      at all, not even as SKIP — that is how 13 Postgres lock sites stayed
#      "verified" for months on the path where every one is a no-op. So this
#      requires a literal `--- PASS: <name>` line and reports SKIP, no-match and
#      unrecognised output as three distinct failures.
#
#   3. A race that can only be demonstrated against a real multi-connection
#      Postgres (not SQLite/mocks) genuinely CANNOT produce a `--- PASS` line
#      in every environment — #1646 and #1780 were left OUT of this ledger
#      entirely for exactly that reason: rule 2 makes any Postgres-gated test
#      SKIP here (this script's own invocations never set KEYORIX_TEST_PG_DSN),
#      which rule 2 then treats as a failure, so a row for either could not be
#      added without either breaking CI or weakening rule 2 for everyone. Two
#      real closures with no row, indistinguishable from closures that never
#      happened — the ledger's completeness became a function of which
#      environment it runs in, not of what was actually fixed. The
#      `verification` column (see docs/security-closures.d/HEADER.txt)
#      fixes this by making the row say which environment its proof requires,
#      so a skip can be judged against that claim instead of against a single
#      hardcoded assumption. This script still does not set the DSN itself —
#      .github/workflows/ci.yml's test-suite job (`core` leg) runs this SAME
#      script a second time, in the one job that already has Postgres — that
#      second run is what actually proves a pg-gated row; this rule just stops
#      the DSN-less run from reporting a false failure for it.
#
# Usage:
#   ./scripts/check-closures.sh              # verify every row in the ledger
#   ./scripts/check-closures.sh --self-test  # prove the check can go red (and
#                                             # that it can go green honestly)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# docs/security-closures.tsv is no longer committed: unless the caller supplies
# CLOSURE_LEDGER (--self-test and check-adr-conformance.sh do), build the flat
# ledger from docs/security-closures.d/ right now. The generator validates the
# fragments first and exits non-zero on a malformed one, which fails this check.
if [ -n "${CLOSURE_LEDGER:-}" ]; then
    LEDGER="$CLOSURE_LEDGER"
else
    LEDGER="$(mktemp)"
    trap 'rm -f "$LEDGER"' EXIT
    "$REPO_ROOT/scripts/gen-security-closures-tsv.sh" --stdout > "$LEDGER" || {
        echo "FAIL: could not build the closure ledger from docs/security-closures.d/" >&2; exit 1
    }
fi
fail=0
checked=0
gated_skips=0
die()  { echo "FAIL: $*" >&2; fail=1; }
note() { echo "  $*"; }

pg_available=false
if [ -n "${KEYORIX_TEST_PG_DSN:-}" ]; then
    pg_available=true
fi

if [ ! -f "$LEDGER" ]; then
    echo "FAIL: closure ledger not found at $LEDGER" >&2; exit 1
fi

rows=$(grep -vE '^[[:space:]]*(#|$)' "$LEDGER" || true)

# Fragment directory (dual-read, C-MERGE-FRICTION): when CLOSURE_LEDGER_D is
# set, every <dir>/*.tsv file is ONE more row in the same format, read in
# addition to the flat ledger above — so a new claim is a new file, not an
# append to a shared one (two PRs appending to one ledger is a guaranteed
# merge conflict). Unset (the default, i.e. the ledger generated from docs/security-closures.d/) means
# no fragments: that ledger is already generated from docs/security-closures.d/
# by scripts/gen-security-closures-tsv.sh, and reading that directory here as
# well would count every claim twice. A fragment must hold exactly one row;
# the duplicate-claim check below runs over legacy + fragment rows together.
LEDGER_D="${CLOSURE_LEDGER_D:-}"
if [ -n "$LEDGER_D" ] && [ -d "$LEDGER_D" ]; then
    for frag in "$LEDGER_D"/*.tsv; do
        [ -e "$frag" ] || continue
        frag_rows=$(grep -vE '^[[:space:]]*(#|$)' "$frag" || true)
        n=$(grep -c . <<<"$frag_rows" || true)
        if [ "$n" -ne 1 ]; then
            die "fragment $frag holds $n rows — a ledger fragment must hold exactly one"
            continue
        fi
        if [ -z "$rows" ]; then rows="$frag_rows"; else rows="$rows"$'\n'"$frag_rows"; fi
    done
fi

if [ -z "$rows" ]; then
    echo "FAIL: closure ledger is empty — a ledger with no rows cannot fail, and" >&2
    echo "      a check that cannot fail is not a check." >&2
    exit 1
fi

dupes=$(cut -f1 <<<"$rows" | sort | uniq -d || true)
if [ -n "$dupes" ]; then
    die "duplicate claim_id in ledger:"; for d in $dupes; do note "$d"; done
fi

# Column order: claim_id  package  proving_test  verification  landed_commit  issue  note
while IFS=$'\t' read -r claim pkg test verification commit issue rest; do
    [ -z "${claim:-}" ] && continue
    case "${verification:-}" in
        default-ci|pg-gated)
            if [ -z "${pkg:-}" ] || [ -z "${test:-}" ]; then
                die "$claim: missing package or proving_test — a closure without a citation is not a closure"
            fi
            ;;
        manual)
            if [ -z "${rest:-}" ]; then
                die "$claim: verification=manual requires a note citing the artefact a skeptical reader could go check"
            fi
            ;;
        *)
            die "$claim: verification column must be default-ci, pg-gated, or manual (got '${verification:-<empty>}')"
            ;;
    esac
    [ -z "${commit:-}" ] && die "$claim: missing landed_commit"
    [ -z "${issue:-}" ] && die "$claim: missing issue column (use '-' explicitly when there is no single corresponding GitHub issue)"
done <<<"$rows"
[ "$fail" -eq 0 ] || exit 1

# manual rows have no test to run — report them once, loudly, as unverified by
# CI (a claim, not evidence), then leave them out of the go-test loop below.
manual_claims=$(awk -F'\t' '$4=="manual" {print $1}' <<<"$rows")
if [ -n "$manual_claims" ]; then
    echo "==> manual (no automated test exists — verified by cited artefact only)"
    while IFS= read -r claim; do
        [ -z "$claim" ] && continue
        artefact=$(awk -F'\t' -v c="$claim" '$1==c {print $NF}' <<<"$rows")
        checked=$((checked + 1))
        note "UNVERIFIED-BY-CI $claim -> $artefact"
        note "   a self-reported artefact is a claim, not evidence — CI cannot check this row;"
        note "   it is accepted only because it says so honestly, not because it was proven"
    done <<<"$manual_claims"
fi

for pkg in $(awk -F'\t' '$4=="default-ci" || $4=="pg-gated" {print $2}' <<<"$rows" | sort -u); do
    tests=$(awk -F'\t' -v p="$pkg" '($4=="default-ci" || $4=="pg-gated") && $2==p {print $3}' <<<"$rows")
    pattern=$(paste -sd'|' - <<<"$tests")
    echo "==> $pkg"
    set +e
    out=$(cd "$REPO_ROOT" && go test -count=1 -v -run "^(${pattern})\$" "$pkg" 2>&1); rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        die "$pkg: go test exited $rc"
        # Show the actual failures, not just the head of the log: the first 40
        # lines are usually a passing test's chatter, which hid every real
        # failure in this step (2026-09-23, #2016/#2021/#2022).
        { grep -nE -- '--- FAIL|^FAIL|panic:|_test\.go:[0-9]+: ' <<<"$out" | head -60
          echo "      ... last 40 lines:"; tail -n 40 <<<"$out"; } | sed 's/^/      /'
        continue
    fi
    while IFS= read -r test; do
        [ -z "$test" ] && continue
        checked=$((checked + 1))
        claim=$(awk -F'\t' -v p="$pkg" -v t="$test" '$2==p && $3==t {print $1}' <<<"$rows")
        verification=$(awk -F'\t' -v p="$pkg" -v t="$test" '$2==p && $3==t {print $4}' <<<"$rows")
        if grep -qE "^--- PASS: ${test}([[:space:]]|$)" <<<"$out"; then
            note "ok   $claim -> $test ($verification)"
        elif grep -qE "^--- SKIP: ${test}([[:space:]]|$)" <<<"$out"; then
            if [ "$verification" = "pg-gated" ] && [ "$pg_available" = false ]; then
                gated_skips=$((gated_skips + 1))
                note "gated-skip $claim -> $test (pg-gated, KEYORIX_TEST_PG_DSN not set in this"
                note "   invocation — expected, not evidence either way; a DIFFERENT CI job must"
                note "   run this script WITH the DSN for this claim to ever actually be proven)"
            else
                die "$claim: proving test $test SKIPPED, not passed."
                if [ "$verification" = "pg-gated" ]; then
                    note "     verification=pg-gated but KEYORIX_TEST_PG_DSN IS set in THIS"
                    note "     invocation, and the test skipped anyway — the gate condition this"
                    note "     row claims is met, so 'gated' is no longer an excuse: either the"
                    note "     test's own skip guard doesn't match what the row claims, or the"
                    note "     row is lying about being provable here."
                else
                    note "     A skipped test proves nothing. If it genuinely needs a DSN, mark"
                    note "     this row verification=pg-gated (and confirm a CI job actually runs"
                    note "     this script WITH that DSN, or the closure still has no evidence)."
                fi
            fi
        elif grep -q "no tests to run" <<<"$out"; then
            die "$claim: proving test $test DOES NOT EXIST (go test matched nothing, exited 0)."
            note "     The false-green case: a renamed, deleted or never-written test"
            note "     still reports success."
        else
            die "$claim: proving test $test produced no PASS line and no recognised failure."
            sed -n '1,20p' <<<"$out" | sed 's/^/      /'
        fi
    done <<<"$tests"
done

if [ "${1:-}" = "--self-test" ]; then
    echo; echo "==> self-test: the check must reject every bad row below, and accept every good one"
    selffail=0

    run_case() {
        # $1=description  $2=expected(reject|accept)  $3=row(s), one per line
        # $4=forced KEYORIX_TEST_PG_DSN for this sub-invocation ("" = unset, "-" = inherit ambient)
        # $5..=optional fragment files, each "name.tsv=<content>" — written into a
        #      fresh CLOSURE_LEDGER_D. Always a fresh dir, so the real fragment
        #      directory a wrapper (check-adr-conformance.sh) exported never leaks in.
        local desc="$1" expect="$2" body="$3" dsn="$4" out rc
        shift 4
        local tmp; tmp=$(mktemp)
        local tmpd; tmpd=$(mktemp -d)
        printf '%s\n' "$body" > "$tmp"
        local frag
        for frag in "$@"; do
            printf '%s\n' "${frag#*=}" > "$tmpd/${frag%%=*}"
        done
        set +e
        if [ "$dsn" = "-" ]; then
            out=$(CLOSURE_LEDGER="$tmp" CLOSURE_LEDGER_D="$tmpd" "$0" 2>&1)
        elif [ -z "$dsn" ]; then
            out=$(CLOSURE_LEDGER="$tmp" CLOSURE_LEDGER_D="$tmpd" env -u KEYORIX_TEST_PG_DSN "$0" 2>&1)
        else
            out=$(CLOSURE_LEDGER="$tmp" CLOSURE_LEDGER_D="$tmpd" KEYORIX_TEST_PG_DSN="$dsn" "$0" 2>&1)
        fi
        rc=$?
        set -e
        rm -rf "$tmp" "$tmpd"
        if [ "$expect" = "reject" ] && [ "$rc" -eq 0 ]; then
            echo "FAIL: self-test case '$desc' PASSED when it must be REJECTED — the checker" >&2
            echo "      cannot detect this bad row and is therefore worthless for it." >&2
            sed -n '1,40p' <<<"$out" | sed 's/^/      /' >&2
            selffail=1
        elif [ "$expect" = "accept" ] && [ "$rc" -ne 0 ]; then
            echo "FAIL: self-test case '$desc' was REJECTED when it must be ACCEPTED — the" >&2
            echo "      checker is too strict and will block an honest, correctly-gated row." >&2
            sed -n '1,40p' <<<"$out" | sed 's/^/      /' >&2
            selffail=1
        else
            echo "  ok: '$desc' correctly ${expect}ed (exit $rc)"
        fi
    }

    run_case "nonexistent test" "reject" \
        'SELF-TEST-1	./internal/core	TestThisNameDoesNotExistAnywhere	default-ci	deadbeef	-	calibration row' \
        "-"

    run_case "default-ci row whose test skips" "reject" \
        'SELF-TEST-2	./internal/core	TestCheckClosuresSelfTestFixture_AlwaysSkip	default-ci	deadbeef	-	calibration row' \
        ""

    run_case "pg-gated row, no DSN available, test skips" "accept" \
        'SELF-TEST-3	./internal/core	TestCheckClosuresSelfTestFixture_SkipsWithoutPGDSN	pg-gated	deadbeef	-	calibration row' \
        ""

    run_case "pg-gated row, DSN available, test skips anyway" "reject" \
        'SELF-TEST-4	./internal/core	TestCheckClosuresSelfTestFixture_AlwaysSkip	pg-gated	deadbeef	-	calibration row' \
        "host=localhost port=1 dbname=x user=x sslmode=disable password=x"

    run_case "invalid verification value" "reject" \
        'SELF-TEST-5	./internal/core	TestCheckClosuresSelfTestFixture_AlwaysSkip	sometimes	deadbeef	-	calibration row' \
        "-"

    run_case "manual row with no artefact note" "reject" \
        'SELF-TEST-6	-	-	manual	deadbeef	-	' \
        "-"

    run_case "manual row with an artefact note, no pkg/test needed" "accept" \
        'SELF-TEST-7	-	-	manual	deadbeef	-	calibration row citing a fake artefact' \
        "-"

    # Fragment-directory cases (CLOSURE_LEDGER_D). Manual rows only, so these
    # exercise the row-collection path without running go test.
    run_case "fragment row duplicating a legacy claim_id" "reject" \
        'SELF-TEST-8	-	-	manual	deadbeef	-	calibration row (legacy)' \
        "-" \
        'SELF-TEST-8.tsv=SELF-TEST-8	-	-	manual	deadbeef	-	calibration row (fragment)'

    run_case "two fragments with the same claim_id" "reject" \
        'SELF-TEST-9	-	-	manual	deadbeef	-	calibration row (legacy)' \
        "-" \
        'a.tsv=SELF-TEST-10	-	-	manual	deadbeef	-	calibration row' \
        'b.tsv=SELF-TEST-10	-	-	manual	deadbeef	-	calibration row'

    run_case "fragment holding two rows" "reject" \
        'SELF-TEST-11	-	-	manual	deadbeef	-	calibration row (legacy)' \
        "-" \
        $'SELF-TEST-12.tsv=SELF-TEST-12\t-\t-\tmanual\tdeadbeef\t-\tone\nSELF-TEST-13\t-\t-\tmanual\tdeadbeef\t-\ttwo'

    run_case "malformed fragment row (bad verification) is checked like a legacy row" "reject" \
        'SELF-TEST-14	-	-	manual	deadbeef	-	calibration row (legacy)' \
        "-" \
        'SELF-TEST-15.tsv=SELF-TEST-15	./internal/core	TestX	sometimes	deadbeef	-	calibration row'

    run_case "fragment-only ledger (legacy file holds comments only)" "accept" \
        '# header only' \
        "-" \
        'SELF-TEST-16.tsv=SELF-TEST-16	-	-	manual	deadbeef	-	calibration row citing a fake artefact'

    run_case "legacy + distinct fragment rows" "accept" \
        'SELF-TEST-17	-	-	manual	deadbeef	-	calibration row citing a fake artefact' \
        "-" \
        $'SELF-TEST-18.tsv=# a comment line is allowed\nSELF-TEST-18\t-\t-\tmanual\tdeadbeef\t-\tcalibration row citing a fake artefact'

    if [ "$selffail" -ne 0 ]; then
        exit 1
    fi
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "ok: $checked closure claim(s) verified ($gated_skips gate-skipped in this invocation — see above)"
else
    echo "CLOSURE VERIFICATION FAILED — do not treat the ledger as accurate" >&2; exit 1
fi
