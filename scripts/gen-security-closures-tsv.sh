#!/bin/bash
# gen-security-closures-tsv.sh — validates docs/security-closures.d/ and builds
# the flat closure ledger from it.
#
# The flat ledger (HEADER.txt + every <claim_id>.tsv fragment, byte-order
# sorted) is a BUILD ARTIFACT, no longer committed: docs/security-closures.tsv
# is gitignored. Committing it made every merged closure PR conflict every
# other open PR (the generated file changed on each one). The fragments in
# docs/security-closures.d/ are the only source of truth.
#
# Consumers (scripts/check-closures.sh, scripts/report-unlisted-security-issues.sh)
# call this with --stdout when CLOSURE_LEDGER is unset, so they always read the
# ledger built from the current fragments -- it cannot be stale.
#
# Usage:
#   scripts/gen-security-closures-tsv.sh            # write docs/security-closures.tsv (untracked, for browsing)
#   scripts/gen-security-closures-tsv.sh --stdout   # print the flat ledger (validates first)
#   scripts/gen-security-closures-tsv.sh --check    # validate the fragments only; exit 1 on any problem
#
# Validation (all three modes, nothing is written if it fails): HEADER.txt
# exists; at least one fragment; every non-comment row in every fragment has at
# least 6 tab-separated columns; no claim_id appears twice across all fragments;
# each file ends in a newline (so concatenation cannot glue two rows together);
# each file holds exactly one non-comment row, on one line, with no carriage
# return anywhere (a second row or an embedded newline/CR in a field is refused,
# naming the file).
#
#   scripts/gen-security-closures-tsv.sh --self-test   # prove those checks go red (and green)
# check-closures.sh --self-test covers the semantic checks and runs this one too.
set -euo pipefail
# Byte-order glob expansion: the output must be identical on macOS and the
# Linux CI runner regardless of either machine's locale collation.
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/closure-pkg.sh
. "$REPO_ROOT/scripts/closure-pkg.sh"
CLOSURES_D="${CLOSURES_D:-$REPO_ROOT/docs/security-closures.d}"
OUT="$REPO_ROOT/docs/security-closures.tsv"
HEADER="$CLOSURES_D/HEADER.txt"

mode="${1:-write}"
case "$mode" in
    write|--stdout|--check) ;;
    --self-test) ;;
    *) echo "usage: $0 [--stdout|--check|--self-test]" >&2; exit 2 ;;
esac

if [ "$mode" = "--self-test" ]; then
    echo "==> self-test: --check must refuse every malformed fragment below, and accept the good one"
    selffail=0
    good='GOOD-1\t-\t-\tmanual\tdeadbeef\t-\tcalibration row citing a fake artefact'

    # $1=description $2=reject|accept $3=exact fragment bytes (printf %b escapes)
    # $4=optional second fragment, same format (written as other.tsv)
    st_case() {
        local desc="$1" expect="$2" content="$3" other="${4:-}" d rc out
        d="$(mktemp -d)"
        printf 'claim_id\tpackage\tproving_test\tverification\tlanded_commit\tissue\tnote\n' > "$d/HEADER.txt"
        printf '%b' "$content" > "$d/frag.tsv"
        [ -z "$other" ] || printf '%b' "$other" > "$d/other.tsv"
        set +e
        out="$(CLOSURES_D="$d" "$0" --check 2>&1)"
        rc=$?
        set -e
        rm -rf "$d"
        if [ "$expect" = "reject" ] && { [ "$rc" -eq 0 ] || ! grep -q 'frag.tsv' <<<"$out"; }; then
            echo "FAIL: self-test case '$desc' must be REJECTED naming frag.tsv (exit $rc)" >&2
            printf '      %s\n' "${out//$'\n'/$'\n'      }" >&2
            selffail=1
        elif [ "$expect" = "accept" ] && [ "$rc" -ne 0 ]; then
            echo "FAIL: self-test case '$desc' must be ACCEPTED (exit $rc)" >&2
            printf '      %s\n' "${out//$'\n'/$'\n'      }" >&2
            selffail=1
        else
            echo "  ok: '$desc' correctly ${expect}ed (exit $rc)"
        fi
    }

    st_case "good one-row fragment" accept "$good\n"
    st_case "good fragment with a leading comment line" accept "# note\n$good\n"
    st_case "two rows in one file" reject \
        "$good\nGOOD-2\t-\t-\tmanual\tdeadbeef\t-\tsecond row\n"
    st_case "row split across lines (embedded newline in a field)" reject \
        "GOOD-1\t-\t-\tmanual\tdeadbeef\t-\tnote with an\nembedded newline\n"
    st_case "embedded newline leaving a well-formed second row" reject \
        "GOOD-1\t-\t-\tmanual\tdeadbeef\t-\tfirst\nGOOD-1b\t-\t-\tmanual\tdeadbeef\t-\tsecond\n"
    st_case "embedded newline whose continuation starts with '#' (row still parses)" reject \
        "GOOD-1\t-\t-\tmanual\tdeadbeef\t-\tnote cut here\n# rest of the note after an embedded newline\n"
    st_case "comment line after the row" reject "$good\n# trailing comment\n"
    st_case "blank line after the row" accept "$good\n\n"
    st_case "CRLF line ending" reject "$good\r\n"
    st_case "bare CR inside a field" reject "GOOD-1\t-\t-\tmanual\tdeadbeef\t-\tnote\rmore\n"
    st_case "no trailing newline" reject "$good"

    [ "$selffail" -eq 0 ] || exit 1
    echo "ok: gen-security-closures-tsv.sh --self-test"
    exit 0
fi

fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }

[ -f "$HEADER" ] || bad "$HEADER missing"

shopt -s nullglob
frags=("$CLOSURES_D"/*.tsv)
[ "${#frags[@]}" -gt 0 ] || bad "no fragments in $CLOSURES_D -- an empty ledger cannot fail, so it is not a ledger"

seen=$'\n'
for f in "${frags[@]}"; do
    rows="$(grep -vE '^[[:space:]]*(#|$)' "$f" || true)"
    if [ -z "$rows" ]; then
        bad "$f holds no row"
        continue
    fi
    # One row, one line, per file. A CR (CRLF line ending, or a bare CR inside a
    # field) would ride along into the flat ledger and corrupt the last column;
    # a second line is either a second row or a row whose field holds an
    # embedded newline. Either way the per-line checks below would misread it, so
    # refuse the file by name and skip them.
    if grep -q $'\r' "$f"; then
        bad "$f contains a carriage return (CRLF line ending or CR inside a field); a fragment is exactly one LF-terminated line"
        continue
    fi
    nrows="$(grep -cvE '^[[:space:]]*(#|$)' "$f" || true)"
    if [ "$nrows" -ne 1 ]; then
        bad "$f holds $nrows non-comment lines; a fragment is exactly one row on one line (two rows in one file, or a field with an embedded newline splitting a row, are both refused)"
        continue
    fi
    # Comments are allowed BEFORE the row only. A comment-looking line AFTER it is
    # what an embedded newline in the last field leaves behind when the text that
    # follows the newline starts with '#': the row above still parses, so the
    # count check cannot see it, and the note would be silently cut short.
    trailing="$(awk '/^[[:space:]]*(#|$)/ { if (seen && $0 !~ /^[[:space:]]*$/) print NR; next } { seen = 1 }' "$f")"
    if [ -n "$trailing" ]; then
        bad "$f: line ${trailing%%$'\n'*} follows the row and is not blank; a fragment is exactly one row on one line, comments only before it (a field with an embedded newline followed by '#' text is refused)"
        continue
    fi
    while IFS= read -r row; do
        cols="$(awk -F'\t' '{print NF}' <<<"$row")"
        claim="$(cut -f1 <<<"$row")"
        [ "$cols" -ge 6 ] || bad "$f: claim '$claim' has $cols tab-separated columns, want at least 6 (claim_id package proving_test verification landed_commit issue [note])"
        # A row that runs a test must name a package check-closures.sh can run:
        # ./<dir> in the root module or ./cli/<dir> in the cli module.
        verification="$(cut -f4 <<<"$row")"
        if [ "$verification" = "default-ci" ] || [ "$verification" = "pg-gated" ]; then
            if ! closure_pkg_resolve "$REPO_ROOT" "$(cut -f2 <<<"$row")"; then
                bad "$f: claim '$claim': $CLOSURE_PKG_ERR"
            fi
        fi
        case "$seen" in
            *$'\n'"$claim"$'\n'*) bad "duplicate claim_id '$claim' (second occurrence in $f)" ;;
        esac
        seen="$seen$claim"$'\n'
    done <<<"$rows"
    [ -z "$(tail -c1 "$f")" ] || bad "$f does not end in a newline"
done

[ "$fail" -eq 0 ] || exit 1

build() {
    cat "$HEADER"
    echo
    for f in "${frags[@]}"; do cat "$f"; done
}

case "$mode" in
    --check)
        echo "ok: ${#frags[@]} closure fragment(s) in docs/security-closures.d/ are well-formed"
        ;;
    --stdout)
        build
        ;;
    write)
        build > "$OUT"
        echo "wrote $OUT (untracked, gitignored) from ${#frags[@]} claim file(s)"
        ;;
esac
