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
# each file ends in a newline (so concatenation cannot glue two rows together).
# (A few historical fragments hold several rows, so one-row-per-file is not
# enforced here; check-closures.sh --self-test covers the semantic checks.)
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
    *) echo "usage: $0 [--stdout|--check]" >&2; exit 2 ;;
esac

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
