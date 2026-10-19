#!/bin/bash
# migrate-to-fragments.sh — moves every row of the dual-read ledgers out of
# the flat legacy TSV and into one-row fragment files under <name>.d/.
#
# Why: on 2026-10-03/04 about 20 approved PRs repeatedly fell out of the merge
# queue on conflicts, nearly all in a few append-only ledgers. Every reader of
# these ledgers already reads legacy TSV + <name>.d/*.tsv (C-MERGE-FRICTION),
# so new rows can go into fragments today without touching the shared file.
# This script finishes the job by moving the EXISTING rows — which rewrites
# the shared files every open PR touches, so it must only be run by the
# coordinator, in a quiet merge window, never on a feature branch.
#
# Ledgers migrated (key column = column 1):
#   docs/adr-conformance-enforced.tsv   -> docs/adr-conformance-enforced.d/   (scripts/check-adr-conformance.sh)
#   docs/review-coverage.tsv            -> docs/review-coverage.d/            (scripts/check-review-coverage.sh)
#   docs/check-then-act-lock-exempt.tsv -> docs/check-then-act-lock-exempt.d/ (internal/core/guards TestCheckThenActLockGuard_*)
# NOT migrated: docs/security-closures.tsv — it is already GENERATED from
# docs/security-closures.d/ (scripts/gen-security-closures-tsv.sh).
#
# What it does, per ledger:
#   - comment and blank lines stay in the legacy file (the header documents
#     the columns; the readers still require the legacy file to exist);
#   - each data row moves, byte-for-byte, to <name>.d/<fragment_name(key)>.tsv;
#   - fragment_name: '/' -> '__', '(' ')' '*' dropped, a bare '.' -> '_root'.
#
# Safety:
#   - Refuses (exit 1, NOTHING written for ANY ledger) on: a duplicate key in
#     the legacy file, two keys mapping to one fragment name, or an existing
#     fragment file with DIFFERENT content than the row it would receive.
#   - Idempotent: an existing fragment with IDENTICAL content is accepted (the
#     legacy row is just dropped), and a second run finds no rows -> no-op.
#   - Deterministic: output depends only on the input files.
#
# Usage:
#   scripts/ledgers/migrate-to-fragments.sh            # migrate in place
#   scripts/ledgers/migrate-to-fragments.sh --dry-run  # print the plan, write nothing
#   LEDGER_ROOT=/some/checkout scripts/ledgers/migrate-to-fragments.sh   # operate on another tree
# Afterwards: run the three readers (see the README.md in each .d/ directory)
# and commit the legacy files + new fragments together.
set -euo pipefail
export LC_ALL=C

ROOT="${LEDGER_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
DRY=false
[ "${1:-}" = "--dry-run" ] && DRY=true

LEDGERS=(
    docs/adr-conformance-enforced.tsv
    docs/review-coverage.tsv
    docs/check-then-act-lock-exempt.tsv
)

fragment_name() {
    local k="$1"
    if [ "$k" = "." ]; then echo "_root"; return; fi
    k="${k//\//__}"; k="${k//(/}"; k="${k//)/}"; k="${k//\*/}"
    echo "$k"
}

fail=0
plan=$(mktemp); trap 'rm -f "$plan"' EXIT

# Pass 1: validate everything and build the plan. No writes.
for rel in "${LEDGERS[@]}"; do
    ledger="$ROOT/$rel"; dir="${ledger%.tsv}.d"
    [ -f "$ledger" ] || { echo "FAIL: $rel not found under $ROOT" >&2; exit 1; }
    keys=$(grep -vE '^[[:space:]]*(#|$)' "$ledger" | cut -f1 || true)
    dups=$(sort <<<"$keys" | uniq -d | grep . || true)
    if [ -n "$dups" ]; then
        echo "FAIL: $rel has duplicate key(s) — resolve by hand first:" >&2; sed 's/^/  /' <<<"$dups" >&2; fail=1
    fi
    names=$(while IFS= read -r k; do if [ -n "$k" ]; then fragment_name "$k"; fi; done <<<"$keys")
    ndups=$(sort <<<"$names" | uniq -d | grep . || true)
    if [ -n "$ndups" ]; then
        echo "FAIL: $rel: distinct keys collide on fragment name(s):" >&2; sed 's/^/  /' <<<"$ndups" >&2; fail=1
    fi
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        case "$line" in \#*) continue ;; esac
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        key="${line%%$'\t'*}"
        frag="$dir/$(fragment_name "$key").tsv"
        if [ -e "$frag" ] && [ "$(cat "$frag")" != "$line" ]; then
            echo "FAIL: $frag already exists with different content than $rel's row for '$key'" >&2; fail=1
        fi
        printf '%s\t%s\n' "$rel" "$frag" >> "$plan"
    done < <(grep -vE '^[[:space:]]*(#|$)' "$ledger" || true)
done
[ "$fail" -eq 0 ] || { echo "nothing written" >&2; exit 1; }

if [ ! -s "$plan" ]; then
    echo "ok: nothing to migrate (every ledger already holds header lines only)"
    exit 0
fi

if $DRY; then
    echo "dry run — would move $(wc -l < "$plan" | tr -d ' ') row(s):"
    cut -f1 "$plan" | uniq -c
    exit 0
fi

# Pass 2: write fragments, then rewrite each legacy file to its non-row lines.
for rel in "${LEDGERS[@]}"; do
    ledger="$ROOT/$rel"; dir="${ledger%.tsv}.d"
    moved=0
    while IFS= read -r line; do
        key="${line%%$'\t'*}"
        mkdir -p "$dir"
        printf '%s\n' "$line" > "$dir/$(fragment_name "$key").tsv"
        moved=$((moved + 1))
    done < <(grep -vE '^[[:space:]]*(#|$)' "$ledger" || true)
    tmp=$(mktemp)
    grep -E '^[[:space:]]*(#|$)' "$ledger" > "$tmp" || true
    cat "$tmp" > "$ledger"; rm -f "$tmp"
    echo "migrated $moved row(s): $rel -> ${rel%.tsv}.d/"
done
