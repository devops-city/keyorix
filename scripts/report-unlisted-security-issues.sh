#!/bin/bash
# report-unlisted-security-issues.sh — lists closed GitHub issues carrying the
# `security` label that docs/security-closures.tsv does not cite by number in
# its `issue` column, so an omitted closure at least becomes VISIBLE instead
# of silently indistinguishable from a defect that never existed.
#
# THIS IS A REPORT, NOT A GATE. It never fails the build (see the bottom of
# this file) and it must not be mistaken for a completeness check. Two
# empirically-confirmed reasons:
#
#   1. The `security` label is under-applied in this repo, badly enough that
#      it would have missed the exact closures that motivated this script.
#      Checked 2026-09-08: #1646 and #1780 (the SoD cross-replica races this
#      ledger's pg-gated rows now cite) carry ZERO labels, and neither does
#      #1551 or #1572 -- two closures that were ALREADY correctly cited in
#      this ledger before this script existed. A detector keyed on this label
#      alone would not have caught the case it exists to catch.
#   2. GitHub's own structural "closed by PR" linkage isn't a reliable
#      fallback either: #1780 was closed via a PR body's "Closes #1780" (so it
#      has a real, structural closer), but #1646 was closed by hand despite
#      two PRs cross-referencing it (closer: null) -- the same issue, same
#      severity, same ledger, one traceable this way and one not.
#
# So an issue missing from this script's output is not proof nothing is
# owed -- it is proof only that this ONE weak signal didn't flag it. A `-` in
# the ledger's own `issue` column carries the identical caveat. Treat both as
# a floor, never a ceiling. There is no known reliable derivation source for
# "is this closed issue a security closure" in this repo today; shipping a
# hand-maintained list of issue numbers here would rot exactly the way the
# ledger itself did, so this queries live GitHub state instead of hardcoding
# one -- its only weakness is input-label completeness, not staleness.
#
# Usage: ./scripts/report-unlisted-security-issues.sh
#   Requires: gh CLI, authenticated (GH_TOKEN/GITHUB_TOKEN), issues:read.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="${GH_REPO:-keyorixhq/keyorix}"
# docs/security-closures.tsv is no longer committed: build the flat ledger from
# docs/security-closures.d/ unless the caller supplies one.
if [ -n "${CLOSURE_LEDGER:-}" ]; then
    LEDGER="$CLOSURE_LEDGER"
else
    LEDGER="$(mktemp)"
    trap 'rm -f "$LEDGER"' EXIT
    "$REPO_ROOT/scripts/gen-security-closures-tsv.sh" --stdout > "$LEDGER"
fi

if [ ! -f "$LEDGER" ]; then
    echo "FAIL: closure ledger not found at $LEDGER" >&2; exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
    echo "SKIP: gh CLI not available -- cannot query GitHub, nothing reported this run." >&2
    exit 0
fi

issues_json=$(gh issue list --repo "$REPO" --label security --state closed --limit 500 \
    --json number,title,url 2>&1) || {
    echo "SKIP: could not query closed security-labeled issues (network/auth?) -- nothing" >&2
    echo "      reported this run. Not treated as a failure: this script is informational." >&2
    echo "$issues_json" >&2
    exit 0
}

total=$(jq 'length' <<<"$issues_json")
echo "==> $total closed issue(s) carry the 'security' label (denominator for this sweep only --"
echo "    see this script's own header for why it is not the true denominator of closures)"

if [ "$total" -eq 0 ]; then
    echo "ok: nothing to cross-reference this run."
    exit 0
fi

cited=0
uncited=0
uncited_list=""
for i in $(seq 0 $((total - 1))); do
    number=$(jq -r ".[$i].number" <<<"$issues_json")
    title=$(jq -r ".[$i].title" <<<"$issues_json")
    url=$(jq -r ".[$i].url" <<<"$issues_json")
    if awk -F'\t' -v n="$number" '$6==n {found=1} END{exit !found}' "$LEDGER"; then
        cited=$((cited + 1))
    else
        uncited=$((uncited + 1))
        uncited_list="${uncited_list}  #${number}	${title}	${url}\n"
    fi
done

echo "    $cited already cited in $LEDGER by issue number"
echo "    $uncited NOT cited -- candidates for a follow-up ledger row (or a reason each is"
echo "    deliberately absent, matching this ledger's own \"NOT LISTED, deliberately\" section):"
if [ "$uncited" -gt 0 ]; then
    printf '%b' "$uncited_list"
fi

echo
echo "report only -- see header. Exiting 0 regardless of the counts above."
exit 0
