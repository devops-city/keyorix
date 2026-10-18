#!/usr/bin/env bash
# complexity-diff.sh: two refs side by side with deltas, and every new
# user-facing item by name.
#
#   scripts/metrics/complexity-diff.sh [--surface-only | --groups LIST] [--image]
#                                      [--fail-on-growth] A B
#
# A and B are git refs (tags, branches, SHAs). Each is measured with
# complexity.sh (see its header for what every metric means), then printed as
# `metric  A  B  delta`. After the table, the USER-FACING SURFACE section lists by
# name what B adds to and removes from A:
#   config keys (and which of the new ones have no default), environment
#   variables, CLI commands and flags, `keyorix-server admin` commands and flags,
#   HTTP API operations, gRPC methods, and user-facing doc pages.
# A release review reads that section to see exactly what was added.
#
#   --surface-only     measure only the SURFACE group (about a minute per ref, no
#                      cross-builds, no startup run)
#   --groups LIST      pass a group list through to complexity.sh
#   --image            include the container image build in both runs
#   --fail-on-growth   exit 1 when B adds any config key, environment variable,
#                      CLI command/flag, admin command/flag, API operation or
#                      gRPC method (for a CI gate; the default always exits 0)
#
# Exit codes: 0 ok, 1 growth found with --fail-on-growth, 2 usage or measurement error.
set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GROUPS_ARG=()
IMAGE_ARG=()
FAIL_ON_GROWTH=0
REFS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --surface-only) GROUPS_ARG=(--groups surface) ;;
    --groups) GROUPS_ARG=(--groups "${2:?--groups needs a list}"); shift ;;
    --image) IMAGE_ARG=(--image) ;;
    --fail-on-growth) FAIL_ON_GROWTH=1 ;;
    -h|--help) sed -n '2,/^set -e/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "complexity-diff.sh: unknown option $1 (try --help)" >&2; exit 2 ;;
    *) REFS+=("$1") ;;
  esac
  shift
done
if [ "${#REFS[@]}" -ne 2 ]; then
  echo "usage: complexity-diff.sh [--surface-only] [--fail-on-growth] A B" >&2
  exit 2
fi
A="${REFS[0]}"; B="${REFS[1]}"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/complexity-diff.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/a" "$TMP/b"

measure() { # REF OUTDIR
  echo "[metrics-diff] measuring $1" >&2
  "$SCRIPT_DIR/complexity.sh" ${GROUPS_ARG[@]+"${GROUPS_ARG[@]}"} ${IMAGE_ARG[@]+"${IMAGE_ARG[@]}"} --surface-out "$2/lists" "$1" > "$2/table.txt" \
    || { echo "complexity-diff.sh: measuring '$1' failed (see the messages above)" >&2; exit 2; }
}
measure "$A" "$TMP/a"
measure "$B" "$TMP/b"

# ---- table ------------------------------------------------------------------
LABEL_A="$(sed -n '1s/^# Keyorix complexity at \([^ ]*\) .*/\1/p' "$TMP/a/table.txt")"
LABEL_B="$(sed -n '1s/^# Keyorix complexity at \([^ ]*\) .*/\1/p' "$TMP/b/table.txt")"
grep -v '^#' "$TMP/a/table.txt" | awk '{print $1 "\t" $2}' > "$TMP/a/rows"
grep -v '^#' "$TMP/b/table.txt" | awk '{print $1 "\t" $2}' > "$TMP/b/rows"

echo "# Keyorix complexity: $LABEL_A -> $LABEL_B"
awk -F'\t' -v la="$LABEL_A" -v lb="$LABEL_B" '
  function isnum(s) { return s ~ /^[0-9]+$/ }
  NR == FNR { a[$1] = $2; order[++n] = $1; next }
  { b[$1] = $2 }
  END {
    printf "%-32s %14s %14s %12s %8s\n", "metric", la, lb, "delta", "%"
    for (i = 1; i <= n; i++) {
      k = order[i]; va = a[k]; vb = (k in b) ? b[k] : "n/a"
      if (isnum(va) && isnum(vb)) {
        d = vb - va; pct = (va > 0) ? sprintf("%+.1f", d * 100 / va) : "-"
        printf "%-32s %14s %14s %+12d %8s\n", k, va, vb, d, pct
      } else printf "%-32s %14s %14s %12s %8s\n", k, va, vb, "-", "-"
    }
  }' "$TMP/a/rows" "$TMP/b/rows"

# ---- named surface ------------------------------------------------------------
GROWTH=0
echo
echo "# USER-FACING SURFACE: what $LABEL_B adds to and removes from $LABEL_A"

section() { # NAME FILE-STEM HEADLINE
  local fa="$TMP/a/lists/$2.txt" fb="$TMP/b/lists/$2.txt"
  [ -f "$fa" ] && [ -f "$fb" ] || return 0
  comm -13 "$fa" "$fb" > "$TMP/added.txt"
  comm -23 "$fa" "$fb" > "$TMP/removed.txt"
  local na nr
  na=$(wc -l < "$TMP/added.txt" | tr -d ' '); nr=$(wc -l < "$TMP/removed.txt" | tr -d ' ')
  if [ "$na" = 0 ] && [ "$nr" = 0 ]; then
    echo "  $3: no change"
    return 0
  fi
  echo "  $3: +$na -$nr"
  sed 's/^/    + /' "$TMP/added.txt"
  sed 's/^/    - /' "$TMP/removed.txt"
  case "$1" in
    growth) GROWTH=$((GROWTH + na)) ;;
  esac
}

section growth config_keys "config keys"
if [ -f "$TMP/a/lists/config_keys_no_default.txt" ] && [ -f "$TMP/b/lists/config_keys_no_default.txt" ]; then
  # New keys with no default are the heavier burden: name them again.
  comm -13 "$TMP/a/lists/config_keys.txt" "$TMP/b/lists/config_keys.txt" > "$TMP/newkeys.txt"
  comm -12 "$TMP/newkeys.txt" "$TMP/b/lists/config_keys_no_default.txt" > "$TMP/newkeys_nodefault.txt"
  if [ -s "$TMP/newkeys_nodefault.txt" ]; then
    echo "    new config keys WITHOUT a default: $(wc -l < "$TMP/newkeys_nodefault.txt" | tr -d ' ')"
    sed 's/^/      ! /' "$TMP/newkeys_nodefault.txt"
  fi
fi
section growth env_vars "environment variables"
section growth cli_commands "CLI commands"
section growth cli_flags "CLI flags"
section growth admin_commands "admin commands"
section growth admin_flags "admin flags"
section growth api_operations "API operations"
section growth grpc_methods "gRPC methods"
section info doc_pages "user-facing doc pages"

echo
if [ "$GROWTH" -gt 0 ]; then
  echo "GROWTH: $GROWTH new user-facing item(s) between $LABEL_A and $LABEL_B (listed above)"
else
  echo "GROWTH: none (no new config key, env var, CLI command/flag, admin command/flag, API operation or gRPC method)"
fi
if [ "$FAIL_ON_GROWTH" = 1 ] && [ "$GROWTH" -gt 0 ]; then exit 1; fi
exit 0
