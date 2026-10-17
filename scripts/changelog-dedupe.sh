#!/usr/bin/env bash
# changelog-dedupe.sh -- find changelog.d/ fragments whose bullets a side-branch
# release already published.
#
# Why: a patch release (v0.96.1) is cut from a release branch, so its CHANGELOG
# section exists only on that tag, while the same fixes still sit as fragments on
# main. Assembling main for the next minor then prints them a second time
# (RELEASE-PREP-1 found 21 such bullets for v0.97.0). Run this BEFORE
# scripts/changelog-assemble.sh in the release commit.
#
#   scripts/changelog-dedupe.sh <previous-tag> [<previous-tag> ...]
#       List fragments whose every bullet already appears in that tag's
#       "## <tag> -- <date>" CHANGELOG section ("duplicate"), and fragments with
#       only some of them ("partial": edit by hand). Changes nothing.
#
#   scripts/changelog-dedupe.sh --delete <previous-tag> [...]
#       Same, then git rm the duplicate fragments. Partial ones are never touched.
#
# A bullet is matched on its first 60 characters. Fragments with no bullet line
# are ignored. Exit 0 always, unless a tag or its section cannot be found.
set -euo pipefail

cd "$(dirname "$0")/.."

delete=0
if [ "${1:-}" = "--delete" ]; then
  delete=1
  shift
fi
[ "$#" -ge 1 ] || { echo "usage: $0 [--delete] <previous-tag> [...]" >&2; exit 2; }

published="$(mktemp)"
trap 'rm -f "$published"' EXIT

for tag in "$@"; do
  git rev-parse -q --verify "refs/tags/$tag" >/dev/null || { echo "changelog-dedupe: no such tag: $tag" >&2; exit 1; }
  section="$(git show "$tag:CHANGELOG.md" | awk -v tag="$tag" '
    /^## / { inside = (index($0, "## " tag " ") == 1) ; next }
    inside { print }')"
  [ -n "$section" ] || { echo "changelog-dedupe: $tag has no CHANGELOG section" >&2; exit 1; }
  printf '%s\n' "$section" | grep -E '^- ' | cut -c1-60 >>"$published" || true
done

dups=()
for f in changelog.d/*.md; do
  [ "$(basename "$f")" = "README.md" ] && continue
  total=0
  hits=0
  while IFS= read -r line; do
    total=$((total + 1))
    if grep -qxF -- "$(printf '%s' "$line" | cut -c1-60)" "$published"; then hits=$((hits + 1)); fi
  done < <(grep -E '^- ' "$f" || true)
  [ "$total" -gt 0 ] || continue
  if [ "$hits" -eq "$total" ]; then
    echo "duplicate  $f"
    dups+=("$f")
  elif [ "$hits" -gt 0 ]; then
    echo "partial    $f ($hits of $total bullets already published)"
  fi
done

if [ "$delete" -eq 1 ] && [ "${#dups[@]}" -gt 0 ]; then
  git rm -q -- "${dups[@]}"
  echo "removed ${#dups[@]} duplicate fragment(s)"
fi
