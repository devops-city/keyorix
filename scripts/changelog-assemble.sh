#!/usr/bin/env bash
# changelog-assemble.sh -- merge changelog.d/*.md fragments into CHANGELOG.md.
#
# Why: every PR used to edit "## Unreleased" in CHANGELOG.md, so each merge
# conflicted with every other open PR. Now each PR adds ONE file to
# changelog.d/ (see changelog.d/README.md) and the maintainer assembles them
# when cutting a release (RELEASING.md).
#
#   scripts/changelog-assemble.sh --check
#       Validate every fragment (non-empty, known `### <Section>` headings,
#       no stray `## ` heading, every section has content). Changes nothing.
#       Exit 1 on the first class of problem, listing every offender.
#
#   scripts/changelog-assemble.sh --notice
#       Non-failing: with origin/$GITHUB_BASE_REF (default main) available,
#       warn if HEAD differs from it in CHANGELOG.md (in CI, HEAD is the PR
#       merge commit). Always exits 0.
#
#   scripts/changelog-assemble.sh <version> [YYYY-MM-DD]
#       Validate, then write a "## <version> — <date>" section into
#       CHANGELOG.md (fragments grouped by section in the fixed order below,
#       fragments within a section in file-name order), then delete the
#       fragments. <version> may be given with or without the leading "v".
#       The heading format matches the existing release headings, which
#       deploy/compose_pins_test.go parses ("## vX.Y.Z").
#       If CHANGELOG.md still has a legacy "## Unreleased" section, its body
#       is kept (after the fragment sections) under the new heading and the
#       "## Unreleased" heading is replaced; otherwise the section is inserted
#       above the newest existing release heading.
#
# Environment: CHANGELOG_FILE / CHANGELOG_DIR override the paths (self-test).
set -euo pipefail

cd "$(dirname "$0")/.."

CHANGELOG_FILE="${CHANGELOG_FILE:-CHANGELOG.md}"
CHANGELOG_DIR="${CHANGELOG_DIR:-changelog.d}"

# Stable section order for the assembled output; also the allowed set.
SECTIONS=(Security Added Changed Deprecated Removed Fixed Documentation Testing Internal)

die() { echo "changelog-assemble: $*" >&2; exit 1; }

fragments() {
  local f
  for f in "$CHANGELOG_DIR"/*.md; do
    [ -e "$f" ] || continue
    [ "$(basename "$f")" = "README.md" ] && continue
    echo "$f"
  done
}

validate() {
  local bad=0 f
  for f in $(fragments); do
    local out
    out="$(awk -v sections="${SECTIONS[*]}" '
      BEGIN { n = split(sections, a, " "); for (i = 1; i <= n; i++) known[a[i]] = 1 }
      function close_section() {
        if (cur != "" && !hasbody) printf "section \"%s\" is empty\n", cur
      }
      /^##[^#]/ || /^# / { printf "line %d: heading level 1/2 not allowed in a fragment: %s\n", NR, $0; next }
      /^### / {
        close_section()
        name = substr($0, 5); sub(/[ \t]+$/, "", name)
        if (!(name in known)) printf "line %d: unknown section \"%s\"\n", NR, name
        cur = name; hasbody = 0; seen++; next
      }
      NF { if (cur == "") { if (!pre++) printf "line %d: text before the first \"### <Section>\" heading\n", NR } else hasbody = 1 }
      END {
        close_section()
        if (!seen) print "no \"### <Section>\" heading found (empty or malformed fragment)"
      }' "$f")"
    if [ -n "$out" ]; then
      bad=1
      while IFS= read -r line; do echo "$f: $line" >&2; done <<<"$out"
    fi
  done
  return $bad
}

notice() {
  local base="${GITHUB_BASE_REF:-main}"
  git rev-parse --verify -q "origin/$base" >/dev/null 2>&1 || { echo "notice: origin/$base not available, skipping"; return 0; }
  if ! git diff --quiet "origin/$base" HEAD -- "$CHANGELOG_FILE" 2>/dev/null; then
    echo "::warning file=$CHANGELOG_FILE::This PR edits $CHANGELOG_FILE directly. Add a changelog.d/ fragment instead (see changelog.d/README.md); direct edits will become a hard failure once the open PRs have drained."
  else
    echo "ok: $CHANGELOG_FILE not edited directly"
  fi
}

assemble() {
  local version="$1" date="${2:-$(date +%Y-%m-%d)}"
  version="v${version#v}"
  [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$ ]] || die "bad version: $version"
  [[ "$date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "bad date: $date (want YYYY-MM-DD)"
  grep -q "^## $version " "$CHANGELOG_FILE" && die "$CHANGELOG_FILE already has a $version heading"

  # shellcheck disable=SC2207
  local files=($(fragments))
  [ "${#files[@]}" -gt 0 ] || die "no fragments in $CHANGELOG_DIR/ -- nothing to assemble"
  validate || die "invalid fragments (see above); nothing changed"

  local body tmp
  tmp="$(mktemp)"
  body="$(mktemp)"
  # Group: for each section in fixed order, every fragment's chunk for it.
  awk -v sections="${SECTIONS[*]}" '
    function flush() {
      if (cur == "") return
      while (n > 0 && chunk[n] ~ /^[ \t]*$/) n--
      for (i = 1; i <= n; i++) out[cur] = out[cur] chunk[i] "\n"
      n = 0
    }
    FNR == 1 { flush(); cur = ""; skipping = 1 }
    /^### / { flush(); cur = substr($0, 5); sub(/[ \t]+$/, "", cur); skipping = 1; next }
    cur == "" { next }
    skipping && /^[ \t]*$/ { next }
    { skipping = 0; chunk[++n] = $0 }
    END {
      flush()
      m = split(sections, order, " ")
      for (k = 1; k <= m; k++) if (out[order[k]] != "") printf "### %s\n%s\n", order[k], out[order[k]]
    }' "${files[@]}" >"$body"

  awk -v heading="## $version — $date" -v bodyfile="$body" '
    function emit(   line) {
      print heading; print ""
      while ((getline line < bodyfile) > 0) print line
      close(bodyfile)
    }
    done { print; next }
    /^## Unreleased[ \t]*$/ { emit(); done = 1; legacy = 1; next }
    /^## v[0-9]/ { emit(); done = 1 }
    { print }
    END { if (!done) emit() }' "$CHANGELOG_FILE" >"$tmp"

  mv "$tmp" "$CHANGELOG_FILE"
  rm -f "$body"
  rm -f "${files[@]}"
  echo "assembled ${#files[@]} fragment(s) into $CHANGELOG_FILE under \"## $version — $date\" and removed them"
}

case "${1:-}" in
  --check)
    validate || die "fragment validation failed"
    echo "ok: $(fragments | wc -l | tr -d ' ') changelog fragment(s) valid"
    ;;
  --notice) notice ;;
  -h|--help|"") sed -n '2,29p' "$0" ;;
  -*) die "unknown flag $1" ;;
  *) assemble "$@" ;;
esac
