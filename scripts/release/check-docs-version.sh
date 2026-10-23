#!/usr/bin/env bash
# check-docs-version.sh TAG: fail if an install doc pins a Keyorix version other than TAG.
#
# Why: the v0.96.3 tag shipped docs that still pointed at v0.96.0 (INSTALL-CLEANROOM-1,
# findings F2/F3). The release checklist says README and QUICK_START at the tag must match
# main for install commands; this script checks the version half of that: every place the
# install docs and compose files PIN a version (an image tag, a release download URL, a
# V=/VERSION= shell variable, a helm --version, a values `tag:`) must equal TAG.
#
# What it checks (the list of recognised pin shapes is PIN_RE below; a version that only
# appears in prose such as "does not exist in v0.95.3" is not a pin and is not checked):
#   README.md QUICK_START.md INSTALL-WITH-AI.md docs/SELF_HOSTING.md docker-compose*.yml
#   deploy/**/docker-compose*.yml (not testdata)
# Intentional exceptions live in scripts/release/docs-version-exceptions.txt, one per line:
#   <path><TAB><fixed text that must appear on the pinning line><TAB><reason>
# Every exception that suppresses a finding is printed (NOTE), and one that matches nothing is
# reported as unused, so the list cannot rot silently. Finding no pin at all is a FAIL: it means
# PIN_RE no longer matches how the docs are written.
#
# Usage: scripts/release/check-docs-version.sh [--root DIR] [--exceptions FILE] TAG
#        scripts/release/check-docs-version.sh --self-test
# Exit: 0 all pins equal TAG | 1 mismatch or no pins found | 3 usage error
# Needs only bash, grep, sort. Read-only.

set -u

SELF=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
EXC=""
VER_RE='[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?'
PIN_RE="ghcr\\.io/keyorixhq/[A-Za-z0-9._/-]+:v?${VER_RE}"
PIN_RE="$PIN_RE|releases/download/v?${VER_RE}"
PIN_RE="$PIN_RE|(^|[^A-Za-z0-9_])(KEYORIX_VERSION|VERSION|V)=[\"']?v?${VER_RE}"
PIN_RE="$PIN_RE|--version[ =]v?${VER_RE}"
PIN_RE="$PIN_RE|(^|[^A-Za-z0-9_])tag:[ ]*[\"']?v?${VER_RE}"

usage() {
  sed -n '2,/^set -u/p' "$SELF" | sed '$d;s/^# \{0,1\}//' >&2
  exit 3
}

# files_of ROOT -> candidate files (relative paths), one per line
files_of() {
  local f
  for f in README.md QUICK_START.md INSTALL-WITH-AI.md docs/SELF_HOSTING.md; do
    [ -f "$1/$f" ] && echo "$f"
  done
  (cd "$1" && ls docker-compose*.yml 2>/dev/null)
  (cd "$1" && find deploy -name 'docker-compose*.yml' -not -path '*/testdata/*' 2>/dev/null | sort)
}

run_check() { # ROOT EXCEPTIONS-FILE TAG -> exit status
  local root=$1 exc=$2 want=${3#v} f line match ver n_pins=0 n_bad=0 n_exc=0 text exc_reason
  local usedfile
  usedfile=$(mktemp)
  USED=$usedfile
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    while IFS= read -r line; do
      n=${line%%:*}
      match=${line#*:}
      # drop a leading separator char the (^|[^A-Za-z0-9_]) group may have captured
      ver=$(printf '%s\n' "$match" | grep -oE "$VER_RE" | head -1)
      ver=${ver%-airgap}
      ver=${ver%.}
      n_pins=$((n_pins + 1))
      [ "$ver" = "$want" ] && continue
      text=$(sed -n "${n}p" "$root/$f")
      if exc_reason=$(exception_for "$exc" "$f" "$text"); then
        n_exc=$((n_exc + 1))
        printf 'NOTE  %s:%s pins %s (not %s): allowed - %s\n' "$f" "$n" "$ver" "$want" "$exc_reason"
        continue
      fi
      n_bad=$((n_bad + 1))
      printf 'FAIL  %s:%s pins %s, release is %s: %s\n' "$f" "$n" "$ver" "$want" "$(printf '%s' "$text" | sed 's/^[[:space:]]*//' | cut -c1-110)"
    done < <(cd "$root" && grep -noE "$PIN_RE" "$f")
  done < <(files_of "$root")
  unused_exceptions "$exc" "$usedfile"
  rm -f "$usedfile"
  if [ "$n_pins" -eq 0 ]; then
    printf 'FAIL  no version pin found in any install doc: PIN_RE in %s no longer matches how the docs are written\n' "$(basename "$SELF")"
    return 1
  fi
  printf 'checked %d version pin(s) against %s: %d mismatch(es), %d allowed by exception\n' "$n_pins" "$want" "$n_bad" "$n_exc"
  [ "$n_bad" -eq 0 ]
}

# exception_for EXC-FILE PATH LINE-TEXT -> prints reason, 0 if allowed
exception_for() {
  local p t r
  [ -f "$1" ] || return 1
  while IFS="$(printf '\t')" read -r p t r; do
    case $p in '' | '#'*) continue ;; esac
    [ "$p" = "$2" ] || continue
    case $3 in *"$t"*)
      printf '%s\t%s\n' "$p" "$t" >>"$USED"
      printf '%s' "${r:-no reason given}"
      return 0
      ;;
    esac
  done <"$1"
  return 1
}

unused_exceptions() { # EXC-FILE USEDFILE
  local p t r
  [ -f "$1" ] || return 0
  while IFS="$(printf '\t')" read -r p t r; do
    case $p in '' | '#'*) continue ;; esac
    grep -qxF "$p	$t" "$2" || printf 'NOTE  unused exception (%s: "%s"): remove it if it no longer applies\n' "$p" "$t"
  done <"$1"
}

# ------------------------------------------------------------------ self-test
OK=0
BAD=0
st_expect() { # NAME WANT-EXIT GOT-EXIT [OUTFILE REGEX]
  if [ "$2" = "$3" ] && { [ -z "${4-}" ] || grep -Eq "$5" "$4"; }; then OK=$((OK + 1)); else
    BAD=$((BAD + 1))
    printf '  SELF-TEST MISMATCH %s: exit %s (want %s), output:\n' "$1" "$3" "$2" >&2
    [ -z "${4-}" ] || sed 's/^/    /' "$4" >&2
  fi
}

st_tree() { # DIR VERSION: a consistent tree pinning VERSION everywhere
  mkdir -p "$1/deploy/x" "$1/docs"
  cat >"$1/docker-compose.yml" <<EOF
services:
  backend:
    image: ghcr.io/keyorixhq/keyorix-server:$2 # pin
  web:
    image: ghcr.io/keyorixhq/keyorix-web:$2
  airgap:
    image: ghcr.io/keyorixhq/keyorix-server:$2-airgap
EOF
  cat >"$1/QUICK_START.md" <<EOF
V=v$2   # the release you want
BASE=https://github.com/keyorixhq/keyorix/releases/download/\$V
This does not exist in v0.1.0 and was added in v0.2.0 (prose, not a pin).
helm install k oci://ghcr.io/keyorixhq/charts/keyorix --version $2
EOF
  printf 'curl -L https://raw.githubusercontent.com/keyorixhq/keyorix/main/install.sh | sh\n' >"$1/README.md"
  printf 'take v0.1.0 or newer\nimage: ghcr.io/keyorixhq/keyorix-web:%s\n' "$2" >"$1/INSTALL-WITH-AI.md"
  printf 'compose pins both images (e.g. :9.9.9, no v)\nghcr.io/keyorixhq/keyorix-web:%s\n' "$2" >"$1/docs/SELF_HOSTING.md"
  printf 'image: ghcr.io/keyorixhq/keyorix-operator:%s\n' "$2" >"$1/deploy/x/docker-compose.yml"
  mkdir -p "$1/deploy/testdata"
  printf 'image: ghcr.io/keyorixhq/keyorix-server:0.0.1\n' >"$1/deploy/testdata/docker-compose.old.yml"
}

self_test() {
  local w t out rc
  w=$(mktemp -d) || { echo "mktemp failed" >&2; exit 3; }
  out="$w/out.txt"
  t="$w/t1"
  st_tree "$t" 1.2.3

  bash "$SELF" --root "$t" --exceptions "$w/none" v1.2.3 >"$out" 2>&1; rc=$?
  st_expect "consistent tree passes (v prefix, -airgap, prose, testdata ignored)" 0 $rc "$out" 'checked 8 version pin'
  bash "$SELF" --root "$t" --exceptions "$w/none" 1.2.3 >"$out" 2>&1; rc=$?
  st_expect "TAG without v accepted" 0 $rc

  # each pin shape, mutated alone, must be caught and must name its file
  local f
  for f in docker-compose.yml QUICK_START.md INSTALL-WITH-AI.md docs/SELF_HOSTING.md deploy/x/docker-compose.yml; do
    rm -rf "$w/m" && cp -R "$t" "$w/m"
    sed 's/1\.2\.3/1.2.2/' "$w/m/$f" >"$w/m/edit" && mv "$w/m/edit" "$w/m/$f"
    bash "$SELF" --root "$w/m" --exceptions "$w/none" v1.2.3 >"$out" 2>&1; rc=$?
    st_expect "stale pin in $f" 1 $rc "$out" "^FAIL  $f:[0-9]+ pins 1\\.2\\.2, release is 1\\.2\\.3"
  done
  rm -rf "$w/m" && cp -R "$t" "$w/m"
  sed 's/^V=v1.2.3/V=v1.2.0/' "$w/m/QUICK_START.md" >"$w/m/edit" && mv "$w/m/edit" "$w/m/QUICK_START.md"
  bash "$SELF" --root "$w/m" --exceptions "$w/none" v1.2.3 >"$out" 2>&1; rc=$?
  st_expect "V= shell variable" 1 $rc "$out" 'QUICK_START.md:1 pins 1\.2\.0'
  sed 's/--version 1.2.3/--version 1.2.0/' "$w/m/QUICK_START.md" >"$w/m/edit" && mv "$w/m/edit" "$w/m/QUICK_START.md"
  bash "$SELF" --root "$w/m" --exceptions "$w/none" v1.2.3 >"$out" 2>&1; rc=$?
  st_expect "helm --version" 1 $rc "$out" 'QUICK_START.md:4 pins 1\.2\.0'
  printf 'curl https://github.com/keyorixhq/keyorix/releases/download/v1.2.0/keyorix\n' >>"$w/m/README.md"
  bash "$SELF" --root "$w/m" --exceptions "$w/none" v1.2.3 >"$out" 2>&1; rc=$?
  st_expect "release download URL" 1 $rc "$out" 'README.md:2 pins 1\.2\.0'

  # exception: allowed only for the named file AND text, printed, and flagged when unused
  printf '# comment\nREADME.md\treleases/download/v1.2.0\tdocumented old-version download\nREADME.md\tno such text\tstale\n' >"$w/exc"
  bash "$SELF" --root "$w/m" --exceptions "$w/exc" v1.2.3 >"$out" 2>&1; rc=$?
  st_expect "exception allows only the matching line (QUICK_START still fails)" 1 $rc "$out" 'NOTE  README.md:2 pins 1\.2\.0 .*allowed - documented old-version download'
  st_expect "unused exception reported" 1 $rc "$out" 'unused exception \(README.md: "no such text"\)'
  printf 'QUICK_START.md\tother text\twrong file text\n' >"$w/exc2"
  bash "$SELF" --root "$w/m" --exceptions "$w/exc2" v1.2.3 >"$out" 2>&1; rc=$?
  st_expect "exception for different text does not suppress" 1 $rc "$out" 'README.md:2 pins 1\.2\.0, release is'
  rm -rf "$w/m" && cp -R "$t" "$w/m"
  printf 'image: ghcr.io/keyorixhq/keyorix-web:1.1.0\n' >>"$w/m/README.md"
  printf 'README.md\tkeyorix-web:1.1.0\told image kept on purpose\n' >"$w/exc3"
  bash "$SELF" --root "$w/m" --exceptions "$w/exc3" v1.2.3 >"$out" 2>&1; rc=$?
  st_expect "fully excepted tree passes" 0 $rc "$out" '1 allowed by exception'

  # vacuous guard: docs with no recognisable pin must not pass
  mkdir -p "$w/empty" && printf 'nothing here\n' >"$w/empty/README.md"
  bash "$SELF" --root "$w/empty" --exceptions "$w/none" v1.2.3 >"$out" 2>&1; rc=$?
  st_expect "no pins found is a FAIL" 1 $rc "$out" 'no version pin found'

  # usage errors
  bash "$SELF" >"$out" 2>&1; rc=$?
  st_expect "no TAG" 3 $rc
  bash "$SELF" --root "$t" notatag >"$out" 2>&1; rc=$?
  st_expect "malformed TAG" 3 $rc

  rm -rf "$w"
  printf 'self-test: %d assertions passed, %d failed\n' "$OK" "$BAD"
  [ "$BAD" -eq 0 ]
  exit $?
}

# ----------------------------------------------------------------------- main
TAG=""
EXC="$ROOT/scripts/release/docs-version-exceptions.txt"
while [ $# -gt 0 ]; do
  case $1 in
    --self-test) self_test ;;
    --root) [ $# -ge 2 ] || usage; ROOT=$2; shift 2 ;;
    --exceptions) [ $# -ge 2 ] || usage; EXC=$2; shift 2 ;;
    -h | --help) usage ;;
    -*) echo "unknown option $1" >&2; usage ;;
    *) TAG=$1; shift ;;
  esac
done
[ -n "$TAG" ] || usage
printf '%s\n' "$TAG" | grep -Eq "^v?${VER_RE}\$" || { echo "TAG must look like v1.2.3 (got '$TAG')" >&2; exit 3; }
printf 'checking install docs under %s for pins other than %s\n' "$ROOT" "${TAG#v}"
run_check "$ROOT" "$EXC" "$TAG"
