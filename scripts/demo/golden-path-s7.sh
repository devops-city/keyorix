#!/usr/bin/env bash
# scripts/demo/golden-path-s7.sh -- execute docs/demo/GOLDEN-PATH.md section 7
# (backup and restore) exactly as written, against the demo scripts/demo/up.sh
# brought up. The commands are EXTRACTED from the document, not copied here, so
# the doc cannot drift from what works (#3145: every `docker run -w /app/data
# <image> <cmd>` failed with `exec: "./entrypoint.sh": no such file` because the
# image's ENTRYPOINT was relative to WORKDIR, and nothing ran the section).
#
# Usage: scripts/demo/golden-path-s7.sh
# Needs the demo up (container keyorix-demo, volume keyorix-demo-data, image
# keyorix-demo:airgap: the names GOLDEN-PATH.md uses). It stops the container,
# backs up, moves keyorix.db aside, restores, starts the container again, and
# requires the restore to report `verify-audit on the restored database: VALID`.
# Lines that need the host CLI (`./bin/keyorix ...`) are not run: they are
# API-level and covered by check.sh's own steps.
# Exit 0 = section 7 works as written; non-zero = it does not (output printed).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

DOC="docs/demo/GOLDEN-PATH.md"
# The names GOLDEN-PATH.md uses; the same KEYORIX_DEMO_* overrides as up.sh map
# them onto a demo brought up under other names (the doc's names are substituted
# in the extracted commands).
DOC_CONTAINER="keyorix-demo"
DOC_VOLUME="keyorix-demo-data"
DOC_IMAGE="keyorix-demo:airgap"
CONTAINER="${KEYORIX_DEMO_CONTAINER:-$DOC_CONTAINER}"
VOLUME="${KEYORIX_DEMO_VOLUME:-$DOC_VOLUME}"
IMAGE="${KEYORIX_DEMO_IMAGE:-$DOC_IMAGE}"

fail() { echo "golden-path-s7: $*" >&2; exit 1; }

docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER" \
  || fail "container $CONTAINER not found; run scripts/demo/up.sh first (names must match $DOC)"
[ -f .demo-2-cli-home/demo-secrets.env ] \
  || fail ".demo-2-cli-home/demo-secrets.env missing; run scripts/demo/up.sh first"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Fenced code blocks of "## 7." up to the next "## " heading.
awk '
  /^## 7\./ { in7 = 1; next }
  in7 && /^## / { exit }
  in7 && /^```/ { fence = !fence; next }
  in7 && fence { print }
' "$DOC" > "$WORK/s7.raw"

# Not vacuous: the section must still contain the commands this guards.
for want in "admin backup" "admin restore" "mv keyorix.db"; do
  grep -q -- "$want" "$WORK/s7.raw" || fail "$DOC section 7 no longer contains '$want'; update this guard with the doc"
done

# Host-CLI lines (and their continuations, none today) are API-level: skipped.
# The ERR trap names the failing command (BASH_COMMAND is the unexpanded text,
# so the demo passphrase variable is never printed; no `set -x`).
{
  echo "trap 'echo \"golden-path-s7: FAILED (line \$LINENO): \$BASH_COMMAND\" >&2' ERR"
  grep -v '^\./bin/keyorix' "$WORK/s7.raw"
} \
  | sed -e "s#$DOC_IMAGE#$IMAGE#g" -e "s#$DOC_VOLUME#$VOLUME#g" \
        -e "s#docker \(stop\|start\) $DOC_CONTAINER#docker \1 $CONTAINER#" > "$WORK/s7.sh"

# A previous run of this guard leaves backup.tar.gz in the volume, and
# `admin backup --output` refuses an existing path. Remove only that artifact so
# the guard can be re-run on the same demo; the doc's commands stay untouched.
docker run --rm --entrypoint /bin/sh -v "$VOLUME:/app/data" "$IMAGE" \
  -c 'rm -f /app/data/backup.tar.gz' > /dev/null

echo "==> running $DOC section 7 verbatim ($(grep -c . "$WORK/s7.sh") lines)"
rc=0
bash -e "$WORK/s7.sh" > "$WORK/out.txt" 2>&1 || rc=$?
cat "$WORK/out.txt"

# Whatever happened, leave the demo running.
docker start "$CONTAINER" > /dev/null 2>&1 || true

[ "$rc" -eq 0 ] || fail "section 7 command failed (exit $rc)"
grep -q 'verify-audit on the restored database: VALID' "$WORK/out.txt" \
  || fail "restore did not report 'verify-audit on the restored database: VALID'"

# The moved-aside and the restored database must both exist.
docker run --rm --entrypoint /bin/sh -v "$VOLUME:/app/data" "$IMAGE" \
  -c 'test -s /app/data/keyorix.db && test -s /app/data/keyorix.db.pre-restore' \
  || fail "keyorix.db / keyorix.db.pre-restore missing after restore"

port="$(docker port "$CONTAINER" 8080/tcp | head -1 | sed 's/.*://')"
for _ in $(seq 1 60); do
  if curl -sf --max-time 3 "http://127.0.0.1:${port}/health" > /dev/null; then
    echo "golden-path-s7: OK (section 7 ran as written; restored database VALID; server healthy again)"
    exit 0
  fi
  sleep 1
done
fail "server did not become healthy after the restore"
