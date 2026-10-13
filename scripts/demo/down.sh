#!/usr/bin/env bash
# scripts/demo/down.sh — stop the one-command Keyorix demo (scripts/demo/up.sh).
#
# By default, stops and removes the container but KEEPS the data volume and
# local state file, so a later up.sh resumes the same seeded demo instantly.
# Pass --wipe to also delete the data volume and state file for a genuinely
# fresh next run.
#
# --wipe refuses to delete the DEFAULT-named data volume (keyorix-demo-data) unless
# --force-default is also given (#3149): on a shared host that name belongs to
# whoever ran up.sh first, and a session once wiped another session's demo by
# running --wipe without its own KEYORIX_DEMO_* overrides. Either way it first
# prints exactly what it is about to remove. down.sh never removes images.
#
# Usage: scripts/demo/down.sh [--wipe [--force-default]]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

CONTAINER_NAME="${KEYORIX_DEMO_CONTAINER:-keyorix-demo}"
VOLUME_NAME="${KEYORIX_DEMO_VOLUME:-keyorix-demo-data}"
STATE_FILE="$REPO_ROOT/.demo-2-state"

DEFAULT_VOLUME="keyorix-demo-data"

WIPE=false
FORCE_DEFAULT=false
for arg in "$@"; do
  case "$arg" in
    --wipe) WIPE=true ;;
    --force-default) FORCE_DEFAULT=true ;;
    *) echo "unknown argument: $arg" >&2; exit 1 ;;
  esac
done
if [ "$FORCE_DEFAULT" = true ] && [ "$WIPE" = false ]; then
  echo "--force-default only makes sense together with --wipe" >&2
  exit 1
fi

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }

if [ "$WIPE" = true ]; then
  echo "down.sh --wipe will remove:"
  echo "  container  $CONTAINER_NAME"
  echo "  volume     $VOLUME_NAME"
  echo "  file       $STATE_FILE"
  echo "  directory  $REPO_ROOT/.demo-2-cli-home"
  echo "(images are never removed)"
  if [ "$VOLUME_NAME" = "$DEFAULT_VOLUME" ] && [ "$FORCE_DEFAULT" = false ]; then
    echo >&2
    echo "down.sh: refusing to wipe the default-named volume $DEFAULT_VOLUME: on a shared host it may be another session's demo." >&2
    echo "         Nothing was removed. If it is yours, re-run with --force-default; otherwise point at your own demo, e.g." >&2
    echo "         KEYORIX_DEMO_CONTAINER=keyorix-demo-mine KEYORIX_DEMO_VOLUME=keyorix-demo-mine-data scripts/demo/down.sh --wipe" >&2
    exit 2
  fi
fi

if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  docker rm -f "$CONTAINER_NAME" >/dev/null
  echo "Stopped and removed container $CONTAINER_NAME"
else
  echo "Container $CONTAINER_NAME is not present"
fi

if [ "$WIPE" = true ]; then
  docker volume rm "$VOLUME_NAME" >/dev/null 2>&1 || true
  rm -f "$STATE_FILE"
  rm -rf "$REPO_ROOT/.demo-2-cli-home"
  echo "Wiped data volume $VOLUME_NAME and local state"
else
  echo "Data volume $VOLUME_NAME kept — scripts/demo/up.sh will resume this demo. Pass --wipe to delete it."
fi
