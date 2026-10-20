#!/usr/bin/env bash
# scripts/demo/native-down.sh [--wipe] — stop the server started by native-up.sh.
# --wipe also deletes .demo-native/ (config, keys, SQLite file, state, logs).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORK="${KEYORIX_DEMO_DIR:-$REPO_ROOT/.demo-native}"
if [ -f "$WORK/server.pid" ]; then
  pid="$(cat "$WORK/server.pid")"
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    echo "stopped server pid $pid"
  fi
  rm -f "$WORK/server.pid"
fi
if [ "${1:-}" = "--wipe" ]; then
  rm -rf "$WORK"
  echo "wiped $WORK"
fi
