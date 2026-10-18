#!/usr/bin/env bash
# refresh-src.sh — fetch+checkout origin/main before every scan run, rebuild
# the stack if the target commit changed, and print the scanned 12-char
# short SHA on stdout (everything else goes to stderr so callers can safely
# capture just the SHA via `SCAN_SHA=$(refresh-src.sh)`).
#
# Always checks out a detached HEAD at the target commit — never a named
# local branch — so there is never a "parked branch" left behind the way
# fix/pre-1642-upgrade-crash was (checked out 2026-09-11, PR #1850 merged
# 2026-09-12, never advanced again: 112 commits stale by 2026-09-21).
#
# Staleness guard: refuses to scan (DAST-ALERT, exit 1) if the checkout has
# not successfully synced with origin/main in over 24h. Set PIN_REF to an
# explicit ref/SHA to intentionally scan something other than current main
# (e.g. reproducing a historical finding) — this bypasses both the sync and
# the guard, and is logged plainly so it's never mistaken for the default.
set -euo pipefail
WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$WORKDIR/src"
SYNC_MARKER="$WORKDIR/.last-sync"
BUILT_MARKER="$WORKDIR/.last-built-sha"

if [ -f "$WORKDIR/.env" ]; then
    # shellcheck source=/dev/null
    set -a; . "$WORKDIR/.env"; set +a
fi
# shellcheck source=/dev/null
. "$WORKDIR/lib-alert.sh"
# shellcheck source=/dev/null
. "$WORKDIR/lib-http.sh"

cd "$SRC_DIR"

if ! fetch_out=$(git fetch origin main --quiet 2>&1); then
    dast_alert "git fetch origin main failed in $SRC_DIR: $fetch_out" >&2
    exit 1
fi
REMOTE_SHA=$(git rev-parse origin/main)
NOW=$(date -u +%s)

if [ -n "${PIN_REF:-}" ]; then
    TARGET_SHA=$(git rev-parse "$PIN_REF")
    echo "[$(date -u +%FT%TZ)] PIN_REF=$PIN_REF override — scanning $TARGET_SHA (origin/main is $REMOTE_SHA)" >&2
else
    TARGET_SHA="$REMOTE_SHA"
    CURRENT_HEAD=$(git rev-parse HEAD 2>/dev/null || echo "")
    if [ "$CURRENT_HEAD" != "$REMOTE_SHA" ]; then
        LAST_SYNC=0
        [ -f "$SYNC_MARKER" ] && LAST_SYNC=$(cat "$SYNC_MARKER")
        AGE=$(( NOW - LAST_SYNC ))
        if [ "$AGE" -gt 86400 ]; then
            LAST_SYNC_STR="never"
            [ "$LAST_SYNC" -gt 0 ] && LAST_SYNC_STR=$(date -u -d "@$LAST_SYNC" +%FT%TZ 2>/dev/null || echo "@$LAST_SYNC")
            dast_alert "src has not synced with origin/main in $((AGE/3600))h (last synced $LAST_SYNC_STR) — refusing to scan. Set PIN_REF to override." >&2
            exit 1
        fi
    fi
fi

git checkout --detach --quiet "$TARGET_SHA"
# Mark as synced whenever we actually land on origin/main's current tip —
# including a PIN_REF that happens to resolve to it (e.g. bootstrapping the
# marker with PIN_REF=origin/main on the very first run, before any marker
# exists). A PIN_REF pointing anywhere else is a deliberate off-main scan
# and must NOT refresh the marker, or the next unpinned run would wrongly
# see itself as in-sync.
if [ "$TARGET_SHA" = "$REMOTE_SHA" ]; then
    echo "$NOW" > "$SYNC_MARKER"
fi

SHORT_SHA=$(git rev-parse --short=12 HEAD)

# Rebuild only when the target commit actually changed since the last build —
# every run re-syncs and re-verifies, but a quiet day on main doesn't pay for
# a full Go+pnpm rebuild it doesn't need.
LAST_BUILT=""
[ -f "$BUILT_MARKER" ] && LAST_BUILT=$(cat "$BUILT_MARKER")
if [ "$LAST_BUILT" != "$TARGET_SHA" ]; then
    echo "[$(date -u +%FT%TZ)] rebuilding keyorix stack at $SHORT_SHA (was ${LAST_BUILT:-none})" >&2
    "$WORKDIR/build-web-dist.sh" >&2
    ( cd "$WORKDIR" && docker compose build keyorix >&2 && docker compose up -d >&2 )
    echo "$TARGET_SHA" > "$BUILT_MARKER"
    for _ in $(seq 1 30); do
        curl -sf http://localhost:8080/openapi.yaml >/dev/null 2>&1 && break
        sleep 2
    done
    if ! curl -sf http://localhost:8080/openapi.yaml >/dev/null 2>&1; then
        dast_alert "keyorix stack did not become ready within 60s after rebuild to $SHORT_SHA" >&2
        exit 1
    fi
else
    echo "[$(date -u +%FT%TZ)] already running $SHORT_SHA, no rebuild needed" >&2
fi

# Post-bootstrap assertion: the admin account is created via an explicit
# POST /system/init call, NOT automatically just because these env vars are
# set in docker-compose.yml -- and the password Keyorix's own policy accepts
# is stricter than what a naive `openssl rand -hex` generator produces (needs
# uppercase+special; hex is lowercase+digit only). Both of those failed
# silently on this exact box for 10+ days: bootstrap never succeeded, the
# `users` table stayed empty, admin login was permanently 401, and nothing
# said so anywhere. Every run now calls /system/init (idempotent -- a no-op
# once already initialized) and proves the admin account actually works by
# logging in with it. If that login fails, bootstrap is broken -- loudly,
# every run, not silently for over a week.
if [ -n "${KEYORIX_ADMIN_USERNAME:-}" ] && [ -n "${KEYORIX_ADMIN_PASSWORD:-}" ]; then
    # The bootstrap token and the admin password stay off argv: the token goes in a 0600
    # header file, the JSON bodies on stdin (lib-http.sh).
    bootstrap_hdr="$(mktemp)"
    printf 'X-Keyorix-Bootstrap-Token: %s\n' "${KEYORIX_BOOTSTRAP_TOKEN:-}" >"$bootstrap_hdr"
    init_resp=$(dast_post_json http://localhost:8080/system/init \
        "{\"username\":\"$KEYORIX_ADMIN_USERNAME\",\"email\":\"${KEYORIX_ADMIN_EMAIL:-}\",\"password\":\"$KEYORIX_ADMIN_PASSWORD\",\"display_name\":\"DAST Admin\"}" \
        -s -o /dev/null -w '%{http_code}' -H "@$bootstrap_hdr" \
        2>/dev/null || echo "000")
    rm -f "$bootstrap_hdr"

    login_code=$(dast_post_json http://localhost:8080/auth/login \
        "{\"username\":\"$KEYORIX_ADMIN_USERNAME\",\"password\":\"$KEYORIX_ADMIN_PASSWORD\"}" \
        -s -o /dev/null -w '%{http_code}' \
        2>/dev/null || echo "000")

    if [ "$login_code" != "200" ]; then
        dast_alert "post-bootstrap check failed: admin login returned $login_code after /system/init (status $init_resp) -- bootstrap is broken, the stored KEYORIX_ADMIN_PASSWORD may not satisfy Keyorix's password policy, or the users table is empty. See lib-passwords.sh for a policy-compliant generator." >&2
        exit 1
    fi
    echo "[$(date -u +%FT%TZ)] post-bootstrap check: admin login OK (init status $init_resp)" >&2
else
    echo "[$(date -u +%FT%TZ)] post-bootstrap check skipped: KEYORIX_ADMIN_USERNAME/PASSWORD not set in .env" >&2
fi

echo "$SHORT_SHA"
