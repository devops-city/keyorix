#!/usr/bin/env bash
# provision-testuser.sh — one-time (idempotent) setup of a persistent,
# lowest-privilege ("viewer") account used by scan-zap-auth.sh's
# regular-user authenticated pass. Safe to re-run: verifies the existing
# credentials still log in before doing anything, and only re-provisions if
# they don't. The generated password is appended straight to .env and never
# printed or returned to the caller.
set -euo pipefail
WORKDIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$WORKDIR/.env"

if [ -f "$ENV_FILE" ]; then
    # shellcheck source=/dev/null
    set -a; . "$ENV_FILE"; set +a
fi
# shellcheck source=/dev/null
. "$WORKDIR/lib-alert.sh"
# shellcheck source=/dev/null
. "$WORKDIR/lib-passwords.sh"
# shellcheck source=/dev/null
. "$WORKDIR/lib-http.sh"

if [ -n "${KEYORIX_TESTUSER_USERNAME:-}" ] && [ -n "${KEYORIX_TESTUSER_PASSWORD:-}" ]; then
    resp=$(dast_post_json http://localhost:8080/auth/login \
        "{\"username\":\"$KEYORIX_TESTUSER_USERNAME\",\"password\":\"$KEYORIX_TESTUSER_PASSWORD\"}" -sf 2>/dev/null || true)
    if echo "${resp:-}" | jq -e '.success == true' >/dev/null 2>&1; then
        echo "dast-viewer test user already provisioned and working — nothing to do."
        exit 0
    fi
    echo "Existing KEYORIX_TESTUSER_* credentials in .env no longer work — reprovisioning."
fi

: "${KEYORIX_ADMIN_USERNAME:?}"
: "${KEYORIX_ADMIN_PASSWORD:?}"

ADMIN_TOKEN=$(dast_post_json http://localhost:8080/auth/login \
    "{\"username\":\"$KEYORIX_ADMIN_USERNAME\",\"password\":\"$KEYORIX_ADMIN_PASSWORD\"}" -sf \
    2>/dev/null | jq -r '.data.token // empty')
if [ -z "$ADMIN_TOKEN" ]; then
    dast_alert "provision-testuser: could not mint admin token to provision the viewer test user"
    exit 1
fi

NEW_PASSWORD="$(generate_compliant_password "dast-viewer" "DAST" "Viewer")"
CREATE_RESP=$(dast_post_json_bearer "$ADMIN_TOKEN" http://localhost:8080/api/v1/users \
    "{\"username\":\"dast-viewer\",\"email\":\"dast-viewer@keyorix.local\",\"display_name\":\"DAST Viewer\",\"password\":\"$NEW_PASSWORD\",\"role\":\"viewer\"}" -s)
unset ADMIN_TOKEN

if ! echo "$CREATE_RESP" | jq -e '.success == true' >/dev/null 2>&1; then
    dast_alert "provision-testuser: failed to create dast-viewer test user: $(echo "$CREATE_RESP" | jq -c '.error // .' 2>/dev/null || echo "$CREATE_RESP")"
    exit 1
fi

{
    echo "KEYORIX_TESTUSER_USERNAME=dast-viewer"
    echo "KEYORIX_TESTUSER_EMAIL=dast-viewer@keyorix.local"
    echo "KEYORIX_TESTUSER_PASSWORD=$NEW_PASSWORD"
} >> "$ENV_FILE"
unset NEW_PASSWORD CREATE_RESP

echo "Provisioned dast-viewer (role=viewer) and appended its credentials to .env."
