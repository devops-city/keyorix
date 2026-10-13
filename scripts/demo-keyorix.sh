#!/bin/bash

# Keyorix Demo Seed + Walkthrough
# Seeds the exact data the demo script (keyorix-gtm.md) expects, then shows the
# headline features. Run AFTER `keyorix system init --server ...` and after the
# CLI is pointed at the server.
#
# Server mode is required: export KEYORIX_SERVER + KEYORIX_TOKEN (or run
# `keyorix connect`) so `keyorix secret create` and the user-seed curl below hit
# the running server, not a local SQLite file.

set -e

echo "🚀 Keyorix Demo Seed + Walkthrough"
echo "=================================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

demo_step() { local msg="$1"; echo -e "${CYAN}➤${NC} $msg"; }
demo_success() { local msg="$1"; echo -e "${GREEN}✅${NC} $msg"; }
demo_info() { local msg="$1"; echo -e "${BLUE}ℹ️${NC}  $msg"; }
demo_warn() { local msg="$1"; echo -e "${YELLOW}⚠️${NC}  $msg"; }

SERVER="${KEYORIX_SERVER:-http://localhost:8080}"

# Scratch dir for this run (demo-user response body + a short-lived curl header
# file). mktemp avoids the fixed-path symlink race a hardcoded /tmp path would
# have, and the header file keeps the bearer token out of argv (ps/procfs
# visible to other local users) — it's read by curl via `-H @file` instead.
DEMO_TMP_DIR=""
cleanup_demo_tmp() {
    [[ -n "$DEMO_TMP_DIR" ]] && rm -rf "$DEMO_TMP_DIR"
}
trap cleanup_demo_tmp EXIT

if [[ -z "$KEYORIX_TOKEN" ]]; then
    demo_warn "KEYORIX_TOKEN is not set. Secrets are created via the CLI's own"
    demo_warn "remote config (cli.yaml from 'keyorix connect'); the demo-user step"
    demo_warn "below needs KEYORIX_TOKEN to call the API. Run 'keyorix connect' and"
    demo_warn "export KEYORIX_TOKEN to seed the demo user automatically."
fi

echo ""
demo_step "1. Creating the three demo secrets (names match the demo script)"
# The value goes in via --from-file (a 0600 file under the current directory; the CLI
# refuses absolute paths), never --value: argv is visible in ps and shell history.
demo_create_secret() {
    local name="$1" value="$2" type="$3" vfile
    vfile="$(mktemp ./.keyorix-demo-value.XXXXXX)"
    printf '%s' "$value" > "$vfile"
    ./keyorix secret create --name "$name" --from-file "$vfile" --type "$type" || { rm -f "$vfile"; return 1; }
    rm -f "$vfile"
}
demo_create_secret "prod-db-password" "super_secure_db_pass_2024" "password"
demo_create_secret "stripe-api-key" "sk_live_demo_51abc123def456" "api_key"
demo_create_secret "jwt-signing-key" "$(head -c 32 /dev/urandom | base64)" "password"

echo ""
demo_step "2. Creating a limited-permission demo user (for the RBAC chapter)"
# New users are auto-assigned the read-only 'viewer' role, so
# 'keyorix rbac check-permission --user demo@keyorix.com --permission secrets.write'
# returns ❌ — the contrast that makes the RBAC chapter land.
if [[ -n "$KEYORIX_TOKEN" ]]; then
    DEMO_TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/keyorix-demo.XXXXXX")
    RESPONSE_FILE="$DEMO_TMP_DIR/keyorix-demo-user.json"
    HEADER_FILE="$DEMO_TMP_DIR/auth.header"
    BODY_FILE="$DEMO_TMP_DIR/keyorix-demo-user-body.json"
    # Generate the demo user's password at runtime rather than hardcoding one:
    # a fixed literal here is easy to copy-paste into a real deployment by
    # someone following this script as a tutorial. Printed below so the
    # operator can still log in as this user.
    DEMO_USER_PASSWORD=$(head -c 24 /dev/urandom | base64)
    (umask 077 && printf 'Authorization: Bearer %s\n' "$KEYORIX_TOKEN" > "$HEADER_FILE")
    (umask 077 && printf '{"username":"demo","email":"demo@keyorix.com","password":"%s","display_name":"Demo User"}' "$DEMO_USER_PASSWORD" > "$BODY_FILE")
    HTTP_CODE=$(curl -s -o "$RESPONSE_FILE" -w "%{http_code}" \
        -X POST "$SERVER/api/v1/users" \
        -H @"$HEADER_FILE" \
        -H "Content-Type: application/json" \
        --data @"$BODY_FILE")
    rm -f "$HEADER_FILE" "$BODY_FILE"
    if [[ "$HTTP_CODE" = "200" ]] || [[ "$HTTP_CODE" = "201" ]]; then
        demo_success "Created demo user demo@keyorix.com (viewer role)"
        demo_info "Demo user password: $DEMO_USER_PASSWORD (save it — needed to log in as this user)"
    elif [[ "$HTTP_CODE" = "409" ]]; then
        demo_info "Demo user demo@keyorix.com already exists — skipping"
    else
        demo_warn "Demo user creation returned HTTP $HTTP_CODE (see $RESPONSE_FILE)"
    fi
else
    demo_warn "Skipped demo-user creation (no KEYORIX_TOKEN). Create it in the web"
    demo_warn "Admin UI instead — new users get the viewer role automatically."
fi

echo ""
demo_step "3. Listing all secrets"
./keyorix secret list

echo ""
demo_step "4. RBAC: roles and a permission check"
./keyorix rbac list-roles
if [[ -n "$KEYORIX_TOKEN" ]]; then
    echo ""
    demo_info "Limited user does NOT have secrets.write:"
    ./keyorix rbac check-permission --user "demo@keyorix.com" --permission "secrets.write" || true
fi

echo ""
demo_step "5. System health"
./keyorix status || true
echo "API health:"
curl -s "$SERVER/health" | jq '.' 2>/dev/null || curl -s "$SERVER/health"

echo ""
echo ""
demo_success "Demo seed complete. Walkthrough script: keyorix-gtm.md → 'Demo Script'."
echo ""
echo "🔐 Highlights to show:"
echo "  • Secrets list + reveal a value + version history (web UI)"
echo "  • RBAC enforced at the API: keyorix rbac check-permission"
echo "  • Audit trail: GET /api/v1/audit/logs (or the Audit Log UI page)"
echo "  • Single binary deploy: keyorix-server + PostgreSQL"
