#!/usr/bin/env bash
# scripts/demo/scenario-run.sh — catalogue scenario 4: `keyorix run`.
#
# Injects a secret into an UNMODIFIED program as an environment variable, then rotates the
# secret and shows the next start of the same program sees the new value. `keyorix run`
# resolves the secret when it starts the child: a running process keeps the value it was
# started with (there is no live reload), so "picks up the new value" means "on its next
# start", which is how a deployment pipeline restarts it after a rotation.
#
#   scenario-run.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/demo/scn-lib.sh
. "$SCRIPT_DIR/scn-lib.sh"
scn_init
scn_token admin

# The "application": a plain shell one-liner that only reads its environment. It has no
# Keyorix SDK and no knowledge of where the value came from. It prints a fingerprint, not
# the value.
APP='printf "app sees STRIPE_API_KEY = %s...%s  (%s chars)\n" "$(printf %s "$STRIPE_API_KEY" | cut -c1-8)" "$(printf %s "$STRIPE_API_KEY" | tail -c 6)" "${#STRIPE_API_KEY}"'

run_app() {
  KEYORIX_TOKEN="$SCN_TOKEN" "$CLI_BIN" run --project default --env development \
    --var STRIPE_API_KEY=stripe-api-key --clean-env -- sh -c "$APP"
}

scn_step "1/4 the app, started under 'keyorix run' (nothing stored on disk, nothing in its config)"
before="$(run_app)"
printf '   %s\n' "$before"
case "$before" in *"app sees STRIPE_API_KEY = sk_"*) ;; *) scn_fail "the app did not receive the secret"; exit 1 ;; esac
scn_ok "secret injected as an environment variable"

scn_step "2/4 the secret is rotated in Keyorix (the new value never touches a file or argv)"
new="sk_test_demo_rot_$(date +%s)"
printf '%s\n' "$new" | KEYORIX_TOKEN="$SCN_TOKEN" "$CLI_BIN" secret rotate --id 1 >/dev/null 2>"$SCN_CLI_HOME/.rotate-err" \
  || { cat "$SCN_CLI_HOME/.rotate-err" >&2; exit 1; }
rm -f "$SCN_CLI_HOME/.rotate-err"
scn_ok "rotated stripe-api-key to a new version"

scn_step "3/4 the next start of the same app gets the new value"
after="$(run_app)"
printf '   %s\n' "$after"
[ "$before" != "$after" ] || { scn_fail "the app saw the same value after rotation"; exit 1; }
case "$after" in *"STRIPE_API_KEY = sk_test_"*) ;; *) scn_fail "unexpected value after rotation"; exit 1 ;; esac
scn_ok "different value, no code or config change in the app"

scn_step "4/4 and it is all in the audit trail"
scn_cli_as admin audit logs --limit 8 | grep -E 'secret\.(read|rotated|updated|version)' | head -n 4 || true
scn_info "a running process keeps its value until restarted; restart the app (or let your orchestrator) after a rotation"
