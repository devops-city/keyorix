#!/usr/bin/env bash
# scripts/demo/scenario-oidc-federation.sh — catalogue scenario 5: CI without stored secrets.
#
# A CI job (think GitHub Actions) authenticates to Keyorix with the short-lived OIDC token its
# platform issues for the run - no Keyorix credential is stored anywhere. Keyorix verifies the
# token's signature against the platform's published keys, maps (issuer, subject) to a machine
# identity, and the read is audited against that identity.
#
# The platform is a local stand-in (scripts/demo/oidcissuer: a JWKS endpoint + RS256 signing
# with a throwaway key); native-up.sh writes it into the demo server's `oidc:` trust list. The
# real-GitHub variant differs only in the issuer URL and subject string.
#
#   scenario-oidc-federation.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/demo/scn-lib.sh
. "$SCRIPT_DIR/scn-lib.sh"
scn_init

OIDC_PORT="${DEMO_OIDC_PORT:-18520}"
ISSUER="http://127.0.0.1:${OIDC_PORT}"
AUD="keyorix-demo"
MACHINE="gha-deploy"
SUBJECT="repo:keyorix-demo/payments:ref:refs/heads/main"
ISSUER_BIN="$SCN_REPO_ROOT/bin/demo-oidcissuer"
[ -x "$ISSUER_BIN" ] || { echo "bin/demo-oidcissuer missing: go build -o bin/demo-oidcissuer ./scripts/demo/oidcissuer" >&2; exit 1; }
grep -q "127.0.0.1:${OIDC_PORT}" "${DEMO_CONFIG:-$SCN_WORK/keyorix.yaml}" 2>/dev/null \
  || { scn_fail "this demo's server does not trust the local issuer (no oidc: block in its config) - recreate it with scripts/demo/native-up.sh"; exit 1; }

"$ISSUER_BIN" serve -dir "$SCN_WORK" -addr "127.0.0.1:${OIDC_PORT}" 2>/dev/null &
ISSUER_PID=$!
trap 'kill "$ISSUER_PID" 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do curl -s -o /dev/null --max-time 1 "$ISSUER/jwks.json" && break; sleep 0.3; done

mint() { # SUBJECT [extra mint flags]
  local sub="$1"; shift
  "$ISSUER_BIN" mint -dir "$SCN_WORK" -issuer "$ISSUER" -sub "$sub" -aud "$AUD" "$@"
}

scn_step "1/5 once: a machine identity for the pipeline, bound to the CI platform's (issuer, subject) - no token is issued"
scn_cli_as admin machine create --name "$MACHINE" --project default --type ci --classification internal >/dev/null 2>&1 || scn_info "$MACHINE already exists"
scn_cli_as admin machine grant-role "$MACHINE" --project default --role project_viewer >/dev/null 2>&1 || true
scn_cli_as admin machine binding add "$MACHINE" --project default --issuer "$ISSUER" --subject "$SUBJECT" >/dev/null 2>&1 || scn_info "binding already present"
scn_cli_as admin machine binding list "$MACHINE" --project default
scn_ok "bound: $SUBJECT -> $MACHINE (viewer on default)"

scn_step "2/5 the CI run: gets its platform token (valid 5 minutes) and reads a secret with it"
jwt="$(mint "$SUBJECT" -ttl 5m)"
scn_info "token: 3-part JWT, ${#jwt} chars, iss=$ISSUER sub=$SUBJECT aud=$AUD, exp +5m"
code="$(scn_http_code "$jwt" "/api/v1/secrets/1?include_value=true")"
[ "$code" = "200" ] || { scn_fail "federated read returned HTTP $code (want 200)"; exit 1; }
scn_ok "HTTP 200 - the secret was read with a token Keyorix never issued"

scn_step "3/5 what must NOT work"
bad=0
code="$(scn_http_code "$(mint 'repo:keyorix-demo/other-repo:ref:refs/heads/main' -ttl 5m)" "/api/v1/secrets/1?include_value=true")"
printf '   another repo (subject not bound)        -> HTTP %s\n' "$code"; [ "$code" = "401" ] || bad=1
code="$(scn_http_code "$(mint "$SUBJECT" -ttl 1m -iat-offset=-2h)" "/api/v1/secrets/1?include_value=true")"
printf '   an expired token                        -> HTTP %s\n' "$code"; [ "$code" = "401" ] || bad=1
code="$("$ISSUER_BIN" mint -dir "$SCN_WORK" -issuer "$ISSUER" -sub "$SUBJECT" -aud "some-other-service" | { read -r t; scn_http_code "$t" "/api/v1/secrets/1?include_value=true"; })"
printf '   a token minted for a different audience -> HTTP %s\n' "$code"; [ "$code" = "401" ] || bad=1
[ "$bad" -eq 0 ] || { scn_fail "a token that should be refused was not refused"; exit 1; }
scn_ok "unbound subject, expired and wrong-audience tokens are all refused"

scn_step "4/5 the read is audited against the machine identity, not a shared credential"
scn_cli_as admin audit logs --actor-type machine_identity --limit 5 | grep -E "$MACHINE|ACTOR" || true
scn_info "no static secret to rotate, leak or revoke: remove the binding and the pipeline loses access"

scn_step "5/5 revoking trust"
scn_cli_as admin machine binding list "$MACHINE" --project default >/dev/null
scn_info "(binding left in place so the scenario is re-runnable; 'keyorix machine binding rm' removes it)"
