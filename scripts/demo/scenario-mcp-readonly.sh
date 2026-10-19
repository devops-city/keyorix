#!/usr/bin/env bash
# scripts/demo/scenario-mcp-readonly.sh — catalogue scenario 10: an AI assistant reads secrets
# through the read-only MCP server.
#
# The assistant (any MCP client - Claude Desktop/Code, an agent framework) talks to
# keyorix-mcp over stdio with a least-privilege machine-identity token. This script plays the
# client: initialise, list the tools, read one allowed secret, try a secret outside the
# allow-list, try tools that do not exist (rotate / delete / write). Every successful read is
# audited against the assistant's identity, and the same token cannot write through the REST
# API either (viewer role) - read-only is enforced twice, in the tool surface and by RBAC.
#
#   scenario-mcp-readonly.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/demo/scn-lib.sh
. "$SCRIPT_DIR/scn-lib.sh"
scn_init
MCP="$SCN_REPO_ROOT/bin/keyorix-mcp"
[ -x "$MCP" ] || { echo "bin/keyorix-mcp missing: go build -o bin/keyorix-mcp ./cmd/keyorix-mcp" >&2; exit 1; }

ASSISTANT="ai-assistant-$(date +%H%M%S)"
ALLOWED="default/development/stripe-api-key"
OTHER="default/development/db-password-nope"

scn_step "1/5 least privilege: a machine identity for the assistant (viewer on the default project only)"
scn_cli_as admin machine create --name "$ASSISTANT" --project default --type service --classification internal >/dev/null
scn_cli_as admin machine grant-role "$ASSISTANT" --project default --role project_viewer >/dev/null
tok="$(scn_cli_as admin machine token issue "$ASSISTANT" --name "${ASSISTANT}-token" --project default --classification internal | grep -oE 'kx_machine_[A-Za-z0-9_-]+' | head -n 1)"
[ -n "$tok" ] || { scn_fail "no machine token issued"; exit 1; }
scn_ok "$ASSISTANT created; the MCP server is further limited to ONE ref: $ALLOWED"

scn_step "2/5 the assistant's MCP session (stdio JSON-RPC)"
reqs="$SCN_CLI_HOME/.mcp-requests"
cat > "$reqs" <<EOF
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo-agent","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"keyorix_get_secret","arguments":{"ref":"$ALLOWED"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"keyorix_get_secret","arguments":{"ref":"$OTHER"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"keyorix_rotate_secret","arguments":{"ref":"$ALLOWED"}}}
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"keyorix_delete_secret","arguments":{"ref":"$ALLOWED"}}}
{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"keyorix_create_secret","arguments":{"ref":"default/development/planted","value":"x"}}}
EOF
resp="$SCN_CLI_HOME/.mcp-responses"
KEYORIX_URL="$SCN_URL" KEYORIX_TOKEN="$tok" KEYORIX_MCP_ALLOWED_REFS="$ALLOWED" "$MCP" < "$reqs" > "$resp" 2>"$SCN_CLI_HOME/.mcp-stderr" || true
rm -f "$reqs"

python3 -I - "$resp" <<'PY'
import json, sys
by_id = {}
for line in open(sys.argv[1]):
    line = line.strip()
    if line:
        m = json.loads(line)
        by_id[m.get("id")] = m

def text(m):
    r = m.get("result") or {}
    c = r.get("content") or []
    return (c[0].get("text") if c else "") or ""

tools = [t["name"] for t in by_id[2]["result"]["tools"]]
print("   tools offered to the assistant: " + ", ".join(tools))
ok = True
want_tools = {"keyorix_get_secret", "keyorix_list_secrets"}
if set(tools) != want_tools:
    print("   FAIL: expected exactly %s" % sorted(want_tools)); ok = False
t3 = text(by_id[3])
v = t3.strip()
print("   read allowed ref        -> %s... (%d chars, value delivered inside a data envelope)" % (v[:18].replace("\n", " "), len(v)) if v and not by_id[3].get("error") and not (by_id[3].get("result") or {}).get("isError") else "   read allowed ref        -> FAILED: %s" % (by_id[3].get("error") or t3))
if by_id[3].get("error") or (by_id[3].get("result") or {}).get("isError") or not v:
    ok = False
for i, label in ((4, "read a ref outside the allow-list"), (5, "rotate"), (6, "delete"), (7, "create")):
    m = by_id[i]
    refused = bool(m.get("error")) or bool((m.get("result") or {}).get("isError"))
    why = (m.get("error") or {}).get("message") or text(m)
    print("   %-23s -> %s (%s)" % (label, "REFUSED" if refused else "ALLOWED!", why[:90]))
    ok = ok and refused
sys.exit(0 if ok else 1)
PY
rc=$?
rm -f "$resp"
[ "$rc" -eq 0 ] || { scn_fail "the MCP session did not behave as a read-only, allow-listed proxy"; exit 1; }
scn_ok "one allowed read; everything else refused; no write/rotate/delete tool exists"

scn_step "3/5 defence in depth: the same token cannot write through the REST API either"
vf="$SCN_CLI_HOME/.mcp-write-value"; ( umask 077; printf 'x' > "$vf" )
out="$(cd "$SCN_REPO_ROOT" && KEYORIX_TOKEN="$tok" "$CLI_BIN" secret create --name planted --from-file "${vf#"$SCN_REPO_ROOT"/}" --project 1 2>&1 || true)"
rm -f "$vf"
printf '   keyorix secret create with the assistant token -> %s\n' "$(printf '%s' "$out" | grep -m1 '^Error' | cut -c1-100)"
printf '%s' "$out" | grep -qE 'HTTP 40[13]|Insufficient permissions|forbidden' || { scn_fail "expected a permission refusal"; exit 1; }
scn_ok "refused by RBAC"

scn_step "4/5 audited as the assistant, not as a person"
scn_cli_as admin audit logs --actor-type machine_identity --limit 6 | grep -E "$ASSISTANT|ACTOR" || true

scn_step "5/5 the assistant is one revoke away from losing everything"
scn_cli_as admin machine revoke "$ASSISTANT" --project default --force >/dev/null
scn_ok "$ASSISTANT revoked"
