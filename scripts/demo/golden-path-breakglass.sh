#!/usr/bin/env bash
# scripts/demo/golden-path-breakglass.sh -- execute the break-glass section of
# docs/demo/GOLDEN-PATH.md ("Optional: emergency access (break-glass)") exactly as
# written, against the demo scripts/demo/up.sh brought up. The commands are
# EXTRACTED from the document, not copied here, so the doc cannot drift from what
# works (#3202: the example used --project-id 1, where the seeded user has no role,
# so the first command as written was refused; nothing ran the section).
#
# Each fenced block runs as the user named in its first line: "# as alice" (the
# seeded project_viewer on backend-api) or "# as an administrator". A line
# starting "keyorix " runs the host CLI; "<id>" is replaced with the activation id
# the activate command printed.
#
# Usage (check.sh supplies these; the tokens are never put in argv):
#   KEYORIX_BG_SERVER=<url> KEYORIX_BG_ALICE_TOKEN=<session> KEYORIX_BG_ADMIN_TOKEN=<session> \
#     scripts/demo/golden-path-breakglass.sh
# KEYORIX_BG_CLI overrides the CLI binary (default bin/keyorix).
# Exit 0 = the section works as written and leaves no active activation behind.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

DOC="${KEYORIX_BG_DOC:-docs/demo/GOLDEN-PATH.md}"
CLI="${KEYORIX_BG_CLI:-$REPO_ROOT/bin/keyorix}"

fail() { echo "golden-path-breakglass: $*" >&2; exit 1; }

: "${KEYORIX_BG_SERVER:?set KEYORIX_BG_SERVER}"
: "${KEYORIX_BG_ALICE_TOKEN:?set KEYORIX_BG_ALICE_TOKEN}"
: "${KEYORIX_BG_ADMIN_TOKEN:?set KEYORIX_BG_ADMIN_TOKEN}"
[ -x "$CLI" ] || fail "CLI $CLI not found (make build-cli)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Fenced code blocks of the break-glass section, up to the next "## " heading.
awk '
  /^## Optional: emergency access \(break-glass\)/ { insec = 1; next }
  insec && /^## / { exit }
  insec && /^```/ { fence = !fence; next }
  insec && fence { print }
' "$DOC" > "$WORK/section.txt"

# Not vacuous: the section must still contain the commands this guards, in the
# project the seed gives alice (backend-api = project 2), and must not reintroduce
# project 1 (the `default` project, where she has no role).
for want in "# as alice" "# as an administrator" "break-glass activate --project-id 2" \
            "break-glass list --project-id 2" "break-glass revoke --project-id 2 --activation-id <id>"; do
  grep -qF -- "$want" "$WORK/section.txt" || fail "$DOC no longer contains '$want'; update this guard with the doc"
done
if grep -Eq -- "--project-id 1([^0-9]|$)" "$WORK/section.txt"; then
  fail "$DOC uses --project-id 1 for break-glass: alice has no role on project 1 (#3202)"
fi

actor_token=""
activation_id=""
ran=0
while IFS= read -r line; do
  case "$line" in
    "# as alice"*) actor_token="$KEYORIX_BG_ALICE_TOKEN"; echo "==> $line"; continue ;;
    "# as an administrator"*) actor_token="$KEYORIX_BG_ADMIN_TOKEN"; echo "==> $line"; continue ;;
    ""|"#"*) continue ;;
  esac
  [ -n "$actor_token" ] || fail "command before any '# as <user>' line: $line"
  case "$line" in
    "keyorix "*) ;;
    *) fail "unexpected line in the break-glass section (only 'keyorix ...' commands are run): $line" ;;
  esac
  cmd="${line#keyorix }"
  if [[ "$cmd" == *"<id>"* ]]; then
    [ -n "$activation_id" ] || fail "'<id>' used before an activate command printed an id: $line"
    cmd="${cmd//<id>/$activation_id}"
  fi
  echo "\$ keyorix $cmd"
  # The documented line is parsed as the shell would parse it (the justification is
  # quoted); the text comes from this repository's own doc, like golden-path-s7.sh.
  eval "set -- $cmd"
  if ! out="$(KEYORIX_SERVER="$KEYORIX_BG_SERVER" KEYORIX_TOKEN="$actor_token" "$CLI" "$@" 2>&1)"; then
    echo "$out"
    fail "command failed as written: keyorix $cmd"
  fi
  echo "$out"
  ran=$((ran + 1))
  case "$cmd" in
    "break-glass activate "*)
      activation_id="$(printf '%s\n' "$out" | sed -n 's/^Emergency access activated (id=\([0-9][0-9]*\)).*/\1/p' | head -1)"
      [ -n "$activation_id" ] || fail "activate did not print 'Emergency access activated (id=N)'"
      ;;
    "break-glass list "*)
      # The list is the administrators' view of the activation just made.
      printf '%s\n' "$out" | grep -Eq "^${activation_id}[[:space:]].*[[:space:]]active[[:space:]]" \
        || fail "the list does not show activation $activation_id as active"
      ;;
    "break-glass revoke "*)
      printf '%s\n' "$out" | grep -q "^Revoked break-glass activation ${activation_id} " \
        || fail "revoke did not report 'Revoked break-glass activation ${activation_id}'"
      ;;
  esac
done < "$WORK/section.txt"

[ "$ran" -ge 3 ] || fail "ran $ran commands, expected activate, list and revoke"
[ -n "$activation_id" ] || fail "no activation was made"
echo "golden-path-breakglass: OK (activate as alice on project 2; list and revoke as an administrator; activation $activation_id ended)"
