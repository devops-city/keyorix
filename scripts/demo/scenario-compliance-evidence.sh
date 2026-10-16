#!/usr/bin/env bash
# scripts/demo/scenario-compliance-evidence.sh — catalogue scenario 9: compliance evidence for
# an auditor.
#
# One command produces a timestamped evidence pack (the control posture plus the records that
# back it: audit-chain anchor, access-review campaigns, break-glass register, rotation
# overdues) with a detached signature. The auditor can later ask the server to verify that the
# pack is authentic and unmodified; changing one byte makes verification fail. The control
# matrix maps every control to ISO 27001, SOC 2, NIS2 and DORA articles.
#
#   scenario-compliance-evidence.sh [OUTPUT_DIR]     # default: the demo's cli-home
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/demo/scn-lib.sh
. "$SCRIPT_DIR/scn-lib.sh"
scn_init
cd "$SCN_REPO_ROOT"

OUT_DIR="${1:-$SCN_CLI_HOME}"
case "$OUT_DIR" in /*) OUT_DIR="${OUT_DIR#"$PWD"/}" ;; esac
PACK="$OUT_DIR/evidence-pack-$(date +%Y%m%d-%H%M%S).json"

scn_step "1/4 the control matrix an auditor reads (mapped to ISO 27001 / SOC 2 / NIS2 / DORA)"
scn_cli_as admin compliance controls | sed -n '1,2p;/NIS2/!d' | head -n 3 || true
scn_cli_as admin compliance controls | grep -cE '^\[(PASS|GAP |n/a )\]' | xargs printf '   %s controls evaluated\n'

scn_step "2/4 export the signed evidence pack"
scn_cli_as admin compliance export --output "$PACK"
[ -s "$PACK" ] || { scn_fail "no pack written"; exit 1; }
python3 -I - "$PACK" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print("   pack sections: " + ", ".join(sorted(d.keys())))
PY
ls "$PACK".sig >/dev/null 2>&1 && scn_ok "pack $PACK + detached signature $PACK.sig" \
  || { scn_fail "no detached signature next to the pack"; exit 1; }

scn_step "3/4 the auditor verifies authenticity against the deployment"
scn_cli_as admin compliance verify --file "$PACK"
scn_ok "pack verified: produced by this deployment, unmodified"

scn_step "4/4 and a single changed byte is caught"
cp "$PACK" "$PACK.tampered"; cp "$PACK.sig" "$PACK.tampered.sig"
python3 -I - "$PACK.tampered" <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
i = b.rfind(b"true")
if i < 0:
    i = b.rfind(b"false")
b[i:i+4] = b"TRUE" if b[i:i+4] == b"true" else b"FALSE"[:4]
open(p, "wb").write(bytes(b))
PY
cmp -s "$PACK" "$PACK.tampered" && { scn_fail "the tamper step changed nothing"; exit 1; }
if scn_cli_as admin compliance verify --file "$PACK.tampered" >/dev/null 2>&1; then
  scn_fail "the tampered pack still verified"; exit 1
fi
scn_ok "tampered copy rejected"
rm -f "$PACK.tampered" "$PACK.tampered.sig"
scn_info "evidence kept at $PACK (+ .sig). Scheduled delivery to storage/SIEM: evidence_delivery config."
