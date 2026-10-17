#!/usr/bin/env bash
# scripts/e2e/web-real-smoke.sh -- I4 (SESSION-I): drives the real web UI
# against a REAL keyorix-server backend (not web/e2e's existing mocked
# specs, which intercept every API call with canned responses -- see
# web/e2e/mocks.ts). Boots a real server the exact same way
# scripts/smoke.sh already proves works (admin init -> admin encryption
# init -> admin migrate -> start -> POST /system/init), points the Vite dev
# server at it via VITE_API_BASE_URL, and runs the Playwright specs under
# web/e2e/real/ (a separate Playwright config, playwright.config.real.ts,
# so this never touches the existing mock-based suite or its config).
#
# SESSION-WEB-E2E (2026-10-02/03): runs web/e2e/real/*.spec.ts in BUDGET
# GROUPS of at most MAX_SPECS_PER_GROUP files each, every group against its
# own freshly-booted server/DB, rather than one Playwright invocation
# covering every spec file against one shared backend.
# server/http/handlers/auth.go's reserveLoginAttempt enforces a shared
# per-IP budget of 10 login attempts (UI or API, success or fail) per 15
# minutes, backed by the DB -- fine for any one spec file alone, but the
# real-backend suite's total login volume across ALL files already exceeds
# it once summed (confirmed live: running every e2e/real/*.spec.ts file
# together in one invocation against one backend 429'd starting with the
# 11th login, mid-suite, with failures that look like broken tests but are
# actually an exhausted rate-limit budget -- nothing to do with any
# individual spec's correctness). A fresh SMOKE_DIR each group gets a fresh
# SQLite DB, which resets the counter (it's keyed in that DB, not wall-clock
# alone) -- so splitting into groups that each stay under budget, rather
# than trying to shave every file's login count down to fit one shared
# budget forever, is the fix that actually scales as more real-backend specs
# get added later instead of recreating this exact collision at some new
# file count.
#
# Groups are discovered dynamically (every e2e/real/*.spec.ts file that
# exists, chunked at MAX_SPECS_PER_GROUP) rather than a hardcoded file list,
# deliberately: a hardcoded list would be wrong -- and Playwright would error
# outright on a named file that doesn't exist -- on every individual PR
# branch that doesn't yet have every other in-flight real-backend spec file
# merged into it. Today's real per-file login counts run 2-5 each.
# MAX_SPECS_PER_GROUP=1 (2026-10-05, #2738): one spec file per freshly-booted
# server, so NO group's budget is ever a sum of per-file counts. The previous
# value of 2 was a hand-tuned number ("the worst real pairing today is 7"), and
# the comment it replaced was itself a hand-tuned 3 that had already broken
# once -- every added spec file re-opens the arithmetic, and the failure mode is
# a mid-suite 429 that reads as a broken test. Adding mfa-disable-dialog.spec.ts
# would have put the [mfa-disable-dialog + mfa-login] pairing at 9 plus the
# group's own 1 project-seeding login = the ceiling exactly, zero margin: the
# precise trap the old comment warned about, two spec files later. At 1 per
# group the binding constraint is a SINGLE file's own login count against the
# full budget, which a spec author can see while writing that file instead of
# having to know what else exists and how the alphabetical chunking lands.
# Today's worst single file is mfa-login at 6 (+1 seeding = 7 of 10).
# Cost: one server boot per spec file instead of per pair.
#
# Usage: scripts/e2e/web-real-smoke.sh [spec-file ...]
#   With no arguments: every e2e/real/*.spec.ts file (what CI runs).
#   With arguments: only those spec files, each still in its own group with its
#   own freshly-booted server -- for iterating on one spec without booting a
#   server for every other file. Paths are relative to web/ (e.g.
#   e2e/real/mfa-disable-dialog.spec.ts).
#   KEYORIX_E2E_SPEC_DIR=e2e/demo (what `make e2e-web-demo` sets) runs the demo-catalogue
#   journeys under web/e2e/demo instead (DEMO-E2E-1), on the same per-spec fresh server. The
#   default, e2e/real, is the suite the pull_request and merge_group jobs run.
#   Requires: go, pnpm, a working `pnpm exec playwright install` (browsers
#   already cached locally is fine -- this script does not re-install them).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER_BIN="$REPO_ROOT/bin/keyorix-server"
WEB_DIR="$REPO_ROOT/web"
MAX_SPECS_PER_GROUP=1

# KEYORIX_E2E_SPEC_DIR picks the spec directory (relative to web/) whose *.spec.ts files the
# no-argument run discovers. Default e2e/real: the suite the pull_request and merge_group jobs
# run. `make e2e-web-demo` sets e2e/demo (DEMO-E2E-1): the demo-catalogue journeys, which run
# in the full CI profile only. The same server boot, seeding and `// e2e-server:` directives
# apply to both. run_group tells playwright.config.real.ts which testDir to use
# (KEYORIX_E2E_TEST_DIR) from the directory of the group's spec, so explicit spec paths
# (arguments, KEYORIX_E2E_SPECS) work for either suite. Any other directory is refused.
SPEC_DIR="${KEYORIX_E2E_SPEC_DIR:-e2e/real}"
case "$SPEC_DIR" in
e2e/real | e2e/demo) ;;
*)
    echo "KEYORIX_E2E_SPEC_DIR must be e2e/real or e2e/demo, got: $SPEC_DIR" >&2
    exit 1
    ;;
esac

# KEYORIX_E2E_SPECS optionally narrows the run to a space-separated list of
# spec paths (relative to web/), for iterating on one file without paying for
# every other group's server boot + Vite start. Unset -- the CI and default
# local behaviour -- runs every e2e/real/*.spec.ts file, as before. This is an
# iteration aid, not a way to land a change that only passes in isolation:
# whatever narrowing happened here, the full run is still what has to be green.
if [ -n "${KEYORIX_E2E_SPECS:-}" ]; then
    # Intentional word-splitting: the variable is a space-separated path list.
    # shellcheck disable=SC2206
    ALL_SPECS=(${KEYORIX_E2E_SPECS})
    echo "==> KEYORIX_E2E_SPECS is set: running only ${ALL_SPECS[*]}"
elif [ "$#" -gt 0 ]; then
    ALL_SPECS=("$@")
    for spec in "${ALL_SPECS[@]}"; do
        [ -f "$WEB_DIR/$spec" ] || { echo "no such spec file: $WEB_DIR/$spec" >&2; exit 1; }
    done
else
    mapfile -t ALL_SPECS < <(cd "$WEB_DIR" && find "$SPEC_DIR" -maxdepth 1 -name '*.spec.ts' | sort)
fi
[ "${#ALL_SPECS[@]}" -gt 0 ] || { echo "no $SPEC_DIR/*.spec.ts files found under $WEB_DIR" >&2; exit 1; }

# KEYORIX_E2E_SHARD=i/n (CI: 1/2 and 2/2 as parallel jobs) runs only shard i of n.
# Spec k (0-based, in the sorted ALL_SPECS order) belongs to shard (k % n) + 1:
# deterministic, no hand-kept file list, so a new spec lands in a shard on its own.
# Round-robin over the sorted names puts mfa-disable-dialog and mfa-login (the slow
# TOTP-step files) in different shards. Before narrowing, every shard's selection is
# computed and checked to cover ALL_SPECS exactly once, so a spec can never be
# assigned to no shard (or two) -- the run fails instead of silently dropping it.
if [ -n "${KEYORIX_E2E_SHARD:-}" ]; then
    case "$KEYORIX_E2E_SHARD" in
    [1-9]*/[1-9]*) ;;
    *) echo "KEYORIX_E2E_SHARD must look like i/n (e.g. 1/2), got: $KEYORIX_E2E_SHARD" >&2; exit 1 ;;
    esac
    shard_idx="${KEYORIX_E2E_SHARD%%/*}"
    shard_cnt="${KEYORIX_E2E_SHARD##*/}"
    [ "$shard_idx" -le "$shard_cnt" ] || { echo "KEYORIX_E2E_SHARD index $shard_idx exceeds count $shard_cnt" >&2; exit 1; }
    SHARD_SPECS=()
    for ((k = 0; k < ${#ALL_SPECS[@]}; k++)); do
        owners=0
        for ((s = 1; s <= shard_cnt; s++)); do
            [ $((k % shard_cnt + 1)) -eq "$s" ] && owners=$((owners + 1))
        done
        if [ "$owners" -ne 1 ]; then
            echo "spec ${ALL_SPECS[$k]} is assigned to $owners shards of $shard_cnt (want exactly 1)" >&2
            exit 1
        fi
        [ $((k % shard_cnt + 1)) -eq "$shard_idx" ] && SHARD_SPECS+=("${ALL_SPECS[$k]}")
    done
    [ "${#SHARD_SPECS[@]}" -gt 0 ] || { echo "shard $KEYORIX_E2E_SHARD has no specs (${#ALL_SPECS[@]} total)" >&2; exit 1; }
    echo "==> shard $KEYORIX_E2E_SHARD: ${#SHARD_SPECS[@]} of ${#ALL_SPECS[@]} spec files: ${SHARD_SPECS[*]}"
    ALL_SPECS=("${SHARD_SPECS[@]}")
fi

SPEC_GROUPS=()
current_group=""
current_count=0
for spec in "${ALL_SPECS[@]}"; do
    if [ "$current_count" -ge "$MAX_SPECS_PER_GROUP" ]; then
        SPEC_GROUPS+=("$current_group")
        current_group=""
        current_count=0
    fi
    current_group="${current_group:+$current_group }$spec"
    current_count=$((current_count + 1))
done
[ -n "$current_group" ] && SPEC_GROUPS+=("$current_group")

fail() {
    echo "" >&2
    echo "WEB E2E SMOKE FAILED: $1" >&2
    exit 1
}

# Port selection (#3174) lives in lib/free-port.sh so it can be unit-tested
# (lib/free-port_test.sh). History: #2738 replaced fixed, interleaving ports
# (18189+group / 18190+group) with a probe; #3174 made the probe check both
# loopback families (a Vite on [::1] was invisible to a 127.0.0.1-only probe) and
# the starting point a random high base per run, overridable with
# KEYORIX_E2E_PORT_BASE (server ports start at BASE+group, web ports at
# BASE+1000+group), so concurrent runs on one host stop walking the same ports.
# shellcheck source=lib/free-port.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/free-port.sh"
PORT_BASE="$(pick_port_base)" || exit 1
echo "==> port base: $PORT_BASE (override with KEYORIX_E2E_PORT_BASE)"

if [ ! -x "$SERVER_BIN" ]; then
    echo "==> bin/keyorix-server not found, building it"
    (cd "$REPO_ROOT" && go build -o "$SERVER_BIN" ./server) || fail "go build did not produce $SERVER_BIN"
fi

REAL_HOME="$HOME"

# CURRENT_SERVER_PID + the EXIT trap below are what make a FAILING run clean up
# after itself (WEB-SWEEP-1). run_group's own `trap group_cleanup RETURN` only
# fires on a normal return; fail() calls `exit`, which terminates the shell
# WITHOUT running a RETURN trap, so until now any group that failed left its
# keyorix-server alive and still listening on that group's port. The next run
# then passed its health check against the PREVIOUS run's orphan -- same port,
# different database -- and died on the first login with a Python KeyError on
# the admin credentials it had just created in a database the server answering
# was not using. Confirmed live: a failing group 1 left PID … on :18190, and the
# next invocation failed in exactly that way with no indication the two were
# related. An EXIT trap covers the fail() path, a Ctrl-C and an unexpected
# `set -e` abort alike.
CURRENT_SERVER_PID=""
cleanup_current_server() {
    [ -n "$CURRENT_SERVER_PID" ] && kill "$CURRENT_SERVER_PID" 2>/dev/null
    return 0
}
trap cleanup_current_server EXIT

if [ ! -d "$WEB_DIR/node_modules" ]; then
    echo "==> pnpm install"
    (cd "$WEB_DIR" && pnpm install --frozen-lockfile)
fi

# seed_demo_data puts realistic content behind every page a real-backend spec
# visits (WEB-SWEEP-1). Before this, each group seeded one empty project, so
# every list page rendered its empty state and a spec could only ever assert
# "the shell rendered" -- a page that silently drops its rows, or a role gate
# that hides content it should show, looks identical to a correctly-rendered
# empty list.
#
# Two API shapes here are easy to get wrong and are spelled out rather than
# left to be rediscovered:
#
#   * POST /api/v1/projects/{id}/members grants a SCOPED ROLE. A project role
#     alone does NOT satisfy the global-scope permission gates most list
#     endpoints use (server/http/router.go gates GET /api/v1/projects with
#     RequirePermission, not RequireScopedPermission), which is exactly why the
#     least-privilege persona below is a genuinely restricted view and not just
#     a second admin.
#   * POST /api/v1/secrets/{id}/share requires the SHARER to be a live member
#     of the secret's project (internal/core/sharing.go's
#     requireLiveOwnerAuthority) as well as the recipient. Creating a project
#     does not make the creator a member of it -- hence the explicit
#     self-membership grant before any share call.
#
# Every call is best-effort on purpose: a seeding failure must not fail the
# suite before Playwright has run, because an empty page is a far clearer
# diagnostic in a spec's own assertion than a curl exit code buried in this
# script's output. Each step echoes what it did.
seed_demo_data() {
    local group_label="$1" server_url="$2" token="$3" project_name="$4"
    local lowpriv_username="$5" lowpriv_password="$6"

    api() { # api METHOD PATH [JSON-BODY]
        if [ -n "${3:-}" ]; then
            curl -s -X "$1" "$server_url$2" -H "Authorization: Bearer $token" \
                -H "Content-Type: application/json" -d "$3"
        else
            curl -s -X "$1" "$server_url$2" -H "Authorization: Bearer $token"
        fi
    }

    echo "==> [group $group_label] seeding project \"$project_name\""
    local pid
    pid="$(api POST /api/v1/projects \
        "{\"name\":\"$project_name\",\"description\":\"real-backend web e2e fixture\"}" |
        python3 -c 'import sys,json
try:
    print(json.load(sys.stdin)["data"]["id"])
except Exception:
    print("")')"
    [ -n "$pid" ] || {
        echo "    (project create returned no id -- later seeding is skipped)" >&2
        return 0
    }

    # The creator is not implicitly a member; sharing below needs this.
    api POST "/api/v1/projects/$pid/members" '{"user_id":1,"role":"project_admin"}' >/dev/null

    # Environment ids are server-assigned per project (development, staging and
    # production are created with the project), so they are read back rather
    # than assumed to be 1/2/3 -- they are not, for any project after the first.
    #
    # Named env_a/env_b, not dev_env/staging_env: the list endpoint returns the
    # three sorted by NAME (development, production, staging), so position 2 is
    # production, not staging. The fixture only needs two distinct environments
    # so that the list page has more than one to group by; naming them after a
    # position-based guess at which is which would be wrong, and the kind of
    # wrong a later reader would believe.
    local env_ids
    env_ids="$(api GET "/api/v1/projects/$pid/environments" |
        python3 -c 'import sys,json
try:
    print(" ".join(str(e["id"]) for e in json.load(sys.stdin)["data"]["environments"]))
except Exception:
    print("")')"
    local env_a env_b
    env_a="$(echo "$env_ids" | cut -d" " -f1)"
    env_b="$(echo "$env_ids" | cut -d" " -f2)"
    [ -n "$env_b" ] || env_b="$env_a"
    echo "    project id=$pid environments=[$env_ids]"

    # One secret per type the UI offers (web/src/constants.ts SECRET_TYPES), so
    # the list page's type column, filters and per-type detail views all have a
    # row to render.
    echo "==> [group $group_label] seeding one secret of every type"
    api POST /api/v1/secrets "{\"name\":\"e2e-api-key\",\"value\":\"sk_test_EXAMPLE_0001\",\"type\":\"api_key\",\"project_id\":$pid,\"environment_id\":$env_a}" >/dev/null
    api POST /api/v1/secrets "{\"name\":\"e2e-password\",\"value\":\"Tr0ubad0ur-Mesa-Quilt-88\",\"type\":\"password\",\"project_id\":$pid,\"environment_id\":$env_a}" >/dev/null
    api POST /api/v1/secrets "{\"name\":\"e2e-plain-text\",\"value\":\"rotate quarterly\",\"type\":\"text\",\"project_id\":$pid,\"environment_id\":$env_b}" >/dev/null
    api POST /api/v1/secrets "{\"name\":\"e2e-certificate\",\"value\":\"-----BEGIN CERTIFICATE-----\\nMIIBkTCB+wIJAEXAMPLE\\n-----END CERTIFICATE-----\",\"type\":\"certificate\",\"project_id\":$pid,\"environment_id\":$env_b}" >/dev/null
    api POST /api/v1/secrets "{\"name\":\"e2e-json-blob\",\"value\":\"{\\\"retries\\\":3}\",\"type\":\"json\",\"project_id\":$pid,\"environment_id\":$env_b}" >/dev/null

    echo "==> [group $group_label] seeding a group, a machine identity and the least-privilege user"
    api POST /api/v1/groups '{"name":"e2e-platform","description":"real-backend web e2e fixture"}' >/dev/null
    api POST "/api/v1/projects/$pid/machine-identities" \
        '{"name":"e2e-ci-runner","identity_type":"ci","description":"real-backend web e2e fixture"}' >/dev/null

    local lowpriv_id
    lowpriv_id="$(api POST /api/v1/users \
        "{\"username\":\"$lowpriv_username\",\"email\":\"$lowpriv_username@example.invalid\",\"display_name\":\"Web E2E Viewer\",\"password\":\"$lowpriv_password\",\"role\":\"system_viewer\"}" |
        python3 -c 'import sys,json
try:
    print(json.load(sys.stdin)["data"]["id"])
except Exception:
    print("")')"
    if [ -n "$lowpriv_id" ]; then
        api POST "/api/v1/projects/$pid/members" \
            "{\"user_id\":$lowpriv_id,\"role\":\"project_viewer\"}" >/dev/null
        # A share so /sharing and the recipient's own shared-with-me view both
        # have a row. Secret ids are per-install sequential; read the first one
        # back rather than assuming it is 1.
        local first_secret
        first_secret="$(api GET /api/v1/secrets |
            python3 -c 'import sys,json
try:
    print(json.load(sys.stdin)["data"]["secrets"][0]["id"])
except Exception:
    print("")')"
        [ -n "$first_secret" ] && api POST "/api/v1/secrets/$first_secret/share" \
            "{\"recipient_id\":$lowpriv_id,\"is_group\":false,\"permission\":\"read\"}" >/dev/null
        echo "    least-privilege user id=$lowpriv_id (system_viewer + project_viewer on $project_name)"
    else
        echo "    (least-privilege user create returned no id)" >&2
    fi

    unset -f api
}

# run_group boots one fresh server+DB, bootstraps an admin, seeds a project,
# runs the given spec files against it, and tears it all down -- isolating
# this group's login-attempt budget from every other group's.
run_group() {
    local group_label="$1"
    shift
    local specs=("$@")
    # Disjoint ranges (server BASE+n, web BASE+1000+n), each probed on both loopback
    # families -- see lib/free-port.sh.
    local server_port
    server_port="$(free_port $((PORT_BASE + group_label)))" || fail "no free server port"
    local server_url="http://127.0.0.1:$server_port"
    local web_port
    web_port="$(free_port $((PORT_BASE + 1000 + group_label)) "$server_port")" || fail "no free web port"

    local smoke_dir
    smoke_dir="$(mktemp -d)"
    local server_pid=""
    group_cleanup() {
        [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
        CURRENT_SERVER_PID=""
        rm -rf "$smoke_dir"
    }
    trap group_cleanup RETURN

    echo "==> [group $group_label] isolated smoke test dir: $smoke_dir"

    # HOME isolation, exactly like scripts/smoke.sh -- a real ~/.keyorix/ must
    # never be visible to (or overwritten by) this run. Restored to REAL_HOME
    # before the pnpm/Playwright section below (Playwright's cached browsers
    # live under the real HOME, not this isolated one).
    export HOME="$smoke_dir"
    export KEYORIX_MASTER_PASSWORD="web-e2e-master-password-$$-${RANDOM}"
    local bootstrap_token="web-e2e-bootstrap-token-$$-${RANDOM}"
    # Deliberately unrelated to the username/email/display_name below --
    # internal/core/rules.DefaultPasswordPolicy rejects a password containing
    # any of those (see scripts/smoke.sh's own header comment on this exact trap).
    local admin_username="webe2eadmin"
    local admin_password="Quartz-Falcon-77-Ridge!-$$-${RANDOM}"
    local admin_email="webe2eadmin@example.invalid"
    # Least-privilege persona (WEB-SWEEP-1): system_viewer globally plus
    # project_viewer on the seeded project. Specs that have to prove a
    # non-admin's view of the UI -- role-gated navigation, 403 pages, an empty
    # project switcher -- need a real second account, not the admin with a flag
    # flipped client-side. Same no-substring rule as the admin password above.
    local lowpriv_username="webe2eviewer"
    local lowpriv_password="Basalt-Heron-42-Glade!-$$-${RANDOM}"
    local seed_project_name="web-e2e-project"

    # Relative to $smoke_dir (every admin subcommand below runs with cwd set
    # there) -- the CLI itself rejects an absolute --config path ("access
    # denied: path ... must be relative"), confirmed live.
    local config_rel="./keyorix.yaml"
    local config_path="$smoke_dir/keyorix.yaml"

    echo "==> [group $group_label] keyorix-server admin init"
    # --dev: the browser specs run against plain HTTP; the secure default (TLS +
    # metrics token) is covered by scripts/smoke.sh and the server tests.
    (cd "$smoke_dir" && "$SERVER_BIN" admin init --dev --config "$config_rel") || fail "admin init exited non-zero"
    [ -f "$config_path" ] || fail "admin init did not create $config_path"
    sed -i.bak -E "s/port: \"8080\"/port: \"$server_port\"/" "$config_path"
    rm -f "$config_path.bak"
    # ADR-112 item 1: security.require_mfa defaults on, which confines a session
    # without MFA to the enrolment endpoints. Every spec here logs in as the
    # shared bootstrap admin, whose MFA state is deliberately never touched (see
    # mfa-login.spec.ts's header: enabling MFA is one-way and would make every
    # other spec's admin login order-dependent). MFA enrolment and MFA login are
    # driven through the real UI by mfa-login.spec.ts on throwaway users, and the
    # default's confinement by scripts/smoke.sh (CLI) and the server tests. Opt
    # out visibly here, for this harness only, by flipping the explicit
    # `require_mfa: true` admin init writes (configs/keyorix.yaml.tpl).
    sed -i.bak -E 's/^  require_mfa: true$/  require_mfa: false/' "$config_path"
    rm -f "$config_path.bak"
    grep -q '^  require_mfa: false$' "$config_path" ||
        fail "could not set security.require_mfa: false in $config_path (did configs/keyorix.yaml.tpl change?)"

    # A spec that needs the deployment policy security.require_mfa=true declares it
    # with a line starting `// e2e-server: require_mfa=true` in its own file; its
    # group (one spec per group, MAX_SPECS_PER_GROUP=1) then boots with that policy.
    # Every other spec -- the default -- boots exactly as before, with require_mfa
    # unset (false). The policy confines every interactive session of an account
    # without MFA to the enrolment endpoints, so a group that sets it must not use
    # the shared admin's Bearer token for fixtures (see seed_demo_data below).
    local require_mfa=false spec
    for spec in "${specs[@]}"; do
        if grep -q '^// e2e-server: require_mfa=true' "$WEB_DIR/$spec"; then
            require_mfa=true
        fi
    done
    if [ "$require_mfa" = true ]; then
        echo "==> [group $group_label] ${specs[*]} asks for security.require_mfa=true"
        # Flip the explicit line back (never insert a second one: a duplicate
        # require_mfa key is a parse error or last-wins, i.e. the policy silently off).
        sed -i.bak -E 's/^  require_mfa: false$/  require_mfa: true/' "$config_path"
        rm -f "$config_path.bak"
    fi
    # Exactly one require_mfa line, with the value this group asked for.
    local want_mfa=false
    [ "$require_mfa" = true ] && want_mfa=true
    [ "$(grep -c '^[[:space:]]*require_mfa:' "$config_path")" = 1 ] ||
        fail "[group $group_label] expected exactly one require_mfa line in $config_path"
    grep -q "^  require_mfa: $want_mfa\$" "$config_path" ||
        fail "[group $group_label] security.require_mfa is not $want_mfa in $config_path"

    # Break-glass is off by default (secure default). A spec that drives it declares so with a
    # line starting `// e2e-server: break_glass=true` in its own file; its group then boots with
    # the feature on (the emergency role is the contained project_developer, as in the demo).
    # Every other group is untouched. The template carries only a commented example, so this
    # appends the one and only `break_glass:` key.
    local spec_wants_break_glass=false
    for spec in "${specs[@]}"; do
        if grep -q '^// e2e-server: break_glass=true' "$WEB_DIR/$spec"; then
            spec_wants_break_glass=true
        fi
    done
    if [ "$spec_wants_break_glass" = true ]; then
        echo "==> [group $group_label] ${specs[*]} asks for break_glass.enabled=true"
        [ "$(grep -c '^break_glass:' "$config_path")" = 0 ] ||
            fail "[group $group_label] $config_path already has a break_glass: section"
        printf '\nbreak_glass:\n  enabled: true\n  emergency_role: project_developer\n  default_ttl: 4h\n  max_ttl: 24h\n' >>"$config_path"
    fi

    # storage.database.insecure_audit_skip_reads is off by default (ADR-112 Amendment 4). A spec
    # that drives its UI banner declares `// e2e-server: insecure_audit_skip_reads=true` in its own
    # file; its group boots with the setting on. The key is inserted once, right after the
    # template's `path:` line inside storage.database, and checked to be there exactly once.
    local spec_wants_skip_reads=false
    for spec in "${specs[@]}"; do
        if grep -q '^// e2e-server: insecure_audit_skip_reads=true' "$WEB_DIR/$spec"; then
            spec_wants_skip_reads=true
        fi
    done
    if [ "$spec_wants_skip_reads" = true ]; then
        echo "==> [group $group_label] ${specs[*]} asks for storage.database.insecure_audit_skip_reads=true"
        awk '{ print } /^    path: "keyorix.db"$/ && !done { print "    insecure_audit_skip_reads: true"; done = 1 }' \
            "$config_path" >"$config_path.tmp" && mv "$config_path.tmp" "$config_path"
        [ "$(grep -c '^    insecure_audit_skip_reads: true$' "$config_path")" = 1 ] ||
            fail "[group $group_label] could not set storage.database.insecure_audit_skip_reads in $config_path (did configs/keyorix.yaml.tpl change?)"
    fi

    # The anomaly detection pass runs hourly by default, which no browser test can wait for. A spec
    # that needs an alert to appear declares `// e2e-server: anomaly_schedule=15s` in its own file;
    # its group then appends the one and only `anomaly_alerts:` section with that cadence (the
    # first pass is deferred a few seconds plus up to one interval of jitter, then it repeats).
    # The detector's scan window is floored at one hour whatever the cadence, so a short schedule
    # changes only how soon a pass happens, never what a pass looks at. Every other group is untouched.
    local anomaly_schedule=""
    for spec in "${specs[@]}"; do
        if grep -q '^// e2e-server: anomaly_schedule=[0-9]*s$' "$WEB_DIR/$spec"; then
            anomaly_schedule="$(grep -m1 '^// e2e-server: anomaly_schedule=' "$WEB_DIR/$spec" | sed -E 's/.*anomaly_schedule=([0-9]+s)$/\1/')"
        fi
    done
    if [ -n "$anomaly_schedule" ]; then
        echo "==> [group $group_label] ${specs[*]} asks for anomaly_alerts.schedule=$anomaly_schedule"
        [ "$(grep -c '^anomaly_alerts:' "$config_path")" = 0 ] ||
            fail "[group $group_label] $config_path already has an anomaly_alerts: section"
        printf '\nanomaly_alerts:\n  enabled: true\n  schedule: %s\n' "$anomaly_schedule" >>"$config_path"
    fi

    echo "==> [group $group_label] keyorix-server admin encryption init"
    (cd "$smoke_dir" && "$SERVER_BIN" admin encryption init --config "$config_rel") ||
        fail "admin encryption init exited non-zero"

    echo "==> [group $group_label] keyorix-server admin migrate"
    (cd "$smoke_dir" && "$SERVER_BIN" admin migrate --config "$config_rel") || fail "admin migrate exited non-zero"

    echo "==> [group $group_label] starting keyorix-server"
    # `exec` replaces the subshell with the server binary itself, so $! below
    # is the server's own PID, not a wrapper subshell's -- without it, killing
    # $! on cleanup would only kill a `cd`-then-exited subshell, leaking the
    # actual server process as an orphan.
    (cd "$smoke_dir" && exec env KEYORIX_CONFIG_PATH="$config_rel" KEYORIX_BOOTSTRAP_TOKEN="$bootstrap_token" "$SERVER_BIN") \
        >"$smoke_dir/server.log" 2>&1 &
    server_pid=$!
    CURRENT_SERVER_PID="$server_pid"

    for _ in $(seq 1 30); do
        if curl -fs "$server_url/health" >/dev/null 2>&1; then break; fi
        # Our server died (e.g. EADDRINUSE: another session took the port between
        # the probe and the bind): stop waiting, so a stranger's /health below
        # cannot pass for ours.
        kill -0 "$server_pid" 2>/dev/null || break
        sleep 0.5
    done
    if ! kill -0 "$server_pid" 2>/dev/null; then
        echo "keyorix-server exited before becoming healthy (port $server_port taken?) -- see $smoke_dir/server.log" >&2
        cat "$smoke_dir/server.log" >&2
        fail "[group $group_label] keyorix-server did not start; re-run, or pin a range with KEYORIX_E2E_PORT_BASE"
    fi
    if ! curl -fs "$server_url/health" >/dev/null 2>&1; then
        echo "server never became healthy -- see $smoke_dir/server.log" >&2
        cat "$smoke_dir/server.log" >&2
        fail "[group $group_label] keyorix-server did not start"
    fi

    echo "==> [group $group_label] bootstrapping admin via POST /system/init"
    local init_code
    init_code="$(curl -s -o "$smoke_dir/init-response.json" -w '%{http_code}' -X POST "$server_url/system/init" \
        -H "Content-Type: application/json" \
        -H "X-Keyorix-Bootstrap-Token: $bootstrap_token" \
        -d "{\"username\":\"$admin_username\",\"email\":\"$admin_email\",\"password\":\"$admin_password\",\"display_name\":\"Web E2E Admin\"}")"
    [ "$init_code" = "200" ] || fail "[group $group_label] POST /system/init returned $init_code: $(cat "$smoke_dir/init-response.json")"

    echo "==> [group $group_label] creating a project + secret so the real pages have something to show"
    # The login response is captured to a file first, and parsed with a guard,
    # so a login that FAILS reports the server's own error instead of a Python
    # KeyError on "data" -- the shape every non-200 login response takes.
    local token
    curl -s -X POST "$server_url/auth/login" -H "Content-Type: application/json" \
        -d "{\"username\":\"$admin_username\",\"password\":\"$admin_password\"}" \
        -o "$smoke_dir/login-response.json"
    token="$(python3 -c 'import sys,json
try:
    print(json.load(open(sys.argv[1]))["data"]["token"])
except Exception:
    print("")' "$smoke_dir/login-response.json")"
    [ -n "$token" ] ||
        fail "[group $group_label] POST /auth/login did not return a token: $(cat "$smoke_dir/login-response.json")"
    if [ "$require_mfa" = true ]; then
        # This Bearer token is an interactive session of an account with no MFA, so
        # the policy 403s every seeding call (MFAEnrollmentRequired). The spec that
        # asked for the policy owns what it needs.
        echo "==> [group $group_label] require_mfa group: skipping seed_demo_data"
    else
        seed_demo_data "$group_label" "$server_url" "$token" "$seed_project_name" \
            "$lowpriv_username" "$lowpriv_password"
    fi

    echo "==> [group $group_label] running Playwright specs against the real backend: ${specs[*]}"
    export HOME="$REAL_HOME"
    export KEYORIX_E2E_BACKEND_URL="$server_url"
    export KEYORIX_E2E_ADMIN_USERNAME="$admin_username"
    export KEYORIX_E2E_ADMIN_PASSWORD="$admin_password"
    export KEYORIX_E2E_LOWPRIV_USERNAME="$lowpriv_username"
    export KEYORIX_E2E_LOWPRIV_PASSWORD="$lowpriv_password"
    export KEYORIX_E2E_PROJECT_NAME="$seed_project_name"
    export KEYORIX_E2E_WEB_PORT="$web_port"
    # Which suite's directory Playwright resolves the spec paths against (playwright.config.real.ts).
    case "${specs[0]}" in
    e2e/demo/*) export KEYORIX_E2E_TEST_DIR="./e2e/demo" ;;
    *) export KEYORIX_E2E_TEST_DIR="./e2e/real" ;;
    esac

    (cd "$WEB_DIR" && pnpm exec playwright test --config=playwright.config.real.ts "${specs[@]}") ||
        fail "[group $group_label] Playwright real-backend specs failed"
}

group_num=0
for group_specs in "${SPEC_GROUPS[@]}"; do
    group_num=$((group_num + 1))
    # Intentional word-splitting: each SPEC_GROUPS element is a
    # space-separated list of relative paths.
    # shellcheck disable=SC2086
    run_group "$group_num" $group_specs
done

echo ""
echo "WEB E2E SMOKE PASSED"
