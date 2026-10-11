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
#   Requires: go, pnpm, a working `pnpm exec playwright install` (browsers
#   already cached locally is fine -- this script does not re-install them).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER_BIN="$REPO_ROOT/bin/keyorix-server"
WEB_DIR="$REPO_ROOT/web"
MAX_SPECS_PER_GROUP=1

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
    mapfile -t ALL_SPECS < <(cd "$WEB_DIR" && find e2e/real -maxdepth 1 -name '*.spec.ts' | sort)
fi
[ "${#ALL_SPECS[@]}" -gt 0 ] || { echo "no e2e/real/*.spec.ts files found under $WEB_DIR" >&2; exit 1; }

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

# free_port prints the first TCP port at or above $1 that nothing is listening on.
#
# 2026-10-05 (#2738): this harness used FIXED ports -- 18189+group for the server and
# 18190+group for the Vite dev server -- two ranges that INTERLEAVE, so group N+1's
# server port IS group N's web port. Two failures follow from that, both confirmed live
# on this machine:
#
#   1. A second concurrent run of this script on the same host collides outright. The
#      colliding server then fails to bind while the /health poll SUCCEEDS, because the
#      other run's server answers it -- so the script sails past its own
#      "did-it-start?" gate and sends the rest of the group's setup, including POST
#      /system/init, to a stranger's server. (Harmless in the event: /system/init on an
#      already-initialised system is a no-op. The next call, /auth/login with this run's
#      own password, 401s against that other admin, and the failure looks like a broken
#      spec.)
#   2. Any lingering dev server from group N makes group N+1's server fail to bind the
#      same way. MAX_SPECS_PER_GROUP=1 multiplies the number of groups, so this went
#      from unlikely to likely.
#
# Probing for a free port cannot be atomic (something may grab it between the probe and
# the bind), but it removes both deterministic collisions. Uses bash's own /dev/tcp
# rather than nc, so it needs nothing extra installed.
free_port() {
    local p=$1
    while [ "$p" -lt 65000 ]; do
        if ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
            echo "$p"
            return 0
        fi
        exec 3<&- 2>/dev/null || true
        p=$((p + 1))
    done
    fail "no free TCP port found at or above $1"
}

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
    # Disjoint ranges (server 182xx, web 183xx), each probed for availability -- see
    # free_port's comment for the interleaved-fixed-ports failures this replaces.
    local server_port
    server_port="$(free_port $((18200 + group_label)))"
    local server_url="http://127.0.0.1:$server_port"
    local web_port
    web_port="$(free_port $((18300 + group_label)))"

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
        sleep 0.5
    done
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
