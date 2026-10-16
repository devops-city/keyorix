#!/usr/bin/env bash
# scripts/demo/seed.sh — the demo's org seed, shared by scripts/demo/up.sh (container)
# and scripts/demo/native-up.sh (host binaries, no Docker). Source it, don't run it.
#
# demo_seed_org seeds a realistic org through the public API/CLI only (never the
# database): 3 projects, 2 groups, alice (least privilege), security-officer (second
# admin), 3 secrets, rotation policies, one machine identity, a first audit trail and
# one completed access-review campaign per project. The seed is CALM: everything on the
# Compliance page is green except one deliberate, explainable gap (payments-webhook-secret
# in Production has no rotation policy).
#
# Caller contract (all must be set; the admin session must already be exported as
# KEYORIX_SERVER / KEYORIX_TOKEN and lib.sh + step/ok/info helpers sourced):
#   CLI_BIN CLI_HOME SERVER_URL PORT ADMIN_EMAIL ALICE_PASSWORD SECOFFICER_PASSWORD
# Results: ALICE_MFA_SECRET ALICE_MFA_URI ALICE_RECOVERY_CODES ALICE_TOKEN
#          SECOFFICER_MFA_SECRET SECOFFICER_MFA_URI SECOFFICER_RECOVERY_CODES
#          SECOFFICER_TOKEN MACHINE_TOKEN
# shellcheck disable=SC2034  # results are read by the sourcing script

demo_seed_org() {
  step "Seeding org structure: 2 projects, 2 groups"
  "$CLI_BIN" project create --name backend-api --description "Backend API" >/dev/null
  "$CLI_BIN" project create --name mobile-app --description "Mobile App" >/dev/null
  # A global role makes nobody a member of any project, and only an owner who is a
  # member of the secret's project may share it (#2976). Make the admin a member of
  # backend-api so the demo's share step works on db-password.
  "$CLI_BIN" rbac assign-role --user "$ADMIN_EMAIL" --role project_admin --project backend-api >/dev/null
  "$CLI_BIN" group create --name platform-team --description "Platform team" >/dev/null
  "$CLI_BIN" group create --name mobile-team --description "Mobile team" >/dev/null
  ok "3 projects (default, backend-api, mobile-app), 2 groups; admin is project_admin on backend-api"

  step "Seeding a least-privilege user"
  KEYORIX_INITIAL_PASSWORD="$ALICE_PASSWORD" "$CLI_BIN" user create --username alice --email alice@keyorix.demo >/dev/null
  "$CLI_BIN" rbac assign-role --user alice@keyorix.demo --role project_viewer --project backend-api >/dev/null
  ok "alice: project_viewer on backend-api only"

  # A healthy fresh posture needs 100% second-factor coverage (control
  # second-factor), so alice is enrolled here, like the admin, and gets one real
  # read below (a grant nobody ever used is a "dormant access" gap). The live
  # enrolment moment of docs/demo/GOLDEN-PATH.md section 2 uses a brand-new user.
  step "Enrolling TOTP for alice (every seeded account has a second factor)"
  demo_enroll_mfa "$SERVER_URL" alice "$ALICE_PASSWORD" || { echo "alice MFA enrolment failed (see above)" >&2; return 1; }
  ALICE_MFA_SECRET="$DEMO_MFA_SECRET"
  ALICE_MFA_URI="$DEMO_MFA_URI"
  ALICE_RECOVERY_CODES="$DEMO_RECOVERY_CODES"
  ALICE_TOKEN="$DEMO_TOKEN"
  ok "alice enrolled"

  # The independent reviewer: with a single global admin, break-glass activations
  # can never be reviewed by anyone but their activator, which the control matrix
  # (rightly) reports as a gap. A second administrator, security-officer, is the
  # separate approver a real deployment has.
  step "Seeding a second administrator (independent break-glass reviewer)"
  KEYORIX_INITIAL_PASSWORD="$SECOFFICER_PASSWORD" "$CLI_BIN" user create --username security-officer --email security-officer@keyorix.demo >/dev/null
  "$CLI_BIN" rbac assign-role --user security-officer@keyorix.demo --role admin >/dev/null
  demo_enroll_mfa "$SERVER_URL" security-officer "$SECOFFICER_PASSWORD" || { echo "security-officer MFA enrolment failed (see above)" >&2; return 1; }
  SECOFFICER_MFA_SECRET="$DEMO_MFA_SECRET"
  SECOFFICER_MFA_URI="$DEMO_MFA_URI"
  SECOFFICER_RECOVERY_CODES="$DEMO_RECOVERY_CODES"
  SECOFFICER_TOKEN="$DEMO_TOKEN"
  ok "security-officer: admin, TOTP enrolled"

  step "Seeding secrets with versions"
  # Values go in via a relative file / stdin, never --value (which warns).
  local seed_value_file="$CLI_HOME/.seed-value"
  _demo_create_secret() { # NAME VALUE PROJECT_ID ENVIRONMENT_ID
    ( umask 077; printf '%s' "$2" > "$seed_value_file" )
    # --from-file refuses absolute paths: run from the file's own directory and pass a bare name.
    ( cd "$CLI_HOME" && "$CLI_BIN" secret create --name "$1" --from-file "$(basename "$seed_value_file")" --project "$3" --environment "$4" >/dev/null )
    rm -f "$seed_value_file"
  }
  _demo_create_secret "stripe-api-key" "sk_test_demo_seed_v1" 1 1
  # rotate has no file flag; its stdin prompt writes "New secret value (hidden):" to
  # stderr, so keep stderr out of the presenter's output unless the command fails.
  printf '%s\n' "sk_test_demo_seed_v2" | "$CLI_BIN" secret rotate --id 1 >/dev/null 2>"$CLI_HOME/.rotate-err" \
    || { cat "$CLI_HOME/.rotate-err" >&2; return 1; }
  rm -f "$CLI_HOME/.rotate-err"
  _demo_create_secret "db-password" "demo-db-pass-v1" 2 4
  # The Secrets tab opens on Production: seed one there too so the presenter's
  # first view of backend-api is not empty (DEMO-WALK-3 finding 36).
  _demo_create_secret "payments-webhook-secret" "whsec_demo_seed_v1" 2 6
  # Ten more service credentials in the default project (ids 4-13). They give the
  # bulk-read anomaly scenario (scripts/demo/trigger-anomaly.sh bulk-read) a realistic
  # vault to "exfiltrate" - the detector needs >= 5 (high: >= 10) secrets a principal has
  # never read - and are covered by the default-90d rotation policy below.
  local svc
  for svc in aws-access-key github-deploy-token sendgrid-api-key slack-bot-token datadog-api-key \
             sentry-dsn redis-password s3-backup-key jwt-signing-key smtp-password; do
    _demo_create_secret "$svc" "demo-${svc}-v1" 1 1
  done
  ok "13 secrets (one with 2 versions); backend-api has one in Development and one in Production; 11 in default"

  # Every secret carries a data-classification label (ISO 27001 A.5.12), so the
  # "Secret data classification" control starts green.
  local sid
  for sid in 1 2 3 4 5 6 7 8 9 10 11 12 13; do
    "$CLI_BIN" secret classify --id "$sid" --level confidential >/dev/null
  done

  # Rotation policies (A.5.15). The two long-standing secrets are covered; the
  # Production webhook secret deliberately is NOT. That one uncovered production
  # secret is the demo's single, deliberate finding (the "Secret-rotation hygiene"
  # control shows "2 of 3 secrets covered") and GOLDEN-PATH.md section 1b fixes it
  # live. Everything else on the Compliance page is green on a fresh demo.
  step "Seeding rotation policies (one production secret deliberately left uncovered)"
  "$CLI_BIN" rotation create --name "default-90d" --scope project --project-id 1 --interval-days 90 >/dev/null
  "$CLI_BIN" rotation create --name "backend-api-dev-90d" --scope environment --environment-id 4 --interval-days 90 >/dev/null
  ok "stripe-api-key and db-password are on a 90-day rotation; payments-webhook-secret (Production) has no policy"

  step "Seeding a machine identity"
  "$CLI_BIN" machine create --name ci-app --project default --type ci --classification internal >/dev/null
  "$CLI_BIN" machine grant-role ci-app --project default --role project_viewer >/dev/null
  local out
  out="$("$CLI_BIN" machine token issue ci-app --name "ci-pipeline-token" --project default --classification internal)"
  MACHINE_TOKEN="$(echo "$out" | grep -oE 'kx_machine_[A-Za-z0-9_-]+' | head -1)"
  ok "ci-app machine identity, project_viewer on default"

  step "Populating an audit trail (reveal + rotate + a machine read already happened above)"
  "$CLI_BIN" secret get --id 1 --show-value >/dev/null
  local hdr="$CLI_HOME/.machine-hdr"
  ( umask 077; printf 'Authorization: Bearer %s\n' "$MACHINE_TOKEN" > "$hdr" )
  curl -s -H "@$hdr" "http://localhost:${PORT}/api/v1/secrets/1?include_value=true" >/dev/null
  rm -f "$hdr"
  demo_api GET "$SERVER_URL" "/api/v1/secrets/value?ref=backend-api%2Fdevelopment%2Fdb-password" "$ALICE_TOKEN"
  [ "$DEMO_HTTP_CODE" = "200" ] || { echo "alice could not read backend-api/development/db-password ($DEMO_HTTP_CODE): $DEMO_BODY" >&2; return 1; }
  ok "Audit trail populated — 'keyorix audit logs' now has real events to show"

  # Access review (A.5.18): one completed recertification campaign per project,
  # every seeded grant attested by the admin, so "Access recertification" starts
  # green. Done last so the campaigns snapshot the final set of grants.
  step "Running the first access-review campaign for each project"
  local pid
  for pid in 1 2 3; do
    demo_review_project "$SERVER_URL" "$KEYORIX_TOKEN" "$SECOFFICER_TOKEN" "$pid" "Initial access review" "Initial demo access review: grant is expected" \
      || { echo "access review of project $pid failed (see above)" >&2; return 1; }
  done
  ok "3 projects reviewed and closed"
}
