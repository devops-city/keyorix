//go:build e2e

package e2e

import (
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// groupMachineIdentities creates a machine identity in the smoke project,
// issues + classifies + revokes a token (mirroring scripts/smoke.sh's
// CLI-driven machine flow, but over raw HTTP), grants/revokes the custom
// role from groupUsersRolesRBAC, transitions its lifecycle state, and
// sweeps the read-only sub-resources (tokens/roles/oidc-bindings list,
// top-level audit/audit.csv). oidc-bindings CREATE/DELETE and
// migrate-from-user are skipped (see coverage.go) -- they need a configured
// external OIDC issuer / a pre-existing user-owned credential to migrate,
// neither of which this fresh-install smoke run has.
func groupMachineIdentities(ctx *smokeCtx) {
	c := ctx.c
	p := fmt.Sprintf("/api/v1/projects/%d", ctx.projectID)

	created := c.callExpect("POST", "POST /api/v1/projects/{id}/machine-identities", p+"/machine-identities",
		map[string]string{"name": "e2e-smoke-machine", "identity_type": "ci"}, 200, 201)
	var miEnv struct {
		MachineIdentity idOnly `json:"machine_identity"`
	}
	c.unmarshalData(created, &miEnv, "create machine identity")
	miID := miEnv.MachineIdentity.ID
	m := fmt.Sprintf("%s/machine-identities/%d", p, miID)

	c.callExpect("PATCH", "PATCH /api/v1/projects/{id}/machine-identities/{machineId}/classification",
		m+"/classification", map[string]string{"classification": "internal"}, 200)
	c.callExpect("PUT", "PUT /api/v1/projects/{id}/machine-identities/{machineId}", m,
		map[string]string{"action": "activate"}, 200, 409)

	tokenCreated := c.callExpect("POST", "POST /api/v1/projects/{id}/machine-identities/{machineId}/tokens",
		m+"/tokens", map[string]interface{}{"name": "e2e-smoke-token", "expires_in_days": 30}, 200, 201)
	var tok idOnly
	c.unmarshalData(tokenCreated, &tok, "issue machine token")
	c.callExpect("GET", "GET /api/v1/projects/{id}/machine-identities/{machineId}/tokens", m+"/tokens", nil, 200)
	if tok.ID != 0 {
		c.callExpect("PATCH", "PATCH /api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}/classification",
			fmt.Sprintf("%s/tokens/%d/classification", m, tok.ID), map[string]string{"classification": "internal"}, 200)
		c.callExpect("DELETE", "DELETE /api/v1/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}",
			fmt.Sprintf("%s/tokens/%d", m, tok.ID), nil, 200, 204)
	}

	if ctx.roleID != 0 {
		c.callExpect("POST", "POST /api/v1/projects/{id}/machine-identities/{machineId}/roles", m+"/roles",
			map[string]interface{}{"role_id": ctx.roleID}, 200, 201)
		c.callExpect("GET", "GET /api/v1/projects/{id}/machine-identities/{machineId}/roles", m+"/roles", nil, 200)
		c.callExpect("DELETE", "DELETE /api/v1/projects/{id}/machine-identities/{machineId}/roles/{roleId}",
			fmt.Sprintf("%s/roles/%d", m, ctx.roleID), nil, 200, 204, 404)
	}

	c.call("GET", "GET /api/v1/projects/{id}/machine-identities/{machineId}/oidc-bindings", m+"/oidc-bindings", nil)
	// Best-effort tail (see groups_catalog.go's identical note): no
	// configured external OIDC issuer exists in this smoke run, so these are
	// expected to 400/422, not 200 -- c.call still proves they don't 5xx.
	c.call("POST", "POST /api/v1/projects/{id}/machine-identities/{machineId}/oidc-bindings", m+"/oidc-bindings",
		map[string]interface{}{"issuer": "https://e2e-smoke-unreachable.invalid", "subject": "e2e-smoke"})
	c.call("DELETE", "DELETE /api/v1/projects/{id}/machine-identities/{machineId}/oidc-bindings/{bindingId}", m+"/oidc-bindings/1", nil)
	c.call("POST", "POST /api/v1/projects/{id}/machine-identities/migrate-from-user", p+"/machine-identities/migrate-from-user",
		map[string]interface{}{"user_id": ctx.userID, "name": "e2e-smoke-migrated"})

	c.callExpect("GET", "GET /api/v1/machine-identities/audit", "/api/v1/machine-identities/audit", nil, 200)
	c.callExpect("GET", "GET /api/v1/machine-identities/audit.csv", "/api/v1/machine-identities/audit.csv", nil, 200)
}

// groupShares grants the smoke user project_admin/project_viewer (Sharing's
// own membership requirement -- see scripts/smoke.sh's own comment on this
// exact prerequisite) for both the admin owner and the recipient, shares
// the smoke secret, then lists/updates/deletes the share.
func groupShares(ctx *smokeCtx) {
	c := ctx.c
	p := fmt.Sprintf("/api/v1/projects/%d", ctx.projectID)
	c.call("POST", "POST /api/v1/projects/{id}/members", p+"/members",
		map[string]interface{}{"user_id": ctx.adminUserID, "role": "project_admin"})

	s := fmt.Sprintf("/api/v1/secrets/%d", ctx.secretID)
	created := c.callExpect("POST", "POST /api/v1/secrets/{id}/share", s+"/share",
		map[string]interface{}{"recipient_id": ctx.userID, "permission": "read"}, 200, 201)
	var share idOnly
	c.unmarshalData(created, &share, "create share")

	c.callExpect("GET", "GET /api/v1/shares", "/api/v1/shares", nil, 200)
	// Owner-scoped list (SHARE-3): the admin was just made a member of the project
	// and created this share, so it is listed here too.
	c.callExpect("GET", "GET /api/v1/shares/owned", "/api/v1/shares/owned", nil, 200)
	if share.ID != 0 {
		sh := fmt.Sprintf("/api/v1/shares/%d", share.ID)
		c.callExpect("PUT", "PUT /api/v1/shares/{id}", sh, map[string]string{"permission": "write"}, 200)
		c.callExpect("DELETE", "DELETE /api/v1/shares/{id}", sh, nil, 200, 204)
	}

	c.callExpect("GET", "GET /api/v1/shared-secrets", "/api/v1/shared-secrets", nil, 200)
}

// groupRotationPolicies exercises project-scoped policy create/list/get/
// update/delete plus the two report endpoints (evaluate/status), and the
// top-level rotation-calendar/rotation-plan reports (distinct feature
// groups, but cheap and dependency-free to fold in here).
func groupRotationPolicies(ctx *smokeCtx) {
	c := ctx.c
	created := c.callExpect("POST", "POST /api/v1/rotation-policies", "/api/v1/rotation-policies", map[string]interface{}{
		"name": "e2e-smoke-rotation-policy", "scope": "project", "project_id": ctx.projectID, "interval_days": 90,
	}, 200, 201)
	var pol idOnly
	c.unmarshalData(created, &pol, "create rotation policy")
	rp := fmt.Sprintf("/api/v1/rotation-policies/%d", pol.ID)

	c.callExpect("GET", "GET /api/v1/rotation-policies", "/api/v1/rotation-policies", nil, 200)
	c.callExpect("GET", "GET /api/v1/rotation-policies/{id}", rp, nil, 200)
	c.callExpect("GET", "GET /api/v1/rotation-policies/evaluate", "/api/v1/rotation-policies/evaluate", nil, 200)
	c.callExpect("GET", "GET /api/v1/rotation-policies/status", "/api/v1/rotation-policies/status", nil, 200)
	c.callExpect("PUT", "PUT /api/v1/rotation-policies/{id}", rp, map[string]interface{}{
		"name": "e2e-smoke-rotation-policy", "scope": "project", "project_id": ctx.projectID, "interval_days": 60,
	}, 200)
	c.callExpect("DELETE", "DELETE /api/v1/rotation-policies/{id}", rp, nil, 200, 204)

	c.callExpect("GET", "GET /api/v1/rotation-calendar", "/api/v1/rotation-calendar?from=2020-01-01&to=2099-01-01", nil, 200)
	c.callExpect("GET", "GET /api/v1/rotation-plan", "/api/v1/rotation-plan", nil, 200)
}

// groupDynamicSecrets creates a config against a syntactically valid but
// unreachable admin DSN (non-private host, so the SSRF guard allows
// registration -- the connection only happens at issue time, which this
// driver never calls, per the research this file's plan was built from:
// internal/core/dynamic_secrets.go's own comment that an unresolvable
// hostname is deliberately allowed at register time). This proves the
// dynamic-secrets CONFIG tables/CRUD work on a fresh install without
// needing a real Postgres/MySQL/AWS backend.
func groupDynamicSecrets(ctx *smokeCtx) {
	c := ctx.c
	created := c.callExpect("POST", "POST /api/v1/dynamic-secrets/configs", "/api/v1/dynamic-secrets/configs", map[string]interface{}{
		"name": "e2e-smoke-dynamic-config", "project_id": ctx.projectID, "environment_id": ctx.environmentID,
		"backend_type": "postgres", "admin_dsn": "postgres://user:pass@e2e-smoke-unreachable.invalid:5432/db",
		"default_ttl_seconds": 300, "max_ttl_seconds": 3600, "max_active_leases": 5,
	}, 200, 201)
	var cfg idOnly
	c.unmarshalData(created, &cfg, "create dynamic secret config")
	dc := fmt.Sprintf("/api/v1/dynamic-secrets/configs/%d", cfg.ID)

	c.callExpect("GET", "GET /api/v1/dynamic-secrets/configs", "/api/v1/dynamic-secrets/configs", nil, 200)
	c.callExpect("GET", "GET /api/v1/dynamic-secrets/configs/{id}", dc, nil, 200)
	c.callExpect("PATCH", "PATCH /api/v1/dynamic-secrets/configs/{id}/classification", dc+"/classification",
		map[string]string{"classification": "internal"}, 200)
	c.callExpect("PATCH", "PATCH /api/v1/dynamic-secrets/configs/{id}/enabled", dc+"/enabled",
		map[string]bool{"enabled": false}, 200)
	c.callExpect("GET", "GET /api/v1/dynamic-secrets/configs/{id}/leases", dc+"/leases", nil, 200)
	c.callExpect("POST", "POST /api/v1/dynamic-secrets/configs/{id}/revoke-all", dc+"/revoke-all", nil, 200)
}

// groupAccessRequests exercises the PROJECT-scoped access-request family
// (distinct from secret-access-requests in groups_catalog.go): create,
// list, resolve individually (PUT), withdraw, and a best-effort pass at the
// two bulk routes. core.RequestProjectAccess (#G82) refuses a second
// PENDING request for the same (user, project) pair, so each request below
// is created only after the PREVIOUS one has been resolved via the proven
// single-item PUT path -- the bulk-approve/bulk-reject routes are exercised
// best-effort (c.call, not gating subsequent creates on their per-item
// result) since BulkApproveAccessRequests reports success/failure PER
// REQUEST ID inside a 200 response body, not via HTTP status, so this
// driver cannot cheaply assert an item actually resolved without parsing
// that inner result -- the route is still genuinely exercised either way.
func groupAccessRequests(ctx *smokeCtx) {
	c := ctx.c
	userClient := newClient(ctx.t, c.baseURL)
	userClient.login("e2esmokeuser", harness.SmokeUserPassword)

	// suggested_role/granted_role here is deliberately "project_admin", NOT
	// "project_viewer" -- ctx.userID already holds project_viewer (granted
	// directly via POST /members in groupUsersRolesRBAC/groupShares), and
	// approving a request that grants an ALREADY-HELD role hits UserRole's
	// composite primary key (AssignUserRole's INSERT fails outright, per
	// ApproveAccessRequestWithExpiry's own doc comment on #1646) with a raw,
	// unclassified storage error -- a real, separately-confirmed gap (see the
	// SESSION-I report), worked around here rather than fixed in this PR
	// series to keep this driver's own scope bounded.
	p := fmt.Sprintf("/api/v1/projects/%d", ctx.projectID)
	reqA := userClient.callExpect("POST", "POST /api/v1/projects/{id}/access-requests", p+"/access-requests",
		map[string]string{"suggested_role": "project_admin", "reason": "e2e smoke A"}, 200, 201)
	c.callExpect("GET", "GET /api/v1/projects/{id}/access-requests", p+"/access-requests", nil, 200)

	var envA accessRequestEnvelope
	userClient.unmarshalData(reqA, &envA, "create project access request A")
	if envA.AccessRequest.ID != 0 {
		rp := fmt.Sprintf("%s/access-requests/%d", p, envA.AccessRequest.ID)
		c.callExpect("PUT", "PUT /api/v1/projects/{id}/access-requests/{requestId}", rp,
			map[string]string{"action": "approve", "granted_role": "project_admin"}, 200)
		c.call("POST", "POST /api/v1/access-requests/bulk-approve", "/api/v1/access-requests/bulk-approve",
			map[string]interface{}{"request_ids": []uint{envA.AccessRequest.ID}})
	}

	reqB := userClient.callExpect("POST", "POST /api/v1/projects/{id}/access-requests", p+"/access-requests",
		map[string]string{"suggested_role": "project_viewer", "reason": "e2e smoke B"}, 200, 201)
	var envB accessRequestEnvelope
	userClient.unmarshalData(reqB, &envB, "create project access request B")
	if envB.AccessRequest.ID != 0 {
		rp := fmt.Sprintf("%s/access-requests/%d", p, envB.AccessRequest.ID)
		c.callExpect("PUT", "PUT /api/v1/projects/{id}/access-requests/{requestId}", rp,
			map[string]string{"action": "reject", "reason": "e2e smoke individual reject"}, 200)
		c.call("POST", "POST /api/v1/access-requests/bulk-reject", "/api/v1/access-requests/bulk-reject",
			map[string]interface{}{"request_ids": []uint{envB.AccessRequest.ID}, "reason": "e2e smoke bulk reject"})
	}

	reqD := userClient.callExpect("POST", "POST /api/v1/projects/{id}/access-requests", p+"/access-requests",
		map[string]string{"suggested_role": "project_viewer", "reason": "e2e smoke D"}, 200, 201)
	var envD accessRequestEnvelope
	userClient.unmarshalData(reqD, &envD, "create project access request D")
	if envD.AccessRequest.ID != 0 {
		userClient.callExpect("POST", "POST /api/v1/projects/{id}/access-requests/{requestId}/withdraw",
			fmt.Sprintf("%s/access-requests/%d/withdraw", p, envD.AccessRequest.ID), nil, 200)
	}

	// The userClient's own route hits merge into c's coverage bookkeeping
	// too, since both clients target the same routes.json key space.
	for _, k := range userClient.hitKeys() {
		c.skip(k)
	}
}

// groupRiskExceptions creates and lists risk exceptions. approve is skipped
// (see coverage.go): risk_exceptions.go enforces dual control (the approver
// must be a DIFFERENT system.write holder than the creator), which this
// driver's single shared admin session cannot satisfy without a second
// distinct privileged account -- not yet automated.
func groupRiskExceptions(ctx *smokeCtx) {
	c := ctx.c
	// expires_at must be in the future but within maxRiskExceptionDuration (365
	// days, internal/core/risk_exceptions.go) -- a fixed far-future literal like
	// "2099-01-01" is rejected with 400 ("must be within N days"); 90 days out
	// is comfortably inside the window regardless of when this test runs.
	expires := time.Now().UTC().Add(90 * 24 * time.Hour).Format(time.RFC3339)
	created := c.callExpect("POST", "POST /api/v1/risk-exceptions", "/api/v1/risk-exceptions", map[string]interface{}{
		"title": "e2e-smoke-risk-exception", "category": "rotation", "reference": "e2e-smoke",
		"justification": "SESSION-I smoke test", "expires_at": expires,
	}, 200, 201)
	var excEnv struct {
		Exception idOnly `json:"exception"`
	}
	c.unmarshalData(created, &excEnv, "create risk exception")
	c.callExpect("GET", "GET /api/v1/risk-exceptions", "/api/v1/risk-exceptions", nil, 200)
	if excEnv.Exception.ID != 0 {
		c.callExpect("DELETE", "DELETE /api/v1/risk-exceptions/{id}", fmt.Sprintf("/api/v1/risk-exceptions/%d", excEnv.Exception.ID), nil, 200, 204)
	} else {
		c.skip("DELETE /api/v1/risk-exceptions/{id}")
	}
}

// groupLegalHold places, reads, and lifts the deployment-wide legal hold.
// Deployment-wide means this must run in a slot where no other group's
// assertions depend on secrets/projects being deletable while the hold is
// active -- placed and immediately lifted back-to-back for that reason.
func groupLegalHold(ctx *smokeCtx) {
	c := ctx.c
	c.callExpect("POST", "POST /api/v1/legal-hold", "/api/v1/legal-hold", map[string]string{"reason": "SESSION-I smoke"}, 200, 201)
	c.callExpect("GET", "GET /api/v1/legal-hold", "/api/v1/legal-hold", nil, 200)
	c.callExpect("DELETE", "DELETE /api/v1/legal-hold", "/api/v1/legal-hold", map[string]string{"reason": "SESSION-I smoke lift"}, 200, 204)
}

// groupInvitations exercises the global (deployment-wide) invite-by-email
// route. The project-scoped sibling (POST /projects/{id}/invitations) plus
// its GET/resend/DELETE routes are exercised inline in
// groupProjectsAndEnvironments's cheap GET sweep and here.
func groupInvitations(ctx *smokeCtx) {
	c := ctx.c
	c.callExpect("POST", "POST /api/v1/invitations", "/api/v1/invitations",
		map[string]string{"email": "e2e-smoke-invitee@smoke.local", "role": "system_viewer"}, 200, 201)

	p := fmt.Sprintf("/api/v1/projects/%d", ctx.projectID)
	created := c.callExpect("POST", "POST /api/v1/projects/{id}/invitations", p+"/invitations",
		map[string]string{"email": "e2e-smoke-project-invitee@smoke.local", "role": "project_viewer"}, 200, 201)
	var inv struct {
		Invitation idOnly `json:"invitation"`
	}
	c.unmarshalData(created, &inv, "create project invitation")
	if inv.Invitation.ID == 0 {
		// Some builds return the invitation flat rather than wrapped.
		var flat idOnly
		c.unmarshalData(created, &flat, "create project invitation (flat)")
		inv.Invitation = flat
	}
	if inv.Invitation.ID != 0 {
		c.callExpect("POST", "POST /api/v1/projects/{id}/invitations/{invitationId}/resend",
			fmt.Sprintf("%s/invitations/%d/resend", p, inv.Invitation.ID), nil, 200, 400)
		c.callExpect("DELETE", "DELETE /api/v1/projects/{id}/invitations/{invitationId}",
			fmt.Sprintf("%s/invitations/%d", p, inv.Invitation.ID), nil, 200, 204)
	}
}

// groupAdminAndSystem sweeps every side-effect-free admin/system report
// endpoint plus one purely-additive job (record-hygiene-snapshot), the
// top-level hygiene/pat-hygiene/machine-token-hygiene reports, and the
// connect (external secret reference) read-only surface. It runs LAST and
// finishes by deleting the project (cascading, force=true) and the smoke
// user this whole run built up -- the two DELETE routes every earlier group
// depended on the target NOT yet being gone.
func groupAdminAndSystem(ctx *smokeCtx) {
	c := ctx.c
	c.callExpect("GET", "GET /api/v1/admin/anomaly-config", "/api/v1/admin/anomaly-config", nil, 200)
	// 403 is a legitimate outcome here, not just 200: billing reporting is
	// commercial-license-gated (see CLAUDE.md's "Commercial feature gating"),
	// and this driver's fresh install has no license configured.
	c.callExpect("GET", "GET /api/v1/admin/billing/report",
		"/api/v1/admin/billing/report?from=2020-01-01T00:00:00Z&to=2099-01-01T00:00:00Z", nil, 200, 403)
	c.callExpect("GET", "GET /api/v1/admin/scheduler-metrics", "/api/v1/admin/scheduler-metrics", nil, 200)
	c.callExpect("GET", "GET /api/v1/admin/usage", "/api/v1/admin/usage", nil, 200)
	c.callExpect("POST", "POST /api/v1/admin/jobs/record-hygiene-snapshot", "/api/v1/admin/jobs/record-hygiene-snapshot", nil, 200)

	c.callExpect("GET", "GET /api/v1/system/auth-config", "/api/v1/system/auth-config", nil, 200)
	c.callExpect("GET", "GET /api/v1/system/encryption-config", "/api/v1/system/encryption-config", nil, 200)
	c.callExpect("GET", "GET /api/v1/system/info", "/api/v1/system/info", nil, 200)
	c.callExpect("GET", "GET /api/v1/system/metrics", "/api/v1/system/metrics", nil, 200)

	c.callExpect("GET", "GET /api/v1/hygiene", "/api/v1/hygiene", nil, 200)
	c.callExpect("GET", "GET /api/v1/pat-hygiene", "/api/v1/pat-hygiene", nil, 200)
	c.callExpect("GET", "GET /api/v1/machine-token-hygiene", "/api/v1/machine-token-hygiene", nil, 200)

	c.callExpect("GET", "GET /api/v1/connect/connectors", "/api/v1/connect/connectors", nil, 200)
	c.callExpect("GET", "GET /api/v1/connect/ref-grants", "/api/v1/connect/ref-grants", nil, 200)
	// Best-effort tail: no external connector is configured on a fresh
	// install, so these are expected to 400/404, not 200 -- proves no 5xx.
	c.call("POST", "POST /api/v1/connect/ref-grants", "/api/v1/connect/ref-grants", map[string]interface{}{
		"connector": "e2e-smoke-connector", "project_id": ctx.projectID,
	})
	c.call("DELETE", "DELETE /api/v1/connect/ref-grants/{id}", "/api/v1/connect/ref-grants/1", nil)
	c.call("POST", "POST /api/v1/connect/{name}/secret:read", "/api/v1/connect/e2e-smoke-connector/secret:read",
		map[string]interface{}{"path": "e2e/smoke"})

	c.callExpect("GET", "GET /api/v1/rbac/permission-matrix", "/api/v1/rbac/permission-matrix", nil, 200)

	rrtCreated := c.callExpect("POST", "POST /api/v1/rejection-reason-templates", "/api/v1/rejection-reason-templates",
		map[string]string{"name": "e2e-smoke-rejection-template", "reason": "SESSION-I smoke"}, 200, 201)
	var rrtEnv idOnly
	c.unmarshalData(rrtCreated, &rrtEnv, "create rejection reason template")
	c.callExpect("GET", "GET /api/v1/rejection-reason-templates", "/api/v1/rejection-reason-templates", nil, 200)
	if rrtEnv.ID != 0 {
		c.callExpect("DELETE", "DELETE /api/v1/rejection-reason-templates/{id}", fmt.Sprintf("/api/v1/rejection-reason-templates/%d", rrtEnv.ID), nil, 200, 204)
	} else {
		c.skip("DELETE /api/v1/rejection-reason-templates/{id}")
	}

	// Secret-scoped routes not reached by groupSecretsAndFolders's sweep: a
	// real X.509 certificate parse (certificate) and the version-comments
	// LIST route (POST/DELETE were already exercised there).
	s := fmt.Sprintf("/api/v1/secrets/%d", ctx.secretID)
	c.call("GET", "GET /api/v1/secrets/{id}/certificate", s+"/certificate", nil)
	c.call("GET", "GET /api/v1/secrets/{id}/versions/{versionId}/comments", s+"/versions/1/comments", nil)

	// Dynamic-secret lease lifecycle (issue/renew/revoke) requires actually
	// dialing a real backend at the configured admin_dsn -- groupDynamicSecrets
	// deliberately registers a config against an unreachable host (see that
	// group's own doc comment) specifically so CONFIG create/read/update/list
	// works without a live external database. issue correctly 502s ("upstream
	// connect failed") against that unreachable host -- a genuine, deliberate
	// status for this exact case, not a bug -- but this driver's own "no 5xx
	// anywhere" invariant treats any 5xx as fatal, so calling it here would
	// require standing up a real Postgres/MySQL backend just to prove a route
	// exists. Left as an explicit, reasoned skip (see coverage.go) rather than
	// worked around with a fragile expected-502 special case.
	ctx.c.skip("POST /api/v1/dynamic-secrets/configs/{id}/issue")
	ctx.c.skip("POST /api/v1/dynamic-secrets/leases/{leaseID}/renew")
	ctx.c.skip("POST /api/v1/dynamic-secrets/leases/{leaseID}/revoke")

	// Remove the smoke user's project membership before deleting the user
	// entirely below -- the one DELETE route groupUsersRolesRBAC's earlier
	// POST /members add left unexercised.
	if ctx.userID != 0 {
		c.callExpect("DELETE", "DELETE /api/v1/projects/{id}/members/{userId}",
			fmt.Sprintf("/api/v1/projects/%d/members/%d", ctx.projectID, ctx.userID), nil, 200, 204)
	} else {
		c.skip("DELETE /api/v1/projects/{id}/members/{userId}")
	}

	// Restore is meaningful only on an already-deleted secret; delete a
	// THROWAWAY secret (not ctx.secretID, still needed by nothing further at
	// this point but kept alive for symmetry with earlier groups) to exercise
	// both DELETE /api/v1/secrets/{id} and POST /api/v1/users/{id}/restore
	// (the latter on the smoke user, restored immediately after being
	// implicitly soft-deleted by nothing yet -- best-effort, proves the route
	// doesn't 5xx on a live, non-deleted user either).
	throwawaySecret := c.callExpect("POST", "POST /api/v1/secrets", "/api/v1/secrets", map[string]interface{}{
		"name": "e2e-smoke-secret-for-delete", "value": "e2e-smoke-throwaway",
		"project_id": ctx.projectID, "environment_id": ctx.environmentID, "type": "generic",
	}, 201)
	var throwawaySecretEnv idOnly
	c.unmarshalData(throwawaySecret, &throwawaySecretEnv, "create throwaway secret for delete")
	if throwawaySecretEnv.ID != 0 {
		c.callExpect("DELETE", "DELETE /api/v1/secrets/{id}", fmt.Sprintf("/api/v1/secrets/%d", throwawaySecretEnv.ID), nil, 200, 204)
	} else {
		c.skip("DELETE /api/v1/secrets/{id}")
	}
	c.call("POST", "POST /api/v1/users/{id}/restore", fmt.Sprintf("/api/v1/users/%d/restore", ctx.userID), nil)

	// Final cleanup: delete the project (cascades its secrets/environments)
	// and the smoke user, exercising the two remaining DELETE routes this
	// whole run depended on running last.
	c.callExpect("DELETE", "DELETE /api/v1/projects/{id}", fmt.Sprintf("/api/v1/projects/%d?force=true", ctx.projectID), nil, 200)
	if ctx.userID != 0 {
		c.callExpect("DELETE", "DELETE /api/v1/users/{id}", fmt.Sprintf("/api/v1/users/%d", ctx.userID), nil, 200, 204)
	}
}
