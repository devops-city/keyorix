//go:build e2e

package e2e

import "fmt"

// idOnly decodes any {"id": N, ...} envelope data payload when only the id
// is needed.
type idOnly struct {
	ID uint `json:"id"`
}

// groupAuthProfile exercises the caller's own profile/session/PAT surface
// (server/http/handlers/auth.go): GET/PUT profile, session listing, and a
// full PAT create/list/delete cycle. Deliberately does NOT call
// change-password or end a session/impersonation -- either could invalidate
// this driver's own bearer token and break every later group in the same
// run (see coverage.go's skipList for the specific justification on each).
func groupAuthProfile(ctx *smokeCtx) {
	c := ctx.c
	profile := c.callExpect("GET", "GET /api/v1/auth/profile", "/api/v1/auth/profile", nil, 200)
	var self idOnly
	c.unmarshalData(profile, &self, "get own profile")
	ctx.adminUserID = self.ID
	c.callExpect("PUT", "PUT /api/v1/auth/profile", "/api/v1/auth/profile",
		map[string]string{"display_name": "E2E Smoke Admin (updated)"}, 200)
	c.callExpect("GET", "GET /api/v1/auth/sessions", "/api/v1/auth/sessions", nil, 200)

	created := c.callExpect("POST", "POST /api/v1/auth/tokens", "/api/v1/auth/tokens",
		map[string]interface{}{"name": "e2e-smoke-pat"}, 200, 201)
	var patEnv struct {
		PAT idOnly `json:"pat"`
	}
	c.unmarshalData(created, &patEnv, "create PAT")

	c.callExpect("GET", "GET /api/v1/auth/tokens", "/api/v1/auth/tokens", nil, 200)
	c.callExpect("GET", "GET /api/v1/auth/tokens/expired", "/api/v1/auth/tokens/expired", nil, 200)
	c.callExpect("DELETE", "DELETE /api/v1/auth/tokens/expired", "/api/v1/auth/tokens/expired", nil, 200, 204)
	if patEnv.PAT.ID != 0 {
		c.callExpect("DELETE", "DELETE /api/v1/auth/tokens/{id}", fmt.Sprintf("/api/v1/auth/tokens/%d", patEnv.PAT.ID), nil, 200, 204)
	} else {
		c.skip("DELETE /api/v1/auth/tokens/{id}")
	}

	// PAT-GUARD-3 (ADR-042): a restricted PAT is refused on an ungated
	// self-service write, and may still revoke itself.
	restricted := c.callExpect("POST", "POST /api/v1/auth/tokens", "/api/v1/auth/tokens",
		map[string]interface{}{"name": "e2e-smoke-restricted-pat", "scopes": []string{"secrets.read"}}, 200, 201)
	var rEnv struct {
		Token string `json:"token"`
		PAT   idOnly `json:"pat"`
	}
	c.unmarshalData(restricted, &rEnv, "create restricted PAT")
	rc := newClient(c.t, c.baseURL)
	rc.token = rEnv.Token
	rc.callExpect("PUT", "PUT /api/v1/auth/profile", "/api/v1/auth/profile",
		map[string]string{"display_name": "changed by a restricted PAT"}, 403)
	rc.callExpect("DELETE", "DELETE /api/v1/auth/tokens/{id}", fmt.Sprintf("/api/v1/auth/tokens/%d", rEnv.PAT.ID), nil, 204)
	rc.callExpect("GET", "GET /api/v1/auth/tokens", "/api/v1/auth/tokens", nil, 401)
}

// groupProjectsAndEnvironments creates the project + two environments (one
// kept for the rest of the run, one thrown away to exercise env deletion)
// this driver's later groups build on, then sweeps every project-scoped
// read-only report/analytics endpoint (health, hygiene, drift, stats,
// members, invitations, break-glass, access-review, rotation-order/plan,
// secrets deleted/expiring/orphaned/name-conformance/inventory) -- each one
// is a real query against the freshly migrated schema even with zero rows,
// which is exactly the class of bug (PR #2258's "no such table") this
// driver exists to catch.
func groupProjectsAndEnvironments(ctx *smokeCtx) {
	c := ctx.c

	created := c.callExpect("POST", "POST /api/v1/projects", "/api/v1/projects",
		map[string]string{"name": "e2e-smoke-project", "description": "SESSION-I smoke"}, 201)
	var proj idOnly
	c.unmarshalData(created, &proj, "create project")
	ctx.projectID = proj.ID
	p := fmt.Sprintf("/api/v1/projects/%d", ctx.projectID)

	c.callExpect("GET", "GET /api/v1/projects", "/api/v1/projects", nil, 200)
	c.callExpect("GET", "GET /api/v1/projects/{id}", p, nil, 200)
	c.callExpect("PUT", "PUT /api/v1/projects/{id}", p,
		map[string]string{"name": "e2e-smoke-project", "description": "SESSION-I smoke (updated)"}, 200)

	envCreated := c.callExpect("POST", "POST /api/v1/projects/{id}/environments", p+"/environments",
		map[string]string{"name": "e2e-main"}, 201)
	var env idOnly
	c.unmarshalData(envCreated, &env, "create environment")
	ctx.environmentID = env.ID

	throwaway := c.callExpect("POST", "POST /api/v1/projects/{id}/environments", p+"/environments",
		map[string]string{"name": "e2e-throwaway"}, 201)
	var throwawayEnv idOnly
	c.unmarshalData(throwaway, &throwawayEnv, "create throwaway environment")

	c.callExpect("GET", "GET /api/v1/projects/{id}/environments", p+"/environments", nil, 200)
	// clone copies secrets FROM srcEnvID INTO an EXISTING destination_environment_id
	// (not "create a new env from this one") -- destination is the main
	// environment created above.
	c.callExpect("POST", "POST /api/v1/projects/{id}/environments/{envId}/clone",
		fmt.Sprintf("%s/environments/%d/clone", p, throwawayEnv.ID),
		map[string]interface{}{"destination_environment_id": ctx.environmentID}, 200, 201)
	c.call("POST", "POST /api/v1/projects/{id}/environments/{envId}/copy-secrets",
		fmt.Sprintf("%s/environments/%d/copy-secrets", p, throwawayEnv.ID),
		map[string]interface{}{"destination_environment_id": ctx.environmentID})
	c.callExpect("POST", "POST /api/v1/projects/{projectId}/environments/{id}/restore",
		fmt.Sprintf("%s/environments/%d/restore", p, throwawayEnv.ID), nil, 200, 400, 404)

	// Top-level environments group.
	c.callExpect("GET", "GET /api/v1/environments", "/api/v1/environments", nil, 200)
	c.callExpect("DELETE", "DELETE /api/v1/environments/{id}", fmt.Sprintf("/api/v1/environments/%d", throwawayEnv.ID), nil, 200, 204)

	// Cheap project-scoped GET sweep -- every one of these is a real query
	// against a freshly migrated database, using only the project ID
	// already in hand.
	cheapGets := []string{
		"health", "hygiene", "drift", "stats", "members", "memberships",
		"invitations", "break-glass", "access-requests", "access-review",
		"access-review/campaigns", "rotation-order", "rotation-plan",
		"machine-identities", "machine-identities/stale",
		"secrets/deleted", "secrets/expiring", "secrets/orphaned",
		"secrets/name-conformance", "secrets/inventory.csv",
	}
	for _, seg := range cheapGets {
		c.call("GET", fmt.Sprintf("GET /api/v1/projects/{id}/%s", seg), fmt.Sprintf("%s/%s", p, seg), nil)
	}

	// Members: add the bootstrap admin's second user isn't created yet at
	// this point in the flow (groupUsersRolesRBAC runs later) -- members
	// add/update/remove is exercised there instead, once ctx.userID exists.

	// Best-effort tail (see the identical note in groupSecretsAndFolders):
	// exact body contracts not individually confirmed, c.call not
	// c.callExpect -- still exercises the route and still fails on 5xx.
	c.call("POST", "POST /api/v1/projects/{id}/restore", p+"/restore", nil)
	c.call("POST", "POST /api/v1/projects/{id}/break-glass", p+"/break-glass", map[string]interface{}{"reason": "e2e smoke break-glass"})
	c.call("POST", "POST /api/v1/projects/{id}/break-glass/{activationId}/revoke", p+"/break-glass/1/revoke", nil)
	c.call("POST", "POST /api/v1/projects/{id}/access-review/attest", p+"/access-review/attest", map[string]interface{}{})
	c.call("POST", "POST /api/v1/projects/{id}/access-review/revoke", p+"/access-review/revoke", map[string]interface{}{})
	campaignCreated := c.call("POST", "POST /api/v1/projects/{id}/access-review/campaigns", p+"/access-review/campaigns",
		map[string]interface{}{"name": "e2e-smoke-campaign"})
	var campaign idOnly
	if campaignCreated.Success {
		c.unmarshalData(campaignCreated, &campaign, "create access review campaign")
	}
	cp := fmt.Sprintf("%s/access-review/campaigns/%d", p, campaign.ID)
	c.call("GET", "GET /api/v1/projects/{id}/access-review/campaigns/{campaignId}", cp, nil)
	c.call("GET", "GET /api/v1/projects/{id}/access-review/campaigns/{campaignId}/export.csv", cp+"/export.csv", nil)
	c.call("POST", "POST /api/v1/projects/{id}/access-review/campaigns/{campaignId}/items/{itemId}/decide", cp+"/items/1/decide",
		map[string]interface{}{"decision": "approve"})
	c.call("POST", "POST /api/v1/projects/{id}/access-review/campaigns/{campaignId}/close", cp+"/close", nil)

	c.call("POST", "POST /api/v1/projects/{id}/secrets/bulk-delete", p+"/secrets/bulk-delete", map[string]interface{}{"secret_ids": []uint{}})
	c.call("POST", "POST /api/v1/projects/{id}/secrets/bulk-rename", p+"/secrets/bulk-rename", map[string]interface{}{"secret_ids": []uint{}})
	c.call("POST", "POST /api/v1/projects/{id}/secrets/bulk-rotate", p+"/secrets/bulk-rotate", map[string]interface{}{"secret_ids": []uint{}})
	c.call("POST", "POST /api/v1/projects/{id}/secrets/extend-expiring", p+"/secrets/extend-expiring", map[string]interface{}{})
	c.call("POST", "POST /api/v1/projects/{id}/secrets/reassign-owner", p+"/secrets/reassign-owner", map[string]interface{}{"new_owner_id": ctx.adminUserID})
	c.call("POST", "POST /api/v1/projects/{id}/secrets/render", p+"/secrets/render", map[string]interface{}{"template": ""})
	c.call("POST", "POST /api/v1/projects/{id}/secrets/resume-all", p+"/secrets/resume-all", map[string]interface{}{})
	c.call("POST", "POST /api/v1/projects/{id}/secrets/suspend-all", p+"/secrets/suspend-all", map[string]interface{}{})
}

// groupSecretsAndFolders creates the secret every later group (shares,
// notifications via share-triggered events, rotation policies) reuses, and
// sweeps the secret-scoped read-only report endpoints the same way
// groupProjectsAndEnvironments does for projects. Folders are a distinct
// tree (SecretNode with is_secret=false) under the same project/environment.
func groupSecretsAndFolders(ctx *smokeCtx) {
	c := ctx.c
	ctx.secretValue = "e2e-smoke-secret-value-do-not-use"

	created := c.callExpect("POST", "POST /api/v1/secrets", "/api/v1/secrets", map[string]interface{}{
		"name": "e2e-smoke-secret", "value": ctx.secretValue,
		"project_id": ctx.projectID, "environment_id": ctx.environmentID, "type": "generic",
		"tags": []string{"e2e"}, "description": "SESSION-I smoke secret",
	}, 201)
	var sec idOnly
	c.unmarshalData(created, &sec, "create secret")
	ctx.secretID = sec.ID
	s := fmt.Sprintf("/api/v1/secrets/%d", ctx.secretID)

	c.callExpect("GET", "GET /api/v1/secrets", "/api/v1/secrets", nil, 200)
	c.callExpect("GET", "GET /api/v1/secrets/{id}", s, nil, 200)

	getVal := c.callExpect("GET", "GET /api/v1/secrets/{id}", s+"?include_value=true", nil, 200)
	var withValue struct {
		Value string `json:"value"`
	}
	c.unmarshalData(getVal, &withValue, "get secret with value")
	if withValue.Value != ctx.secretValue {
		ctx.t.Fatalf("secret value round-trip failed: got %q, want %q", withValue.Value, ctx.secretValue)
	}

	c.callExpect("PUT", "PUT /api/v1/secrets/{id}", s, map[string]interface{}{"metadata": map[string]string{"e2e": "true"}}, 200)
	c.callExpect("PATCH", "PATCH /api/v1/secrets/{id}/description", s+"/description", map[string]string{"description": "updated by smoke"}, 200)
	c.callExpect("PATCH", "PATCH /api/v1/secrets/{id}/classification", s+"/classification", map[string]string{"classification": "internal"}, 200)
	c.callExpect("PUT", "PUT /api/v1/secrets/{id}/tags", s+"/tags", map[string]interface{}{"tags": []string{"e2e", "smoke"}}, 200)
	c.callExpect("PATCH", "PATCH /api/v1/secrets/{id}/auto-rotate", s+"/auto-rotate", map[string]interface{}{"enabled": false}, 200)
	c.callExpect("PATCH", "PATCH /api/v1/secrets/{id}/retention", s+"/retention", map[string]interface{}{}, 200, 400)

	sched := map[string]interface{}{"cron": "0 0 1 * *"}
	c.callExpect("PUT", "PUT /api/v1/secrets/{id}/schedule", s+"/schedule", sched, 200, 201, 400)

	cheapGets := []string{
		"access", "access-log", "acl", "audit", "blast-radius", "dependencies",
		"impact", "impact-preview", "ownership-history", "read-summary", "risk",
		"rotation-state", "schedule", "shares", "stats", "tags", "versions",
	}
	for _, seg := range cheapGets {
		c.call("GET", fmt.Sprintf("GET /api/v1/secrets/{id}/%s", seg), fmt.Sprintf("%s/%s", s, seg), nil)
	}
	c.call("GET", "GET /api/v1/secrets/{id}/access-log/export", s+"/access-log/export", nil)

	// Top-level secret report/utility endpoints -- global, not per-id.
	c.call("GET", "GET /api/v1/secrets/by-name", fmt.Sprintf("/api/v1/secrets/by-name?project_id=%d&environment_id=%d&name=e2e-smoke-secret", ctx.projectID, ctx.environmentID), nil)
	c.call("GET", "GET /api/v1/secrets/inventory.csv", "/api/v1/secrets/inventory.csv", nil)
	c.call("GET", "GET /api/v1/secrets/name-conformance", "/api/v1/secrets/name-conformance", nil)
	c.call("GET", "GET /api/v1/secrets/policy", "/api/v1/secrets/policy", nil)
	c.call("GET", "GET /api/v1/secrets/quota-report", "/api/v1/secrets/quota-report", nil)
	c.call("GET", "GET /api/v1/secrets/usage/most-accessed", "/api/v1/secrets/usage/most-accessed", nil)
	c.call("GET", "GET /api/v1/secrets/usage/unused", "/api/v1/secrets/usage/unused", nil)
	c.call("GET", "GET /api/v1/secrets/value", fmt.Sprintf("/api/v1/secrets/value?project_id=%d&environment_id=%d&name=e2e-smoke-secret", ctx.projectID, ctx.environmentID), nil)

	// Best-effort tail: these routes' exact request-body contracts weren't
	// individually confirmed against handler source the way the calls above
	// were, so c.call (not c.callExpect) is used -- it still records the
	// route as exercised and still fails the test on a 5xx (the actual
	// invariant this driver checks), it just doesn't assert a specific 2xx.
	// A wrong/incomplete body producing a 400 here is an acceptable,
	// informative outcome; a 500 is not.
	c.call("POST", "POST /api/v1/secrets/{id}/suspend", s+"/suspend", nil)
	c.call("POST", "POST /api/v1/secrets/{id}/resume", s+"/resume", nil)
	c.call("POST", "POST /api/v1/secrets/{id}/rotate", s+"/rotate", map[string]interface{}{"new_value": "e2e-smoke-rotated-value"})
	c.call("POST", "POST /api/v1/secrets/{id}/rotation/simulate", s+"/rotation/simulate", nil)
	c.call("POST", "POST /api/v1/secrets/{id}/transfer-ownership", s+"/transfer-ownership", map[string]interface{}{"new_owner_id": ctx.userID})
	c.call("POST", "POST /api/v1/secrets/{id}/copy", s+"/copy", map[string]interface{}{
		"project_id": ctx.projectID, "environment_id": ctx.environmentID, "name": "e2e-smoke-secret-copy",
	})
	c.call("POST", "POST /api/v1/secrets/{id}/move", s+"/move", map[string]interface{}{
		"project_id": ctx.projectID, "environment_id": ctx.environmentID,
	})
	c.call("POST", "POST /api/v1/secrets/{id}/restore", s+"/restore", nil)
	c.call("POST", "POST /api/v1/secrets/{id}/rollback", s+"/rollback", map[string]interface{}{"version": 1})
	c.call("POST", "POST /api/v1/secrets/{id}/acl", s+"/acl", map[string]interface{}{
		"user_id": ctx.userID, "permission": "read",
	})
	c.call("DELETE", "DELETE /api/v1/secrets/{id}/acl/{aclId}", s+"/acl/1", nil)
	c.call("POST", "POST /api/v1/secrets/{id}/dependencies", s+"/dependencies", map[string]interface{}{
		"depends_on_secret_id": ctx.secretID,
	})
	c.call("DELETE", "DELETE /api/v1/secrets/{id}/dependencies/{depId}", s+"/dependencies/1", nil)
	c.call("POST", "POST /api/v1/secrets/{id}/versions/{versionId}/comments", s+"/versions/1/comments",
		map[string]string{"comment": "e2e smoke comment"})
	c.call("DELETE", "DELETE /api/v1/secrets/{id}/versions/{versionId}/comments/{commentId}", s+"/versions/1/comments/1", nil)
	c.call("GET", "GET /api/v1/secrets/{id}/versions/{from}/diff/{to}", s+"/versions/1/diff/1", nil)
	c.call("DELETE", "DELETE /api/v1/secrets/{id}/schedule", s+"/schedule", nil)
	c.call("DELETE", "DELETE /api/v1/secrets/{id}/self-share", s+"/self-share", nil)

	// Folders: an independent tree in the same project/environment.
	folderCreated := c.callExpect("POST", "POST /api/v1/folders", "/api/v1/folders", map[string]interface{}{
		"name": "e2e-smoke-folder", "project_id": ctx.projectID, "environment_id": ctx.environmentID,
	}, 201)
	var folder idOnly
	c.unmarshalData(folderCreated, &folder, "create folder")
	c.callExpect("GET", "GET /api/v1/folders", fmt.Sprintf("/api/v1/folders?project_id=%d", ctx.projectID), nil, 200)
	c.callExpect("DELETE", "DELETE /api/v1/folders/{id}", fmt.Sprintf("/api/v1/folders/%d", folder.ID), nil, 200, 204)
}

// groupSecretTemplates exercises create/list/get/update/apply/delete for
// secret templates -- a metadata-only resource (no secret value), so apply
// (which stamps a new secret from the template) is safe to run without
// disturbing ctx.secretID.
func groupSecretTemplates(ctx *smokeCtx) {
	c := ctx.c
	created := c.callExpect("POST", "POST /api/v1/secret-templates", "/api/v1/secret-templates", map[string]interface{}{
		"name": "e2e-smoke-template", "description": "SESSION-I smoke",
		"default_classification": "internal", "rotation_hint_days": 90,
	}, 201)
	var tmpl idOnly
	c.unmarshalData(created, &tmpl, "create secret template")
	tp := fmt.Sprintf("/api/v1/secret-templates/%d", tmpl.ID)

	c.callExpect("GET", "GET /api/v1/secret-templates", "/api/v1/secret-templates", nil, 200)
	c.callExpect("GET", "GET /api/v1/secret-templates/{id}", tp, nil, 200)
	c.callExpect("PUT", "PUT /api/v1/secret-templates/{id}", tp, map[string]interface{}{
		"name": "e2e-smoke-template", "description": "SESSION-I smoke (updated)",
		"default_classification": "internal", "rotation_hint_days": 90,
	}, 200)
	c.callExpect("POST", "POST /api/v1/secret-templates/{id}/apply", tp+"/apply", map[string]interface{}{
		"project_id": ctx.projectID, "environment_id": ctx.environmentID,
		"name": "e2e-smoke-from-template", "value": "e2e-template-value",
	}, 200, 201, 400)
	c.callExpect("DELETE", "DELETE /api/v1/secret-templates/{id}", tp, nil, 200, 204)
}

// accessRequestWire mirrors internal/storage/models.AccessRequest's field
// names EXACTLY (that model carries no `json:"..."` tags at all, so Go's
// encoding/json serializes/deserializes using the bare Go field names --
// confirmed by reading the model directly; getting the capitalization wrong
// here silently produces zero values, not a decode error).
type accessRequestWire struct {
	ID       uint
	SecretID *uint
	State    string
}

type accessRequestEnvelope struct {
	AccessRequest accessRequestWire `json:"access_request"`
}

// groupSecretAccessRequests exercises the secret-scoped access-request
// family (distinct from the project-scoped access-requests family covered
// in groupAccessRequests): create, list, get, withdraw. The PUT resolve
// (approve/reject) route is exercised best-effort only -- core.
// ApproveSecretAccessRequest enforces maker != checker ("a requester cannot
// approve their own access request"), and this driver's admin is both the
// project owner AND the only actor available at this point in the run
// (groupUsersRolesRBAC's second user doesn't exist yet), so a self-approve
// attempt correctly, deterministically 403s -- proving the guard works, not
// a bug. Withdraw has no such restriction (a requester withdrawing their
// own request is always allowed), so that's the success-path exercised here.
func groupSecretAccessRequests(ctx *smokeCtx) {
	c := ctx.c
	body := map[string]interface{}{"secret_id": ctx.secretID, "reason": "SESSION-I smoke access request"}

	created := c.callExpect("POST", "POST /api/v1/secret-access-requests", "/api/v1/secret-access-requests", body, 201)
	var envA accessRequestEnvelope
	c.unmarshalData(created, &envA, "create secret access request A")
	reqA := envA.AccessRequest

	c.callExpect("GET", "GET /api/v1/secret-access-requests", "/api/v1/secret-access-requests", nil, 200)

	if reqA.ID != 0 {
		rp := fmt.Sprintf("/api/v1/secret-access-requests/%d", reqA.ID)
		c.callExpect("GET", "GET /api/v1/secret-access-requests/{requestId}", rp, nil, 200)
		// Best-effort: expected to 403 (maker != checker), see doc comment above.
		c.call("PUT", "PUT /api/v1/secret-access-requests/{requestId}", rp, map[string]string{"action": "approve"})
		c.callExpect("POST", "POST /api/v1/secret-access-requests/{requestId}/withdraw",
			rp+"/withdraw", nil, 200)
	}
}
