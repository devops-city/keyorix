// bulk_access_requests_machine_actor_test.go — the HTTP half of #2495
// (INV-CORE-14), driving POST /api/v1/access-requests/bulk-approve the way a
// real machine-authenticated client drives it.
//
// internal/core/bulk_access_request_machine_actor_test.go proves the core
// behaviour; it cannot prove the HANDLER derives the acting machine identity at
// all. Those are different claims, and the gap between them is precisely where
// this defect class keeps landing: #1545's finding was a handler passing a
// hardcoded false while core was already correct, and the sibling test
// groups_members_machine_ceiling_test.go exists for the same reason one layer
// over.
//
// Before the fix the handler called core with no machine identity, so a machine
// approver was reported to the escalation-by-proxy ceiling as the trusted system
// pseudo-actor (approverID=0, approverMachineID=0) — and the per-item
// authorization, resolving that same 0 as a USER id, refused every item, which
// is both a functional bug and the only thing keeping the ceiling skip
// unreachable.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// bulkMachineWorld bootstraps a real core, creates a requester plus a pending
// access request in project 1 suggesting project_viewer, and returns the core,
// the machine identity, and the request ID.
func bulkMachineWorld(t *testing.T, suffix, machineRole string) (*core.KeyorixCore, uint, uint) {
	t.Helper()
	cs := freshCoreS11(t)
	bootstrapS11(t, cs, suffix)
	ctx := context.Background()

	requester, err := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username:    "bulkmach-" + suffix + "-req",
		Email:       "bulkmach-" + suffix + "-req@example.com",
		DisplayName: "Requester", Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, err)

	machine, err := cs.CreateMachineIdentity(ctx, 1, "bulkmach-"+suffix, core.MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	role, err := cs.Storage().GetRoleByName(ctx, machineRole)
	require.NoError(t, err)
	require.NoError(t, cs.Storage().AssignMachineRole(ctx, machine.ID, role.ID, storage.Scope{ProjectID: 1}))

	req, err := cs.RequestProjectAccess(ctx, 1, requester.ID, "project_viewer", "need read access")
	require.NoError(t, err)
	return cs, machine.ID, req.ID
}

// postBulkApproveAsMachine drives the handler with a machine UserContext — the
// exact shape server/middleware/auth.go builds for a machine token: UserID 0,
// ActorType machine_identity, MachineIdentityID set.
func postBulkApproveAsMachine(t *testing.T, cs *core.KeyorixCore, machineID, requestID uint) *httptest.ResponseRecorder {
	t.Helper()
	h := NewCatalogHandler(cs)
	body, err := json.Marshal(map[string]any{"request_ids": []uint{requestID}})
	require.NoError(t, err)
	req := httptest.NewRequest("POST", "/api/v1/access-requests/bulk-approve", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), &middleware.UserContext{
		UserID:            0,
		ActorType:         core.ActorTypeMachine,
		MachineIdentityID: &machineID,
	}))
	w := httptest.NewRecorder()
	h.BulkApproveAccessRequests(w, req)
	return w
}

// decodeBulkApproveFailures pulls the per-item errors out of the envelope the
// handler returns, so an assertion can distinguish WHICH refusal happened.
func decodeBulkApproveFailures(t *testing.T, w *httptest.ResponseRecorder) (approved []any, failed []map[string]any) {
	t.Helper()
	var env struct {
		Data struct {
			Result struct {
				Approved []any            `json:"approved"`
				Failed   []map[string]any `json:"failed"`
			} `json:"result"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env), "body: %s", w.Body.String())
	return env.Data.Result.Approved, env.Data.Result.Failed
}

// A machine identity holding project_admin at the request's project bundles
// roles.assign AND every permission project_viewer bundles, so it clears the
// ceiling and the bulk approval must land. Before the fix every item came back
// "permission denied".
func TestBulkApproveAccessRequests_MachineActorWithFullAuthority_Approves(t *testing.T) {
	cs, machineID, reqID := bulkMachineWorld(t, "full", "project_admin")

	w := postBulkApproveAsMachine(t, cs, machineID, reqID)
	require.Equal(t, 200, w.Code, "body: %s", w.Body.String())

	approved, failed := decodeBulkApproveFailures(t, w)
	assert.Empty(t, failed, "a machine approver with full authority must not be refused: %v", failed)
	assert.Len(t, approved, 1)

	reloaded, err := cs.Storage().GetAccessRequest(context.Background(), reqID)
	require.NoError(t, err)
	assert.Equal(t, "approved", reloaded.State)
	assert.Equal(t, machineID, reloaded.ResolvedByMachineIdentityID,
		"the HTTP layer must thread WHICH machine approved, not 0")
}

// The security half at the HTTP boundary: a machine identity that holds
// roles.assign (so it reaches and passes the per-item authorization) but NOT the
// granted role's own permissions must be refused BY THE CEILING, and nothing may
// be granted.
func TestBulkApproveAccessRequests_MachineActorMissingPermissions_RefusedByCeiling(t *testing.T) {
	cs := freshCoreS11(t)
	bootstrapS11(t, cs, "ceil")
	ctx := context.Background()

	requester, err := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username: "bulkmach-ceil-req", Email: "bulkmach-ceil-req@example.com",
		DisplayName: "Requester", Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, err)
	machine, err := cs.CreateMachineIdentity(ctx, 1, "bulkmach-ceil", core.MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)

	// A bespoke role bundling ONLY roles.assign: enough to pass the per-item
	// authorization, not enough to grant project_viewer's secrets.read.
	folded, err := identity.NewFoldedName("bulkmach-assigner")
	require.NoError(t, err)
	assigner, err := cs.Storage().CreateRole(ctx, folded, "roles.assign only")
	require.NoError(t, err)
	perms, err := cs.Storage().ListPermissions(ctx)
	require.NoError(t, err)
	var assignPermID uint
	for _, p := range perms {
		if p.Name == "roles.assign" {
			assignPermID = p.ID
		}
	}
	require.NotZero(t, assignPermID, "roles.assign must be seeded")
	require.NoError(t, cs.Storage().AssignPermissionToRole(ctx, assigner.ID, assignPermID))
	require.NoError(t, cs.Storage().AssignMachineRole(ctx, machine.ID, assigner.ID, storage.Scope{ProjectID: 1}))

	req, err := cs.RequestProjectAccess(ctx, 1, requester.ID, "project_viewer", "need read access")
	require.NoError(t, err)

	w := postBulkApproveAsMachine(t, cs, machine.ID, req.ID)
	require.Equal(t, 200, w.Code, "body: %s", w.Body.String())

	approved, failed := decodeBulkApproveFailures(t, w)
	assert.Empty(t, approved, "a machine approver missing the granted role's permissions must grant nothing")
	require.Len(t, failed, 1)
	assert.Contains(t, fmt.Sprint(failed[0]["error"]), "you do not hold permission",
		"the refusal must be the escalation-by-proxy ceiling. A refusal for any other reason is "+
			"indistinguishable from the ceiling having been skipped — which is exactly what a hardcoded "+
			"approverMachineID=0 causes")

	reloaded, err := cs.Storage().GetAccessRequest(ctx, req.ID)
	require.NoError(t, err)
	assert.Equal(t, "pending", reloaded.State, "the refused request must stay pending")
	ids, err := cs.Storage().GetUserRoleIDsAt(ctx, requester.ID, storage.Scope{ProjectID: 1})
	require.NoError(t, err)
	viewer, err := cs.Storage().GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	assert.NotContains(t, ids, viewer.ID, "no role may have been granted")
}
