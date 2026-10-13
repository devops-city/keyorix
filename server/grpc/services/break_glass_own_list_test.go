package services

// break_glass_own_list_test.go — BREAKGLASS-OWN-1 over gRPC: the same decision as GET
// /projects/{id}/break-glass (core.ListBreakGlassActivationsForCaller). A user
// without roles.read lists only their own activations; roles.read lists the project;
// a machine identity without roles.read is refused as before.

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func bgOwnIDs(resp *pb.ListBreakGlassActivationsResponse) []uint32 {
	out := make([]uint32, 0, len(resp.GetActivations()))
	for _, a := range resp.GetActivations() {
		out = append(out, a.GetId())
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func TestBreakGlassGRPC_OwnList(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	require.NoError(t, h.DB.AutoMigrate(&models.BreakGlassActivation{}, &models.AuditEvent{}))
	h.AssignUserRole(t, 1, 1, nil) // user 1: global super_admin (roles.read everywhere)
	h.CreateTestRole(t, "emergency", "break-glass role", 90)
	h.CoreService.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: true, EmergencyRole: "emergency", DefaultTTL: time.Hour, MaxTTL: 4 * time.Hour,
	})
	svc := NewBreakGlassService(h.CoreService)

	p1, p2 := uint(1), uint(2)
	h.CreateTestUser(t, "alice", 10)
	h.CreateTestUser(t, "bob", 11)
	h.AssignUserRole(t, 10, 4, &p1) // viewer at 1: a member, no roles.read
	h.AssignUserRole(t, 10, 4, &p2) // and at 2
	h.AssignUserRole(t, 11, 4, &p1)
	alice, bob := authCtx(10, "alice"), authCtx(11, "bob")

	activate := func(ctx context.Context, pid uint32, why string) uint32 {
		t.Helper()
		a, err := svc.ActivateBreakGlass(ctx, &pb.ActivateBreakGlassRequest{ProjectId: pid, Justification: why})
		require.NoError(t, err)
		return a.GetId()
	}
	aliceRevoked := activate(alice, 1, "BREAKGLASS-OWN-1 alice first")
	_, err := svc.RevokeBreakGlass(bgCtx(), &pb.RevokeBreakGlassRequest{ProjectId: 1, ActivationId: aliceRevoked})
	require.NoError(t, err)
	aliceP1 := activate(alice, 1, "BREAKGLASS-OWN-1 alice second")
	aliceP2 := activate(alice, 2, "BREAKGLASS-OWN-1 alice at 2")
	bobP1 := activate(bob, 1, "BREAKGLASS-OWN-1 bob")

	sorted := func(in ...uint32) []uint32 {
		sort.Slice(in, func(i, j int) bool { return in[i] < in[j] })
		return in
	}

	// Member A sees only A's (active + revoked), never B's or A's elsewhere.
	resp, err := svc.ListBreakGlassActivations(alice, &pb.ListBreakGlassActivationsRequest{ProjectId: 1})
	require.NoError(t, err)
	assert.Equal(t, core.BreakGlassListScopeOwn, resp.GetScope())
	assert.Equal(t, sorted(aliceP1, aliceRevoked), bgOwnIDs(resp))
	states := map[uint32]string{}
	for _, a := range resp.GetActivations() {
		assert.Equal(t, uint32(10), a.GetUserId())
		assert.Equal(t, uint32(1), a.GetProjectId())
		states[a.GetId()] = a.GetState()
	}
	assert.Equal(t, "revoked", states[aliceRevoked])
	assert.Equal(t, "active", states[aliceP1])
	// FIX-3184: the own view says "revoked" (state, revoked_at) but not WHO revoked it.
	for _, a := range resp.GetActivations() {
		assert.Nil(t, a.RevokedBy, "own view must not carry the revoker id (activation %d)", a.GetId())
		if a.GetId() == aliceRevoked {
			assert.NotNil(t, a.GetRevokedAt())
		}
	}

	// Member B sees only B's.
	resp, err = svc.ListBreakGlassActivations(bob, &pb.ListBreakGlassActivationsRequest{ProjectId: 1})
	require.NoError(t, err)
	assert.Equal(t, []uint32{bobP1}, bgOwnIDs(resp))

	// Cross-project: A at 2 sees only the activation at 2; B (not a member) is refused.
	resp, err = svc.ListBreakGlassActivations(alice, &pb.ListBreakGlassActivationsRequest{ProjectId: 2})
	require.NoError(t, err)
	assert.Equal(t, []uint32{aliceP2}, bgOwnIDs(resp))
	_, err = svc.ListBreakGlassActivations(bob, &pb.ListBreakGlassActivationsRequest{ProjectId: 2})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// roles.read: the whole project, unchanged.
	resp, err = svc.ListBreakGlassActivations(bgCtx(), &pb.ListBreakGlassActivationsRequest{ProjectId: 1})
	require.NoError(t, err)
	assert.Equal(t, core.BreakGlassListScopeProject, resp.GetScope())
	assert.Equal(t, sorted(aliceP1, aliceRevoked, bobP1), bgOwnIDs(resp))
	for _, a := range resp.GetActivations() {
		if a.GetId() == aliceRevoked {
			require.NotNil(t, a.RevokedBy, "project view keeps the revoker id")
			assert.Equal(t, uint32(1), a.GetRevokedBy())
		}
	}

	// A machine identity without roles.read: refused, as before.
	_, err = svc.ListBreakGlassActivations(machineCtx(77), &pb.ListBreakGlassActivationsRequest{ProjectId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}
