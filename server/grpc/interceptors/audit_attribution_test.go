package interceptors

// audit_attribution_test.go — INV-GRPC-09 (#2523): withAuditAttribution
// isolated at the interceptor level.
//
// Invariant: an audit event written downstream of the gRPC auth interceptors
// carries the same actor accountability HTTP records — ActorType
// machine_identity plus WHICH machine (MachineIdentityID) for a machine
// principal, and ImpersonatedBy/Impersonation for an impersonation session.
//
// Pre-existing coverage: auth_test.go drives the unary AuthInterceptor end to
// end but asserts only ActorType for a machine — never MachineIdentityID;
// interceptors_s22_test.go's TestWithAuditAttribution_S22_* call the function
// directly but assert only that a derived context came back, so a tag with the
// wrong value (or a dropped WithMachineActor) passes them; and nothing drives
// StreamAuthInterceptor's call of withAuditAttribution. This file closes those
// gaps:
//   - TestWithAuditAttribution_StampsAuditFields calls the function directly
//     over every principal shape, observed through a real audit row (the tags'
//     context keys are core-private, so the row is the only honest oracle);
//   - the two stream tests drive StreamAuthInterceptor with a real machine
//     token and a real impersonation session.

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// latestAuditAfter writes one audit event with ctx and returns the row.
func latestAuditAfter(t *testing.T, h *testhelper.RBACTestHelper, ctx context.Context, actorID uint) models.AuditEvent {
	t.Helper()
	h.CoreService.LogRoleAssigned(ctx, actorID, 1, 4, core.Scope{ProjectID: 2})
	var ev models.AuditEvent
	require.NoError(t, h.DB.Order("id desc").First(&ev).Error)
	return ev
}

func uintp(v uint) *uint { return &v }

func TestWithAuditAttribution_StampsAuditFields(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AuditEvent{}))

	cases := []struct {
		name            string
		userCtx         *UserContext
		actorID         uint
		wantActorType   string
		wantMachineID   *uint
		wantImpersonate *uint
	}{
		{name: "nil principal leaves ctx untagged", userCtx: nil, actorID: 5, wantActorType: core.ActorTypeUser},
		{name: "human user", userCtx: &UserContext{UserID: 5}, actorID: 5, wantActorType: core.ActorTypeUser},
		{
			name:    "machine identity: actor kind AND which machine",
			userCtx: &UserContext{ActorType: core.ActorTypeMachine, MachineIdentityID: 42},
			actorID: 42, wantActorType: core.ActorTypeMachine, wantMachineID: uintp(42),
		},
		{
			name:    "impersonation session records the initiating admin",
			userCtx: &UserContext{UserID: 5, ImpersonatedBy: uintp(7)},
			actorID: 5, wantActorType: core.ActorTypeUser, wantImpersonate: uintp(7),
		},
		{
			name:    "machine and impersonation tags are independent",
			userCtx: &UserContext{ActorType: core.ActorTypeMachine, MachineIdentityID: 43, ImpersonatedBy: uintp(8)},
			actorID: 43, wantActorType: core.ActorTypeMachine, wantMachineID: uintp(43), wantImpersonate: uintp(8),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := context.Background()
			ctx := withAuditAttribution(base, tc.userCtx)
			if tc.userCtx == nil {
				assert.Equal(t, base, ctx, "a nil principal must return ctx unchanged")
			}
			ev := latestAuditAfter(t, h, ctx, tc.actorID)

			assert.Equal(t, tc.wantActorType, ev.ActorType)
			assert.Equal(t, tc.wantMachineID, ev.MachineIdentityID, "MachineIdentityID")
			assert.Equal(t, tc.wantImpersonate, ev.ImpersonatedBy, "ImpersonatedBy")
			assert.Equal(t, tc.wantImpersonate != nil, ev.Impersonation, "Impersonation flag")
			if tc.wantActorType == core.ActorTypeMachine {
				assert.Nil(t, ev.UserID, "a machine actor's id must never occupy UserID")
			}
		})
	}
}

// streamCapture runs StreamAuthInterceptor for token and returns the context
// the downstream handler saw.
func streamCapture(t *testing.T, h *testhelper.RBACTestHelper, token string) context.Context {
	t.Helper()
	var captured context.Context
	err := StreamAuthInterceptor(h.CoreService, false)(nil, &fakeStream{ctx: bearerCtx(token)},
		&grpc.StreamServerInfo{FullMethod: "/keyorix.v1.AuditService/StreamAuditLogs", IsServerStream: true},
		func(_ any, s grpc.ServerStream) error {
			captured = s.Context()
			return nil
		})
	require.NoError(t, err)
	require.NotNil(t, captured)
	return captured
}

func TestStreamAuthInterceptor_MachineTokenStampsMachineActorInAudit(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.MachineIdentity{}, &models.MachineIdentityCredential{}, &models.MachineIdentityRole{}, &models.AuditEvent{}))

	m, err := h.CoreService.CreateMachineIdentity(context.Background(), 2, "ci-bot", "service", "", "", 1, 0)
	require.NoError(t, err)
	proj2 := uint(2)
	h.AssignUserRole(t, 1, 2, &proj2) // admin at project 2: the issuer's privilege ceiling
	tok, err := h.CoreService.IssueMachineToken(context.Background(), 2, m.ID, 1, core.IssueMachineTokenParams{Name: "tok"})
	require.NoError(t, err)

	ev := latestAuditAfter(t, h, streamCapture(t, h, tok.PlainToken), m.ID)
	assert.Equal(t, core.ActorTypeMachine, ev.ActorType, "a machine stream must be audited as a machine")
	require.NotNil(t, ev.MachineIdentityID, "a machine stream's audit must record WHICH machine")
	assert.Equal(t, m.ID, *ev.MachineIdentityID)
	assert.Nil(t, ev.UserID)
}

func TestStreamAuthInterceptor_ImpersonationSessionStampsAdminInAudit(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AuditEvent{}))

	const adminID, targetID uint = 7101, 7102
	h.CreateTestUser(t, "imp-target", targetID)
	h.CreateTestUser(t, "imp-admin", adminID)
	h.AssignUserRole(t, adminID, 1, nil) // super_admin: the impersonation ceiling is re-checked per request
	exp := time.Now().Add(time.Hour)
	admin := adminID
	_, err := h.Storage.CreateSession(context.Background(), &models.Session{
		UserID: targetID, SessionToken: "imp-stream-token", ExpiresAt: &exp, ImpersonatedBy: &admin,
	})
	require.NoError(t, err)

	ev := latestAuditAfter(t, h, streamCapture(t, h, "imp-stream-token"), targetID)
	require.NotNil(t, ev.ImpersonatedBy, "an impersonated stream's audit must record the initiating admin")
	assert.Equal(t, adminID, *ev.ImpersonatedBy)
	assert.True(t, ev.Impersonation)
	assert.Equal(t, core.ActorTypeUser, ev.ActorType)
}
