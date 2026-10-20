package interceptors

// audit_attribution_unary_test.go — INV-GRPC-09 (#2523), the unary half.
//
// audit_attribution_test.go isolates withAuditAttribution and drives
// StreamAuthInterceptor; auth_test.go drives the unary AuthInterceptor for a
// machine token but asserts only ActorType, never WHICH machine, and drives an
// impersonation session separately. This file closes the remaining cell of the
// matrix: the UNARY interceptor, with a real machine token and a real
// impersonation session, asserted on the audit row the downstream handler's
// context produces — actor kind, MachineIdentityID, ImpersonatedBy and the
// Impersonation flag together. The tags' context keys are core-private, so the
// row is the only honest oracle.
//
// Red proof (commit message): withAuditAttribution made to drop
// core.WithMachineActor, or core.WithImpersonation, applied with
// `go test -overlay` (auth.go itself is not edited), turns the matching subtest
// red.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestAuthInterceptor_UnaryAuditRowCarriesActorKindMachineIDAndImpersonator(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.MachineIdentity{}, &models.MachineIdentityCredential{}, &models.MachineIdentityRole{}, &models.AuditEvent{}))
	interceptor := AuthInterceptor(h.CoreService, false)

	// unaryCtx runs the real unary interceptor for token and returns the context
	// its handler saw.
	unaryCtx := func(t *testing.T, token string) context.Context {
		t.Helper()
		var captured context.Context
		_, err := interceptor(bearerCtx(token), nil,
			&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(&captured))
		require.NoError(t, err)
		require.NotNil(t, captured)
		return captured
	}

	t.Run("machine identity", func(t *testing.T) {
		m, err := h.CoreService.CreateMachineIdentity(context.Background(), 2, "unary-bot", "service", "", "", 1, 0)
		require.NoError(t, err)
		proj2 := uint(2)
		h.AssignUserRole(t, 1, 2, &proj2) // admin at project 2: the issuer's privilege ceiling
		tok, err := h.CoreService.IssueMachineToken(context.Background(), 2, m.ID, 1, core.IssueMachineTokenParams{Name: "tok"})
		require.NoError(t, err)

		ev := latestAuditAfter(t, h, unaryCtx(t, tok.PlainToken), m.ID)
		assert.Equal(t, core.ActorTypeMachine, ev.ActorType, "actor kind")
		require.NotNil(t, ev.MachineIdentityID, "the audit row must record WHICH machine")
		assert.Equal(t, m.ID, *ev.MachineIdentityID)
		assert.Nil(t, ev.UserID, "a machine actor's id must never occupy UserID")
		assert.Nil(t, ev.ImpersonatedBy)
		assert.False(t, ev.Impersonation)
	})

	t.Run("impersonating session", func(t *testing.T) {
		const adminID, targetID uint = 7201, 7202
		h.CreateTestUser(t, "unary-imp-target", targetID)
		h.CreateTestUser(t, "unary-imp-admin", adminID)
		h.AssignUserRole(t, adminID, 1, nil) // super_admin: the impersonation ceiling is re-checked per request
		exp := time.Now().Add(time.Hour)
		admin := adminID
		_, err := h.Storage.CreateSession(context.Background(), &models.Session{
			UserID: targetID, SessionToken: "unary-imp-token", ExpiresAt: &exp, ImpersonatedBy: &admin,
		})
		require.NoError(t, err)

		ev := latestAuditAfter(t, h, unaryCtx(t, "unary-imp-token"), targetID)
		assert.Equal(t, core.ActorTypeUser, ev.ActorType, "actor kind")
		require.NotNil(t, ev.ImpersonatedBy, "the audit row must record the initiating admin")
		assert.Equal(t, adminID, *ev.ImpersonatedBy)
		assert.True(t, ev.Impersonation)
		assert.Nil(t, ev.MachineIdentityID, "a human session must not carry a machine id")
	})
}
