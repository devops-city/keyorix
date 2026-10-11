package grpc_test

// pat_restriction_self_service_test.go — PAT-GUARD-2, the gRPC half of
// server/http/pat_restriction_self_service_test.go: BreakGlassService.
// ActivateBreakGlass is refused for a restricted PAT (Andrei's decision of
// 2026-10-11, ADR-042). Activation is self-service and never reaches Authorize,
// so a token confined below its owner could otherwise grant that owner an
// emergency role. gRPC has no own-token or own-session revoke RPC, so the allowed
// half of the decision is HTTP-only.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// TestGRPCPATRestriction_RestrictedPATCannotActivateBreakGlass: every restricted
// persona of both owners gets PermissionDenied and creates no activation; the same
// owners' unrestricted PATs then activate, so the refusal is the restriction.
func TestGRPCPATRestriction_RestrictedPATCannotActivateBreakGlass(t *testing.T) {
	w := newGRPCPATGuardWorld(t)
	// project_developer: a contained project role neither owner holds (both are
	// project_admin at the canary project), so a real activation can succeed.
	w.core.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: true, EmergencyRole: "project_developer", DefaultTTL: time.Hour, MaxTTL: time.Hour,
	})
	client := pb.NewBreakGlassServiceClient(w.conn)
	activate := func(token string) error {
		ctx, cancel := context.WithTimeout(
			metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token)), 10*time.Second)
		defer cancel()
		_, err := client.ActivateBreakGlass(ctx, &pb.ActivateBreakGlassRequest{
			ProjectId: uint32(w.canaryPID), Justification: "PAT-GUARD-2 incident response drill", //nolint:gosec // fixture id is tiny
		})
		return err
	}
	restricted := []string{"pat_decoy_project", "pat_decoy_env", "pat_users_read_only", "pat_secrets_read_decoy", "pat_system_read_only"}
	owners := []string{"", "admin_"}

	for _, o := range owners {
		for _, persona := range restricted {
			t.Run(o+persona, func(t *testing.T) {
				err := activate(w.tokens[o+persona])
				assert.Equal(t, codes.PermissionDenied, status.Code(err), "%v", err)
				assert.Contains(t, status.Convert(err).Message(), core.ErrRestrictedPATCannotBreakGlass.Error())
			})
		}
	}
	activations, err := w.core.ListBreakGlassActivations(context.Background(), uint(w.canaryPID))
	require.NoError(t, err)
	require.Empty(t, activations, "a refused activation must not grant anything")

	for _, o := range owners {
		t.Run("control_"+o+"pat_unrestricted", func(t *testing.T) {
			assert.NoError(t, activate(w.tokens[o+"pat_unrestricted"]))
		})
	}
	activations, err = w.core.ListBreakGlassActivations(context.Background(), uint(w.canaryPID))
	require.NoError(t, err)
	assert.Len(t, activations, len(owners), "the unrestricted controls must activate")
}
