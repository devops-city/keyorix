package interceptors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestEnforceGRPCAccountSetup is the decision table of the gRPC side of the
// account-setup gate (#3024, #3041 review). The every-RPC walk is
// server/grpc/setup_session_gate_test.go.
func TestEnforceGRPCAccountSetup(t *testing.T) {
	restrictedNoFactor := &models.User{AccountState: core.AccountPasswordResetRequired}
	done := &models.User{AccountState: core.AccountActive, MFAEnabled: true}
	onlyMFAOwed := &models.User{AccountState: core.AccountActive}

	cases := []struct {
		name                    string
		user                    *models.User
		requireMFA, viaSession  bool
		setupOnly, impersonated bool
		wantCode                codes.Code
		wantMsg                 string
	}{
		{"setup-only, both steps owed", restrictedNoFactor, true, true, true, false, codes.PermissionDenied, grpcSetupOnlyMsg},
		{"setup-only, one step owed", onlyMFAOwed, true, true, true, false, codes.PermissionDenied, grpcSetupOnlyMsg},
		{"setup-only, nothing owed (revocation did not land)", done, true, true, true, false, codes.Unauthenticated, grpcSetupCompleteMsg},
		{"setup-only, policy off on this transport", restrictedNoFactor, false, true, true, false, codes.PermissionDenied, grpcSetupOnlyMsg},
		{"ordinary session owing both steps", restrictedNoFactor, true, true, false, false, codes.Unauthenticated, grpcSetupReauthMsg},
		{"impersonation session owing both steps: left to the access policy", restrictedNoFactor, true, true, false, true, codes.OK, ""},
		{"ordinary session owing one step: left to the access policy", onlyMFAOwed, true, true, false, false, codes.OK, ""},
		{"PAT of a restricted account: left to the access policy", restrictedNoFactor, true, false, false, false, codes.OK, ""},
		{"ordinary session owing nothing", done, true, true, false, false, codes.OK, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := enforceGRPCAccountSetup(tc.user, tc.requireMFA, tc.viaSession, tc.setupOnly, tc.impersonated)
			st := status.Convert(err)
			assert.Equal(t, tc.wantCode, st.Code(), st.Message())
			if tc.wantMsg != "" {
				assert.Equal(t, tc.wantMsg, st.Message())
			}
		})
	}
}
