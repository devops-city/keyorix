package interceptors

// auth_mfa_grace_test.go -- #2923 over gRPC: during ADR-112's require_mfa
// upgrade grace period a session without a second factor passes the MFA gate
// (unary and stream), and once the period is over the same session is refused
// with requireMFA still the configured true.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
)

func graceWindow(start time.Time) core.MFAUpgradeGraceWindow {
	return core.MFAUpgradeGraceWindow{
		Start: start, Deadline: start.Add(config.ADR112RequireMFAGracePeriod), Floor: start,
		EnforcedMarkerKey: config.ADR112RequireMFAEnforcedMarker, ClockKey: config.ADR112RequireMFAGraceClockKey,
	}
}

func TestAuthInterceptor_MFAUpgradeGrace(t *testing.T) {
	for name, tc := range map[string]struct {
		start   time.Time
		allowed bool
	}{
		"inside the grace period": {start: time.Now().Add(-24 * time.Hour), allowed: true},
		"past the deadline":       {start: time.Now().Add(-config.ADR112RequireMFAGracePeriod - time.Minute), allowed: false},
	} {
		t.Run(name, func(t *testing.T) {
			h := setupAuthHelper(t)
			defer h.Cleanup()
			mintSessionForTest(t, h, 9800, "grpc-grace", "grace-token", time.Now().Add(time.Hour))
			h.CoreService.StartMFAUpgradeGrace(graceWindow(tc.start))

			unary := AuthInterceptor(h.CoreService, true /*requireMFA*/)
			_, uerr := unary(bearerCtx("grace-token"), nil, &grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
			stream := StreamAuthInterceptor(h.CoreService, true)
			serr := stream(nil, &fakeStream{ctx: streamBearerCtx("grace-token")},
				&grpc.StreamServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"},
				func(_ any, _ grpc.ServerStream) error { return nil })
			if tc.allowed {
				require.NoError(t, uerr, "no MFA confinement during the grace period")
				require.NoError(t, serr)
				return
			}
			assert.Equal(t, codes.PermissionDenied, status.Code(uerr), "after the grace period the MFA gate applies: %v", uerr)
			assert.Equal(t, codes.PermissionDenied, status.Code(serr))
		})
	}
}
