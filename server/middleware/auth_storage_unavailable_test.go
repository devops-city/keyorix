package middleware

// auth_storage_unavailable_test.go -- core.ErrAuthStorageUnavailable (a failed
// credential/account/identity lookup, found by scripts/drills/disaster.sh pgdown,
// PROD-OPS-1) gets the same treatment as core.ErrRoleResolutionUnavailable: a
// retryable 503, no negative-cache entry, no per-IP brute-force strike. Before, the
// middleware answered 401, negative-cached the token for invalidTokenTTL and charged
// the caller's IP for it while the database was down.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
)

const (
	storageDownMachine = "kx_machine_storagedown"
	storageDownSession = "session-storagedown"
)

type storageDownValidator struct{ fakeValidator }

func (v storageDownValidator) ValidateMachineToken(ctx context.Context, token string) (*models.MachineIdentity, []string, *core.MachineTokenRestriction, uint, error) {
	if token == storageDownMachine {
		return nil, nil, nil, 0, core.ErrAuthStorageUnavailable
	}
	return v.fakeValidator.ValidateMachineToken(ctx, token)
}

func (v storageDownValidator) ValidateSessionToken(ctx context.Context, token string) (*models.User, []string, error) {
	if token == storageDownSession {
		return nil, nil, fmt.Errorf("validate: %w", core.ErrAuthStorageUnavailable)
	}
	return v.fakeValidator.ValidateSessionToken(ctx, token)
}

func TestHandleAuthRequest_AuthStorageUnavailable_Is503AndUncached(t *testing.T) {
	cases := []struct {
		name, token, remoteAddr, ip string
	}{
		{"machine token", storageDownMachine, "203.0.113.60:5555", "203.0.113.60"},
		{"session", storageDownSession, "203.0.113.61:5555", "203.0.113.61"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			handler := authenticationWithValidator(storageDownValidator{}, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			req.RemoteAddr = tc.remoteAddr
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusServiceUnavailable, rr.Code,
				"a storage fault while looking the credential up must be a retryable 503, not a 401")
			assert.Equal(t, "2", rr.Header().Get("Retry-After"))
			assert.False(t, reached)
			_, found := cacheGet(tokenKey(tc.token))
			assert.False(t, found, "the outage must not be negative-cached as an invalid token")
			for i := range tokenAuthFailureBurst {
				assert.True(t, recordTokenAuthFailure(tc.ip), "budget slot %d must still be available", i)
			}
		})
	}
}

func TestIsTransientValidationError_AuthStorageUnavailable(t *testing.T) {
	assert.True(t, isTransientValidationError(context.Background(), core.ErrAuthStorageUnavailable))
	assert.True(t, isTransientValidationError(context.Background(), fmt.Errorf("wrap: %w", core.ErrAuthStorageUnavailable)))
}
