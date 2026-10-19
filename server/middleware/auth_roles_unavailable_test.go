package middleware

// auth_roles_unavailable_test.go — regression coverage for #1944 (PAT,
// session) and #2748 (machine token, OIDC JWT).
//
// When ValidatePATToken/ValidateSessionToken/ValidateMachineToken/
// ValidateOIDCToken report
// core.ErrRoleResolutionUnavailable (the credential checked out but the
// owner's roles could not be read from storage), the auth middleware must
// treat it like any other transient infrastructure failure: a retryable 503,
// no negative-cache entry, no per-IP brute-force strike — and, above all, no
// positively-cached UserContext carrying a bogus empty role list.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
)

const (
	rolesDownPAT     = "kx_pat_rolesdown1944"
	rolesDownSession = "session-rolesdown-1944"
	// #2748: the two MACHINE credential paths had the same soft-fail #1944
	// removed from the user paths. A machine-token cache HIT only ever
	// refreshes the credential's restriction/revocation state, never its
	// roles, so a positively-cached empty role list would have survived for
	// the whole validTokenTTL window.
	rolesDownMachine = "kx_machine_rolesdown2748"
	rolesDownOIDC    = "header.rolesdown2748.sig"
)

// rolesUnavailableValidator behaves like fakeValidator except that the two
// user-credential validators fail role resolution for the #1944 tokens.
type rolesUnavailableValidator struct{ fakeValidator }

func (v rolesUnavailableValidator) ValidatePATToken(ctx context.Context, token string) (*models.User, []string, *core.PATRestriction, uint, error) {
	if token == rolesDownPAT {
		return nil, nil, nil, 0, core.ErrRoleResolutionUnavailable
	}
	return v.fakeValidator.ValidatePATToken(ctx, token)
}

func (v rolesUnavailableValidator) ValidateSessionToken(ctx context.Context, token string) (*models.User, []string, error) {
	if token == rolesDownSession {
		// Wrapped, to prove the classifier uses errors.Is rather than ==.
		return nil, nil, fmt.Errorf("validate: %w", core.ErrRoleResolutionUnavailable)
	}
	return v.fakeValidator.ValidateSessionToken(ctx, token)
}

func (v rolesUnavailableValidator) ValidateMachineToken(ctx context.Context, token string) (*models.MachineIdentity, []string, *core.MachineTokenRestriction, uint, error) {
	if token == rolesDownMachine {
		return nil, nil, nil, 0, core.ErrRoleResolutionUnavailable
	}
	return v.fakeValidator.ValidateMachineToken(ctx, token)
}

func (v rolesUnavailableValidator) ValidateOIDCToken(ctx context.Context, token string) (*models.MachineIdentity, []string, time.Time, error) {
	if token == rolesDownOIDC {
		return nil, nil, time.Time{}, fmt.Errorf("validate: %w", core.ErrRoleResolutionUnavailable)
	}
	return v.fakeValidator.ValidateOIDCToken(ctx, token)
}

func TestHandleAuthRequest_RoleResolutionUnavailable_Is503AndUncached(t *testing.T) {
	cases := []struct {
		name, token, remoteAddr, ip string
	}{
		{"PAT", rolesDownPAT, "203.0.113.44:5555", "203.0.113.44"},
		{"session", rolesDownSession, "203.0.113.45:5555", "203.0.113.45"},
		{"machine token", rolesDownMachine, "203.0.113.46:5555", "203.0.113.46"},
		{"OIDC JWT", rolesDownOIDC, "203.0.113.47:5555", "203.0.113.47"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			handler := authenticationWithValidator(rolesUnavailableValidator{}, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			req.RemoteAddr = tc.remoteAddr
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusServiceUnavailable, rr.Code,
				"a role-resolution storage failure must be a retryable 503, not a 401 and not a 200 with empty roles")
			assert.Equal(t, "2", rr.Header().Get("Retry-After"))
			assert.False(t, reached, "the request must not reach the handler with a half-built identity")

			_, found := cacheGet(tokenKey(tc.token))
			assert.False(t, found, "neither a negative nor a positive cache entry may be written")

			for i := range tokenAuthFailureBurst {
				assert.True(t, recordTokenAuthFailure(tc.ip),
					"budget slot %d must still be available — this is not a bad-credential attempt", i)
			}
		})
	}
}

func TestIsTransientValidationError_RoleResolutionUnavailable(t *testing.T) {
	assert.True(t, isTransientValidationError(context.Background(), core.ErrRoleResolutionUnavailable))
	assert.True(t, isTransientValidationError(context.Background(), fmt.Errorf("wrap: %w", core.ErrRoleResolutionUnavailable)))
}
