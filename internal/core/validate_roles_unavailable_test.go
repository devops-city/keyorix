package core

// validate_roles_unavailable_test.go — regression coverage for #1944 (user
// credentials) and #2748 (machine credentials).
//
// ValidatePATToken and ValidateSessionToken used to soft-fail a GetUserRoles
// storage error into ([]string{}, nil): a successful-looking validation with
// an empty role list, which the HTTP auth middleware then positively cached as
// UserContext.Roles. Both must now return the distinguishable, retryable
// ErrRoleResolutionUnavailable — and no half-built identity — so the caller
// can answer "retry" instead of silently misreporting the user's roles.
//
// #2748: ValidateMachineToken (ADR-030) and ValidateOIDCToken (ADR-031) had
// the SAME soft-fail that #1944 removed from the two user-credential paths,
// and were missed by it. They are held to the identical contract here.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var errRolesStorageDown = errors.New("pq: connection reset by peer")

func TestValidatePATToken_RolesLookupFailure_ReturnsRetryableError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	raw := patPrefix + "rolesdown1944"

	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ms.On("GetPersonalAccessTokenByHash", ctx, sha256Hex(raw)).Return(&models.PersonalAccessToken{ID: 9, UserID: 1}, nil)
	ms.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: acctTestUser, IsActive: true, AccountState: AccountActive}, nil)
	ms.On("GetUserRoles", ctx, uint(1)).Return(nil, errRolesStorageDown)

	user, roles, restriction, patID, err := c.ValidatePATToken(ctx, raw)
	require.ErrorIs(t, err, ErrRoleResolutionUnavailable)
	assert.NotErrorIs(t, err, errRolesStorageDown, "the storage error's detail must not be wrapped into the caller-visible error")
	assert.Nil(t, user, "no half-built identity may be returned alongside the error")
	assert.Nil(t, roles)
	assert.Nil(t, restriction)
	assert.Zero(t, patID, "a zero patID keeps the caller from stamping last_used_at for a failed validation")
	assert.NotErrorIs(t, err, ErrPATRevoked)
	assert.NotErrorIs(t, err, ErrPATExpired)
}

func TestValidateSessionToken_RolesLookupFailure_ReturnsRetryableError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ms.On("GetSession", ctx, "tok-1944").Return(&models.Session{ID: 7, UserID: 2}, nil)
	ms.On("TouchSession", ctx, uint(7), mock.Anything, mock.Anything).Return(nil)
	ms.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, IsActive: true, AccountState: AccountActive}, nil)
	ms.On("GetUserRoles", ctx, uint(2)).Return(nil, errRolesStorageDown)

	user, roles, err := c.ValidateSessionToken(ctx, "tok-1944")
	c.FlushLastUsed(ctx) // write the coalesced stamp now, not from a timer after the test
	require.ErrorIs(t, err, ErrRoleResolutionUnavailable)
	assert.NotErrorIs(t, err, errRolesStorageDown)
	assert.Nil(t, user)
	assert.Nil(t, roles)
}

// #2748: a GetMachineRoles storage failure must fail the validation with the
// same retryable sentinel the PAT/session paths use, not hand back a
// successful-looking machine principal with an empty role list. The empty-roles
// result was never a privilege gain (zero roles only ever fails closed at
// core.Authorize), but the HTTP middleware POSITIVELY CACHES whatever
// UserContext it gets for up to validTokenTTL, and a machine-token cache HIT
// refreshes only the credential's restriction/revocation state — never its
// roles. So one blip silently stripped a machine identity of every grant for
// the rest of the cache window, long after storage recovered, and reported
// success the whole time.
func TestValidateMachineToken_RolesLookupFailure_ReturnsRetryableError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	raw := machineTokenPrefix + "rolesdown2748"

	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ms.On("GetMachineIdentityCredentialByHash", ctx, sha256Hex(raw)).
		Return(&models.MachineIdentityCredential{ID: 11, MachineIdentityID: 4, AllowedCIDRs: "10.0.0.0/8"}, nil)
	ms.On("GetMachineIdentity", ctx, uint(4)).
		Return(&models.MachineIdentity{ID: 4, Name: "ci", State: MachineActive}, nil)
	ms.On("GetMachineRoles", ctx, uint(4)).Return(nil, errRolesStorageDown)

	m, roles, restriction, credID, err := c.ValidateMachineToken(ctx, raw)
	require.ErrorIs(t, err, ErrRoleResolutionUnavailable)
	assert.NotErrorIs(t, err, errRolesStorageDown, "the storage error's detail must not be wrapped into the caller-visible error")
	assert.Nil(t, m, "no half-built machine principal may be returned alongside the error")
	assert.Nil(t, roles)
	assert.Nil(t, restriction)
	assert.Zero(t, credID, "a zero credential id keeps the caller from stamping last_used_at for a failed validation")
	assert.NotErrorIs(t, err, ErrMachineTokenRevoked)
	assert.NotErrorIs(t, err, ErrMachineTokenExpired)
}

// #2748, sibling: the federated (ADR-031) path shares the same GetMachineRoles
// call and had the same soft-fail.
func TestValidateOIDCToken_RolesLookupFailure_ReturnsRetryableError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ms := new(MockStorage)
	ms.On("GetMachineByOIDCSubject", mock.Anything, "https://k8s.local", "sa").
		Return(&models.MachineIdentity{ID: 7, Name: "ci", State: MachineActive}, nil)
	ms.On("GetMachineRoles", mock.Anything, uint(7)).Return(nil, errRolesStorageDown)

	c := NewKeyorixCore(ms)
	c.SetOIDCVerifier(newTestVerifier(t, key))
	raw := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://k8s.local", "sub": "sa", "aud": []string{"keyorix"},
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	m, roles, err := c.ValidateOIDCToken(ctx, raw)
	require.ErrorIs(t, err, ErrRoleResolutionUnavailable)
	assert.NotErrorIs(t, err, errRolesStorageDown)
	assert.Nil(t, m)
	assert.Nil(t, roles)
}
