// core_s34_test.go — sprint-34 coverage blitz:
// sso.go (extractTokenStringList branches),
// oidc.go (DeleteOIDCBinding branches),
// mfa.go (CreateMFAChallenge success),
// dynamic_secrets.go (requireLiveProjectAndEnvironment extra branches),
// invitations.go (revokeSystemRoleGrant branches, requireAdminAuthorityAt extra),
// rbac_management.go (extra branches),
// jit_access.go (assignUserRoleWithExpirySkipSoD),
// webauthn.go (storeWebAuthnSession success).
package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// ── sso.go — extractTokenStringList ──────────────────────────────────────

func makeJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, _ := json.Marshal(claims)
	b64payload := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + b64payload + ".sig"
}

func TestExtractTokenStringList_InvalidParts(t *testing.T) {
	t.Parallel()
	// Not 3 parts → false
	_, ok := extractTokenStringList("onlytwoparts.here", "groups")
	assert.False(t, ok)
}

func TestExtractTokenStringList_InvalidBase64Payload(t *testing.T) {
	t.Parallel()
	// Part 2 is invalid base64url
	_, ok := extractTokenStringList("header.!!!invalid.sig", "groups")
	assert.False(t, ok)
}

func TestExtractTokenStringList_InvalidJSONPayload(t *testing.T) {
	t.Parallel()
	// Valid base64 but not JSON
	bad := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
	_, ok := extractTokenStringList("header."+bad+".sig", "groups")
	assert.False(t, ok)
}

func TestExtractTokenStringList_ClaimNotFound(t *testing.T) {
	t.Parallel()
	tok := makeJWT(map[string]any{"other": "val"})
	result, ok := extractTokenStringList(tok, "groups")
	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestExtractTokenStringList_StringSliceClaim(t *testing.T) {
	t.Parallel()
	tok := makeJWT(map[string]any{"groups": []string{"a", "b"}})
	result, ok := extractTokenStringList(tok, "groups")
	assert.True(t, ok)
	assert.Equal(t, []string{"a", "b"}, result)
}

func TestExtractTokenStringList_AnySliceClaim(t *testing.T) {
	t.Parallel()
	// JSON with mixed types (numeric → skipped, string → kept)
	tok := makeJWT(map[string]any{"groups": []any{"x", 42}})
	result, ok := extractTokenStringList(tok, "groups")
	assert.True(t, ok)
	assert.Equal(t, []string{"x"}, result)
}

func TestExtractTokenStringList_SingleStringClaim(t *testing.T) {
	t.Parallel()
	tok := makeJWT(map[string]any{"role": "admin"})
	result, ok := extractTokenStringList(tok, "role")
	assert.True(t, ok)
	assert.Equal(t, []string{"admin"}, result)
}

func TestExtractTokenStringList_UnrecognizedShape(t *testing.T) {
	t.Parallel()
	// A number — not a string, not a slice → return nil, true (present but unrecognized)
	tok := makeJWT(map[string]any{"count": 42})
	result, ok := extractTokenStringList(tok, "count")
	assert.True(t, ok)
	assert.Nil(t, result)
}

// ── oidc.go — DeleteOIDCBinding ──────────────────────────────────────────

func TestDeleteOIDCBinding_MachineNotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetMachineIdentity", mock.Anything, uint(1)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.DeleteOIDCBinding(context.Background(), 1, 1, 1, 0)
	require.Error(t, err)
}

func TestDeleteOIDCBinding_BindingNotFound_s34(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetMachineIdentity", mock.Anything, uint(1)).Return(&models.MachineIdentity{ID: 1, ProjectID: 1}, nil)
	ms.On("GetOIDCBindingByID", mock.Anything, uint(5)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.DeleteOIDCBinding(context.Background(), 1, 1, 5, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "binding not found")
}

func TestDeleteOIDCBinding_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	machine := &models.MachineIdentity{ID: 1, ProjectID: 1}
	ms.On("GetMachineIdentity", mock.Anything, uint(1)).Return(machine, nil)
	binding := &models.MachineIdentityOIDCBinding{ID: 5, MachineIdentityID: 1}
	ms.On("GetOIDCBindingByID", mock.Anything, uint(5)).Return(binding, nil)
	ms.On("DeleteOIDCBinding", mock.Anything, uint(5)).Return(nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	err := c.DeleteOIDCBinding(context.Background(), 1, 1, 5, 0)
	require.NoError(t, err)
}

// ── mfa.go — CreateMFAChallenge ───────────────────────────────────────────

func TestCreateMFAChallenge_Success(t *testing.T) {
	t.Parallel()
	// MockStorage.CreateMFAChallenge is a hardcoded stub returning nil.
	c := NewKeyorixCore(new(MockStorage))
	token, err := c.CreateMFAChallenge(context.Background(), 5)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

// ── dynamic_secrets.go — requireLiveProjectAndEnvironment ─────────────────

func TestRequireLiveProjectAndEnvironment_ProjectNotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetProject", mock.Anything, uint(99)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.requireLiveProjectAndEnvironment(context.Background(), 99, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project not found")
}

func TestRequireLiveProjectAndEnvironment_ProjectFoundNoEnv(t *testing.T) {
	t.Parallel()
	// GetProject smart stub returns &models.Project{} by default when not mocked → success.
	// environmentID=0 → skip env check
	c := NewKeyorixCore(new(MockStorage))
	err := c.requireLiveProjectAndEnvironment(context.Background(), 1, 0)
	require.NoError(t, err)
}

func TestRequireLiveProjectAndEnvironment_ProjectFoundWithEnv(t *testing.T) {
	t.Parallel()
	// GetEnvironment stub always returns a valid env.
	c := NewKeyorixCore(new(MockStorage))
	err := c.requireLiveProjectAndEnvironment(context.Background(), 1, 2)
	require.NoError(t, err)
}

// ── invitations.go — revokeSystemRoleGrant ───────────────────────────────

func TestRevokeSystemRoleGrant_EmptySystemRole_s34(t *testing.T) {
	t.Parallel()
	c := NewKeyorixCore(new(MockStorage))
	inv := &models.ProjectInvitation{SystemRole: ""}
	// Empty SystemRole → return immediately.
	c.revokeSystemRoleGrant(context.Background(), inv, 1)
}

func TestRevokeSystemRoleGrant_RoleNotFound_s34(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetRoleByName", mock.Anything, "admin").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	inv := &models.ProjectInvitation{SystemRole: "admin"}
	// GetRoleByName fails → return early without error (best-effort).
	c.revokeSystemRoleGrant(context.Background(), inv, 1)
}

func TestRevokeSystemRoleGrant_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetRoleByName", mock.Anything, "viewer").Return(&models.Role{ID: 2, Name: "viewer"}, nil)
	// RemoveUserRole calls installAdminRoleIDSet which tries GetRoleByName for admin role names
	ms.On("GetRoleByName", mock.Anything, "super_admin").Return(nil, errors.New("not found"))
	ms.On("GetRoleByName", mock.Anything, "admin").Return(nil, errors.New("not found"))
	ms.On("GetRoleByName", mock.Anything, "system_admin").Return(nil, errors.New("not found"))
	ms.On("RemoveRole", mock.Anything, uint(1), uint(2), mock.AnythingOfType("storage.Scope")).Return(nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	// evictUserSessionCache: evicts the removed-role user's cached sessions.
	ms.On("ListSessionTokenHashesForUser", mock.Anything, uint(1)).Return([]string{}, nil)
	c := NewKeyorixCore(ms)
	inv := &models.ProjectInvitation{SystemRole: "viewer"}
	c.revokeSystemRoleGrant(context.Background(), inv, 1)
}

// ── jit_access.go — assignUserRoleWithExpirySkipSoD ──────────────────────

func TestAssignUserRoleWithExpirySkipSoD_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetRole", mock.Anything, uint(2)).Return(&models.Role{ID: 2, Name: "test-role-2"}, nil).Maybe() // #3546 role-scope check
	ms.On("AssignRoleWithExpiry", mock.Anything, uint(1), uint(2), mock.AnythingOfType("storage.Scope"), mock.AnythingOfType("time.Time")).Return(nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	err := c.assignUserRoleWithExpirySkipSoD(context.Background(), 0, 1, 2, Scope{}, time.Now().Add(time.Hour))
	require.NoError(t, err)
}

func TestAssignUserRoleWithExpirySkipSoD_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetRole", mock.Anything, uint(2)).Return(&models.Role{ID: 2, Name: "test-role-2"}, nil).Maybe() // #3546 role-scope check
	ms.On("AssignRoleWithExpiry", mock.Anything, uint(1), uint(2), mock.AnythingOfType("storage.Scope"), mock.AnythingOfType("time.Time")).Return(errors.New("db error"))
	c := NewKeyorixCore(ms)
	err := c.assignUserRoleWithExpirySkipSoD(context.Background(), 0, 1, 2, Scope{}, time.Now().Add(time.Hour))
	require.Error(t, err)
}

// ── webauthn.go — storeWebAuthnSession ───────────────────────────────────

func TestStoreWebAuthnSession_Success(t *testing.T) {
	t.Parallel()
	// CreateWebAuthnSession is a hardcoded stub returning nil.
	c := NewKeyorixCore(new(MockStorage))
	sd := &gowebauthn.SessionData{}
	token, err := c.storeWebAuthnSession(context.Background(), 1, "registration", sd)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}
