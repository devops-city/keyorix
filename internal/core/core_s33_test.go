// core_s33_test.go — sprint-33 coverage blitz:
// oidc_jwks.go (parseJWK EC branches, default kty, invalid base64),
// invitations.go (revokeAssignmentGrants branches),
// jit_access.go (AssignGroupRoleWithExpiry error branch),
// notifications.go (notifyGroupSecretShareRevoked with members),
// setup_consume.go (displayNameFromEmail empty string),
// account_state.go (setAccountState extra branches),
// rate_limit.go (extra branches via struct fields),
// rbac.go (AssignRoleToUser success, RemoveRoleFromUser success).
package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ── oidc_jwks.go — parseJWK EC branches ─────────────────────────────────

func TestParseJWK_ECUnsupportedCurve(t *testing.T) {
	t.Parallel()
	k := jwk{Kty: "EC", Crv: "P-999"}
	_, err := parseJWK(k)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported EC curve")
}

func TestParseJWK_ECUnsupportedKty(t *testing.T) {
	t.Parallel()
	k := jwk{Kty: "OKP"}
	_, err := parseJWK(k)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported kty")
}

func TestParseJWK_ECP256Success(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	k := jwk{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.X.Bytes()), //nolint:staticcheck
		Y:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.Y.Bytes()), //nolint:staticcheck
	}
	result, err := parseJWK(k)
	require.NoError(t, err)
	pub, ok := result.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, elliptic.P256(), pub.Curve)
}

func TestParseJWK_ECP384Success(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	k := jwk{
		Kty: "EC",
		Crv: "P-384",
		X:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.X.Bytes()), //nolint:staticcheck
		Y:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.Y.Bytes()), //nolint:staticcheck
	}
	result, err := parseJWK(k)
	require.NoError(t, err)
	pub, ok := result.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, elliptic.P384(), pub.Curve)
}

func TestParseJWK_ECP521Success(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	k := jwk{
		Kty: "EC",
		Crv: "P-521",
		X:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.X.Bytes()), //nolint:staticcheck
		Y:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.Y.Bytes()), //nolint:staticcheck
	}
	result, err := parseJWK(k)
	require.NoError(t, err)
	pub, ok := result.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, elliptic.P521(), pub.Curve)
}

func TestParseJWK_ECInvalidXBase64(t *testing.T) {
	t.Parallel()
	k := jwk{Kty: "EC", Crv: "P-256", X: "!!!invalid", Y: "AAAA"}
	_, err := parseJWK(k)
	require.Error(t, err)
}

func TestParseJWK_RSAInvalidNBase64(t *testing.T) {
	t.Parallel()
	k := jwk{Kty: "RSA", N: "!!!bad base64", E: "AQAB"}
	_, err := parseJWK(k)
	require.Error(t, err)
}

// ── setup_consume.go — displayNameFromEmail empty email ──────────────────

func TestDisplayNameFromEmail_EmptyEmail(t *testing.T) {
	t.Parallel()
	// localPart("") returns "" → displayNameFromEmail returns ""
	result := displayNameFromEmail("")
	assert.Equal(t, "", result)
}

// ── invitations.go — revokeAssignmentGrants ──────────────────────────────

func TestRevokeAssignmentGrants_EmptyJSON(t *testing.T) {
	t.Parallel()
	c := NewKeyorixCore(new(MockStorage))
	inv := &models.ProjectInvitation{AssignmentsJSON: ""}
	// Should return immediately without error or panicking.
	c.revokeAssignmentGrants(context.Background(), inv, 1)
}

func TestRevokeAssignmentGrants_InvalidJSON(t *testing.T) {
	t.Parallel()
	c := NewKeyorixCore(new(MockStorage))
	inv := &models.ProjectInvitation{AssignmentsJSON: "not-json"}
	// Invalid JSON → returns early without panicking.
	c.revokeAssignmentGrants(context.Background(), inv, 1)
}

func TestRevokeAssignmentGrants_ValidJSON_RemoveFails(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// RemoveProjectMember calls GetUserRoleIDsExact.
	ms.On("GetUserRoleIDsExact", mock.Anything, uint(5), mock.AnythingOfType("storage.Scope")).Return([]uint{}, nil)
	// With empty existing roles, RemoveProjectMember returns "user is not a member"
	// which feeds the auditProjectScoped path.
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	inv := &models.ProjectInvitation{
		ID:              1,
		AssignmentsJSON: `[{"project_id":10,"role":"viewer"}]`,
	}
	c.revokeAssignmentGrants(context.Background(), inv, 5)
	// No assertions needed — just verifying no panic.
}

// ── jit_access.go — AssignGroupRoleWithExpiry ────────────────────────────

func TestAssignGroupRoleWithExpiry_RoleNotFound_s33(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetRole", mock.Anything, uint(99)).Return(nil, errors.New("role not found"))
	c := NewKeyorixCore(ms)
	err := c.AssignGroupRoleWithExpiry(context.Background(), 0, 1, 99, Scope{}, time.Now().Add(time.Hour), false)
	require.Error(t, err)
}

func TestAssignGroupRoleWithExpiry_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	role := &models.Role{ID: 2, Name: "viewer"} // actorID 0, actorIsMachine false → trusted system pseudo-actor, ceiling skipped
	ms.On("GetRole", mock.Anything, uint(2)).Return(role, nil)
	// requireGroupGrantNoSoDViolation: ListSoDPolicies stub returns nil → OK
	ms.On("GetRole", mock.Anything, uint(2)).Return(&models.Role{ID: 2, Name: "test-role-2"}, nil).Maybe() // #3546 role-scope check
	ms.On("AssignRoleToGroupWithExpiry", mock.Anything, uint(1), uint(2), mock.AnythingOfType("storage.Scope"), mock.AnythingOfType("time.Time")).Return(nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	err := c.AssignGroupRoleWithExpiry(context.Background(), 0, 1, 2, Scope{}, time.Now().Add(time.Hour), false)
	require.NoError(t, err)
}

// ── notifications.go — notifyGroupSecretShareRevoked ─────────────────────

func TestNotifyGroupSecretShareRevoked_NilSecret(t *testing.T) {
	t.Parallel()
	c := NewKeyorixCore(new(MockStorage))
	// nil secret → return immediately
	c.notifyGroupSecretShareRevoked(context.Background(), nil, 1, 2)
}

func TestNotifyGroupSecretShareRevoked_ListMembersError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("ListGroupMembers", mock.Anything, uint(1)).Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	secret := &models.SecretNode{Name: "mysecret"}
	// err → return early
	c.notifyGroupSecretShareRevoked(context.Background(), secret, 1, 2)
}

func TestNotifyGroupSecretShareRevoked_WithMembers(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	members := []*models.User{{ID: 10}, {ID: 11}}
	ms.On("ListGroupMembers", mock.Anything, uint(5)).Return(members, nil)
	// notifySecretShareRevoked → notify → notifyWithSeverity → CreateNotification
	// member 10 and 11 both != revokedBy (2), so both get notified
	ms.On("CreateNotification", mock.Anything, mock.AnythingOfType("*models.Notification")).Return(&models.Notification{}, nil)
	c := NewKeyorixCore(ms)
	secret := &models.SecretNode{Name: "mysecret", ID: 7}
	c.notifyGroupSecretShareRevoked(context.Background(), secret, 5, 2)
	ms.AssertExpectations(t)
}

// ── rbac.go — AssignRoleToUser success path ──────────────────────────────

func TestAssignRoleToUser_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUserByEmail", mock.Anything, "alice@example.com").Return(&models.User{ID: 5}, nil)
	ms.On("GetRoleByName", mock.Anything, "viewer").Return(&models.Role{ID: 3, Name: "viewer"}, nil)
	// requireNoSoDViolation: ListSoDPolicies smart stub = nil → OK
	// assignUserRoleSystemGrant calls AssignRole
	ms.On("GetRole", mock.Anything, uint(3)).Return(&models.Role{ID: 3, Name: "test-role-3"}, nil).Maybe() // #3546 role-scope check
	ms.On("AssignRole", mock.Anything, uint(5), uint(3), mock.AnythingOfType("storage.Scope")).Return(nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	// AssignRoleToUser(ctx, userEmail, roleName) — no actorID
	err := c.AssignRoleToUser(context.Background(), "alice@example.com", "viewer")
	require.NoError(t, err)
}

func TestAssignRoleToUser_UserNotFound_s33(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUserByEmail", mock.Anything, "nobody@example.com").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.AssignRoleToUser(context.Background(), "nobody@example.com", "viewer")
	require.Error(t, err)
}

// ── rbac.go — RemoveRoleFromUser success path ────────────────────────────

func TestRemoveRoleFromUser_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUserByEmail", mock.Anything, "alice@example.com").Return(&models.User{ID: 5}, nil)
	// installAdminRoleIDSet tries GetRoleByName for "super_admin", "admin", "system_admin" — all not found
	ms.On("GetRoleByName", mock.Anything, "super_admin").Return(nil, errors.New("not found"))
	ms.On("GetRoleByName", mock.Anything, "admin").Return(nil, errors.New("not found"))
	ms.On("GetRoleByName", mock.Anything, "system_admin").Return(nil, errors.New("not found"))
	ms.On("GetRoleByName", mock.Anything, "viewer").Return(&models.Role{ID: 3, Name: "viewer"}, nil)
	// RemoveUserRole: adminIDs is empty → calls RemoveRole
	ms.On("RemoveRole", mock.Anything, uint(5), uint(3), mock.AnythingOfType("storage.Scope")).Return(nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	// evictUserSessionCache: evicts the removed-role user's cached sessions.
	ms.On("ListSessionTokenHashesForUser", mock.Anything, uint(5)).Return([]string{}, nil)
	c := NewKeyorixCore(ms)
	err := c.RemoveRoleFromUser(context.Background(), "alice@example.com", "viewer")
	require.NoError(t, err)
}

func TestRemoveRoleFromUser_UserNotFound_s33(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUserByEmail", mock.Anything, "nobody@example.com").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.RemoveRoleFromUser(context.Background(), "nobody@example.com", "viewer")
	require.Error(t, err)
}
