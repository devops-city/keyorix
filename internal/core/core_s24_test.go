// core_s24_test.go — sprint-24 coverage blitz:
// service.go (SetAuditForwarder, HasLicensedFeature, AuditLicenseState, WebAuthnEnabled,
// SetPasswordPolicy, SetSessionTTLs, ListActiveSecrets, HealthCheck, ResolveUsernames,
// SetSecretNamePolicy), secret_policy_info.go (SecretPolicies),
// secret_name_policy.go (DefaultSecretNamePolicy, compileNamePattern, validateSecretName),
// secrets.go (GetSecretByName, GetSecretByNameWithPermissionCheck, DeleteSecret,
// DeleteSecretWithPermissionCheck, RestoreSecret, UpdateSecretWithPermissionCheck),
// versions.go (GetSecretVersions, GetSecretVersionsWithPermissionCheck, GetSecretVersion,
// GetSecretVersionWithPermissionCheck, GetLatestSecretVersion, GetLatestSecretVersionWithPermissionCheck,
// GetSecretValueWithPermissionCheck, GetSecretValueByVersionWithPermissionCheck),
// sharing_query.go (ListSharedSecrets, ListSecretShares, ListSecretSharesWithPermissionCheck,
// CheckSharePermission, ListUserShareViews),
// usage_analytics.go (MostAccessedSecrets, UnusedSecrets),
// users.go (GetUser, ListUsers, GetUserByEmail, GetUserByUsername, GetUserByExternalID),
// scim_groups.go (DeprovisionSCIMGroup).
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ── service.go — setters and simple accessors ─────────────────────────────────

func TestSetAuditForwarder(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// Setting a nil forwarder must not panic.
	c.SetAuditForwarder(nil)
	assert.Nil(t, c.auditForwarder)
}

func TestWebAuthnEnabled_False(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	assert.False(t, c.WebAuthnEnabled())
}

func TestSetPasswordPolicy_Stored(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	p := PasswordPolicy{MinLength: 12}
	c.SetPasswordPolicy(p)
	assert.Equal(t, 12, c.passwordPolicy.MinLength)
}

func TestSetSessionTTLs_Stored(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetSessionTTLs(30*time.Minute, 8*time.Hour)
	assert.Equal(t, 30*time.Minute, c.sessionAccessTTL)
	assert.Equal(t, 8*time.Hour, c.sessionAbsoluteTTL)
}

func TestHealthCheck_StorageNil(t *testing.T) {
	t.Parallel()
	// Bypass NewKeyorixCore to construct a nil-storage core.
	c := &KeyorixCore{storage: nil}
	err := c.HealthCheck(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage not initialized")
}

func TestHealthCheck_StorageOK(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("HealthCheck", mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	require.NoError(t, c.HealthCheck(context.Background()))
	ms.AssertExpectations(t)
}

func TestHealthCheck_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("HealthCheck", mock.Anything).Return(errors.New("db down"))
	c := NewKeyorixCore(ms)
	err := c.HealthCheck(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db down")
}

func TestListActiveSecrets_Empty(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("ListSecrets", mock.Anything, mock.Anything).Return(nil, int64(0), nil)
	c := NewKeyorixCore(ms)
	secrets := c.ListActiveSecrets(context.Background())
	assert.Empty(t, secrets)
}

func TestListActiveSecrets_NonEmpty(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	nodes := []*models.SecretNode{{ID: 1, Name: "s1"}, {ID: 2, Name: "s2"}}
	ms.On("ListSecrets", mock.Anything, mock.Anything).Return(nodes, int64(2), nil)
	c := NewKeyorixCore(ms)
	secrets := c.ListActiveSecrets(context.Background())
	assert.Len(t, secrets, 2)
}

func TestListActiveSecrets_ErrorReturnsNil(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("ListSecrets", mock.Anything, mock.Anything).Return(nil, int64(0), errors.New("boom"))
	c := NewKeyorixCore(ms)
	secrets := c.ListActiveSecrets(context.Background())
	assert.Nil(t, secrets)
}

func TestResolveUsernames_EmptyEvents(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	result := c.ResolveUsernames(context.Background(), nil)
	assert.Equal(t, map[uint]string{0: "system"}, result)
}

func TestResolveUsernames_ResolvesUserID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	uid := uint(42)
	ms.On("GetUsernamesByIDs", mock.Anything, []uint{uid}).Return(map[uint]string{uid: "alice"}, nil)
	c := NewKeyorixCore(ms)
	events := []*models.AuditEvent{{UserID: &uid}}
	result := c.ResolveUsernames(context.Background(), events)
	assert.Equal(t, "alice", result[uid])
	assert.Equal(t, "system", result[0])
}

func TestResolveUsernames_UserNotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	uid := uint(99)
	ms.On("GetUsernamesByIDs", mock.Anything, []uint{uid}).Return(map[uint]string{}, nil)
	c := NewKeyorixCore(ms)
	events := []*models.AuditEvent{{UserID: &uid}}
	result := c.ResolveUsernames(context.Background(), events)
	assert.Equal(t, "unknown", result[uid])
}

func TestResolveUsernames_ImpersonatedBy(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	uid := uint(5)
	ms.On("GetUsernamesByIDs", mock.Anything, []uint{uid}).Return(map[uint]string{uid: "admin"}, nil)
	c := NewKeyorixCore(ms)
	events := []*models.AuditEvent{{ImpersonatedBy: &uid}}
	result := c.ResolveUsernames(context.Background(), events)
	assert.Equal(t, "admin", result[uid])
}

// ── secret_policy_info.go — SecretPolicies ────────────────────────────────────

func TestSecretPolicies_DefaultsDisabled(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	info := c.SecretPolicies()
	assert.False(t, info.Name.Enabled)
	assert.False(t, info.Value.Enabled)
}

func TestSecretPolicies_AfterSetNamePolicy(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.SetSecretNamePolicy(SecretNamePolicy{Enabled: true, Pattern: "[A-Z_]+", MaxLength: 64})
	require.NoError(t, err)
	info := c.SecretPolicies()
	assert.True(t, info.Name.Enabled)
	assert.Equal(t, "[A-Z_]+", info.Name.Pattern)
	assert.Equal(t, 64, info.Name.MaxLength)
}

// ── secret_name_policy.go ────────────────────────────────────────────────────

func TestDefaultSecretNamePolicy_Disabled(t *testing.T) {
	t.Parallel()
	p := DefaultSecretNamePolicy()
	assert.False(t, p.Enabled)
	assert.Empty(t, p.Pattern)
	assert.Zero(t, p.MaxLength)
}

func TestCompileNamePattern_Empty(t *testing.T) {
	t.Parallel()
	re, err := compileNamePattern("")
	require.NoError(t, err)
	assert.Nil(t, re)
}

func TestCompileNamePattern_Valid(t *testing.T) {
	t.Parallel()
	re, err := compileNamePattern("[A-Z_]+")
	require.NoError(t, err)
	require.NotNil(t, re)
	assert.True(t, re.MatchString("HELLO_WORLD"))
	assert.False(t, re.MatchString("hello"))
}

func TestCompileNamePattern_Invalid(t *testing.T) {
	t.Parallel()
	_, err := compileNamePattern("[invalid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret name pattern")
}

func TestValidateSecretName_PolicyDisabled(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// policy disabled by default — any name passes
	assert.NoError(t, c.validateSecretName("ANY_thing!"))
}

func TestValidateSecretName_MaxLengthExceeded(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.SetSecretNamePolicy(SecretNamePolicy{Enabled: true, MaxLength: 5})
	require.NoError(t, err)
	err = c.validateSecretName("toolongname")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "5-character maximum")
}

func TestValidateSecretName_PatternMismatch(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.SetSecretNamePolicy(SecretNamePolicy{Enabled: true, Pattern: "[A-Z_]+"})
	require.NoError(t, err)
	err = c.validateSecretName("lower_case")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match the required pattern")
}

func TestValidateSecretName_PatternMatches(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	require.NoError(t, c.SetSecretNamePolicy(SecretNamePolicy{Enabled: true, Pattern: "[A-Z_]+"}))
	assert.NoError(t, c.validateSecretName("UPPER_CASE"))
}

func TestSetSecretNamePolicy_InvalidPattern(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.SetSecretNamePolicy(SecretNamePolicy{Enabled: true, Pattern: "[broken"})
	require.Error(t, err)
}

// ── secrets.go — GetSecretByName ─────────────────────────────────────────────

func TestGetSecretByName_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	node := &models.SecretNode{ID: 5, Name: "db-pass", ProjectID: 1, EnvironmentID: 1}
	ms.On("GetSecretByName", mock.Anything, "db-pass", uint(1), uint(1)).Return(node, nil)
	c := NewKeyorixCore(ms)
	got, err := c.GetSecretByName(context.Background(), "db-pass", 1, 1)
	require.NoError(t, err)
	assert.Equal(t, uint(5), got.ID)
}

func TestGetSecretByName_NotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecretByName", mock.Anything, "missing", uint(1), uint(1)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretByName(context.Background(), "missing", 1, 1)
	require.Error(t, err)
}

func TestGetSecretByName_Expired(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	exp := time.Now().Add(-time.Hour)
	node := &models.SecretNode{ID: 5, Name: "old", Expiration: &exp}
	ms.On("GetSecretByName", mock.Anything, "old", uint(1), uint(1)).Return(node, nil)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretByName(context.Background(), "old", 1, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

// ── secrets.go — GetSecretByNameWithPermissionCheck ──────────────────────────

func TestGetSecretByNameWithPermissionCheck_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecretByName", mock.Anything, "x", uint(1), uint(1)).Return(nil, errors.New("db err"))
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretByNameWithPermissionCheck(context.Background(), "x", 1, 1, 10)
	require.Error(t, err)
}

// ── secrets.go — DeleteSecret ─────────────────────────────────────────────────

func TestDeleteSecret_ZeroID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.DeleteSecret(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

func TestDeleteSecret_NotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(99)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.DeleteSecret(context.Background(), 99)
	require.Error(t, err)
}

func TestDeleteSecret_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(3)).Return(&models.SecretNode{ID: 3, ProjectID: 1}, nil)
	ms.On("DeleteSecret", mock.Anything, uint(3)).Return(nil)
	// emitDependencyLifecycleEvents lists the project's edges after delete.
	ms.On("ListSecretDependenciesForProject", mock.Anything, uint(1)).Return([]*models.SecretDependency{}, nil)
	c := NewKeyorixCore(ms)
	require.NoError(t, c.DeleteSecret(context.Background(), 3))
}

func TestDeleteSecret_StorageFails(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(3)).Return(&models.SecretNode{ID: 3}, nil)
	ms.On("DeleteSecret", mock.Anything, uint(3)).Return(errors.New("io error"))
	c := NewKeyorixCore(ms)
	err := c.DeleteSecret(context.Background(), 3)
	require.Error(t, err)
}

// ── secrets.go — DeleteSecretWithPermissionCheck ─────────────────────────────

func TestDeleteSecretWithPermissionCheck_ZeroUserID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.DeleteSecretWithPermissionCheck(context.Background(), 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

// ── secrets.go — RestoreSecret ────────────────────────────────────────────────

func TestRestoreSecret_ZeroID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.RestoreSecret(context.Background(), 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

func TestRestoreSecret_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// GetSecretIncludingDeleted is called before RestoreSecret to obtain name+projectID.
	ms.On("GetSecretIncludingDeleted", mock.Anything, uint(5)).Return(&models.SecretNode{ID: 5, ProjectID: 1}, nil)
	ms.On("RestoreSecret", mock.Anything, uint(5)).Return(errors.New("not found"))
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	err := c.RestoreSecret(context.Background(), 1, 5)
	require.Error(t, err)
}

func TestRestoreSecret_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// GetSecretIncludingDeleted is called before RestoreSecret to obtain name+projectID.
	ms.On("GetSecretIncludingDeleted", mock.Anything, uint(5)).Return(&models.SecretNode{ID: 5, ProjectID: 1}, nil)
	ms.On("RestoreSecret", mock.Anything, uint(5)).Return(nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	// emitDependencyLifecycleEvents lists the project's edges after restore.
	ms.On("ListSecretDependenciesForProject", mock.Anything, uint(1)).Return([]*models.SecretDependency{}, nil)
	c := NewKeyorixCore(ms)
	require.NoError(t, c.RestoreSecret(context.Background(), 1, 5))
}

// ── secrets.go — UpdateSecretWithPermissionCheck ──────────────────────────────

func TestUpdateSecretWithPermissionCheck_ZeroUserID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	req := &UpdateSecretRequest{ID: 1, UserID: 0, UpdatedBy: "alice"}
	_, err := c.UpdateSecretWithPermissionCheck(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

// ── versions.go — GetSecretVersions ──────────────────────────────────────────

func TestGetSecretVersions_ZeroID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretVersions(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

func TestGetSecretVersions_SecretNotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(99)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretVersions(context.Background(), 99)
	require.Error(t, err)
}

func TestGetSecretVersions_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{ID: 1}, nil)
	versions := []*models.SecretVersion{{ID: 1, VersionNumber: 1}, {ID: 2, VersionNumber: 2}}
	ms.On("GetSecretVersions", mock.Anything, uint(1)).Return(versions, nil)
	c := NewKeyorixCore(ms)
	got, err := c.GetSecretVersions(context.Background(), 1)
	require.NoError(t, err)
	assert.Len(t, got, 2)
}

func TestGetSecretVersions_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{ID: 1}, nil)
	ms.On("GetSecretVersions", mock.Anything, uint(1)).Return(nil, errors.New("db err"))
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretVersions(context.Background(), 1)
	require.Error(t, err)
}

// ── versions.go — GetSecretVersionsWithPermissionCheck ────────────────────────

func TestGetSecretVersionsWithPermissionCheck_ZeroUserID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretVersionsWithPermissionCheck(context.Background(), 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

// ── versions.go — GetSecretVersion ───────────────────────────────────────────

func TestGetSecretVersion_ZeroSecretID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretVersion(context.Background(), 0, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

func TestGetSecretVersion_ZeroVersionNumber(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretVersion(context.Background(), 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version number must be positive")
}

func TestGetSecretVersion_VersionNotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecretVersions", mock.Anything, uint(1)).Return([]*models.SecretVersion{
		{ID: 1, VersionNumber: 1},
	}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretVersion(context.Background(), 1, 99)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGetSecretVersion_Found(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecretVersions", mock.Anything, uint(1)).Return([]*models.SecretVersion{
		{ID: 2, VersionNumber: 2},
		{ID: 1, VersionNumber: 1},
	}, nil)
	c := NewKeyorixCore(ms)
	got, err := c.GetSecretVersion(context.Background(), 1, 2)
	require.NoError(t, err)
	assert.Equal(t, uint(2), got.ID)
}

// ── versions.go — GetSecretVersionWithPermissionCheck ────────────────────────

func TestGetSecretVersionWithPermissionCheck_ZeroUserID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretVersionWithPermissionCheck(context.Background(), 1, 0, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

// ── versions.go — GetLatestSecretVersion ─────────────────────────────────────

func TestGetLatestSecretVersion_ZeroID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetLatestSecretVersion(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

func TestGetLatestSecretVersion_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecretVersions", mock.Anything, uint(1)).Return(nil, errors.New("db err"))
	c := NewKeyorixCore(ms)
	_, err := c.GetLatestSecretVersion(context.Background(), 1)
	require.Error(t, err)
}

func TestGetLatestSecretVersion_NoVersions(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecretVersions", mock.Anything, uint(1)).Return([]*models.SecretVersion{}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.GetLatestSecretVersion(context.Background(), 1)
	require.Error(t, err)
}

func TestGetLatestSecretVersion_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecretVersions", mock.Anything, uint(1)).Return([]*models.SecretVersion{
		{ID: 3, VersionNumber: 3},
		{ID: 2, VersionNumber: 2},
	}, nil)
	c := NewKeyorixCore(ms)
	got, err := c.GetLatestSecretVersion(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, uint(3), got.ID)
}

// ── versions.go — GetLatestSecretVersionWithPermissionCheck ──────────────────

func TestGetLatestSecretVersionWithPermissionCheck_ZeroUserID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetLatestSecretVersionWithPermissionCheck(context.Background(), 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

// ── versions.go — GetSecretValueWithPermissionCheck ──────────────────────────

func TestGetSecretValueWithPermissionCheck_ZeroUserID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretValueWithPermissionCheck(context.Background(), 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

// ── versions.go — GetSecretValueByVersionWithPermissionCheck ─────────────────

func TestGetSecretValueByVersionWithPermissionCheck_ZeroUserID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretValueByVersionWithPermissionCheck(context.Background(), 1, 0, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

// ── sharing_query.go — ListSharedSecrets ─────────────────────────────────────

func TestListSharedSecrets_ZeroUserID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.ListSharedSecrets(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestListSharedSecrets_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("ListSharedSecrets", mock.Anything, uint(1)).Return(nil, errors.New("db err"))
	c := NewKeyorixCore(ms)
	_, err := c.ListSharedSecrets(context.Background(), 1)
	require.Error(t, err)
}

func TestListSharedSecrets_NilReturnsEmpty(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("ListSharedSecrets", mock.Anything, uint(1)).Return(([]*models.SecretNode)(nil), nil)
	c := NewKeyorixCore(ms)
	got, err := c.ListSharedSecrets(context.Background(), 1)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestListSharedSecrets_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	secrets := []*models.SecretNode{{ID: 10, Name: "shared-secret"}}
	ms.On("ListSharedSecrets", mock.Anything, uint(2)).Return(secrets, nil)
	c := NewKeyorixCore(ms)
	got, err := c.ListSharedSecrets(context.Background(), 2)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

// ── sharing_query.go — ListSecretShares ──────────────────────────────────────

func TestListSecretShares_ZeroSecretID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.ListSecretShares(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

func TestListSecretShares_SecretNotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(99)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.ListSecretShares(context.Background(), 99)
	require.Error(t, err)
}

func TestListSecretShares_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{ID: 1}, nil)
	ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return(nil, errors.New("db err"))
	c := NewKeyorixCore(ms)
	_, err := c.ListSecretShares(context.Background(), 1)
	require.Error(t, err)
}

func TestListSecretShares_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{ID: 1}, nil)
	ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{{ID: 1, SecretID: 1, Permission: "read"}}, nil)
	c := NewKeyorixCore(ms)
	got, err := c.ListSecretShares(context.Background(), 1)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

// ── sharing_query.go — ListSecretSharesWithPermissionCheck ────────────────────

func TestListSecretSharesWithPermissionCheck_ZeroSecretID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.ListSecretSharesWithPermissionCheck(context.Background(), 0, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

func TestListSecretSharesWithPermissionCheck_SecretNotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(5)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.ListSecretSharesWithPermissionCheck(context.Background(), 5, 1)
	require.Error(t, err)
}

func TestListSecretSharesWithPermissionCheck_NotOwner(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// Secret owned by user 2, caller is user 1
	ms.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{ID: 1, OwnerID: 2}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.ListSecretSharesWithPermissionCheck(context.Background(), 1, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
}

func TestListSecretSharesWithPermissionCheck_OwnerSuccess(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{ID: 1, OwnerID: 7, ProjectID: 5}, nil)
	ms.On("IsProjectMember", mock.Anything, uint(7), uint(5)).Return(true, nil)
	ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{{ID: 3, SecretID: 1}}, nil)
	c := NewKeyorixCore(ms)
	got, err := c.ListSecretSharesWithPermissionCheck(context.Background(), 1, 7)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

// TestListSecretSharesWithPermissionCheck_DepartedOwnerDenied is the RBAC-001
// regression test: a departed owner (removed from the secret's project, but the
// secret row's OwnerID tag is untouched until ClearProjectSecretOwnership runs)
// must not be able to enumerate the secret's share/recipient list, matching
// ShareSecret/UpdateSharePermission/RevokeShare (sharing_test.go) and
// ShareSecretWithGroup (group_sharing_test.go). Pre-fix, the bare secretOwnedBy
// check let a departed owner through since OwnerID still matched — this test
// fails against that old code (confirmed red before the requireLiveOwnerAuthority
// swap) and passes now that IsProjectMember is consulted.
func TestListSecretSharesWithPermissionCheck_DepartedOwnerDenied(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{ID: 1, OwnerID: 7, ProjectID: 5}, nil)
	// The owner still carries OwnerID 7 on the secret row, but no longer holds a
	// live role grant in the secret's project.
	ms.On("IsProjectMember", mock.Anything, uint(7), uint(5)).Return(false, nil)
	c := NewKeyorixCore(ms)
	_, err := c.ListSecretSharesWithPermissionCheck(context.Background(), 1, 7)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
	ms.AssertNotCalled(t, "ListSharesBySecret", mock.Anything, mock.Anything)
}

// ── sharing_query.go — CheckSharePermission ───────────────────────────────────

func TestCheckSharePermission_ZeroSecretID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.CheckSharePermission(context.Background(), 0, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

func TestCheckSharePermission_ZeroUserID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.CheckSharePermission(context.Background(), 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestCheckSharePermission_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("CheckSharePermission", mock.Anything, uint(1), uint(2)).Return("", errors.New("no share"))
	c := NewKeyorixCore(ms)
	_, err := c.CheckSharePermission(context.Background(), 1, 2)
	require.Error(t, err)
}

func TestCheckSharePermission_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("CheckSharePermission", mock.Anything, uint(1), uint(2)).Return("read", nil)
	c := NewKeyorixCore(ms)
	perm, err := c.CheckSharePermission(context.Background(), 1, 2)
	require.NoError(t, err)
	assert.Equal(t, "read", perm)
}

// ── sharing_query.go — ListUserShareViews ─────────────────────────────────────

func TestListUserShareViews_ZeroUserID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.ListUserShareViews(context.Background(), 0)
	require.Error(t, err)
}

func TestListUserShareViews_StorageErrorOnReceived(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("ListSharesByUser", mock.Anything, uint(1)).Return(nil, errors.New("db err"))
	c := NewKeyorixCore(ms)
	_, err := c.ListUserShareViews(context.Background(), 1)
	require.Error(t, err)
}

func TestListUserShareViews_EmptyShares(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("ListSharesByUser", mock.Anything, uint(1)).Return([]*models.ShareRecord{}, nil)
	ms.On("ListSharesByOwner", mock.Anything, uint(1)).Return([]*models.ShareRecord{}, nil)
	c := NewKeyorixCore(ms)
	views, err := c.ListUserShareViews(context.Background(), 1)
	require.NoError(t, err)
	assert.Empty(t, views)
}

func TestListUserShareViews_UserShare(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	share := &models.ShareRecord{
		ID:          1,
		SecretID:    10,
		OwnerID:     1,
		RecipientID: 2,
		IsGroup:     false,
		Permission:  "read",
		CreatedAt:   time.Now(),
	}
	ms.On("ListSharesByUser", mock.Anything, uint(1)).Return([]*models.ShareRecord{share}, nil)
	ms.On("ListSharesByOwner", mock.Anything, uint(1)).Return([]*models.ShareRecord{}, nil)
	ms.On("GetUsernamesByIDs", mock.Anything, mock.Anything).Return(map[uint]string{1: "owner", 2: "recipient"}, nil)
	// The secret no longer resolves, so the view carries no name (#3153).
	ms.On("GetSecretsByIDs", mock.Anything, []uint{10}).Return([]*models.SecretNode{}, nil)
	c := NewKeyorixCore(ms)
	views, err := c.ListUserShareViews(context.Background(), 1)
	require.NoError(t, err)
	require.Len(t, views, 1)
	assert.Equal(t, "user", views[0].RecipientType)
	assert.Equal(t, "recipient", views[0].RecipientName)
}

func TestListUserShareViews_GroupShare(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	share := &models.ShareRecord{
		ID:          2,
		SecretID:    10,
		OwnerID:     1,
		RecipientID: 99,
		IsGroup:     true,
		Permission:  "write",
		CreatedAt:   time.Now(),
	}
	ms.On("ListSharesByUser", mock.Anything, uint(1)).Return([]*models.ShareRecord{}, nil)
	ms.On("ListSharesByOwner", mock.Anything, uint(1)).Return([]*models.ShareRecord{share}, nil)
	ms.On("GetUsernamesByIDs", mock.Anything, mock.Anything).Return(map[uint]string{1: "owner"}, nil)
	ms.On("GetGroupNamesByIDs", mock.Anything, []uint{99}).Return(map[uint]string{99: "ops-team"}, nil)
	ms.On("GetSecretsByIDs", mock.Anything, []uint{10}).Return([]*models.SecretNode{}, nil)
	c := NewKeyorixCore(ms)
	views, err := c.ListUserShareViews(context.Background(), 1)
	require.NoError(t, err)
	require.Len(t, views, 1)
	assert.Equal(t, "group", views[0].RecipientType)
	assert.Equal(t, "ops-team", views[0].RecipientName)
}

// ── usage_analytics.go — MostAccessedSecrets ─────────────────────────────────

func TestMostAccessedSecrets_DefaultsApplied(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// Expect defaults: days=30, limit=10
	stats := []storage.SecretUsageStat{{SecretID: 1, SecretName: "db-pass", ReadCount: 42}}
	ms.On("MostAccessedSecrets", mock.Anything, (*uint)(nil), (*uint)(nil), mock.AnythingOfType("time.Time"), 10).Return(stats, nil)
	c := NewKeyorixCore(ms)
	got, err := c.MostAccessedSecrets(context.Background(), nil, nil, 0, 0)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

func TestMostAccessedSecrets_LimitCapped(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("MostAccessedSecrets", mock.Anything, (*uint)(nil), (*uint)(nil), mock.AnythingOfType("time.Time"), 100).Return([]storage.SecretUsageStat{}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.MostAccessedSecrets(context.Background(), nil, nil, 7, 9999)
	require.NoError(t, err)
	ms.AssertExpectations(t)
}

func TestMostAccessedSecrets_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("MostAccessedSecrets", mock.Anything, (*uint)(nil), (*uint)(nil), mock.AnythingOfType("time.Time"), 10).Return(nil, errors.New("query failed"))
	c := NewKeyorixCore(ms)
	_, err := c.MostAccessedSecrets(context.Background(), nil, nil, 0, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "most-accessed")
}

// TestMostAccessedSecrets_WithEnvironmentScope confirms the environmentID
// argument (added to close the scope-widening leak where the HTTP handler
// ignored environment_id and always returned the whole project's aggregate)
// is threaded through to the storage layer unchanged.
func TestMostAccessedSecrets_WithEnvironmentScope(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	pid := uint(5)
	eid := uint(9)
	ms.On("MostAccessedSecrets", mock.Anything, &pid, &eid, mock.AnythingOfType("time.Time"), 10).Return([]storage.SecretUsageStat{{SecretID: 1}}, nil)
	c := NewKeyorixCore(ms)
	got, err := c.MostAccessedSecrets(context.Background(), &pid, &eid, 0, 0)
	require.NoError(t, err)
	assert.Len(t, got, 1)
	ms.AssertExpectations(t)
}

// ── usage_analytics.go — UnusedSecrets ───────────────────────────────────────

func TestUnusedSecrets_DefaultsApplied(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("UnusedSecrets", mock.Anything, (*uint)(nil), (*uint)(nil), mock.AnythingOfType("time.Time")).Return([]storage.UnusedSecretStat{}, nil)
	c := NewKeyorixCore(ms)
	got, err := c.UnusedSecrets(context.Background(), nil, nil, 0)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestUnusedSecrets_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("UnusedSecrets", mock.Anything, (*uint)(nil), (*uint)(nil), mock.AnythingOfType("time.Time")).Return(nil, errors.New("db err"))
	c := NewKeyorixCore(ms)
	_, err := c.UnusedSecrets(context.Background(), nil, nil, 30)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unused secrets")
}

func TestUnusedSecrets_WithProjectScope(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	pid := uint(5)
	ms.On("UnusedSecrets", mock.Anything, &pid, (*uint)(nil), mock.AnythingOfType("time.Time")).Return([]storage.UnusedSecretStat{{SecretID: 3}}, nil)
	c := NewKeyorixCore(ms)
	got, err := c.UnusedSecrets(context.Background(), &pid, nil, 14)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

// TestUnusedSecrets_WithEnvironmentScope confirms the environmentID argument
// is threaded through to the storage layer unchanged.
func TestUnusedSecrets_WithEnvironmentScope(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	pid := uint(5)
	eid := uint(9)
	ms.On("UnusedSecrets", mock.Anything, &pid, &eid, mock.AnythingOfType("time.Time")).Return([]storage.UnusedSecretStat{{SecretID: 3}}, nil)
	c := NewKeyorixCore(ms)
	got, err := c.UnusedSecrets(context.Background(), &pid, &eid, 14)
	require.NoError(t, err)
	assert.Len(t, got, 1)
	ms.AssertExpectations(t)
}

// ── users.go — GetUser ────────────────────────────────────────────────────────

func TestGetUser_ZeroID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetUser(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestGetUser_NotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUser", mock.Anything, uint(99)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.GetUser(context.Background(), 99)
	require.Error(t, err)
}

func TestGetUser_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUser", mock.Anything, uint(1)).Return(&models.User{ID: 1, Username: "alice"}, nil)
	c := NewKeyorixCore(ms)
	u, err := c.GetUser(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, "alice", u.Username)
}

// ── users.go — ListUsers ──────────────────────────────────────────────────────

func TestListUsers_DefaultPagination(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("ListUsers", mock.Anything, mock.MatchedBy(func(f *storage.UserFilter) bool {
		return f.Page == 1 && f.PageSize == 20
	})).Return([]*models.User{}, int64(0), nil)
	c := NewKeyorixCore(ms)
	users, total, err := c.ListUsers(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, users)
	assert.Equal(t, int64(0), total)
}

func TestListUsers_PageSizeCapped(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("ListUsers", mock.Anything, mock.MatchedBy(func(f *storage.UserFilter) bool {
		return f.PageSize == 100
	})).Return([]*models.User{}, int64(0), nil)
	c := NewKeyorixCore(ms)
	_, _, err := c.ListUsers(context.Background(), &storage.UserFilter{Page: 1, PageSize: 9999})
	require.NoError(t, err)
	ms.AssertExpectations(t)
}

func TestListUsers_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("ListUsers", mock.Anything, mock.Anything).Return(nil, int64(0), errors.New("db err"))
	c := NewKeyorixCore(ms)
	_, _, err := c.ListUsers(context.Background(), nil)
	require.Error(t, err)
}

// ── users.go — GetUserByEmail ─────────────────────────────────────────────────

func TestGetUserByEmail_EmptyEmail(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetUserByEmail(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}

func TestGetUserByEmail_NotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUserByEmail", mock.Anything, "x@y.com").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.GetUserByEmail(context.Background(), "x@y.com")
	require.Error(t, err)
}

func TestGetUserByEmail_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUserByEmail", mock.Anything, "alice@example.com").Return(&models.User{ID: 1, Email: "alice@example.com"}, nil)
	c := NewKeyorixCore(ms)
	u, err := c.GetUserByEmail(context.Background(), "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", u.Email)
}

// ── users.go — GetUserByUsername ──────────────────────────────────────────────

func TestGetUserByUsername_Empty(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetUserByUsername(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "username is required")
}

func TestGetUserByUsername_NotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUserByUsername", mock.Anything, "nobody").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.GetUserByUsername(context.Background(), "nobody")
	require.Error(t, err)
}

func TestGetUserByUsername_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUserByUsername", mock.Anything, "alice").Return(&models.User{ID: 1, Username: "alice"}, nil)
	c := NewKeyorixCore(ms)
	u, err := c.GetUserByUsername(context.Background(), "alice")
	require.NoError(t, err)
	assert.Equal(t, "alice", u.Username)
}

// ── users.go — GetUserByExternalID ───────────────────────────────────────────

func TestGetUserByExternalID_Empty(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetUserByExternalID(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "external_id is required")
}

func TestGetUserByExternalID_NotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUserByExternalID", mock.Anything, "sso|abc123").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.GetUserByExternalID(context.Background(), "sso|abc123")
	require.Error(t, err)
}

func TestGetUserByExternalID_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUserByExternalID", mock.Anything, "sso|alice").Return(&models.User{ID: 1, ExternalID: "sso|alice"}, nil)
	c := NewKeyorixCore(ms)
	u, err := c.GetUserByExternalID(context.Background(), "sso|alice")
	require.NoError(t, err)
	assert.Equal(t, "sso|alice", u.ExternalID)
}

// ── scim_groups.go — DeprovisionSCIMGroup ────────────────────────────────────

func TestDeprovisionSCIMGroup_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// guardLastGlobalAdminGroupDelete (#G02) resolves the install-admin role IDs
	// first; none exist in this fixture, so the guard is a no-op and the delete
	// proceeds to the simulated storage failure under test.
	ms.On("GetRoleByName", mock.Anything, "super_admin").Return(nil, errors.New("not found"))
	ms.On("GetRoleByName", mock.Anything, "admin").Return(nil, errors.New("not found"))
	ms.On("GetRoleByName", mock.Anything, "system_admin").Return(nil, errors.New("not found"))
	// guardLastProjectAdminGroupDelete (core-project-members.json#3) runs next;
	// no group role assignments in this fixture, so it's a no-op too.
	ms.On("ListGroupRoleAssignments", mock.Anything, uint(10)).Return([]storage.RoleAssignment{}, nil)
	// SESSION-AT #2352: DeprovisionSCIMGroup now shares deleteGroupGuarded
	// (withGroupProjectAdminGuardLocks -> projectAdminScopesHeldByGroup ->
	// GetGroup), same as the native DeleteGroup path.
	ms.On("GetGroup", mock.Anything, uint(10)).Return(&models.Group{ID: 10, Name: "g"}, nil)
	ms.On("DeleteGroup", mock.Anything, uint(10)).Return(errors.New("not found"))
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	err := c.DeprovisionSCIMGroup(context.Background(), 1, 10)
	require.Error(t, err)
}

func TestDeprovisionSCIMGroup_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetRoleByName", mock.Anything, "super_admin").Return(nil, errors.New("not found"))
	ms.On("GetRoleByName", mock.Anything, "admin").Return(nil, errors.New("not found"))
	ms.On("GetRoleByName", mock.Anything, "system_admin").Return(nil, errors.New("not found"))
	ms.On("ListGroupRoleAssignments", mock.Anything, uint(10)).Return([]storage.RoleAssignment{}, nil)
	// SESSION-AT #2352: DeprovisionSCIMGroup now shares deleteGroupGuarded
	// (withGroupProjectAdminGuardLocks -> projectAdminScopesHeldByGroup ->
	// GetGroup), same as the native DeleteGroup path.
	ms.On("GetGroup", mock.Anything, uint(10)).Return(&models.Group{ID: 10, Name: "g"}, nil)
	ms.On("DeleteGroup", mock.Anything, uint(10)).Return(nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	require.NoError(t, c.DeprovisionSCIMGroup(context.Background(), 1, 10))
	ms.AssertCalled(t, "DeleteGroup", mock.Anything, uint(10))
}
