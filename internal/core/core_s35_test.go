// core_s35_test.go — sprint-35 coverage blitz targeting remaining low-coverage
// functions across sod.go, sharing_audit.go, anomaly*.go, account.go,
// auth_bootstrap.go, versions.go, and audit_checkpoint.go.
package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ─── SoD helpers (sod.go) ────────────────────────────────────────────────────

// TestSodViolationReference_S35 pins the stable reference format used by risk-exception
// matching; any format change would silently break suppression of existing exceptions.
func TestSodViolationReference_S35(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "sod:policy:3:user:7", sodViolationReference(3, "user", 7))
	assert.Equal(t, "sod:policy:10:machine:1", sodViolationReference(10, "machine", 1))
	assert.Equal(t, "sod:policy:0:user:0", sodViolationReference(0, "user", 0))
}

// TestSodBlockedErr_S35 confirms the error message contains the policy name and both
// permissions so operators can act on it directly.
func TestSodBlockedErr_S35(t *testing.T) {
	t.Parallel()
	pol := &models.SoDPolicy{Name: "write-vs-approve", PermissionA: "secrets.write", PermissionB: "access.approve"}
	err := sodBlockedErr(pol, "grant this role")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write-vs-approve")
	assert.Contains(t, err.Error(), "secrets.write")
	assert.Contains(t, err.Error(), "access.approve")
	assert.Contains(t, err.Error(), "grant this role")
}

// TestSodPolicyNewlyCompletedBy_S35 exercises every branch of the predicate:
// already-violated (skip), newly-completed (return), and harmless (nil).
func TestSodPolicyNewlyCompletedBy_S35(t *testing.T) {
	t.Parallel()
	pol := &models.SoDPolicy{
		ID: 1, Name: "p", PermissionA: "secrets.write", PermissionB: "secrets.read",
	}
	policies := []*models.SoDPolicy{pol}

	t.Run("nil when neither side is held or added", func(t *testing.T) {
		result := sodPolicyNewlyCompletedBy(policies, map[string]bool{}, map[string]bool{})
		assert.Nil(t, result)
	})

	t.Run("nil when only one side in held", func(t *testing.T) {
		result := sodPolicyNewlyCompletedBy(policies,
			map[string]bool{"secrets.write": true},
			map[string]bool{})
		assert.Nil(t, result)
	})

	t.Run("nil when only one side in adding", func(t *testing.T) {
		result := sodPolicyNewlyCompletedBy(policies,
			map[string]bool{},
			map[string]bool{"secrets.write": true})
		assert.Nil(t, result)
	})

	t.Run("nil when already violated (skip — not created by this change)", func(t *testing.T) {
		// Both sides already held — the policy is already violated, this grant doesn't *newly* complete it.
		result := sodPolicyNewlyCompletedBy(policies,
			map[string]bool{"secrets.write": true, "secrets.read": true},
			map[string]bool{"secrets.read": true})
		assert.Nil(t, result)
	})

	t.Run("returns policy when adding completes a side held", func(t *testing.T) {
		result := sodPolicyNewlyCompletedBy(policies,
			map[string]bool{"secrets.write": true},
			map[string]bool{"secrets.read": true})
		require.NotNil(t, result)
		assert.Equal(t, uint(1), result.ID)
	})

	t.Run("returns policy when adding provides both sides", func(t *testing.T) {
		result := sodPolicyNewlyCompletedBy(policies,
			map[string]bool{},
			map[string]bool{"secrets.write": true, "secrets.read": true})
		require.NotNil(t, result)
		assert.Equal(t, uint(1), result.ID)
	})

	t.Run("multiple policies — first newly-completed wins", func(t *testing.T) {
		pol2 := &models.SoDPolicy{ID: 2, Name: "p2", PermissionA: "users.read", PermissionB: "users.write"}
		result := sodPolicyNewlyCompletedBy([]*models.SoDPolicy{pol, pol2},
			map[string]bool{"secrets.write": true},
			map[string]bool{"secrets.read": true})
		require.NotNil(t, result)
		assert.Equal(t, uint(1), result.ID)
	})

	t.Run("empty policies slice always returns nil", func(t *testing.T) {
		result := sodPolicyNewlyCompletedBy(nil,
			map[string]bool{"secrets.write": true},
			map[string]bool{"secrets.read": true})
		assert.Nil(t, result)
	})
}

// TestSodViolationsReport_Degrade_S35 confirms degrade flips Degraded and appends a reason.
func TestSodViolationsReport_Degrade_S35(t *testing.T) {
	t.Parallel()
	r := &SoDViolationsReport{Violations: []SoDViolation{}}
	assert.False(t, r.Degraded)

	r.degrade("user_permissions:user=7", fmt.Errorf("db timeout"))
	assert.True(t, r.Degraded)
	require.Len(t, r.DegradedReasons, 1)
	assert.Contains(t, r.DegradedReasons[0], "user_permissions:user=7")
	assert.Contains(t, r.DegradedReasons[0], "db timeout")

	r.degrade("machine_identities", fmt.Errorf("connect refused"))
	assert.Len(t, r.DegradedReasons, 2)
}

// TestListSoDPolicies_S35_StorageError covers the error path of ListSoDPolicies.
func TestListSoDPolicies_S35_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ms.On("ListSoDPolicies", mock.Anything).Return(([]*models.SoDPolicy)(nil), fmt.Errorf("db error"))
	_, err := c.ListSoDPolicies(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db error")
}

// TestListSoDPolicies_S35_Empty covers the empty-slice path.
func TestListSoDPolicies_S35_Empty(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ms.On("ListSoDPolicies", mock.Anything).Return([]*models.SoDPolicy{}, nil)
	policies, err := c.ListSoDPolicies(context.Background())
	require.NoError(t, err)
	assert.Empty(t, policies)
}

// TestCreateSoDPolicy_S35_ValidationErrors exercises the early-return validation paths:
// blank name, blank permissions, identical permissions.
func TestCreateSoDPolicy_S35_ValidationErrors(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ctx := context.Background()

	_, err := c.CreateSoDPolicy(ctx, 1, "", "desc", "secrets.read", "secrets.write")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy name is required")

	_, err = c.CreateSoDPolicy(ctx, 1, "p", "desc", "", "secrets.write")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "two permissions are required")

	_, err = c.CreateSoDPolicy(ctx, 1, "p", "desc", "secrets.read", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "two permissions are required")

	_, err = c.CreateSoDPolicy(ctx, 1, "p", "desc", "secrets.read", "secrets.read")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be different")
}

// TestDetectSoDViolations_S35_EmptyPolicies confirms no violations when there are no policies.
func TestDetectSoDViolations_S35_EmptyPolicies(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ms.On("ListSoDPolicies", mock.Anything).Return([]*models.SoDPolicy{}, nil)

	report, err := c.DetectSoDViolations(context.Background())
	require.NoError(t, err)
	assert.Empty(t, report.Violations)
	assert.False(t, report.Degraded)
}

// TestDetectSoDViolations_S35_ListUsersError covers the ListUsers error path.
func TestDetectSoDViolations_S35_ListUsersError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ms.On("ListSoDPolicies", mock.Anything).Return([]*models.SoDPolicy{
		{ID: 1, PermissionA: "a", PermissionB: "b"},
	}, nil)
	ms.On("ListUsers", mock.Anything, mock.Anything).Return(
		([]*models.User)(nil), int64(0), fmt.Errorf("users unavailable"))

	_, err := c.DetectSoDViolations(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "users unavailable")
}

// ─── anomaly isOffHours (anomaly.go) ─────────────────────────────────────────

// TestIsOffHours_S35 exercises the wrap-midnight path and the nil-loc (zero-value) guard.
func TestIsOffHours_S35(t *testing.T) {
	t.Parallel()
	utcBand := offHoursPolicy{loc: time.UTC, start: 22, end: 6}

	// Inside the wrap-midnight band: 23:00 UTC → off hours.
	assert.True(t, utcBand.isOffHours(time.Date(2026, 1, 1, 23, 0, 0, 0, time.UTC)))
	// Inside the early-morning half: 04:00 UTC → off hours.
	assert.True(t, utcBand.isOffHours(time.Date(2026, 1, 1, 4, 0, 0, 0, time.UTC)))
	// Just inside the band end (exclusive): 06:00 UTC → NOT off hours.
	assert.False(t, utcBand.isOffHours(time.Date(2026, 1, 1, 6, 0, 0, 0, time.UTC)))
	// Midday: clearly not off hours.
	assert.False(t, utcBand.isOffHours(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)))

	// Non-wrapping band: 08:00–17:00 UTC.
	dayBand := offHoursPolicy{loc: time.UTC, start: 8, end: 17}
	assert.True(t, dayBand.isOffHours(time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)))
	assert.False(t, dayBand.isOffHours(time.Date(2026, 1, 1, 4, 0, 0, 0, time.UTC)))

	// nil loc (zero-value policy) must not panic — treated as UTC.
	nilLocBand := offHoursPolicy{start: 22, end: 6}
	assert.NotPanics(t, func() {
		_ = nilLocBand.isOffHours(time.Date(2026, 1, 1, 23, 0, 0, 0, time.UTC))
	})
}

// ─── anomaly_ml randomSeed (anomaly_ml.go) ────────────────────────────────────

// TestRandomSeed_S35 confirms randomSeed always returns a positive value.
func TestRandomSeed_S35(t *testing.T) {
	t.Parallel()
	for range 5 {
		s := randomSeed()
		assert.Positive(t, s, "randomSeed must return a positive int64")
	}
}

// ─── generateSecureToken (auth.go) ──────────────────────────────────────────

// TestGenerateSecureToken_S35 confirms the token is non-empty, has the expected
// hex length (64 chars for 32 random bytes), and is different each call.
func TestGenerateSecureToken_S35(t *testing.T) {
	t.Parallel()
	tok1, err := generateSecureToken()
	require.NoError(t, err)
	assert.Len(t, tok1, 64)

	tok2, err := generateSecureToken()
	require.NoError(t, err)
	assert.NotEqual(t, tok1, tok2, "each call must produce a unique token")
}

// ─── PasswordExpired (account.go) ─────────────────────────────────────────────

// TestPasswordExpired_S35 exercises the nil-user, disabled-policy, no-PasswordChangedAt
// (falls back to CreatedAt), zero-CreatedAt, and expired paths.
func TestPasswordExpired_S35(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)

	t.Run("nil user → false", func(t *testing.T) {
		assert.False(t, c.PasswordExpired(nil))
	})

	t.Run("MaxAgeDays=0 → false (disabled)", func(t *testing.T) {
		c.passwordPolicy.MaxAgeDays = 0
		u := &models.User{ID: 1}
		u.PasswordChangedAt = nil
		assert.False(t, c.PasswordExpired(u))
	})

	t.Run("PasswordChangedAt set, not expired", func(t *testing.T) {
		c.passwordPolicy.MaxAgeDays = 90
		recent := time.Now().Add(-10 * 24 * time.Hour)
		u := &models.User{PasswordChangedAt: &recent}
		assert.False(t, c.PasswordExpired(u))
	})

	t.Run("PasswordChangedAt set, expired", func(t *testing.T) {
		c.passwordPolicy.MaxAgeDays = 90
		old := time.Now().Add(-100 * 24 * time.Hour)
		u := &models.User{PasswordChangedAt: &old}
		assert.True(t, c.PasswordExpired(u))
	})

	t.Run("no PasswordChangedAt, falls back to CreatedAt, not expired", func(t *testing.T) {
		c.passwordPolicy.MaxAgeDays = 90
		u := &models.User{CreatedAt: time.Now().Add(-10 * 24 * time.Hour)}
		assert.False(t, c.PasswordExpired(u))
	})

	t.Run("no PasswordChangedAt, zero CreatedAt → false (can't determine age)", func(t *testing.T) {
		c.passwordPolicy.MaxAgeDays = 90
		u := &models.User{}
		assert.False(t, c.PasswordExpired(u))
	})
}

// ─── passwordReused (account.go) ──────────────────────────────────────────────

// TestPasswordReused_S35 covers the disabled-policy path and the current-hash match.
func TestPasswordReused_S35(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ctx := context.Background()

	t.Run("HistoryCount=0 → false (disabled)", func(t *testing.T) {
		c.passwordPolicy.HistoryCount = 0
		u := &models.User{ID: 1, PasswordHash: "$bogus$"}
		assert.False(t, c.passwordReused(ctx, u, "anything"))
		ms.AssertNotCalled(t, "RecentPasswordHashes")
	})

	t.Run("HistoryCount>0 but storage error → false (best-effort)", func(t *testing.T) {
		c.passwordPolicy.HistoryCount = 3
		u := &models.User{ID: 1, PasswordHash: "$bogus$hash"}
		ms.On("RecentPasswordHashes", ctx, uint(1), 3).Return(nil, fmt.Errorf("db error"))
		// current-hash bcrypt compare fails (bogus hash), then history lookup errors → false
		assert.False(t, c.passwordReused(ctx, u, "newpassword"))
	})
}

// ─── sharing_audit group-flag branch (sharing_audit.go) ─────────────────────

// TestLogShareCreated_S35_GroupBranch confirms the description says "group" when IsGroup=true.
func TestLogShareCreated_S35_GroupBranch(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}
	ctx := context.Background()

	var desc string
	ms.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		desc = e.Description
		return e.EventType == string(ShareAuditEventCreated)
	})).Return(nil)

	c.LogShareCreated(ctx, &ShareAuditContext{ActorID: 1, SecretID: 5, RecipientID: 8, IsGroup: true, Permission: "read"})
	ms.AssertExpectations(t)
	assert.Contains(t, desc, "group")
	assert.Contains(t, desc, "8")
}

// TestLogShareUpdated_S35_GroupBranch confirms the description says "group" when IsGroup=true.
func TestLogShareUpdated_S35_GroupBranch(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}
	ctx := context.Background()

	var desc string
	ms.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		desc = e.Description
		return e.EventType == string(ShareAuditEventUpdated)
	})).Return(nil)

	c.LogShareUpdated(ctx, &ShareAuditContext{
		ActorID: 1, SecretID: 5, RecipientID: 8,
		IsGroup: true, Permission: "write", OldPermission: "read",
	})
	ms.AssertExpectations(t)
	assert.Contains(t, desc, "group")
}

// TestLogShareRevoked_S35_GroupBranch confirms the description says "group" when IsGroup=true.
func TestLogShareRevoked_S35_GroupBranch(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}
	ctx := context.Background()

	var desc string
	ms.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		desc = e.Description
		return e.EventType == string(ShareAuditEventRevoked)
	})).Return(nil)

	c.LogShareRevoked(ctx, &ShareAuditContext{ActorID: 1, SecretID: 5, RecipientID: 8, IsGroup: true})
	ms.AssertExpectations(t)
	assert.Contains(t, desc, "group")
}

// TestLogSelfRemovalFromShare_S35 exercises the LogSelfRemovalFromShare path.
func TestLogSelfRemovalFromShare_S35(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := &KeyorixCore{storage: ms, now: time.Now}
	ctx := context.Background()

	var captured *models.AuditEvent
	ms.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		captured = e
		return e.EventType == string(ShareAuditEventSelfRemoved)
	})).Return(nil)

	c.LogSelfRemovalFromShare(ctx, &ShareAuditContext{ActorID: 3, SecretID: 9, RecipientID: 3, Permission: "read"})
	require.NotNil(t, captured)
	assert.Contains(t, captured.Description, "removed themselves")
}

// ─── parseAuditHighWater (audit_checkpoint.go) ───────────────────────────────

// TestParseAuditHighWater_S35 exercises the malformed-input path (len!=6, not v1).
func TestParseAuditHighWater_S35(t *testing.T) {
	t.Parallel()
	t.Run("empty string → not ok", func(t *testing.T) {
		_, _, ok := parseAuditHighWater("")
		assert.False(t, ok)
	})

	sep := auditHighWaterSep

	t.Run("wrong version prefix → not ok", func(t *testing.T) {
		val := "v2" + sep + "100" + sep + "5" + sep + "abc" + sep + "v1" + sep + "sig"
		_, _, ok := parseAuditHighWater(val)
		assert.False(t, ok)
	})

	t.Run("too few fields → not ok", func(t *testing.T) {
		val := "v1" + sep + "100" + sep + "5"
		_, _, ok := parseAuditHighWater(val)
		assert.False(t, ok)
	})

	t.Run("non-numeric chained → not ok", func(t *testing.T) {
		val := "v1" + sep + "NaN" + sep + "5" + sep + "headhash" + sep + "kv" + sep + "sig"
		_, _, ok := parseAuditHighWater(val)
		assert.False(t, ok)
	})

	t.Run("non-numeric headID → not ok", func(t *testing.T) {
		val := "v1" + sep + "100" + sep + "NaN" + sep + "headhash" + sep + "kv" + sep + "sig"
		_, _, ok := parseAuditHighWater(val)
		assert.False(t, ok)
	})

	t.Run("valid well-formed value round-trips", func(t *testing.T) {
		// Build a value with the correct separator so parseAuditHighWater can parse it.
		val := "v1" + sep + "42" + sep + "7" + sep + "deadbeef" + sep + "v1" + sep + "mysig"
		cp, sig, ok := parseAuditHighWater(val)
		require.True(t, ok)
		assert.Equal(t, int64(42), cp.ChainedEvents)
		assert.Equal(t, uint(7), cp.HeadID)
		assert.Equal(t, "deadbeef", cp.HeadHash)
		assert.Equal(t, "v1", cp.KeyVersion)
		assert.Equal(t, "mysig", sig)
	})
}

// ─── SystemNeedsBootstrap (auth_bootstrap.go) ────────────────────────────────

// TestSystemNeedsBootstrap_S35_MetadataError covers the storage-error early-return.
func TestSystemNeedsBootstrap_S35_MetadataError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ms.On("GetSystemMetadata", mock.Anything, systemInitializedKey).
		Return("", false, fmt.Errorf("storage unavailable"))

	_, err := c.SystemNeedsBootstrap(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage unavailable")
}

// TestSystemNeedsBootstrap_S35_MarkerFound covers the "marker present → already initialised" path.
func TestSystemNeedsBootstrap_S35_MarkerFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ms.On("GetSystemMetadata", mock.Anything, systemInitializedKey).
		Return("1", true, nil)

	needs, err := c.SystemNeedsBootstrap(context.Background())
	require.NoError(t, err)
	assert.False(t, needs)
}

// TestSystemNeedsBootstrap_S35_ListUsersError covers the ListUsers error path.
func TestSystemNeedsBootstrap_S35_ListUsersError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ms.On("GetSystemMetadata", mock.Anything, systemInitializedKey).Return("", false, nil)
	ms.On("ListUsers", mock.Anything, mock.Anything).
		Return(([]*models.User)(nil), int64(0), fmt.Errorf("list users failed"))

	_, err := c.SystemNeedsBootstrap(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list users failed")
}

// TestSystemNeedsBootstrap_S35_HasUsers covers the "users exist → doesn't need bootstrap" path.
func TestSystemNeedsBootstrap_S35_HasUsers(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ms.On("GetSystemMetadata", mock.Anything, systemInitializedKey).Return("", false, nil)
	ms.On("ListUsers", mock.Anything, mock.Anything).
		Return([]*models.User{{ID: 1}}, int64(1), nil)

	needs, err := c.SystemNeedsBootstrap(context.Background())
	require.NoError(t, err)
	assert.False(t, needs)
}

// ─── GetSecretVersions zero-ID guard (versions.go) ───────────────────────────

// TestGetSecretVersions_S35_ZeroID covers the secretID==0 validation guard.
func TestGetSecretVersions_S35_ZeroID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretVersions(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
	ms.AssertNotCalled(t, "GetSecret")
}

// TestGetSecretVersion_S35_ZeroID and non-positive version cover those validation guards.
func TestGetSecretVersion_S35_Validations(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)

	_, err := c.GetSecretVersion(context.Background(), 0, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")

	ms.On("GetSecretVersions", mock.Anything, uint(1)).Return([]*models.SecretVersion{}, nil)
	_, err = c.GetSecretVersion(context.Background(), 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version number must be positive")

	_, err = c.GetSecretVersion(context.Background(), 1, -3)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version number must be positive")
}

// TestGetSecretVersion_S35_NotFound covers the "version not found" path.
func TestGetSecretVersion_S35_NotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ms.On("GetSecretVersions", mock.Anything, uint(42)).Return([]*models.SecretVersion{
		{ID: 1, VersionNumber: 3},
	}, nil)

	_, err := c.GetSecretVersion(context.Background(), 42, 99)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version 99 not found")
}

// TestGetSecretVersion_S35_Found covers the happy path.
func TestGetSecretVersion_S35_Found(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	want := &models.SecretVersion{ID: 5, VersionNumber: 2}
	ms.On("GetSecretVersions", mock.Anything, uint(42)).Return([]*models.SecretVersion{
		{ID: 4, VersionNumber: 3},
		want,
	}, nil)

	got, err := c.GetSecretVersion(context.Background(), 42, 2)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// TestGetSecretVersionsWithPermissionCheck_S35_ZeroUser ensures userID==0 is rejected.
func TestGetSecretVersionsWithPermissionCheck_S35_ZeroUser(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretVersionsWithPermissionCheck(context.Background(), 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

// TestGetSecretValueWithPermissionCheck_S35_ZeroUser ensures userID==0 is rejected.
func TestGetSecretValueWithPermissionCheck_S35_ZeroUser(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretValueWithPermissionCheck(context.Background(), 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

// TestGetLatestSecretVersionWithPermissionCheck_S35_ZeroUser ensures userID==0 is rejected.
func TestGetLatestSecretVersionWithPermissionCheck_S35_ZeroUser(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetLatestSecretVersionWithPermissionCheck(context.Background(), 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

// TestGetSecretVersionWithPermissionCheck_S35_ZeroUser ensures userID==0 is rejected.
func TestGetSecretVersionWithPermissionCheck_S35_ZeroUser(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretVersionWithPermissionCheck(context.Background(), 1, 0, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

// TestGetSecretValueByVersionWithPermissionCheck_S35_ZeroUser ensures userID==0 is rejected.
func TestGetSecretValueByVersionWithPermissionCheck_S35_ZeroUser(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretValueByVersionWithPermissionCheck(context.Background(), 1, 0, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

// TestGetLatestSecretVersion_S35_NoVersions covers the "no versions found" path.
func TestGetLatestSecretVersion_S35_NoVersions(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ms.On("GetSecretVersions", mock.Anything, uint(7)).Return([]*models.SecretVersion{}, nil)

	_, err := c.GetLatestSecretVersion(context.Background(), 7)
	require.Error(t, err)
}

// TestGetLatestSecretVersion_S35_ZeroID ensures secretID==0 is rejected.
func TestGetLatestSecretVersion_S35_ZeroID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetLatestSecretVersion(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

// ─── AnomalyDetector.SetBusinessHours (anomaly.go) ───────────────────────────

// TestSetBusinessHours_S35 covers error branches: unknown timezone and start==end.
func TestSetBusinessHours_S35(t *testing.T) {
	t.Parallel()
	d := NewAnomalyDetector(&captureStore{})

	t.Run("unknown timezone is rejected", func(t *testing.T) {
		err := d.SetBusinessHours(context.Background(), "Not/ATimezone", 22, 6)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timezone")
	})

	t.Run("start==end (non-zero) is rejected as degenerate", func(t *testing.T) {
		err := d.SetBusinessHours(context.Background(), "", 10, 10)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "start_hour and end_hour must differ")
	})

	t.Run("both zero keeps the default band (not treated as start==end)", func(t *testing.T) {
		err := d.SetBusinessHours(context.Background(), "", 0, 0)
		require.NoError(t, err)
	})

	t.Run("valid timezone and band is accepted", func(t *testing.T) {
		err := d.SetBusinessHours(context.Background(), "America/New_York", 22, 6)
		require.NoError(t, err)
	})
}

// ─── addRoleGrant dedup helper (users.go) ─────────────────────────────────────

// TestAddRoleGrant_S35 confirms deduplication: the same roleID+projectID is added only once.
func TestAddRoleGrant_S35(t *testing.T) {
	t.Parallel()
	grants := make([]storage.RoleGrant, 0)
	seen := map[[2]uint]bool{}
	addRoleGrant(&grants, seen, 5, 0)
	addRoleGrant(&grants, seen, 5, 0) // duplicate — should be skipped
	addRoleGrant(&grants, seen, 6, 0)
	addRoleGrant(&grants, seen, 5, 2) // same role, different project — distinct
	assert.Len(t, grants, 3)
}

// ─── actorPtr (sod.go) ────────────────────────────────────────────────────────

// TestActorPtr_S35 pins the behaviour: 0 → nil, non-zero → pointer to value.
func TestActorPtr_S35(t *testing.T) {
	t.Parallel()
	assert.Nil(t, actorPtr(0))
	p := actorPtr(7)
	require.NotNil(t, p)
	assert.Equal(t, uint(7), *p)
	p = actorPtr(1)
	require.NotNil(t, p)
	assert.Equal(t, uint(1), *p)
}

// ─── AnomalyDetector nil-storage guard (anomaly.go) ─────────────────────────

// TestSetBusinessHours_S35_NilStorage confirms auditBusinessHoursConfig is a no-op when
// the detector's storage is nil (prevents a nil-deref in tests that build a bare struct).
func TestSetBusinessHours_S35_NilStorage(t *testing.T) {
	t.Parallel()
	d := &AnomalyDetector{}
	require.NotPanics(t, func() {
		_ = d.SetBusinessHours(context.Background(), "", 22, 6)
	})
}
