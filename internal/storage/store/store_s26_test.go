// store_s26_test.go — s26 coverage blitz for internal/storage/store.
//
// Targets (local_*.go functions with low coverage not yet hit by s1-s25):
//
//	local_rbac.go
//	  ListGlobalAdminAssignmentsForUpdate — empty IDs early-return + happy path + error path
//	  ListGroupRoleAssignments            — error path
//
//	local_audit_chain.go
//	  verifyBatchEvents  — chained row with empty EntryHash breaks chain
//	  LogAuditEvent      — ActorType="" normalisation + Success=nil normalisation
//
//	local_access_review_campaigns.go
//	  CreateAccessReviewCampaign  — error path
//	  UpdateAccessReviewCampaign  — zero-rows (false) + error path
//
//	local_sod.go
//	  ListSoDPolicies   — error path
//	  DeleteSoDPolicy   — not-found + error path
//
//	local_risk_exceptions.go
//	  ListRiskExceptions — activeOnly=true branch + error path
//
//	local_rotation_policies.go
//	  GetRotationPolicy       — not-found + error path
//	  ListRotationPolicies    — environmentID filter branch + error path
//
//	local_users.go
//	  DeleteGroup     — not-found (underlying GetGroup fails) + error path
//	  RestoreGroup    — zero-rows not-found + error path
//	  ListGroupsPage  — error path
//	  AddUserToGroup  — user-not-found, group-not-found, internal-DB-error paths
//
//	local_sharing.go
//	  CreateShareRecord       — validation error + secret-not-found + non-owner + group/user count errors
//	  CheckSharePermission    — secret-not-found error path
//
//	local_secrets.go
//	  DeleteEnvironment       — active-secrets block + DB error path
//	  SetSecretCertNotAfter   — error path
//	  GetSecretIncludingDeleted — error path
//
//	local_purge.go
//	  PurgeDeletedUsersBefore    — error path (broken DB)
//	  PurgeDeletedProjectsBefore — error path (broken DB)
//	  PurgeDeletedSecretsBefore  — error path (broken DB)
//
//	local_audit.go
//	  AcknowledgeAnomalyAlert — zero-rows not-found + error path
//	  scanTime.Value / scanTime.Scan — nil + time.Time + unsupported type branches
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newS26Store opens a unique in-memory SQLite DB with the requested models
// auto-migrated. The "_s26" suffix in the DSN prevents collisions with other
// test files that use the same test-name-keyed DSN pattern.
func newS26Store(t *testing.T, mods ...any) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "stores26_", sqlite.Open, &gorm.Config{})
	if len(mods) > 0 {
		require.NoError(t, db.AutoMigrate(mods...))
	}
	return NewLocalStorage(db)
}

// ---------------------------------------------------------------------------
// local_rbac.go — ListGlobalAdminAssignmentsForUpdate
// ---------------------------------------------------------------------------

// TestListGlobalAdminAssignmentsForUpdate_S26_EmptyIDsEarlyReturn verifies the
// len(adminRoleIDs)==0 early-return path returns (nil, nil) without touching
// the database.
func TestListGlobalAdminAssignmentsForUpdate_S26_EmptyIDsEarlyReturn(t *testing.T) {
	ls := newBrokenDB(t) // broken DB — must not be touched
	got, err := ls.ListGlobalAdminAssignmentsForUpdate(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, got)
}

// TestListGlobalAdminAssignmentsForUpdate_S26_HappyPath verifies the function
// returns user and group role assignments for the matching global-scope rows.
func TestListGlobalAdminAssignmentsForUpdate_S26_HappyPath(t *testing.T) {
	ls := newS26Store(t, &models.UserRole{}, &models.GroupRole{})
	ctx := context.Background()

	// Insert one global-scope user role and one global-scope group role for role 1.
	require.NoError(t, ls.db.Create(&models.UserRole{
		UserID: 10, RoleID: 1, ProjectID: 0, EnvironmentID: 0,
	}).Error)
	require.NoError(t, ls.db.Create(&models.GroupRole{
		GroupID: 20, RoleID: 1, ProjectID: 0, EnvironmentID: 0,
	}).Error)
	// Insert a project-scoped row that must NOT appear (ProjectID != 0).
	require.NoError(t, ls.db.Create(&models.UserRole{
		UserID: 11, RoleID: 1, ProjectID: 5, EnvironmentID: 0,
	}).Error)

	got, err := ls.ListGlobalAdminAssignmentsForUpdate(ctx, []uint{1})
	require.NoError(t, err)
	require.Len(t, got, 2)

	var userAssign, groupAssign storage.RoleAssignment
	for _, a := range got {
		switch a.PrincipalType {
		case "user":
			userAssign = a
		case "group":
			groupAssign = a
		}
	}
	assert.Equal(t, uint(10), userAssign.PrincipalID)
	assert.Equal(t, uint(20), groupAssign.PrincipalID)
}

// TestListGlobalAdminAssignmentsForUpdate_S26_BrokenDB verifies the error path
// when the user_roles table doesn't exist.
func TestListGlobalAdminAssignmentsForUpdate_S26_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListGlobalAdminAssignmentsForUpdate(context.Background(), []uint{1})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_rbac.go — ListGroupRoleAssignments
// ---------------------------------------------------------------------------

func TestListGroupRoleAssignments_S26_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListGroupRoleAssignments(context.Background(), 1)
	require.Error(t, err)
}

// TestListGroupRoleAssignments_S26_HappyPath verifies that all group_roles for
// a given groupID are returned as RoleAssignment values with the correct fields.
func TestListGroupRoleAssignments_S26_HappyPath(t *testing.T) {
	ls := newS26Store(t, &models.GroupRole{})
	ctx := context.Background()

	require.NoError(t, ls.db.Create(&models.GroupRole{
		GroupID: 5, RoleID: 7, ProjectID: 3, EnvironmentID: 0,
	}).Error)

	got, err := ls.ListGroupRoleAssignments(ctx, 5)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "group", got[0].PrincipalType)
	assert.Equal(t, uint(5), got[0].PrincipalID)
	assert.Equal(t, uint(7), got[0].RoleID)
	assert.Equal(t, uint(3), got[0].ProjectID)
}

// ---------------------------------------------------------------------------
// local_audit_chain.go — verifyBatchEvents
// ---------------------------------------------------------------------------

// TestVerifyBatchEvents_S26_EmptyHashOnStartedChain exercises the branch
// where a chained event (started == true) has an empty EntryHash — this must
// mark the chain as broken with the "missing entry hash" reason.
func TestVerifyBatchEvents_S26_EmptyHashOnStartedChain(t *testing.T) {
	result := &storage.AuditChainVerification{Valid: true}
	// first event: a properly chained event that sets started=true
	good := &models.AuditEvent{
		EntryHash: "aabbcc",
		PrevHash:  auditGenesisHash,
	}
	// second event: started but empty EntryHash
	bad := &models.AuditEvent{
		EntryHash: "",
		PrevHash:  "aabbcc",
	}
	// Manually compute good.EntryHash to satisfy the hash check in verifyBatchEvents.
	good.EntryHash = computeAuditEntryHash(good, auditGenesisHash)
	// Reset bad's PrevHash to the computed good hash.
	bad.PrevHash = good.EntryHash

	batch := []*models.AuditEvent{good, bad}
	_, _, _, broke := verifyBatchEvents(batch, auditGenesisHash, false, result)
	assert.True(t, broke, "an empty EntryHash on a chained event must break the chain")
	assert.False(t, result.Valid)
	assert.Contains(t, result.Reason, "missing entry hash")
}

// ---------------------------------------------------------------------------
// local_audit_chain.go — LogAuditEvent
// ---------------------------------------------------------------------------

// TestLogAuditEvent_S26_NormalizesActorType verifies that an event whose
// ActorType is "" is stored (and hashed) with ActorType = "user".
func TestLogAuditEvent_S26_NormalizesActorType(t *testing.T) {
	ls := newS26Store(t, &models.AuditEvent{})
	ctx := context.Background()

	trueVal := true
	event := &models.AuditEvent{
		EventType: "secret.read",
		EventTime: time.Now(),
		ActorType: "", // should be normalised to "user"
		Success:   &trueVal,
	}
	require.NoError(t, ls.LogAuditEvent(ctx, event))
	assert.Equal(t, "user", event.ActorType, "ActorType must be normalised to 'user' before hashing")
}

// TestLogAuditEvent_S26_NormalizesNilSuccess verifies that an event whose
// Success is nil is stored (and hashed) with Success = true.
func TestLogAuditEvent_S26_NormalizesNilSuccess(t *testing.T) {
	ls := newS26Store(t, &models.AuditEvent{})
	ctx := context.Background()

	event := &models.AuditEvent{
		EventType: "secret.read",
		EventTime: time.Now(),
		ActorType: "user",
		Success:   nil, // should be normalised to &true
	}
	require.NoError(t, ls.LogAuditEvent(ctx, event))
	require.NotNil(t, event.Success, "Success must be non-nil after normalisation")
	assert.True(t, *event.Success, "Success must be true after normalisation")
}

// ---------------------------------------------------------------------------
// local_access_review_campaigns.go — CreateAccessReviewCampaign error path
// ---------------------------------------------------------------------------

func TestCreateAccessReviewCampaign_S26_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.CreateAccessReviewCampaign(context.Background(), &models.AccessReviewCampaign{
		ProjectID: 1, Name: "Q1", State: "open",
	})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_access_review_campaigns.go — UpdateAccessReviewCampaign
// ---------------------------------------------------------------------------

// TestUpdateAccessReviewCampaign_S26_ZeroRowsReturnsFalse verifies the
// RowsAffected==0 path: updating a campaign that's no longer "open" must
// return (false, nil).
func TestUpdateAccessReviewCampaign_S26_ZeroRowsReturnsFalse(t *testing.T) {
	ls := newS26Store(t, &models.AccessReviewCampaign{})
	ctx := context.Background()

	c, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 1, Name: "Q1", State: "closed", // already closed
	})
	require.NoError(t, err)

	c.Name = "Q1-updated"
	ok, err := ls.UpdateAccessReviewCampaign(ctx, c)
	require.NoError(t, err)
	assert.False(t, ok, "updating a non-open campaign must return false")
}

func TestUpdateAccessReviewCampaign_S26_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.UpdateAccessReviewCampaign(context.Background(), &models.AccessReviewCampaign{ID: 1, State: "open"})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_sod.go — ListSoDPolicies / DeleteSoDPolicy
// ---------------------------------------------------------------------------

func TestListSoDPolicies_S26_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListSoDPolicies(context.Background())
	require.Error(t, err)
}

// TestDeleteSoDPolicy_S26_NotFound verifies the RowsAffected==0 branch: deleting
// a non-existent policy must return a "not found" error.
func TestDeleteSoDPolicy_S26_NotFound(t *testing.T) {
	ls := newS26Store(t, &models.SoDPolicy{})
	err := ls.DeleteSoDPolicy(context.Background(), 9999)
	require.Error(t, err)
}

func TestDeleteSoDPolicy_S26_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.DeleteSoDPolicy(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_risk_exceptions.go — ListRiskExceptions
// ---------------------------------------------------------------------------

// TestListRiskExceptions_S26_ActiveOnlyFilter verifies the activeOnly=true
// branch: revoked rows are excluded from the result.
func TestListRiskExceptions_S26_ActiveOnlyFilter(t *testing.T) {
	ls := newS26Store(t, &models.RiskException{})
	ctx := context.Background()

	_, err := ls.CreateRiskException(ctx, &models.RiskException{Title: "active", Revoked: false})
	require.NoError(t, err)
	_, err = ls.CreateRiskException(ctx, &models.RiskException{Title: "revoked", Revoked: true})
	require.NoError(t, err)

	all, err := ls.ListRiskExceptions(ctx, false)
	require.NoError(t, err)
	assert.Len(t, all, 2)

	active, err := ls.ListRiskExceptions(ctx, true)
	require.NoError(t, err)
	assert.Len(t, active, 1)
	assert.Equal(t, "active", active[0].Title)
}

func TestListRiskExceptions_S26_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListRiskExceptions(context.Background(), false)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_rotation_policies.go
// ---------------------------------------------------------------------------

// TestGetRotationPolicy_S26_NotFound verifies the not-found sentinel error.
func TestGetRotationPolicy_S26_NotFound(t *testing.T) {
	ls := newS26Store(t, &models.RotationPolicy{})
	_, err := ls.GetRotationPolicy(context.Background(), 9999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGetRotationPolicy_S26_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.GetRotationPolicy(context.Background(), 1)
	require.Error(t, err)
}

// TestListRotationPolicies_S26_EnvironmentIDFilter exercises the environmentID
// != nil branch.
func TestListRotationPolicies_S26_EnvironmentIDFilter(t *testing.T) {
	ls := newS26Store(t, &models.RotationPolicy{})
	ctx := context.Background()

	eid1 := uint(1)
	eid2 := uint(2)
	require.NoError(t, ls.CreateRotationPolicy(ctx, &models.RotationPolicy{
		Name: "p1", Scope: "environment", EnvironmentID: &eid1,
		IntervalDays: 30, CreatedBy: "admin",
	}))
	require.NoError(t, ls.CreateRotationPolicy(ctx, &models.RotationPolicy{
		Name: "p2", Scope: "environment", EnvironmentID: &eid2,
		IntervalDays: 30, CreatedBy: "admin",
	}))

	got, err := ls.ListRotationPolicies(ctx, nil, &eid1)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "p1", got[0].Name)
}

func TestListRotationPolicies_S26_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListRotationPolicies(context.Background(), nil, nil)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_users.go — DeleteGroup / RestoreGroup / ListGroupsPage / AddUserToGroup
// ---------------------------------------------------------------------------

// TestDeleteGroup_S26_NotFound verifies DeleteGroup returns an error when
// GetGroup can't find the requested ID.
func TestDeleteGroup_S26_NotFound(t *testing.T) {
	ls := newS26Store(t, &models.Group{})
	err := ls.DeleteGroup(context.Background(), 9999)
	require.Error(t, err)
}

// TestRestoreGroup_S26_NotFound verifies RestoreGroup returns an error when no
// soft-deleted row matches the id.
func TestRestoreGroup_S26_NotFound(t *testing.T) {
	ls := newS26Store(t, &models.Group{})
	err := ls.RestoreGroup(context.Background(), 9999)
	require.Error(t, err)
}

func TestRestoreGroup_S26_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.RestoreGroup(context.Background(), 1)
	require.Error(t, err)
}

func TestListGroupsPage_S26_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, _, err := ls.ListGroupsPage(context.Background(), 0, 10)
	require.Error(t, err)
}

// TestListGroupsPage_S26_HappyPath verifies pagination returns total count and
// the expected subset.
func TestListGroupsPage_S26_HappyPath(t *testing.T) {
	ls := newS26Store(t, &models.Group{})
	ctx := context.Background()

	for _, name := range []string{"alpha", "beta", "gamma"} {
		_, err := ls.CreateGroup(ctx, &models.Group{Name: name, NameFolded: name})
		require.NoError(t, err)
	}

	page, total, err := ls.ListGroupsPage(ctx, 0, 2)
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
	assert.Len(t, page, 2)
}

// TestAddUserToGroup_S26_UserNotFound verifies AddUserToGroup returns an error
// when the user doesn't exist.
func TestAddUserToGroup_S26_UserNotFound(t *testing.T) {
	ls := newS26Store(t, &models.User{}, &models.Group{}, &models.UserGroup{})
	ctx := context.Background()

	grp, err := ls.CreateGroup(ctx, &models.Group{Name: "g1", NameFolded: "g1"})
	require.NoError(t, err)

	// User 9999 doesn't exist.
	err = ls.AddUserToGroup(ctx, 9999, grp.ID, 0)
	require.Error(t, err)
}

// TestAddUserToGroup_S26_GroupNotFound verifies AddUserToGroup returns an error
// when the group doesn't exist.
func TestAddUserToGroup_S26_GroupNotFound(t *testing.T) {
	ls := newS26Store(t, &models.User{}, &models.Group{}, &models.UserGroup{})
	ctx := context.Background()

	user, err := ls.CreateUser(ctx, &models.User{
		Username: "u1", UsernameFolded: "u1", Email: "u1@test.com", EmailFolded: "u1@test.com", PasswordHash: "x",
	})
	require.NoError(t, err)

	// Group 9999 doesn't exist.
	err = ls.AddUserToGroup(ctx, user.ID, 9999, 0)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_sharing.go — CreateShareRecord error paths
// ---------------------------------------------------------------------------

// TestCreateShareRecord_S26_ValidationError verifies that an invalid share
// record (e.g. zero SecretID) returns a validation error without touching the DB.
func TestCreateShareRecord_S26_ValidationError(t *testing.T) {
	ls := newS26Store(t, &models.SecretNode{}, &models.ShareRecord{}, &models.User{})
	// SecretID = 0 fails ValidateShareRecord.
	_, err := ls.CreateShareRecord(context.Background(), &models.ShareRecord{
		SecretID:    0,
		RecipientID: 1,
		OwnerID:     1,
		Permission:  "read",
	})
	require.Error(t, err)
}

// TestCreateShareRecord_S26_SecretNotFound verifies that referencing a
// non-existent secret returns an error.
func TestCreateShareRecord_S26_SecretNotFound(t *testing.T) {
	ls := newS26Store(t, &models.SecretNode{}, &models.ShareRecord{}, &models.User{}, &models.Group{})
	_, err := ls.CreateShareRecord(context.Background(), &models.ShareRecord{
		SecretID:    9999, // does not exist
		RecipientID: 1,
		OwnerID:     1,
		Permission:  "read",
	})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_sharing.go — CheckSharePermission error path
// ---------------------------------------------------------------------------

// TestCheckSharePermission_S26_SecretNotFound verifies that looking up a
// non-existent secret returns an error.
func TestCheckSharePermission_S26_SecretNotFound(t *testing.T) {
	ls := newS26Store(t, &models.SecretNode{}, &models.ShareRecord{})
	_, err := ls.CheckSharePermission(context.Background(), 9999, 1, time.Now())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_secrets.go — DeleteEnvironment
// ---------------------------------------------------------------------------

// TestDeleteEnvironment_S26_ActiveSecretsBlock verifies that DeleteEnvironment
// returns an error when the environment still has active secrets.
func TestDeleteEnvironment_S26_ActiveSecretsBlock(t *testing.T) {
	ls := newS26Store(t, &models.Project{}, &models.Environment{}, &models.SecretNode{})
	ctx := context.Background()

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "p"})
	require.NoError(t, err)

	env, err := ls.CreateEnvironment(ctx, &models.Environment{
		ProjectID: proj.ID, Name: "prod",
	})
	require.NoError(t, err)

	_, err = ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID: proj.ID, EnvironmentID: env.ID,
		Name: "my-secret", IsSecret: true, Status: "active",
	})
	require.NoError(t, err)

	err = ls.DeleteEnvironment(ctx, env.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "active secret")
}

// TestDeleteEnvironment_S26_NotFound verifies the RowsAffected==0 path when
// the environment doesn't exist.
func TestDeleteEnvironment_S26_NotFound(t *testing.T) {
	ls := newS26Store(t, &models.SecretNode{}, &models.Environment{})
	err := ls.DeleteEnvironment(context.Background(), 9999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// local_secrets.go — SetSecretCertNotAfter error path
// ---------------------------------------------------------------------------

func TestSetSecretCertNotAfter_S26_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	now := time.Now()
	err := ls.SetSecretCertNotAfter(context.Background(), 1, &now)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_secrets.go — GetSecretIncludingDeleted error path
// ---------------------------------------------------------------------------

func TestGetSecretIncludingDeleted_S26_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.GetSecretIncludingDeleted(context.Background(), 1)
	require.Error(t, err)
}

// TestGetSecretIncludingDeleted_S26_NotFound verifies error is returned for a
// non-existent ID even with Unscoped.
func TestGetSecretIncludingDeleted_S26_NotFound(t *testing.T) {
	ls := newS26Store(t, &models.SecretNode{})
	_, err := ls.GetSecretIncludingDeleted(context.Background(), 9999)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_purge.go — error paths (broken DB)
// ---------------------------------------------------------------------------

func TestPurgeDeletedUsersBefore_S26_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.PurgeDeletedUsersBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func TestPurgeDeletedProjectsBefore_S26_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.PurgeDeletedProjectsBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func TestPurgeDeletedSecretsBefore_S26_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.PurgeDeletedSecretsBefore(context.Background(), time.Now())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_audit.go — AcknowledgeAnomalyAlert
// ---------------------------------------------------------------------------

// TestAcknowledgeAnomalyAlert_S26_NotFound verifies the RowsAffected==0 path:
// acknowledging a non-existent alert must return a "not found" error.
func TestAcknowledgeAnomalyAlert_S26_NotFound(t *testing.T) {
	ls := newS26Store(t, &models.AnomalyAlert{})
	err := ls.AcknowledgeAnomalyAlert(context.Background(), 9999, 1, time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAcknowledgeAnomalyAlert_S26_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.AcknowledgeAnomalyAlert(context.Background(), 1, 1, time.Now())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_audit.go — scanTime.Value / Scan
// ---------------------------------------------------------------------------

// TestScanTime_S26_Value_Nil verifies scanTime.Value returns (nil, nil) when
// the internal time pointer is nil.
func TestScanTime_S26_Value_Nil(t *testing.T) {
	s := scanTime{}
	v, err := s.Value()
	require.NoError(t, err)
	assert.Nil(t, v)
}

// TestScanTime_S26_Value_NonNil verifies scanTime.Value returns the time value
// when the pointer is set.
func TestScanTime_S26_Value_NonNil(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := scanTime{t: &now}
	v, err := s.Value()
	require.NoError(t, err)
	gotTime, ok := v.(time.Time)
	require.True(t, ok, "expected a time.Time from Value()")
	assert.Equal(t, now, gotTime)
}

// TestScanTime_S26_Scan_Nil verifies Scan(nil) sets t to nil without error.
func TestScanTime_S26_Scan_Nil(t *testing.T) {
	s := scanTime{}
	err := s.Scan(nil)
	require.NoError(t, err)
	assert.Nil(t, s.t)
}

// TestScanTime_S26_Scan_TimeTime verifies Scan(time.Time) stores it directly.
func TestScanTime_S26_Scan_TimeTime(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := scanTime{}
	err := s.Scan(now)
	require.NoError(t, err)
	require.NotNil(t, s.t)
	assert.Equal(t, now, *s.t)
}

// TestScanTime_S26_Scan_UnsupportedType verifies Scan returns an error for an
// unrecognised value type (int).
func TestScanTime_S26_Scan_UnsupportedType(t *testing.T) {
	s := scanTime{}
	err := s.Scan(42)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported type")
}

// TestScanTime_S26_Scan_StringValid verifies Scan parses a well-formed RFC3339
// string into a time.Time without error.
func TestScanTime_S26_Scan_StringValid(t *testing.T) {
	s := scanTime{}
	err := s.Scan("2026-07-18 10:30:00")
	require.NoError(t, err)
	require.NotNil(t, s.t)
}

// TestScanTime_S26_Scan_StringInvalid verifies Scan returns an error for an
// unparseable string.
func TestScanTime_S26_Scan_StringInvalid(t *testing.T) {
	s := scanTime{}
	err := s.Scan("not-a-time")
	require.Error(t, err)
}

// TestScanTime_S26_Scan_ByteSliceValid verifies Scan parses a valid []byte
// timestamp (some drivers return timestamps as []byte, not string).
func TestScanTime_S26_Scan_ByteSliceValid(t *testing.T) {
	s := scanTime{}
	err := s.Scan([]byte("2026-07-18 10:30:00"))
	require.NoError(t, err)
	require.NotNil(t, s.t)
}
