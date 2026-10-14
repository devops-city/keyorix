// concurrency_g04_threshold_race_test.go — #G04 regressions: three independent
// "read a threshold/dual-control count, decide, then write" sequences with no
// transaction or lock spanning the read and the write, so two legitimate
// concurrent actions can each observe a stale below-threshold state and both
// proceed — creating exactly the combination the check exists to prevent.
package core_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func openRaceDB(t *testing.T, name string) *gorm.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), name+".db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	return db
}

// newSoDGrantFixture creates a fresh DB with an SoD policy pairing two
// permissions, two non-admin roles each granting one side, and one user
// holding neither role yet.
func newSoDGrantFixture(t *testing.T, dbFile string) (c *core.KeyorixCore, db *gorm.DB, roleAID, roleBID uint) {
	t.Helper()
	db = openRaceDB(t, dbFile)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.SoDPolicy{}, &models.AuditEvent{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		// GetUserRoleIDsAt/GetUserGroupRoleIDsAt (isGlobalAdminRoleName's
		// scopedRoleIDs) LEFT JOIN projects/environments unconditionally, even
		// for a global-scope (ProjectID 0) query -- missing here, this always
		// errored "no such table: projects", previously invisible because
		// isGlobalAdminRoleName silently swallowed any resolution error into
		// "" (docs/findings/2026-10-02-FINDING-sod-policy-create-getrole-error-
		// misread-as-not-admin.md). A genuine fixture gap, not new with that fix.
		&models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "perm.a", Resource: "r", Action: "a"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "perm.b", Resource: "r", Action: "a"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "role_a"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 11, Name: "role_b"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 10, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 11, PermissionID: 2}).Error)
	require.NoError(t, db.Create(&models.SoDPolicy{Name: "toxic-a-b", PermissionA: "perm.a", PermissionB: "perm.b"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "u"}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db, 10, 11
}

// TestConcurrency_AssignUserRole_SoDGrantRace is the #G04 regression for
// sod.go's requireNoSoDViolation / rbac_management.go's AssignUserRole: two
// concurrent grants of role_a and role_b to the same user, where holding both
// completes an SoD policy neither role alone violates. Correct behavior is
// exactly one grant succeeding — the second must observe the first's
// already-committed permission and refuse. Without serialization both could
// read the user's pre-grant permission set before either write commits, and
// both succeed, leaving the user holding the full toxic combination.
func TestConcurrency_AssignUserRole_SoDGrantRace(t *testing.T) {
	t.Parallel()
	const trials = 50
	var bothGranted, neitherGranted int
	for trial := range trials {
		c, db, roleAID, roleBID := newSoDGrantFixture(t, fmt.Sprintf("sod_grant_%d", trial))
		ctx := context.Background()

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; _ = c.AssignUserRole(ctx, 0, 1, roleAID, core.Scope{}, false) }()
		go func() { defer wg.Done(); <-start; _ = c.AssignUserRole(ctx, 0, 1, roleBID, core.Scope{}, false) }()
		close(start)
		wg.Wait()

		var count int64
		require.NoError(t, db.Model(&models.UserRole{}).Where("user_id = ?", 1).Count(&count).Error)
		switch count {
		case 2:
			bothGranted++
		case 0:
			neitherGranted++
		}
	}
	assert.Zero(t, bothGranted, "%d/%d trials granted BOTH toxic roles, a live separation-of-duties violation the preventive gate exists to block", bothGranted, trials)
	assert.Zero(t, neitherGranted, "%d/%d trials refused BOTH grants (should allow exactly one)", neitherGranted, trials)
}

// TestConcurrency_DecideAccessReviewItem_AttestRevokeRace is the #G04
// regression for access_review_campaign.go's DecideAccessReviewItem. It
// deliberately races an "attest" against a "revoke" on the SAME item (not two
// identical decisions, unlike the pre-existing #319 redecide test) because
// only a MIXED race can expose the bug this closes: persistItemDecision's
// conditional UPDATE already stops a second STAMP from persisting, but
// without accessReviewDecisionMu both callers can still read
// Decision==pending and both execute their real action (grant kept vs. grant
// removed) before either commits — so the loser's real-world action still
// happened even though only the winner's stamp survives, leaving recorded
// evidence that disagrees with the actual grant state.
func TestConcurrency_DecideAccessReviewItem_AttestRevokeRace(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	const trials = 30
	for trial := range trials {
		db := openRaceDB(t, fmt.Sprintf("arc_mixed_%d", trial))
		require.NoError(t, db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.AuditEvent{}, &models.UserRole{}, &models.GroupRole{}, &models.Group{}, &models.Permission{}, &models.RolePermission{}))

		const proj = uint(2)
		campaign := &models.AccessReviewCampaign{ProjectID: proj, Name: "race", State: core.CampaignStateOpen}
		require.NoError(t, db.Create(campaign).Error)
		require.NoError(t, db.Create(&models.UserRole{UserID: 999, RoleID: 1, ProjectID: proj}).Error)
		item := &models.AccessReviewItem{CampaignID: campaign.ID, PrincipalType: "role", PrincipalID: 999, RoleID: 1, Source: "role", Decision: core.ReviewItemPending}
		require.NoError(t, db.Create(item).Error)

		c := core.NewKeyorixCore(store.NewLocalStorage(db))
		ctx := context.Background()

		var attestErr, revokeErr error
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			attestErr = c.DecideAccessReviewItem(ctx, 100, proj, campaign.ID, item.ID, "attest", "concurrent attest")
		}()
		go func() {
			defer wg.Done()
			<-start
			revokeErr = c.DecideAccessReviewItem(ctx, 101, proj, campaign.ID, item.ID, "revoke", "concurrent revoke")
		}()
		close(start)
		wg.Wait()

		attestWon := attestErr == nil
		revokeWon := revokeErr == nil
		require.False(t, attestWon && revokeWon, "trial %d: BOTH attest and revoke succeeded on the same item — the action ran twice", trial)
		require.True(t, attestWon || revokeWon, "trial %d: NEITHER decision succeeded", trial)
		if attestWon {
			require.ErrorContains(t, revokeErr, "already been decided", "trial %d: the losing revoke must fail with the clear rejection, not silently apply", trial)
		} else {
			require.ErrorContains(t, attestErr, "already been decided", "trial %d: the losing attest must fail with the clear rejection, not silently apply", trial)
		}

		var got models.AccessReviewItem
		require.NoError(t, db.First(&got, item.ID).Error)
		var grantCount int64
		require.NoError(t, db.Model(&models.UserRole{}).Where("user_id = ? AND role_id = ? AND project_id = ?", 999, 1, proj).Count(&grantCount).Error)

		if attestWon {
			assert.Equal(t, core.ReviewItemAttested, got.Decision, "trial %d: attest won, the persisted decision must say attested", trial)
			assert.Equal(t, int64(1), grantCount, "trial %d: attest keeps the grant — it must still exist, matching the persisted 'attested' evidence", trial)
		} else {
			assert.Equal(t, core.ReviewItemRevoked, got.Decision, "trial %d: revoke won, the persisted decision must say revoked", trial)
			assert.Equal(t, int64(0), grantCount, "trial %d: revoke removes the grant — it must be gone, matching the persisted 'revoked' evidence", trial)
		}
	}
}

// newDualControlFixture creates a fresh DB with a project, a non-admin
// "editor" role, a requester, three distinct approvers, and a pending
// AccessRequest already carrying ONE recorded approval — so a required=2
// threshold is exactly one more genuine approval away from crossing.
func newDualControlFixture(t *testing.T, dbFile string) (c *core.KeyorixCore, db *gorm.DB, requestID uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db = openRaceDB(t, dbFile)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.AuditEvent{}, &models.SoDPolicy{},
		&models.AccessRequest{}, &models.AccessRequestApproval{}, &models.Notification{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 20, Name: "editor"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "requester"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "approver-existing"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "approver-a"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 4, Username: "approver-b"}).Error)
	// F6 sweep (2026-09-22): approving now ALSO requires roles.assign as a
	// baseline, independent of "editor"'s own (here empty) permission bundle.
	// Give both racing approvers a real roles.assign grant at the request's
	// project so this test still isolates the threshold race (its actual
	// subject) from that separate baseline.
	require.NoError(t, db.Create(&models.Permission{ID: 900, Name: "roles.assign", Resource: "roles", Action: "assign"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 21, Name: "race-approver"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 21, PermissionID: 900}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 21, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 4, RoleID: 21, ProjectID: 1}).Error)

	req := &models.AccessRequest{ProjectID: 1, UserID: 1, SuggestedRole: "editor", State: core.AccessRequestPending, CreatedAt: time.Now()}
	require.NoError(t, db.Create(req).Error)
	require.NoError(t, db.Create(&models.AccessRequestApproval{RequestID: req.ID, ApproverID: 2, CreatedAt: time.Now()}).Error)

	c = core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetDualControlPolicy(2)
	return c, db, req.ID
}

// TestConcurrency_ApproveAccessRequestWithExpiry_ThresholdRace is the #G04
// regression for invitations.go's ApproveAccessRequestWithExpiry: with one
// approval already recorded and a threshold of 2, two DIFFERENT new approvers
// racing to cast the second, threshold-crossing sign-off must not both
// finalize. Unserialized, both can read the same below-threshold approval count
// before either's row commits and both finalize — granting the role and
// recording the approval twice, defeating the "K distinct approvers" guarantee.
//
// #G04-HA: the serializing guard is now storage.WithNamedLock keyed per request,
// not the KeyorixCore-level dualControlApprovalMu this test was written against
// (that field is gone — it never serialized anything across replicas). Both
// callers here share one KeyorixCore and one SQLite store, where WithNamedLock
// is a process mutex, so this in-process assertion is unchanged; the
// cross-replica half lives in the Postgres tests alongside it.
func TestConcurrency_ApproveAccessRequestWithExpiry_ThresholdRace(t *testing.T) {
	t.Parallel()
	const trials = 30
	for trial := range trials {
		c, db, requestID := newDualControlFixture(t, fmt.Sprintf("dual_control_%d", trial))
		ctx := context.Background()

		var finalized atomic.Int64
		var unexpected atomic.Int64
		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, approverID := range []uint{3, 4} {
			wg.Add(1)
			go func(approverID uint) {
				defer wg.Done()
				<-start
				_, err := c.ApproveAccessRequestWithExpiry(ctx, 1, requestID, approverID, 0, "", 0)
				switch {
				case err == nil:
					finalized.Add(1)
				case strings.Contains(err.Error(), "only a pending request can be approved"):
					// expected loser outcome: the per-request named lock made this caller
					// re-read the request AFTER the winner's finalize committed, so it
					// sees the request is no longer pending and gets a clean rejection —
					// never touching the grant/approval-count logic at all.
				default:
					// Notably, a bare unique-key "failed to grant role: ... already
					// assigned" error (which G21's already-fixed local_rbac.go
					// assignUserRole transaction happens to produce here, since both
					// approvers are locked to the SAME suggested role) is deliberately
					// NOT accepted as an expected outcome: relying on that unrelated
					// constraint would leave this exact race un-asserted (a backend
					// without that transactional grant guard would sail through
					// unnoticed).
					unexpected.Add(1)
				}
			}(approverID)
		}
		close(start)
		wg.Wait()

		assert.Zero(t, unexpected.Load(), "trial %d: the losing approval must fail with the clean 'only a pending request can be approved' rejection — not a confusing downstream 'already assigned' grant error, and not any other unexpected error", trial)
		assert.Equal(t, int64(1), finalized.Load(), "trial %d: exactly one of the two racing approvals may cross the threshold and finalize", trial)

		var approvalCount int64
		require.NoError(t, db.Model(&models.AccessRequestApproval{}).Where("request_id = ?", requestID).Count(&approvalCount).Error)
		assert.Equal(t, int64(2), approvalCount, "trial %d: exactly 2 approvals total (1 pre-existing + 1 winner) must be recorded, never 3", trial)

		var grantCount int64
		require.NoError(t, db.Model(&models.UserRole{}).Where("user_id = ? AND role_id = ?", 1, 20).Count(&grantCount).Error)
		assert.Equal(t, int64(1), grantCount, "trial %d: the role must be granted exactly once, never twice", trial)
	}
}
