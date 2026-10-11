package core

// #2955 follow-up (NOTIFY-1): every "tell the project's admins" notifier read
// ListProjectMembers only, which matches user_roles.project_id exactly, so an
// install-wide (global) admin -- who holds admin authority on every project but
// no project-scoped row -- was never notified. These assert the EFFECT (a
// persisted notification row for the global admin, none for people who must not
// see the subject), not a return value: notify() is best-effort by design.
//
// The documented recipient set for every project-admin notifier is
// docs/CONFIGURATION.md's "the project's admins" plus -- where the docs are
// silent on install-wide admins -- the break-glass rule from #2959: approver-role
// project members PLUS every active holder of an install-wide admin-bypass role,
// directly or through a group (projectAdminRecipients).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	testGlobalAdminID   = uint(70)
	testGroupAdminID    = uint(71)
	testInactiveAdminID = uint(72)
	testOutsiderID      = uint(73) // active user with no role anywhere
	testRequesterID     = uint(74)
)

// seedInstallWideAdmins adds, on top of a fixture that already has project 1,
// project_admin user 5 and viewer user 6: a global admin (70), a group-inherited
// global admin (71), a deactivated global admin (72), a role-less outsider (73)
// and a requester (74). Returns nothing; assertions look up notifications by user.
func seedInstallWideAdmins(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&models.Group{}, &models.GroupRole{}, &models.UserGroup{}))
	require.NoError(t, db.Create(&models.Role{ID: 30, Name: "admin", BypassesPermissionChecks: true}).Error)
	for _, u := range []models.User{
		{ID: testGlobalAdminID, Username: "gadmin", Email: "gadmin@x.io", IsActive: true},
		{ID: testGroupAdminID, Username: "grpadmin", Email: "grpadmin@x.io", IsActive: true},
		{ID: testOutsiderID, Username: "outsider", Email: "outsider@x.io", IsActive: true},
		{ID: testRequesterID, Username: "requester", Email: "requester@x.io", IsActive: true},
	} {
		require.NoError(t, db.Create(&u).Error)
	}
	inactive := models.User{ID: testInactiveAdminID, Username: "offboarded", Email: "off@x.io", IsActive: true}
	require.NoError(t, db.Create(&inactive).Error)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", testInactiveAdminID).Update("is_active", false).Error)

	for _, uid := range []uint{testGlobalAdminID, testInactiveAdminID} {
		require.NoError(t, db.Create(&models.UserRole{UserID: uid, RoleID: 30}).Error)
	}
	grp := models.Group{ID: 40, Name: "global-admins", NameFolded: "global-admins"}
	require.NoError(t, db.Create(&grp).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: grp.ID, RoleID: 30}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: testGroupAdminID, GroupID: grp.ID}).Error)
}

func notificationsFor(t *testing.T, db *gorm.DB, userID uint, nType string) []models.Notification {
	t.Helper()
	var notes []models.Notification
	require.NoError(t, db.Where("user_id = ? AND type = ?", userID, nType).Find(&notes).Error)
	return notes
}

// assertProjectAdminAudience is the shared expectation: the project admin (5),
// the global admin (70) and the group-inherited global admin (71) are notified
// exactly once; the viewer (6), the role-less outsider (73) and the deactivated
// global admin (72) are not.
func assertProjectAdminAudience(t *testing.T, db *gorm.DB, nType string) {
	t.Helper()
	for _, uid := range []uint{5, testGlobalAdminID, testGroupAdminID} {
		assert.Lenf(t, notificationsFor(t, db, uid, nType), 1, "user %d must be notified exactly once", uid)
	}
	for _, uid := range []uint{6, testOutsiderID, testInactiveAdminID} {
		assert.Emptyf(t, notificationsFor(t, db, uid, nType), "user %d must NOT be notified", uid)
	}
}

func TestSendExpiryReminders_NotifiesInstallWideAdmins(t *testing.T) {
	t.Parallel()
	c, db, _ := newExpiryReminderCore(t)
	seedInstallWideAdmins(t, db)
	_, err := c.SendExpiryReminders(context.Background(), 14)
	require.NoError(t, err)
	assertProjectAdminAudience(t, db, NotificationExpiryReminder)
}

func TestSendRotationReminders_NotifiesInstallWideAdmins(t *testing.T) {
	t.Parallel()
	c, db, _ := newRotationReminderCore(t)
	seedInstallWideAdmins(t, db)
	_, err := c.SendRotationReminders(context.Background())
	require.NoError(t, err)
	assertProjectAdminAudience(t, db, NotificationRotationDue)
}

func TestScanCertificateExpiry_NotifiesInstallWideAdmins(t *testing.T) {
	t.Parallel()
	c, db, _ := newCertExpiryCore(t)
	seedInstallWideAdmins(t, db)
	_, err := c.ScanCertificateExpiry(context.Background(), 30)
	require.NoError(t, err)
	assertProjectAdminAudience(t, db, NotificationCertificateExpiry)
}

func TestRemindRecertificationAdmins_NotifiesInstallWideAdmins(t *testing.T) {
	t.Parallel()
	c, db, _ := newExpiryReminderCore(t)
	seedInstallWideAdmins(t, db)
	c.remindRecertificationAdmins(context.Background(), 1, "due")
	assertProjectAdminAudience(t, db, NotificationRecertificationDue)
}

func TestNotifyAnomalyAdmins_NotifiesInstallWideAdmins(t *testing.T) {
	t.Parallel()
	c, db, _ := newExpiryReminderCore(t)
	seedInstallWideAdmins(t, db)
	require.NoError(t, c.notifyAnomalyAdmins(context.Background(), 1,
		&models.AnomalyAlert{Severity: "high", AlertType: "burst", SecretName: "db-password"}))
	assertProjectAdminAudience(t, db, EventAnomalyDetected)
}

func TestNotifyAccessRequested_NotifiesInstallWideAdmins(t *testing.T) {
	t.Parallel()
	c, db, _ := newExpiryReminderCore(t)
	seedInstallWideAdmins(t, db)
	require.NoError(t, c.notifyAccessRequested(context.Background(), &models.AccessRequest{ProjectID: 1, UserID: testRequesterID, SuggestedRole: "project_viewer"}))
	assertProjectAdminAudience(t, db, NotificationAccessRequested)
	assert.Empty(t, notificationsFor(t, db, testRequesterID, NotificationAccessRequested), "the requester is never told about their own request")
}

// A global admin who files the request is the requester: skipped, same as a
// project admin who requests access to their own project.
func TestNotifyAccessRequested_SkipsGlobalAdminRequester(t *testing.T) {
	t.Parallel()
	c, db, _ := newExpiryReminderCore(t)
	seedInstallWideAdmins(t, db)
	require.NoError(t, c.notifyAccessRequested(context.Background(), &models.AccessRequest{ProjectID: 1, UserID: testGlobalAdminID, SuggestedRole: "project_viewer"}))
	assert.Empty(t, notificationsFor(t, db, testGlobalAdminID, NotificationAccessRequested))
	assert.Len(t, notificationsFor(t, db, 5, NotificationAccessRequested), 1)
}

func TestNotifySecretAccessRequested_NotifiesInstallWideAdmins(t *testing.T) {
	t.Parallel()
	c, db, _ := newExpiryReminderCore(t)
	seedInstallWideAdmins(t, db)
	require.NoError(t, c.notifySecretAccessRequested(context.Background(),
		&models.AccessRequest{ProjectID: 1, UserID: testRequesterID}, &models.SecretNode{ID: 10, Name: "expired-key"}))
	assertProjectAdminAudience(t, db, NotificationAccessRequested)
}

func TestNotifyApprovalProgress_NotifiesInstallWideAdmins(t *testing.T) {
	t.Parallel()
	c, db, _ := newExpiryReminderCore(t)
	seedInstallWideAdmins(t, db)
	require.NoError(t, c.notifyApprovalProgress(context.Background(), &models.AccessRequest{ID: 3, ProjectID: 1, UserID: testRequesterID}, 1, 2))
	assertProjectAdminAudience(t, db, NotificationAccessRequested)
}

// A user who is both a project admin and an install-wide admin is one recipient.
func TestSendExpiryReminders_DedupesAdminWithBothScopes(t *testing.T) {
	t.Parallel()
	c, db, _ := newExpiryReminderCore(t)
	seedInstallWideAdmins(t, db)
	require.NoError(t, db.Create(&models.UserRole{UserID: testGlobalAdminID, RoleID: 1, ProjectID: 1}).Error)
	_, err := c.SendExpiryReminders(context.Background(), 14)
	require.NoError(t, err)
	assert.Len(t, notificationsFor(t, db, testGlobalAdminID, NotificationExpiryReminder), 1)
}

// Review point 1 (MERGE-MASTER, #2987): a member of an install-wide admin group
// whose OWN membership is scoped to another project (user_groups.project_id != 0)
// derives no install-wide authority from it, so must not receive this project's
// admin notifications. ListGroupMembers ignored that scope.
func TestSendExpiryReminders_ProjectScopedAdminGroupMemberNotNotified(t *testing.T) {
	t.Parallel()
	c, db, _ := newExpiryReminderCore(t)
	seedInstallWideAdmins(t, db)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "other"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 75, Username: "scoped", Email: "scoped@x.io", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 75, GroupID: 40, ProjectID: 2}).Error)
	_, err := c.SendExpiryReminders(context.Background(), 14)
	require.NoError(t, err)
	assert.Empty(t, notificationsFor(t, db, 75, NotificationExpiryReminder),
		"a member of the admin group scoped to project 2 must not be told about project 1")
	assertProjectAdminAudience(t, db, NotificationExpiryReminder)
}

// Review point 2: one vetting rule (active AND login not blocked) for BOTH the
// install-wide admins and the approver-role project members.
func TestSendExpiryReminders_SuspendedAccountsNotNotified(t *testing.T) {
	t.Parallel()
	c, db, _ := newExpiryReminderCore(t)
	seedInstallWideAdmins(t, db)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", testGlobalAdminID).Update("account_state", AccountSuspended).Error)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 5).Update("account_state", AccountSuspended).Error)
	require.NoError(t, db.Create(&models.User{ID: 76, Username: "deprov", Email: "deprov@x.io", IsActive: true}).Error)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 76).Update("account_state", AccountDeprovisioned).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 76, RoleID: 30}).Error)
	_, err := c.SendExpiryReminders(context.Background(), 14)
	require.NoError(t, err)
	for _, uid := range []uint{testGlobalAdminID, 5, 76} {
		assert.Emptyf(t, notificationsFor(t, db, uid, NotificationExpiryReminder), "user %d (login blocked) must NOT be notified", uid)
	}
	assert.Len(t, notificationsFor(t, db, testGroupAdminID, NotificationExpiryReminder), 1, "the healthy group-inherited admin still is")
}
