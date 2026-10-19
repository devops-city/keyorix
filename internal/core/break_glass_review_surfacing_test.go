// break_glass_review_surfacing_test.go — #2461 coordinator review item 2:
// unreviewed break-glass activations must actually be SURFACED.
//
// Before this, ListUnreviewedBreakGlassActivations and
// config.BreakGlassConfig.GetReviewWindow had no non-test callers anywhere, so
// ADR-112's "every activation must be reviewed afterwards: an open activation
// without a recorded review shows as a posture deviation" was true of the
// prose and of nothing else. These tests pin the two places that claim now
// rests on: the compliance posture report, and the periodic reminder.
//
// What "enforced" means is exactly what ADR-112 says — a posture deviation
// plus the mandatory alert/audit event — and NOT a lockout. See
// RunBreakGlassReviewReminder's doc comment.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestBreakGlassReviewWindowDefaultMatchesConfig keeps internal/core's
// duplicated 72h default honest against internal/config's. The duplication is
// deliberate (internal/core must not import internal/config, ADR-109) and so
// is this check: a drift would make the posture report and the operator-facing
// config documentation disagree about when a review is overdue.
func TestBreakGlassReviewWindowDefaultMatchesConfig(t *testing.T) {
	t.Parallel()
	assert.Equal(t, config.BreakGlassConfig{}.GetReviewWindow(), defaultBreakGlassReviewWindow)
}

// TestBreakGlassReviewWindow_ZeroPolicyFallsBackToDefault: a core built
// without SetBreakGlassPolicy (every unit test, and any embedder) must not
// treat a zero window as "now - 0", which would report every activation that
// has ever existed as overdue.
func TestBreakGlassReviewWindow_ZeroPolicyFallsBackToDefault(t *testing.T) {
	t.Parallel()
	c := NewKeyorixCore(new(MockStorage))
	assert.Equal(t, defaultBreakGlassReviewWindow, c.breakGlassReviewWindow())

	c.SetBreakGlassPolicy(BreakGlassPolicy{ReviewWindow: 12 * time.Hour})
	assert.Equal(t, 12*time.Hour, c.breakGlassReviewWindow())
}

// TestAccumulateBreakGlassPosture_CountsUnreviewedPastTheWindow is the posture
// deviation itself. Four activations exercise every edge of the rule in one
// pass: overdue-unreviewed (counted), reviewed (not counted no matter how old),
// unreviewed but still inside the window (not counted yet), and
// overdue-unreviewed AND STILL ACTIVE (counted — ADR-112 says "an OPEN
// activation without a recorded review", and ReviewBreakGlass deliberately
// refuses to review a still-active one, so excluding those would hide exactly
// the activations that cannot be closed out yet).
func TestAccumulateBreakGlassPosture_CountsUnreviewedPastTheWindow(t *testing.T) {
	t.Parallel()
	fixed := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	reviewedAt := fixed.Add(-24 * time.Hour)

	c := NewKeyorixCore(new(MockStorage))
	c.now = func() time.Time { return fixed }
	c.SetBreakGlassPolicy(BreakGlassPolicy{ReviewWindow: 72 * time.Hour})

	acts := []*models.BreakGlassActivation{
		// 200h old, never reviewed -> the deviation, and the oldest.
		{ID: 1, ProjectID: 1, UserID: 10, State: BreakGlassRevoked, CreatedAt: fixed.Add(-200 * time.Hour)},
		// 300h old but REVIEWED -> never a deviation, however old.
		{ID: 2, ProjectID: 1, UserID: 11, State: BreakGlassRevoked, CreatedAt: fixed.Add(-300 * time.Hour), ReviewedBy: 99, ReviewedAt: &reviewedAt},
		// 10h old, unreviewed -> still inside the window, not yet overdue.
		{ID: 3, ProjectID: 1, UserID: 12, State: BreakGlassExpired, CreatedAt: fixed.Add(-10 * time.Hour)},
		// 100h old, unreviewed, STILL ACTIVE -> counted.
		{ID: 4, ProjectID: 1, UserID: 13, State: BreakGlassActive, CreatedAt: fixed.Add(-100 * time.Hour)},
	}

	p := &CompliancePosture{}
	snap := &complianceSnapshot{
		breakGlassByProject:    map[uint][]*models.BreakGlassActivation{1: acts},
		breakGlassErrByProject: map[uint]error{},
	}
	c.accumulateBreakGlassPosture(p, 1, snap)

	assert.Equal(t, 4, p.EmergencyAccess.TotalActivations)
	assert.Equal(t, 1, p.EmergencyAccess.ActiveActivations)
	assert.Equal(t, 2, p.EmergencyAccess.UnreviewedActivations,
		"activations 1 and 4 are unreviewed past the window; 2 is reviewed and 3 is still inside it")
	assert.Equal(t, 200, p.EmergencyAccess.OldestUnreviewedAgeHours,
		"the age reported must be the WORST outstanding one -- a bare count cannot tell 'a day late' from 'ignored for a year'")
	assert.Equal(t, 72, p.EmergencyAccess.ReviewWindowHours,
		"the threshold must travel with the counts, or the report is uninterpretable without the deployment's config")
}

// TestAccumulateBreakGlassPosture_SingleAdminDeploymentFlagsIndependentReviewImpossible
// is INV-CORE-break-glass-independent-review-impossible-is-visible's proving
// test (#2461 round 2, Andrei's decision item (c)):
// a deployment with exactly one active global admin-tier holder must flag
// IndependentReviewImpossible, and a second admin must clear it. Uses a real
// LocalStorage (newSCIMGuardCore) rather than MockStorage because the
// underlying check (resolveGlobalAdminHolders) walks real role-assignment and
// user rows, the same mechanism guardLastGlobalAdmin* already relies on.
func TestAccumulateBreakGlassPosture_SingleAdminDeploymentFlagsIndependentReviewImpossible(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error)

	p := &CompliancePosture{}
	c.accessGovernancePostureFromSnapshot(ctx, p, &complianceSnapshot{})
	assert.True(t, p.EmergencyAccess.IndependentReviewImpossible,
		"the install's only admin-tier holder could never independently review their own activation")

	// A second admin joins -- independent review becomes possible.
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "second", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 10}).Error)

	p2 := &CompliancePosture{}
	c.accessGovernancePostureFromSnapshot(ctx, p2, &complianceSnapshot{})
	assert.False(t, p2.EmergencyAccess.IndependentReviewImpossible,
		"a second admin-tier holder means independent review is no longer structurally impossible")
}

// TestRunBreakGlassReviewReminder_WarnsAndAuditsOncePerPass pins the periodic
// half: it reports the count, and emits exactly ONE audit event per pass rather
// than one per activation (a long-ignored review would otherwise spam the audit
// log it exists to make legible).
func TestRunBreakGlassReviewReminder_WarnsAndAuditsOncePerPass(t *testing.T) {
	fixed := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	ms := new(MockStorage)

	var gotCutoff time.Time
	ms.On("ListUnreviewedBreakGlassActivationsBefore", mock.Anything, mock.AnythingOfType("time.Time")).
		Run(func(args mock.Arguments) { gotCutoff = args.Get(1).(time.Time) }).
		Return([]*models.BreakGlassActivation{
			{ID: 1, ProjectID: 1, UserID: 10, CreatedAt: fixed.Add(-200 * time.Hour)},
			{ID: 2, ProjectID: 2, UserID: 11, CreatedAt: fixed.Add(-100 * time.Hour)},
		}, nil)

	var events []*models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { events = append(events, args.Get(1).(*models.AuditEvent)) }).Return(nil)

	c := NewKeyorixCore(ms)
	c.now = func() time.Time { return fixed }
	c.SetBreakGlassPolicy(BreakGlassPolicy{ReviewWindow: 48 * time.Hour})

	n, err := c.RunBreakGlassReviewReminder(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, fixed.Add(-48*time.Hour), gotCutoff, "the cutoff must come from the CONFIGURED window, not the default")

	require.Len(t, events, 1, "one event per pass, not one per activation")
	assert.Equal(t, EventBreakGlassReviewOverdue, events[0].EventType)
	assert.Contains(t, events[0].Description, "2 activation(s) unreviewed")
	assert.Contains(t, events[0].Description, "activation 1",
		"the oldest activation must be named -- the storage query orders created_at ASC")
}

// TestRunBreakGlassReviewReminder_QuietWhenNothingOverdue: a clean pass must
// write nothing. An audit event on every tick of a 6h scheduler would bury the
// one that matters.
func TestRunBreakGlassReviewReminder_QuietWhenNothingOverdue(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListUnreviewedBreakGlassActivationsBefore", mock.Anything, mock.AnythingOfType("time.Time")).
		Return([]*models.BreakGlassActivation{}, nil)

	c := NewKeyorixCore(ms)
	n, err := c.RunBreakGlassReviewReminder(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	ms.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}

// TestRunBreakGlassReviewReminder_StorageErrorIsReported: the scheduler needs a
// real error to mark the run failed. Swallowing it would make a permanently
// broken query look like "nothing is overdue" forever -- the failure mode this
// whole item exists to close.
func TestRunBreakGlassReviewReminder_StorageErrorIsReported(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListUnreviewedBreakGlassActivationsBefore", mock.Anything, mock.AnythingOfType("time.Time")).
		Return([]*models.BreakGlassActivation(nil), assert.AnError)

	c := NewKeyorixCore(ms)
	_, err := c.RunBreakGlassReviewReminder(context.Background())
	require.Error(t, err)
	ms.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}

// reviewReminderNotifySpy backs TestRunBreakGlassReviewReminder_NotifiesAdmins.
// Embeds storage.Storage as nil like breakGlassNotifyPanicSpy above — any
// unstubbed method panics on a nil pointer dereference if reached.
type reviewReminderNotifySpy struct {
	inner       storage.Storage
	unreviewed  []*models.BreakGlassActivation
	membersByID map[uint][]storage.ProjectMember
	notified    []uint
	notifiedPID []*uint
}

func (s *reviewReminderNotifySpy) ListUnreviewedBreakGlassActivationsBefore(_ storage.Storage, _ context.Context, _ time.Time) ([]*models.BreakGlassActivation, error) {
	return s.unreviewed, nil
}

func (s *reviewReminderNotifySpy) ListProjectMembers(_ storage.Storage, _ context.Context, projectID uint) ([]storage.ProjectMember, error) {
	return s.membersByID[projectID], nil
}

// The #2955 install-wide-admin lookup: this spy models an install with none, so
// the project-member behaviour under test is unchanged.
func (s *reviewReminderNotifySpy) ListAdminBypassRoleIDs(_ storage.Storage, _ context.Context) ([]uint, error) {
	return nil, nil
}

func (s *reviewReminderNotifySpy) ListGlobalAdminAssignmentsForUpdate(_ storage.Storage, _ context.Context, _ []uint) ([]storage.RoleAssignment, error) {
	return nil, nil
}

// projectAdminRecipients vets every candidate's account (active, login not blocked).
func (s *reviewReminderNotifySpy) GetUser(_ storage.Storage, _ context.Context, id uint) (*models.User, error) {
	return &models.User{ID: id, IsActive: true, AccountState: AccountActive}, nil
}

func (s *reviewReminderNotifySpy) CreateNotification(_ storage.Storage, _ context.Context, n *models.Notification) (*models.Notification, error) {
	s.notified = append(s.notified, n.UserID)
	s.notifiedPID = append(s.notifiedPID, n.ProjectID)
	return n, nil
}

func (s *reviewReminderNotifySpy) LogAuditEvent(_ storage.Storage, _ context.Context, _ *models.AuditEvent) error {
	return nil
}

// wrap returns inner decorated with reviewReminderNotifySpy's overrides.
func (s *reviewReminderNotifySpy) wrap(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		ListUnreviewedBreakGlassActivationsBefore: s.ListUnreviewedBreakGlassActivationsBefore,
		ListProjectMembers:                        s.ListProjectMembers,
		ListAdminBypassRoleIDs:                    s.ListAdminBypassRoleIDs,
		ListGlobalAdminAssignmentsForUpdate:       s.ListGlobalAdminAssignmentsForUpdate,
		GetUser:                                   s.GetUser,
		CreateNotification:                        s.CreateNotification,
		LogAuditEvent:                             s.LogAuditEvent,
	})
}

// store returns s.inner decorated with reviewReminderNotifySpy's overrides.
func (s *reviewReminderNotifySpy) store() storage.Storage { return s.wrap(s.inner) }

// TestRunBreakGlassReviewReminder_NotifiesAdmins is #2461 round 2's proving
// test for Andrei's decision item (b): an overdue review must actively reach
// each affected project's admins, not just a log line and an audit event
// nobody is looking at. Two projects, each with one approver-role member and
// one non-approver member — only the approver in each must be notified, and
// a project with no overdue rows must get no notification at all.
func TestRunBreakGlassReviewReminder_NotifiesAdmins(t *testing.T) {
	fixed := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	spy := &reviewReminderNotifySpy{
		unreviewed: []*models.BreakGlassActivation{
			{ID: 1, ProjectID: 1, UserID: 10, CreatedAt: fixed.Add(-200 * time.Hour)},
			{ID: 2, ProjectID: 2, UserID: 11, CreatedAt: fixed.Add(-100 * time.Hour)},
		},
		membersByID: map[uint][]storage.ProjectMember{
			1: {{UserID: 100, RoleName: "project_admin"}, {UserID: 101, RoleName: "project_developer"}},
			2: {{UserID: 200, RoleName: "admin"}},
			3: {{UserID: 300, RoleName: "project_admin"}}, // no overdue rows -- never notified
		},
	}
	c := &KeyorixCore{storage: spy.store(), now: func() time.Time { return fixed }}
	c.SetBreakGlassPolicy(BreakGlassPolicy{ReviewWindow: 48 * time.Hour})

	n, err := c.RunBreakGlassReviewReminder(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, n)

	assert.ElementsMatch(t, []uint{100, 200}, spy.notified,
		"only the approver-role member of each AFFECTED project is notified; the non-approver and the unaffected project's admin are not")
}
