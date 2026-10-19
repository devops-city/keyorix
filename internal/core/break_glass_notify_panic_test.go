package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Z3: notifyBreakGlassAdmins (break_glass.go) is called strictly after the
// break-glass grant is already committed and audited (ActivateBreakGlass,
// same file), and its caller only ever logs a plain returned error —
// same shape as Z2's deleteSessionsForUserAndEvict. An unrecovered panic
// here used to escape uncaught, turning an already-succeeded emergency
// grant into a failed activation response. These reproduce a panic at each
// of the two points this function can panic (listing project members, and
// the notify fan-out loop's CreateNotification call), confirm the recover
// added to notifyBreakGlassAdmins turns both green, and confirm the normal
// path is unaffected.

// breakGlassNotifyPanicSpy backs both panic sites. Embeds storage.Storage as
// nil like cascadePanicSpy in catalog_delete_project_cascade_panic_test.go —
// any unstubbed method panics on a nil pointer dereference if reached, so an
// unexpected call fails loudly rather than silently returning a zero value.
type breakGlassNotifyPanicSpy struct {
	inner               storage.Storage
	panicOnListMembers  bool
	panicOnNotification bool
	members             []storage.ProjectMember
	auditEvents         []*models.AuditEvent
	notified            []uint
}

func (s *breakGlassNotifyPanicSpy) ListProjectMembers(_ storage.Storage, _ context.Context, _ uint) ([]storage.ProjectMember, error) {
	if s.panicOnListMembers {
		panic("simulated ListProjectMembers panic")
	}
	return s.members, nil
}

// The #2955 install-wide-admin lookup: this spy models an install with none, so
// the project-member behaviour under test is unchanged.
func (s *breakGlassNotifyPanicSpy) ListAdminBypassRoleIDs(_ storage.Storage, _ context.Context) ([]uint, error) {
	return nil, nil
}

func (s *breakGlassNotifyPanicSpy) ListGlobalAdminAssignmentsForUpdate(_ storage.Storage, _ context.Context, _ []uint) ([]storage.RoleAssignment, error) {
	return nil, nil
}

// projectAdminRecipients vets every candidate's account (active, login not blocked).
func (s *breakGlassNotifyPanicSpy) GetUser(_ storage.Storage, _ context.Context, id uint) (*models.User, error) {
	return &models.User{ID: id, IsActive: true, AccountState: AccountActive}, nil
}

func (s *breakGlassNotifyPanicSpy) CreateNotification(_ storage.Storage, _ context.Context, n *models.Notification) (*models.Notification, error) {
	if s.panicOnNotification {
		panic("simulated CreateNotification panic")
	}
	s.notified = append(s.notified, n.UserID)
	return n, nil
}

func (s *breakGlassNotifyPanicSpy) LogAuditEvent(_ storage.Storage, _ context.Context, event *models.AuditEvent) error {
	s.auditEvents = append(s.auditEvents, event)
	return nil
}

// wrap returns inner decorated with breakGlassNotifyPanicSpy's overrides.
func (s *breakGlassNotifyPanicSpy) wrap(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		ListProjectMembers:                  s.ListProjectMembers,
		ListAdminBypassRoleIDs:              s.ListAdminBypassRoleIDs,
		ListGlobalAdminAssignmentsForUpdate: s.ListGlobalAdminAssignmentsForUpdate,
		GetUser:                             s.GetUser,
		CreateNotification:                  s.CreateNotification,
		LogAuditEvent:                       s.LogAuditEvent,
	})
}

// store returns s.inner decorated with breakGlassNotifyPanicSpy's overrides.
func (s *breakGlassNotifyPanicSpy) store() storage.Storage { return s.wrap(s.inner) }

func TestNotifyBreakGlassAdmins_PanicListingMembers_StillReturnsNilAndAudits(t *testing.T) {
	t.Parallel()
	spy := &breakGlassNotifyPanicSpy{panicOnListMembers: true}
	c := &KeyorixCore{storage: spy.store(), now: time.Now}

	err := c.notifyBreakGlassAdmins(context.Background(), 3, 7, "project_developer", time.Now().Add(time.Hour), false)
	require.NoError(t, err, "the break-glass grant already committed and was audited — a panic notifying admins must not surface as an error")

	require.Len(t, spy.auditEvents, 1)
	assert.Equal(t, EventBreakGlassNotifyPanicked, spy.auditEvents[0].EventType)
	assert.Contains(t, spy.auditEvents[0].Description, "simulated ListProjectMembers panic",
		"the audit event must include the panic value, not just a generic message")
	assert.Contains(t, spy.auditEvents[0].Description, "break-glass admin notification failed")
}

func TestNotifyBreakGlassAdmins_PanicInNotifyFanOut_StillReturnsNilAndAudits(t *testing.T) {
	t.Parallel()
	spy := &breakGlassNotifyPanicSpy{
		panicOnNotification: true,
		members:             []storage.ProjectMember{{UserID: 42, RoleName: "project_admin"}},
	}
	c := &KeyorixCore{storage: spy.store(), now: time.Now}

	err := c.notifyBreakGlassAdmins(context.Background(), 3, 7, "project_developer", time.Now().Add(time.Hour), false)
	require.NoError(t, err, "the break-glass grant already committed — a panic mid-fan-out must not surface as an error")

	require.Len(t, spy.auditEvents, 1)
	assert.Equal(t, EventBreakGlassNotifyPanicked, spy.auditEvents[0].EventType)
	assert.Contains(t, spy.auditEvents[0].Description, "simulated CreateNotification panic")
}

func TestNotifyBreakGlassAdmins_NoPanic_NormalPathUnchanged(t *testing.T) {
	t.Parallel()
	spy := &breakGlassNotifyPanicSpy{
		members: []storage.ProjectMember{
			{UserID: 42, RoleName: "project_admin"},
			{UserID: 43, RoleName: "project_developer"}, // not an approver role — must not be notified
		},
	}
	c := &KeyorixCore{storage: spy.store(), now: time.Now}

	err := c.notifyBreakGlassAdmins(context.Background(), 3, 7, "project_developer", time.Now().Add(time.Hour), false)
	require.NoError(t, err)

	assert.Equal(t, []uint{42}, spy.notified, "only the approver-role member is notified")
	for _, e := range spy.auditEvents {
		assert.NotEqual(t, EventBreakGlassNotifyPanicked, e.EventType, "a normal run must not write a panic audit event")
	}
}
