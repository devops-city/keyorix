// saml_reconcile_refusal_test.go — #2903 review findings 1, 2, 3 and 5, against a
// REAL SQLite store so the state a refused login leaves behind is read back
// from the database rather than inferred from which mock was called.
//
// Class C means a refused reconcile is NOT rolled back: whatever applied before
// the failing step stays applied. These tests pin exactly that persisted state,
// and that the audit trail says so -- the review found the trail either silent
// (a failed removal with nothing else to change wrote no event at all) or
// wrong (a partial change was recorded as a plain successful sync).
package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// reconcileFaultStorage fails chosen reconcile writes/reads on a real store.
// WithTransaction re-wraps the tx handle so a write made through a transaction
// is faulted too (the tx-handle blind spot failSetAccountStateStorage documents).
type reconcileFaultStorage struct {
	inner           storage.Storage
	failRemoveGroup map[uint]bool
	failRemoveRole  map[uint]bool
	failListGroups  bool
	// #2910 fuzzer finding: the escalation guard's own lookups.
	failGetGroupRoles      bool
	failGetRolePermissions bool
	// #2910 fuzzer finding: the best-effort last-login stamp panicking.
	panicUpdateLastLogin bool
}

func (s *reconcileFaultStorage) UpdateLastLogin(next storage.Storage, ctx context.Context, userID uint, at time.Time) error {
	if s.panicUpdateLastLogin {
		panic("injected fault: UpdateLastLogin")
	}
	return next.UpdateLastLogin(ctx, userID, at)
}

func (s *reconcileFaultStorage) GetGroupRoles(next storage.Storage, ctx context.Context, groupID uint) ([]*models.Role, error) {
	if s.failGetGroupRoles {
		return nil, errors.New("injected fault: GetGroupRoles")
	}
	return next.GetGroupRoles(ctx, groupID)
}

func (s *reconcileFaultStorage) GetRolePermissions(next storage.Storage, ctx context.Context, roleID uint) ([]*models.Permission, error) {
	if s.failGetRolePermissions {
		return nil, errors.New("injected fault: GetRolePermissions")
	}
	return next.GetRolePermissions(ctx, roleID)
}

func (s *reconcileFaultStorage) RemoveUserFromGroup(next storage.Storage, ctx context.Context, userID, groupID, projectID uint) error {
	if s.failRemoveGroup[groupID] {
		return fmt.Errorf("injected fault: RemoveUserFromGroup(group %d)", groupID)
	}
	return next.RemoveUserFromGroup(ctx, userID, groupID, projectID)
}

func (s *reconcileFaultStorage) RemoveRole(next storage.Storage, ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	if s.failRemoveRole[roleID] {
		return fmt.Errorf("injected fault: RemoveRole(role %d)", roleID)
	}
	return next.RemoveRole(ctx, userID, roleID, scope)
}

func (s *reconcileFaultStorage) ListGroups(next storage.Storage, ctx context.Context) ([]*models.Group, error) {
	if s.failListGroups {
		return nil, errors.New("injected fault: ListGroups")
	}
	return next.ListGroups(ctx)
}

// wrap returns inner decorated with reconcileFaultStorage's overrides.
func (s *reconcileFaultStorage) wrap(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		UpdateLastLogin:     s.UpdateLastLogin,
		GetGroupRoles:       s.GetGroupRoles,
		GetRolePermissions:  s.GetRolePermissions,
		RemoveUserFromGroup: s.RemoveUserFromGroup,
		RemoveRole:          s.RemoveRole,
		ListGroups:          s.ListGroups,
		WrapTx:              true,
	})
}

// store returns s.inner decorated with reconcileFaultStorage's overrides.
func (s *reconcileFaultStorage) store() storage.Storage { return s.wrap(s.inner) }

type samlReconcileFixture struct {
	t     *testing.T
	c     *KeyorixCore
	db    *gorm.DB
	fault *reconcileFaultStorage
}

// The SSO user every fixture logs in as: JIT-shaped (provider-scoped external
// id, no password), id 7.
const samlReconcileUserID = uint(7)

func newSAMLReconcileFixture(t *testing.T, info *ports.SAMLAssertion, groupRoleMap map[string]string) *samlReconcileFixture {
	t.Helper()
	// A named shared-cache in-memory DB, not ":memory:": every pooled
	// connection to ":memory:" is its own empty database.
	db := sqlitetest.OpenWithConfig(t, "samlreconcilerefusal_", &gorm.Config{})
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	require.NoError(t, db.Create(&models.User{
		ID: samlReconcileUserID, Username: "ada", UsernameFolded: "ada",
		Email: "ada@x.io", EmailFolded: "ada@x.io", ExternalID: "sso:corp:corp|123",
		AccountState: AccountActive, IsActive: true,
	}).Error)
	fault := &reconcileFaultStorage{inner: store.NewLocalStorage(db), failRemoveGroup: map[uint]bool{}, failRemoveRole: map[uint]bool{}}
	p := &SSOProvider{
		Name: "corp", Type: "saml", SAML: &stubSAML{info: info},
		GroupSync: true, GroupRoleMap: groupRoleMap,
	}
	c := &KeyorixCore{storage: fault.store(), now: time.Now, ssoProviders: map[string]*SSOProvider{"corp": p}}
	return &samlReconcileFixture{t: t, c: c, db: db, fault: fault}
}

func (f *samlReconcileFixture) group(id uint, name string) {
	require.NoError(f.t, f.db.Create(&models.Group{ID: id, Name: name, NameFolded: strings.ToLower(name)}).Error)
}

func (f *samlReconcileFixture) role(id uint, name string, bypass bool) {
	require.NoError(f.t, f.db.Create(&models.Role{ID: id, Name: name, NameFolded: strings.ToLower(name), BypassesPermissionChecks: bypass}).Error)
}

func (f *samlReconcileFixture) member(userID, groupID uint) {
	require.NoError(f.t, f.db.Create(&models.UserGroup{UserID: userID, GroupID: groupID}).Error)
}

func (f *samlReconcileFixture) grant(userID, roleID uint) {
	require.NoError(f.t, f.db.Create(&models.UserRole{UserID: userID, RoleID: roleID}).Error)
}

func (f *samlReconcileFixture) groupGrant(groupID, roleID uint) {
	require.NoError(f.t, f.db.Create(&models.GroupRole{GroupID: groupID, RoleID: roleID}).Error)
}

func (f *samlReconcileFixture) login() (*models.Session, error) {
	f.t.Helper()
	require.NoError(f.t, f.db.Create(&models.SSOLoginState{
		State: "relay-1", Nonce: "req-1", Provider: "corp", ReturnTo: "/home",
		ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
	}).Error)
	req := httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", nil)
	session, _, _, err := f.c.CompleteSAML(context.Background(), "corp", req, "relay-1", "ua", "1.2.3.4")
	return session, err
}

func (f *samlReconcileFixture) memberOf(groupID uint) bool {
	var n int64
	require.NoError(f.t, f.db.Model(&models.UserGroup{}).Where("user_id = ? AND group_id = ?", samlReconcileUserID, groupID).Count(&n).Error)
	return n > 0
}

func (f *samlReconcileFixture) holds(roleID uint) bool {
	var n int64
	require.NoError(f.t, f.db.Model(&models.UserRole{}).Where("user_id = ? AND role_id = ?", samlReconcileUserID, roleID).Count(&n).Error)
	return n > 0
}

func (f *samlReconcileFixture) sessions() int64 {
	var n int64
	require.NoError(f.t, f.db.Model(&models.Session{}).Count(&n).Error)
	return n
}

func (f *samlReconcileFixture) events(eventType string) []models.AuditEvent {
	var evs []models.AuditEvent
	require.NoError(f.t, f.db.Where("event_type = ?", eventType).Find(&evs).Error)
	return evs
}

// assertRefusedWithoutSession is what every refusal below shares: an error that
// carries the reconcile sentinel, a client-safe message with no wrapped detail
// in it, no session row and no login event.
func (f *samlReconcileFixture) assertRefusedWithoutSession(session *models.Session, err error, wantMsg string) {
	f.t.Helper()
	require.Error(f.t, err)
	assert.Nil(f.t, session)
	assert.ErrorIs(f.t, err, ErrSSOReconcileIncomplete, "the refusal must carry the reconcile sentinel for errors.Is")
	assert.Equal(f.t, wantMsg, err.Error(),
		"the refusal's Error() must be exactly the client-safe text -- isSafeSSOError is a substring match, "+
			"so any wrapped storage detail appended to it would be reflected to the browser")
	assert.Zero(f.t, f.sessions(), "a refused login must not have created a session")
	assert.Empty(f.t, f.events(EventSSOLogin), "no login event for a refused login")
}

// ── Finding 1 + 3: partial application is persisted AND audited as partial ───

// TestCompleteSAML_PartialGroupReconcile_AddAppliedThenRemovalFails is the
// case the review found missing: the add succeeds, a later removal fails. The
// add is not rolled back (class C), so the user ends up in BOTH groups -- and
// the trail must say the login was refused, what failed, and that +1 was
// already applied.
//
// RED before the fix: the error did not wrap ErrSSOReconcileIncomplete, and the
// only event written was auth.sso_groups_synced "+1/-0", recording the partial
// change as an ordinary successful sync.
func TestCompleteSAML_PartialGroupReconcile_AddAppliedThenRemovalFails(t *testing.T) {
	f := newSAMLReconcileFixture(t, &ports.SAMLAssertion{Subject: "corp|123", Groups: []string{"engineers"}, GroupsPresent: true}, nil)
	f.group(41, "engineers")   // asserted, not held -> add (succeeds)
	f.group(42, "contractors") // held, not asserted -> remove (fails)
	f.member(samlReconcileUserID, 42)
	f.fault.failRemoveGroup[42] = true

	session, err := f.login()

	f.assertRefusedWithoutSession(session, err, SSOMsgGroupReconcileRefused)
	assert.True(t, f.memberOf(41), "the add applied before the failure stays applied (class C, no rollback)")
	assert.True(t, f.memberOf(42), "the failed removal left the revoked membership in place -- which is why the login is refused")

	refused := f.events(EventSSOReconcileRefused)
	require.Len(t, refused, 1, "exactly one refusal event for the group reconcile")
	d := refused[0].Description
	assert.Contains(t, d, `remove group 42 "contractors"`, "the event must name the step that failed")
	assert.Contains(t, d, "+1/-0", "the event must record what had already been applied")
	assert.Empty(t, f.events(EventSSOGroupsSynced), "a refused reconcile must not also be recorded as a successful sync")
}

// TestCompleteSAML_PartialRoleReconcile_TwoOfThreeApplied: three managed roles
// change on one login, two grants succeed and the revocation fails. Map
// iteration order is random, so this holds whichever runs first: every step is
// attempted, the failure is reported, the successes persist.
func TestCompleteSAML_PartialRoleReconcile_TwoOfThreeApplied(t *testing.T) {
	f := newSAMLReconcileFixture(t,
		&ports.SAMLAssertion{Subject: "corp|123", Groups: []string{"g-a", "g-b"}, GroupsPresent: true},
		map[string]string{"g-a": "role_a", "g-b": "role_b", "g-c": "role_c"})
	f.role(51, "role_a", false)
	f.role(52, "role_b", false)
	f.role(53, "role_c", false)
	f.grant(samlReconcileUserID, 53) // held, its group no longer asserted -> revoke (fails)
	f.fault.failRemoveRole[53] = true

	session, err := f.login()

	f.assertRefusedWithoutSession(session, err, SSOMsgRoleReconcileRefused)
	assert.True(t, f.holds(51), "grant 1 of 3 applied and stays applied")
	assert.True(t, f.holds(52), "grant 2 of 3 applied and stays applied")
	assert.True(t, f.holds(53), "the failed revocation left role_c held")

	refused := f.events(EventSSOReconcileRefused)
	require.Len(t, refused, 1)
	d := refused[0].Description
	assert.Contains(t, d, `revoke role "role_c"`)
	assert.Contains(t, d, "+2/-0")
	assert.Empty(t, f.events(EventSSORolesSynced))
}

// TestCompleteSAML_FailedRemovalWithNothingElseToChangeIsAudited is the
// headline scenario with NOTHING else to change: before the fix the event was
// gated on added|removed|blocked > 0, so this wrote no audit event at all and
// the refusal existed only in a log line.
func TestCompleteSAML_FailedRemovalWithNothingElseToChangeIsAudited(t *testing.T) {
	f := newSAMLReconcileFixture(t, &ports.SAMLAssertion{Subject: "corp|123", Groups: []string{"engineers"}, GroupsPresent: true}, nil)
	f.group(41, "engineers")
	f.group(42, "idp-admins")
	f.member(samlReconcileUserID, 41)
	f.member(samlReconcileUserID, 42)
	f.fault.failRemoveGroup[42] = true

	session, err := f.login()

	f.assertRefusedWithoutSession(session, err, SSOMsgGroupReconcileRefused)
	refused := f.events(EventSSOReconcileRefused)
	require.Len(t, refused, 1, "a refusal with nothing applied must still be in the audit trail")
	assert.Contains(t, refused[0].Description, `remove group 42 "idp-admins"`)
	assert.Contains(t, refused[0].Description, "+0/-0")
}

// TestCompleteSAML_ReconcileReadFailureIsAudited: the "desired state unknown"
// refusal names the read that failed.
func TestCompleteSAML_ReconcileReadFailureIsAudited(t *testing.T) {
	f := newSAMLReconcileFixture(t, &ports.SAMLAssertion{Subject: "corp|123", Groups: []string{"engineers"}, GroupsPresent: true}, nil)
	f.fault.failListGroups = true

	session, err := f.login()

	f.assertRefusedWithoutSession(session, err, SSOMsgGroupReconcileRefused)
	refused := f.events(EventSSOReconcileRefused)
	require.Len(t, refused, 1)
	assert.Contains(t, refused[0].Description, "list native groups")
}

// ── Finding 2: an empty groups attribute reconciles to zero ─────────────────

// TestCompleteSAML_EmptyGroupsAttributeReconcilesToZero: the IdP asserts the
// groups attribute with no values -- "this user is in no groups". Every stale
// membership and every managed role must go, and the login proceeds.
//
// RED before the fix: CompleteSAML gated reconcile on len(info.Groups) > 0, so
// it skipped entirely and the session was minted with the stale membership and
// role intact.
func TestCompleteSAML_EmptyGroupsAttributeReconcilesToZero(t *testing.T) {
	f := newSAMLReconcileFixture(t, &ports.SAMLAssertion{Subject: "corp|123", GroupsPresent: true}, map[string]string{"ops": "ops_role"})
	f.group(42, "ops")
	f.member(samlReconcileUserID, 42)
	f.role(51, "ops_role", false)
	f.grant(samlReconcileUserID, 51)

	session, err := f.login()

	require.NoError(t, err)
	require.NotNil(t, session)
	assert.False(t, f.memberOf(42), "an asserted-but-empty groups attribute must remove every stale membership")
	assert.False(t, f.holds(51), "and revoke every managed role")
}

// TestCompleteSAML_AbsentGroupsAttributeLeavesMembershipsAlone is the other
// side of the same distinction, and the decision #2903 documents: an ABSENT
// attribute is "no group information", not "no groups". Many IdPs only send
// groups when a specific attribute release is configured; reading absence as
// emptiness would strip every membership on every login from such an IdP.
// Keyorix has no setting that requires the attribute, so absent = keep.
func TestCompleteSAML_AbsentGroupsAttributeLeavesMembershipsAlone(t *testing.T) {
	f := newSAMLReconcileFixture(t, &ports.SAMLAssertion{Subject: "corp|123"}, map[string]string{"ops": "ops_role"})
	f.group(42, "ops")
	f.member(samlReconcileUserID, 42)
	f.role(51, "ops_role", false)
	f.grant(samlReconcileUserID, 51)

	session, err := f.login()

	require.NoError(t, err)
	require.NotNil(t, session)
	assert.True(t, f.memberOf(42))
	assert.True(t, f.holds(51))
}

// ── Finding 5: the last-admin refusal keeps refusing, distinctly audited ────

// TestCompleteSAML_LastAdminGroupRemovalRefused: the IdP drops the install's
// only administrator from the group that confers admin. The last-admin guard
// refuses the removal, and the login stays refused (Andrei, 2026-10-10: the
// IdP's revocation wins). What #2903 adds is that this is diagnosable: a
// distinct audit event telling the operator the two ways back, and a message
// at the browser that says what happened.
//
// RED before the fix: a generic message, no sentinel, and no event at all.
func TestCompleteSAML_LastAdminGroupRemovalRefused(t *testing.T) {
	f := newSAMLReconcileFixture(t, &ports.SAMLAssertion{Subject: "corp|123", Groups: []string{"engineers"}, GroupsPresent: true}, nil)
	f.group(41, "engineers")
	f.group(42, "idp-admins")
	f.role(60, "admin", true)
	f.groupGrant(42, 60)
	f.member(samlReconcileUserID, 41)
	f.member(samlReconcileUserID, 42)

	session, err := f.login()

	f.assertRefusedWithoutSession(session, err, SSOMsgLastAdminRemovalRefused)
	assert.ErrorIs(t, err, storage.ErrWouldStrandLastAdmin)
	assert.True(t, f.memberOf(42), "the guard refused the removal; the install keeps its administrator")

	ev := f.events(EventSSOReconcileLastAdminRefused)
	require.Len(t, ev, 1, "the last-admin refusal gets its own event type, so it can be alerted on")
	assert.Contains(t, ev[0].Description, `remove group 42 "idp-admins"`)
	assert.Contains(t, ev[0].Description, "recover-admin", "the event must name the out-of-band way back")
	assert.Empty(t, f.events(EventSSOReconcileRefused), "one event per refusal, of the more specific type")
}

// TestCompleteSAML_LastAdminRoleRevocationRefused is the role-path counterpart:
// the admin role itself is a managed GroupRoleMap role and the IdP stopped
// asserting the group that maps to it.
func TestCompleteSAML_LastAdminRoleRevocationRefused(t *testing.T) {
	f := newSAMLReconcileFixture(t, &ports.SAMLAssertion{Subject: "corp|123", Groups: []string{"engineers"}, GroupsPresent: true},
		map[string]string{"idp-admins": "admin"})
	f.role(60, "admin", true)
	f.grant(samlReconcileUserID, 60)

	session, err := f.login()

	f.assertRefusedWithoutSession(session, err, SSOMsgLastAdminRemovalRefused)
	assert.ErrorIs(t, err, storage.ErrWouldStrandLastAdmin)
	assert.True(t, f.holds(60))
	ev := f.events(EventSSOReconcileLastAdminRefused)
	require.Len(t, ev, 1)
	assert.Contains(t, ev[0].Description, `revoke role "admin"`)
}

// TestCompleteSAML_AdminGroupRemovalWithASecondAdminSucceeds is the
// calibration for the two above: with another administrator present the guard
// has nothing to protect, the removal applies and the login proceeds -- so the
// refusal above is the guard, not reconcile refusing every admin removal.
func TestCompleteSAML_AdminGroupRemovalWithASecondAdminSucceeds(t *testing.T) {
	f := newSAMLReconcileFixture(t, &ports.SAMLAssertion{Subject: "corp|123", Groups: []string{"engineers"}, GroupsPresent: true}, nil)
	f.group(41, "engineers")
	f.group(42, "idp-admins")
	f.role(60, "admin", true)
	f.groupGrant(42, 60)
	f.member(samlReconcileUserID, 41)
	f.member(samlReconcileUserID, 42)
	require.NoError(t, f.db.Create(&models.User{
		ID: 8, Username: "root", UsernameFolded: "root", Email: "root@x.io", EmailFolded: "root@x.io",
		AccountState: AccountActive, IsActive: true,
	}).Error)
	require.NoError(t, f.db.Create(&models.UserRole{UserID: 8, RoleID: 60}).Error)

	session, err := f.login()

	require.NoError(t, err)
	require.NotNil(t, session)
	assert.False(t, f.memberOf(42))
	assert.Len(t, f.events(EventSSOGroupsSynced), 1)
	assert.Empty(t, f.events(EventSSOReconcileLastAdminRefused))
	assert.Empty(t, f.events(EventSSOReconcileRefused))
}
