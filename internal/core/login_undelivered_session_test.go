package core

// #2844: a login either delivers the session it wrote or leaves no usable
// session behind. Each test drives the real core over real SQLite and reads the
// session table back, because the defect is a row that outlives a failure the
// caller was told about: no return value distinguishes it.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const undeliveredTestPassword = "BootstrapPass123!"

var errInjectedAfterCommit = errors.New("injected: the write committed but reported an error")

// createSessionThenFail commits the session, then reports failure the way a
// lost acknowledgement does (err) or panics after the commit (panicAfter).
type createSessionThenFail struct {
	storage.Storage
	panicAfter bool
}

func (s *createSessionThenFail) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	if _, err := s.Storage.CreateSession(ctx, session); err != nil {
		return nil, err
	}
	if s.panicAfter {
		panic("injected: panic after CreateSession committed")
	}
	return nil, errInjectedAfterCommit
}

// createSessionFailsBeforeWrite never writes: the honest failure.
type createSessionFailsBeforeWrite struct{ storage.Storage }

func (s *createSessionFailsBeforeWrite) CreateSession(context.Context, *models.Session) (*models.Session, error) {
	return nil, errors.New("injected: insert refused")
}

// createSessionThenFailUnverifiable commits, reports an error, and then cannot
// answer the read-back either.
type createSessionThenFailUnverifiable struct{ createSessionThenFail }

func (s *createSessionThenFailUnverifiable) GetSession(context.Context, string) (*models.Session, error) {
	return nil, errors.New("injected: session lookup unavailable")
}

// panicOnGetUserRoles panics in the response-identity read.
type panicOnGetUserRoles struct{ storage.Storage }

func (s *panicOnGetUserRoles) GetUserRoles(context.Context, uint) ([]*models.Role, error) {
	panic("injected: GetUserRoles")
}

// rotateSessionThenFail commits the rotation, then reports an error.
type rotateSessionThenFail struct{ storage.Storage }

func (s *rotateSessionThenFail) RotateSession(ctx context.Context, oldID uint, newSession *models.Session, now time.Time) (*models.Session, bool, error) {
	if _, _, err := s.Storage.RotateSession(ctx, oldID, newSession, now); err != nil {
		return nil, false, err
	}
	return nil, false, errInjectedAfterCommit
}

func adminSessions(t *testing.T, st *store.LocalStorage) []*models.Session {
	t.Helper()
	u, err := st.GetUserByUsername(context.Background(), "admin")
	require.NoError(t, err)
	rows, err := st.ListSessionsByUser(context.Background(), u.ID)
	require.NoError(t, err)
	return rows
}

func auditEventCount(t *testing.T, st *store.LocalStorage, eventType string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, st.DB().Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
	return n
}

func TestLogin_SessionWriteCommittedDespiteError_DeliversThatSession(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	before := len(adminSessions(t, st))
	c.storage = &createSessionThenFail{Storage: st}

	session, _, err := c.Login(context.Background(), &LoginRequest{Username: "admin", Password: undeliveredTestPassword})
	require.NoError(t, err, "the session row committed; reporting the login as failed leaves a live session the client never receives")
	require.NotNil(t, session)

	rows := adminSessions(t, st)
	require.Len(t, rows, before+1, "exactly the one session this login wrote")
	live, err := st.GetSession(context.Background(), session.SessionToken)
	require.NoError(t, err, "the delivered token must be the committed row's token")
	assert.Equal(t, live.ID, session.ID)
}

func TestLogin_SessionWriteFailedForReal_StillFailsAndWritesNothing(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	before := len(adminSessions(t, st))
	c.storage = &createSessionFailsBeforeWrite{Storage: st}

	session, _, err := c.Login(context.Background(), &LoginRequest{Username: "admin", Password: undeliveredTestPassword})
	require.Error(t, err, "calibration: an insert that never landed is still a failed login")
	assert.Nil(t, session)
	assert.Len(t, adminSessions(t, st), before)
}

func TestLogin_SessionWriteUnverifiable_FailsClosedAndAudits(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	c.storage = &createSessionThenFailUnverifiable{createSessionThenFail{Storage: st}}

	session, _, err := c.Login(context.Background(), &LoginRequest{Username: "admin", Password: undeliveredTestPassword})
	require.Error(t, err, "when it cannot be confirmed that the row landed, the login must not be reported as successful")
	assert.Nil(t, session)
	assert.EqualValues(t, 1, auditEventCount(t, st, EventUndeliveredSessionUnresolved),
		"a possibly-live undelivered session must be audited, not silent")
}

// #3277: on a login the panic no longer propagates. createSession still
// deletes the committed row first; mintLoginSession then returns the panic as
// a post-verdict error, so the login is denied like the insert's error (and a
// panic is still never turned into a success).
func TestLogin_SessionWritePanicsAfterCommit_RevokesTheRowAndDenies(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	before := len(adminSessions(t, st))
	c.storage = &createSessionThenFail{Storage: st, panicAfter: true}

	var session *models.Session
	var err error
	require.NotPanics(t, func() {
		session, _, err = c.Login(context.Background(), &LoginRequest{Username: "admin", Password: undeliveredTestPassword})
	})
	require.ErrorIs(t, err, ErrLoginPostVerdict)
	require.ErrorIs(t, err, ErrLoginWritePanicked)
	assert.Nil(t, session, "no token may be returned for a row that was deleted")

	assert.Len(t, adminSessions(t, st), before, "the committed row must be deleted before the login is denied")
	assert.EqualValues(t, 1, auditEventCount(t, st, EventUndeliveredSessionRevoked))
}

func TestLoginWithIdentity_IdentityReadPanic_LeavesNoSession(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	before := len(adminSessions(t, st))
	c.storage = &panicOnGetUserRoles{Storage: st}

	// #3267: the panic no longer propagates. resolveLoginIdentityBeforeMint
	// returns it as its post-verdict error, so the login is denied exactly as
	// for the read's error kind (login_identity_read_panic_test.go).
	var err error
	require.NotPanics(t, func() {
		_, _, _, err = c.LoginWithIdentity(context.Background(), &LoginRequest{Username: "admin", Password: undeliveredTestPassword})
	})
	require.ErrorIs(t, err, ErrLoginPostVerdict)
	require.ErrorIs(t, err, ErrLoginIdentityUnavailable)

	assert.Len(t, adminSessions(t, st), before,
		"the identity read runs before the session is written, so a panic in it can leave nothing behind")
}

func TestLoginWithIdentity_ReturnsTheIdentityOfASuccessfulLogin(t *testing.T) {
	t.Parallel()
	c, _ := newBootstrappedCore(t)
	session, user, identity, err := c.LoginWithIdentity(context.Background(), &LoginRequest{Username: "admin", Password: undeliveredTestPassword})
	require.NoError(t, err)
	require.NotNil(t, session)
	want, err := c.GetUserIdentity(context.Background(), user.ID)
	require.NoError(t, err)
	assert.Equal(t, want, identity)
	assert.NotEmpty(t, identity.Roles, "calibration: the bootstrap admin has roles, so an empty identity would be a wrong answer")
}

func TestRefreshSession_RotationCommittedDespiteError_DeliversTheNewSession(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	old, _, err := c.Login(ctx, &LoginRequest{Username: "admin", Password: undeliveredTestPassword})
	require.NoError(t, err)
	c.storage = &rotateSessionThenFail{Storage: st}

	fresh, err := c.RefreshSession(ctx, old.SessionToken)
	require.NoError(t, err, "the rotation committed: failing it leaves the client a retired token and an undelivered live one")
	require.NotNil(t, fresh)
	live, err := st.GetSession(ctx, fresh.SessionToken)
	require.NoError(t, err)
	assert.Equal(t, live.ID, fresh.ID)
	_, err = st.GetSession(ctx, old.SessionToken)
	assert.True(t, storage.IsSessionNotFound(err), "the old token was retired by the committed rotation")
}
