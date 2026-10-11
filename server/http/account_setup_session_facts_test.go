// account_setup_session_facts_test.go — #3041 review, finding 1: after the
// token validated, the auth middleware re-read the session for its per-session
// facts (setup-only flag, impersonator, row id, expiry). When that read failed
// it served the request anyway with SetupOnly=false (and no impersonator, no
// expiry clamp) and cached that identity. A setup-only session whose
// revocation did not land then had full API access the moment the store
// faltered, and kept it from the cache after the store recovered.
package http

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// sessionReadFaultStorage is the real storage with two switchable faults:
// failRevoke makes the session purge fail (the revocation that ends a
// setup-only session does not land), and failReadsAfterFirst lets the first
// GetSession of a request through (token validation) and fails every later one
// (the store goes away right after validation).
type sessionReadFaultStorage struct {
	storage.Storage
	mu                  sync.Mutex
	failRevoke          bool
	failReadsAfterFirst bool
	reads               int
}

var errInjectedSessionRead = errors.New("injected: session read failed")

func (f *sessionReadFaultStorage) GetSession(ctx context.Context, token string) (*models.Session, error) {
	f.mu.Lock()
	f.reads++
	fail := f.failReadsAfterFirst && f.reads > 1
	f.mu.Unlock()
	if fail {
		return nil, errInjectedSessionRead
	}
	return f.Storage.GetSession(ctx, token)
}

func (f *sessionReadFaultStorage) DeleteSessionsForUserExcept(ctx context.Context, userID, exceptID uint) error {
	f.mu.Lock()
	fail := f.failRevoke
	f.mu.Unlock()
	if fail {
		return errors.New("injected: session purge failed")
	}
	return f.Storage.DeleteSessionsForUserExcept(ctx, userID, exceptID)
}

func (f *sessionReadFaultStorage) set(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
	f.reads = 0
}

// TestAccountSetup_SessionFactsReadFailure_FailsClosed: a recovered admin
// finishes both setup steps, the revocation of the setup-only session fails,
// and the next request's post-validation session read fails too. The request
// must be refused (503, the server's generic retry answer), nothing cached,
// and the refusal audited; once the store recovers the session is sent to
// re-authenticate, never served.
func TestAccountSetup_SessionFactsReadFailure_FailsClosed(t *testing.T) {
	f := &sessionReadFaultStorage{}
	e := newSetupGateEnvWrapped(t, func(real storage.Storage) storage.Storage {
		f.Storage = real
		return f
	})
	username, otp := e.recoverAdminState()
	token, _ := e.passwordLogin(username, otp)
	require.NotEmpty(t, token)

	// Both setup steps, the last one with the session purge failing.
	e.enrolTOTP(token, otp)
	f.set(func() { f.failRevoke = true })
	r := e.do(http.MethodPost, "/api/v1/auth/change-password", token,
		map[string]string{"current_password": otp, "new_password": setupGateNewPassword})
	require.Equal(t, http.StatusOK, r.status, r.raw)
	f.set(func() { f.failRevoke = false })

	ctx := context.Background()
	sess, err := e.core.Storage().GetSession(ctx, token)
	require.NoError(t, err, "precondition: the setup-only session survived its failed revocation")
	require.True(t, sess.SetupOnly)
	customMiddleware.ClearTokenCacheForToken(token)

	f.set(func() { f.failReadsAfterFirst = true })
	r = e.do(http.MethodGet, "/api/v1/notifications", token, nil)
	f.set(func() { f.failReadsAfterFirst = false })
	assert.Equal(t, http.StatusServiceUnavailable, r.status,
		"a session whose facts cannot be read must be refused, not served as an ordinary session: %s", r.raw)
	assert.Equal(t, "ServiceUnavailable", r.body["error"], r.raw)

	// Nothing was cached from the failed read: the recovered store's answer is
	// the backstop's 401, not the access a defaulted SetupOnly=false would give.
	r = e.do(http.MethodGet, "/api/v1/notifications", token, nil)
	assert.Equal(t, http.StatusUnauthorized, r.status, r.raw)
	assert.Equal(t, "ReauthenticationRequired", r.body["error"], r.raw)

	action := core.EventSessionFactsUnavailable
	events, _, err := e.core.Storage().GetAuditLogs(ctx, &storage.AuditFilter{Action: &action})
	require.NoError(t, err)
	require.Len(t, events, 1, "the refusal must be audited")
	require.NotNil(t, events[0].UserID)
	assert.Equal(t, sess.UserID, *events[0].UserID)
	assert.Contains(t, events[0].Description, "http request")

	// The failed revocation itself is on record and does not claim success.
	completed := core.EventAccountSetupCompleted
	events, _, err = e.core.Storage().GetAuditLogs(ctx, &storage.AuditFilter{Action: &completed})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Contains(t, events[0].Description, "could not be revoked")
	assert.NotContains(t, events[0].Description, "every session was revoked")
}
