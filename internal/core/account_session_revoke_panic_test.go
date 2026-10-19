package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Z2: deleteSessionsForUserAndEvict (account.go) has 8 call sites, all
// post-commit, all discarding the returned error (`_ = c.deleteSessionsForUserAndEvict(...)`)
// because the primary operation (password change, MFA activate/disable, SCIM
// deprovision, setup-token consume, WebAuthn registration) has already
// committed. A panic here used to escape uncaught, turning an already-succeeded
// primary operation into a 500 — same shape as X1/#2325's DeleteProject cascade
// and the pre-existing evictUserSessionCache recover. These reproduce a panic
// at each of the two points this function can panic (listing session hashes /
// deleting them, and the cache-eviction loop), confirm the recover added to
// deleteSessionsForUserAndEvict turns both green, and confirm the normal path
// is unaffected.

// sessionRevokePanicSpy backs both panic sites via storage calls, plus lets the
// cache-eviction loop panic via a wired invalidator. Embeds storage.Storage as
// nil like cascadePanicSpy in catalog_delete_project_cascade_panic_test.go — any
// unstubbed method panics on a nil pointer dereference if reached, so an
// unexpected call fails loudly rather than silently returning a zero value.
type sessionRevokePanicSpy struct {
	inner             storage.Storage
	panicOnListHashes bool
	panicOnDelete     bool
	hashes            []string
	auditEvents       []*models.AuditEvent
}

func (s *sessionRevokePanicSpy) ListSessionTokenHashesForUser(_ storage.Storage, _ context.Context, _ uint) ([]string, error) {
	if s.panicOnListHashes {
		panic("simulated ListSessionTokenHashesForUser panic")
	}
	return s.hashes, nil
}

func (s *sessionRevokePanicSpy) DeleteSessionsForUserExcept(_ storage.Storage, _ context.Context, _, _ uint) error {
	if s.panicOnDelete {
		panic("simulated DeleteSessionsForUserExcept panic")
	}
	return nil
}

func (s *sessionRevokePanicSpy) LogAuditEvent(_ storage.Storage, _ context.Context, event *models.AuditEvent) error {
	s.auditEvents = append(s.auditEvents, event)
	return nil
}

// wrap returns inner decorated with sessionRevokePanicSpy's overrides.
func (s *sessionRevokePanicSpy) wrap(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		ListSessionTokenHashesForUser: s.ListSessionTokenHashesForUser,
		DeleteSessionsForUserExcept:   s.DeleteSessionsForUserExcept,
		LogAuditEvent:                 s.LogAuditEvent,
	})
}

// store returns s.inner decorated with sessionRevokePanicSpy's overrides.
func (s *sessionRevokePanicSpy) store() storage.Storage { return s.wrap(s.inner) }

func TestDeleteSessionsForUserAndEvict_PanicListingOrDeletingSessions_StillReturnsNilAndAudits(t *testing.T) {
	t.Parallel()
	spy := &sessionRevokePanicSpy{panicOnDelete: true}
	c := &KeyorixCore{storage: spy.store()}

	err := c.deleteSessionsForUserAndEvict(context.Background(), 7, 0, "")
	require.NoError(t, err, "the primary operation already committed — a panic in this best-effort session cleanup must not surface as an error")

	require.Len(t, spy.auditEvents, 1)
	assert.Equal(t, EventSessionRevocationPanicked, spy.auditEvents[0].EventType)
	assert.Contains(t, spy.auditEvents[0].Description, "simulated DeleteSessionsForUserExcept panic",
		"the audit event must include the panic value, not just a generic message")
	require.NotNil(t, spy.auditEvents[0].UserID, "the audit event must name the affected user")
	assert.Equal(t, uint(7), *spy.auditEvents[0].UserID)
}

func TestDeleteSessionsForUserAndEvict_PanicInCacheEvictLoop_StillReturnsNilAndAudits(t *testing.T) {
	t.Parallel()
	spy := &sessionRevokePanicSpy{hashes: []string{"h1"}}
	c := &KeyorixCore{storage: spy.store()}
	c.SetTokenCacheInvalidator(func(string) { panic("simulated cache-evict panic") })

	err := c.deleteSessionsForUserAndEvict(context.Background(), 9, 0, "")
	require.NoError(t, err, "the session deletion already committed — a panic evicting the auth cache must not surface as an error")

	require.Len(t, spy.auditEvents, 1)
	assert.Equal(t, EventSessionRevocationPanicked, spy.auditEvents[0].EventType)
	assert.Contains(t, spy.auditEvents[0].Description, "simulated cache-evict panic")
	require.NotNil(t, spy.auditEvents[0].UserID)
	assert.Equal(t, uint(9), *spy.auditEvents[0].UserID)
}

func TestDeleteSessionsForUserAndEvict_NoPanic_NormalPathUnchanged(t *testing.T) {
	t.Parallel()
	spy := &sessionRevokePanicSpy{hashes: []string{"h1", "h2", "keep-me"}}
	c := &KeyorixCore{storage: spy.store()}
	var evicted []string
	c.SetTokenCacheInvalidator(func(h string) { evicted = append(evicted, h) })

	err := c.deleteSessionsForUserAndEvict(context.Background(), 11, 0, "keep-me")
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"h1", "h2"}, evicted, "every hash except keepHash is evicted")
	for _, e := range spy.auditEvents {
		assert.NotEqual(t, EventSessionRevocationPanicked, e.EventType, "a normal run must not write a panic audit event")
	}
}
