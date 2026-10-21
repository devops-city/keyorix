package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newMachineCore(store *MockStorage) *KeyorixCore {
	fixed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	return &KeyorixCore{storage: store, now: func() time.Time { return fixed }}
}

func TestCanTransitionMachine(t *testing.T) {
	valid := [][2]string{
		{MachinePending, MachineActive},
		{MachineActive, MachineSuspended},
		{MachineSuspended, MachineActive},
		{MachineActive, MachineRevoked},
		{MachineSuspended, MachineRevoked},
		{MachinePending, MachineRevoked},
	}
	for _, tc := range valid {
		assert.True(t, canTransitionMachine(tc[0], tc[1]), "%s→%s allowed", tc[0], tc[1])
	}
	invalid := [][2]string{
		{MachinePending, MachineSuspended},
		{MachineRevoked, MachineActive}, // terminal
		{MachineActive, MachinePending},
	}
	for _, tc := range invalid {
		assert.False(t, canTransitionMachine(tc[0], tc[1]), "%s→%s rejected", tc[0], tc[1])
	}
}

func TestCreateMachineIdentity(t *testing.T) {
	t.Run("creates an active identity and audits", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("CreateMachineIdentity", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.State == MachineActive && m.IdentityType == MachineTypeCI && m.ProjectID == 1
		})).Return(&models.MachineIdentity{ID: 10, ProjectID: 1, Name: "ci-runner", IdentityType: MachineTypeCI, State: MachineActive}, nil)
		store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
			return e.EventType == "machine_identity.created"
		})).Return(nil)

		m, err := c.CreateMachineIdentity(ctx, 1, "ci-runner", MachineTypeCI, "GitHub Actions", "", 9, 0)
		require.NoError(t, err)
		assert.Equal(t, MachineActive, m.State)
		store.AssertExpectations(t)
	})

	// #1573: a machine identity holding project-scoped roles.assign can create
	// another machine identity (a machine-provisioning-machine chain). createdBy
	// (0, ADR-030) alone loses which machine did it; createdByMachineID must
	// carry it through to the persisted row.
	t.Run("records the acting machine identity when created by a machine", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("CreateMachineIdentity", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.CreatedBy == 0 && m.CreatedByMachineIdentityID == 42
		})).Return(&models.MachineIdentity{ID: 11, ProjectID: 1, Name: "provisioner-created", State: MachineActive}, nil)
		store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)

		_, err := c.CreateMachineIdentity(ctx, 1, "provisioner-created", MachineTypeCI, "", "", 0, 42)
		require.NoError(t, err)
		store.AssertExpectations(t)
	})

	t.Run("rejects an unknown identity type", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		_, err := c.CreateMachineIdentity(context.Background(), 1, "x", "robot", "", "", 9, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid identity_type")
		store.AssertNotCalled(t, "CreateMachineIdentity", mock.Anything, mock.Anything)
	})

	t.Run("defaults a blank type to other", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("CreateMachineIdentity", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.IdentityType == MachineTypeOther
		})).Return(&models.MachineIdentity{ID: 11, IdentityType: MachineTypeOther, State: MachineActive}, nil)
		store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)

		_, err := c.CreateMachineIdentity(ctx, 1, "x", "", "", "", 9, 0)
		require.NoError(t, err)
	})
}

func TestTransitionMachineIdentity(t *testing.T) {
	t.Run("suspends an active identity", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("LockMachineIdentityForUpdate", ctx, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1, State: MachineActive}, nil)
		store.On("TransitionMachineIdentityState", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.State == MachineSuspended
		}), MachineActive).Return(true, nil)
		store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
		// AUDIT-TX-3: suspend/revoke owe their audit row (recorded in the transaction, claimed on append).
		store.On("CreatePendingAuditEvent", ctx, mock.Anything).Return(nil)
		// Cache eviction: suspend calls MachineTokenHashes which calls ListMachineIdentityCredentials.
		store.On("ListMachineIdentityCredentials", ctx, uint(10)).Return([]*models.MachineIdentityCredential{}, nil)

		m, err := c.TransitionMachineIdentity(ctx, 1, 10, MachineSuspended, 9)
		require.NoError(t, err)
		assert.Equal(t, MachineSuspended, m.State)
	})

	t.Run("revoke stamps revoked_at", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("LockMachineIdentityForUpdate", ctx, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1, State: MachineActive}, nil)
		store.On("TransitionMachineIdentityState", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.State == MachineRevoked && m.RevokedAt != nil
		}), MachineActive).Return(true, nil)
		store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
		// AUDIT-TX-3: suspend/revoke owe their audit row (recorded in the transaction, claimed on append).
		store.On("CreatePendingAuditEvent", ctx, mock.Anything).Return(nil)
		// Cache eviction: revoke calls MachineTokenHashes which calls ListMachineIdentityCredentials.
		store.On("ListMachineIdentityCredentials", ctx, uint(10)).Return([]*models.MachineIdentityCredential{}, nil)

		_, err := c.TransitionMachineIdentity(ctx, 1, 10, MachineRevoked, 9)
		require.NoError(t, err)
	})

	t.Run("rejects an illegal transition", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("LockMachineIdentityForUpdate", ctx, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1, State: MachineRevoked}, nil)

		_, err := c.TransitionMachineIdentity(ctx, 1, 10, MachineActive, 9)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot transition")
		store.AssertNotCalled(t, "TransitionMachineIdentityState", mock.Anything, mock.Anything, mock.Anything)
	})

	// Cross-project guard: a machine in project 2 must not be reachable when the
	// caller is authorized for project 1.
	t.Run("rejects a machine in another project", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("LockMachineIdentityForUpdate", ctx, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 2, State: MachineActive}, nil)

		_, err := c.TransitionMachineIdentity(ctx, 1, 10, MachineSuspended, 9)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		store.AssertNotCalled(t, "TransitionMachineIdentityState", mock.Anything, mock.Anything, mock.Anything)
	})

	// #388: a concurrent revoke and reactivate racing off the same pre-transition
	// state must not silently un-revoke — the second transition observes the
	// FIRST one's already-committed state under the row lock and is rejected as an
	// illegal transition (revoked is terminal), not applied blindly.
	t.Run("second racing transition sees the first's committed state, not the stale one", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		// Both callers "observed" active/suspended before racing; by the time the second
		// transition's LockMachineIdentityForUpdate call runs, the first has already
		// committed revoked — WithTransaction in tests calls fn directly, so this models
		// the real DB row-lock serializing to reflect the just-committed state.
		store.On("LockMachineIdentityForUpdate", ctx, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1, State: MachineRevoked}, nil)

		_, err := c.TransitionMachineIdentity(ctx, 1, 10, MachineActive, 9)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot transition")
		store.AssertNotCalled(t, "TransitionMachineIdentityState", mock.Anything, mock.Anything, mock.Anything)
	})

	// #518: even after the row-lock read reports a legal from-state, a
	// concurrent writer (only possible under storage.type: remote, where
	// WithTransaction is a no-op and the "lock" is a plain read — see
	// TransitionMachineIdentityState's interface doc) can still win the actual
	// write race. TransitionMachineIdentityState reporting matched=false must be
	// treated exactly like an illegal transition, not silently accepted.
	t.Run("lost race on the conditional write is reported like an illegal transition", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		ctx := context.Background()
		store.On("LockMachineIdentityForUpdate", ctx, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1, State: MachineActive}, nil)
		store.On("TransitionMachineIdentityState", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.State == MachineSuspended
		}), MachineActive).Return(false, nil)

		_, err := c.TransitionMachineIdentity(ctx, 1, 10, MachineSuspended, 9)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot transition")
		store.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
	})

	t.Run("suspend evicts auth cache", func(t *testing.T) {
		ms := new(MockStorage)
		c := newMachineCore(ms)
		ctx := context.Background()
		ms.On("LockMachineIdentityForUpdate", ctx, uint(20)).Return(&models.MachineIdentity{ID: 20, ProjectID: 1, State: MachineActive}, nil)
		ms.On("TransitionMachineIdentityState", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.State == MachineSuspended
		}), MachineActive).Return(true, nil)
		ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
		ms.On("CreatePendingAuditEvent", mock.Anything, mock.Anything).Return(nil)
		ms.On("ListMachineIdentityCredentials", ctx, uint(20)).Return([]*models.MachineIdentityCredential{
			{ID: 1, TokenHash: "hash-cred-abc"},
		}, nil)

		var evicted []string
		c.SetTokenCacheInvalidator(func(h string) { evicted = append(evicted, h) })

		_, err := c.TransitionMachineIdentity(ctx, 1, 20, MachineSuspended, 9)
		require.NoError(t, err)
		assert.Contains(t, evicted, "hash-cred-abc", "suspend must evict the machine token from cache")
		ms.AssertExpectations(t)
	})

	t.Run("revoke evicts auth cache", func(t *testing.T) {
		ms := new(MockStorage)
		c := newMachineCore(ms)
		ctx := context.Background()
		ms.On("LockMachineIdentityForUpdate", ctx, uint(21)).Return(&models.MachineIdentity{ID: 21, ProjectID: 1, State: MachineActive}, nil)
		ms.On("TransitionMachineIdentityState", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.State == MachineRevoked && m.RevokedAt != nil
		}), MachineActive).Return(true, nil)
		ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
		ms.On("CreatePendingAuditEvent", mock.Anything, mock.Anything).Return(nil)
		ms.On("ListMachineIdentityCredentials", ctx, uint(21)).Return([]*models.MachineIdentityCredential{
			{ID: 2, TokenHash: "hash-cred-def"},
		}, nil)

		var evicted []string
		c.SetTokenCacheInvalidator(func(h string) { evicted = append(evicted, h) })

		_, err := c.TransitionMachineIdentity(ctx, 1, 21, MachineRevoked, 9)
		require.NoError(t, err)
		assert.Contains(t, evicted, "hash-cred-def", "revoke must evict the machine token from cache")
		ms.AssertExpectations(t)
	})

	// CMI-3: TransitionMachineIdentity is the ONLY eviction path for gRPC-originated
	// suspend/revoke (server/grpc/services/machine_identity_service.go has no
	// independent fallback re-fetch/evict the way the HTTP handler does). A storage
	// error fetching the token hashes must not vanish silently — it must be
	// retried once and, if still failing, logged loudly so operators can see that
	// tokens may remain live in the auth cache past the transition.
	t.Run("suspend logs loudly and does not evict when hash lookup keeps failing", func(t *testing.T) {
		ms := new(MockStorage)
		c := newMachineCore(ms)
		ctx := context.Background()
		ms.On("LockMachineIdentityForUpdate", ctx, uint(30)).Return(&models.MachineIdentity{ID: 30, ProjectID: 1, State: MachineActive}, nil)
		ms.On("TransitionMachineIdentityState", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.State == MachineSuspended
		}), MachineActive).Return(true, nil)
		ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
		ms.On("CreatePendingAuditEvent", mock.Anything, mock.Anything).Return(nil)
		ms.On("ListMachineIdentityCredentials", ctx, uint(30)).Return(nil, errors.New("db unavailable"))

		var evicted []string
		c.SetTokenCacheInvalidator(func(h string) { evicted = append(evicted, h) })

		var err error
		logged := captureLog(t, func() {
			_, err = c.TransitionMachineIdentity(ctx, 1, 30, MachineSuspended, 9)
		})
		require.NoError(t, err, "a cache-eviction failure must not fail the already-committed transition")
		assert.Empty(t, evicted, "nothing to evict when the hash lookup failed")
		assert.Contains(t, logged, "SECURITY", "the failure must be logged loudly, not swallowed")
		assert.Contains(t, logged, "30", "the log must identify the affected machine identity")
		// One initial attempt plus one retry — not swallowed on the first transient error.
		ms.AssertNumberOfCalls(t, "ListMachineIdentityCredentials", 2)
	})

	t.Run("suspend recovers via the single retry after a transient hash-lookup error", func(t *testing.T) {
		ms := new(MockStorage)
		c := newMachineCore(ms)
		ctx := context.Background()
		ms.On("LockMachineIdentityForUpdate", ctx, uint(31)).Return(&models.MachineIdentity{ID: 31, ProjectID: 1, State: MachineActive}, nil)
		ms.On("TransitionMachineIdentityState", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.State == MachineSuspended
		}), MachineActive).Return(true, nil)
		ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
		ms.On("CreatePendingAuditEvent", mock.Anything, mock.Anything).Return(nil)
		ms.On("ListMachineIdentityCredentials", ctx, uint(31)).Return(nil, errors.New("db unavailable")).Once()
		ms.On("ListMachineIdentityCredentials", ctx, uint(31)).Return([]*models.MachineIdentityCredential{
			{ID: 3, TokenHash: "hash-cred-ghi"},
		}, nil).Once()

		var evicted []string
		c.SetTokenCacheInvalidator(func(h string) { evicted = append(evicted, h) })

		var err error
		logged := captureLog(t, func() {
			_, err = c.TransitionMachineIdentity(ctx, 1, 31, MachineSuspended, 9)
		})
		require.NoError(t, err)
		assert.Contains(t, evicted, "hash-cred-ghi", "the retry must still evict once it succeeds")
		assert.Empty(t, logged, "a transient error that the retry recovers from should not be logged")
		ms.AssertExpectations(t)
	})

	t.Run("activate does not evict auth cache", func(t *testing.T) {
		ms := new(MockStorage)
		c := newMachineCore(ms)
		ctx := context.Background()
		ms.On("LockMachineIdentityForUpdate", ctx, uint(22)).Return(&models.MachineIdentity{ID: 22, ProjectID: 1, State: MachineSuspended}, nil)
		ms.On("TransitionMachineIdentityState", ctx, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			return m.State == MachineActive
		}), MachineSuspended).Return(true, nil)
		ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
		// ListMachineIdentityCredentials must NOT be called for activate.

		var evicted []string
		c.SetTokenCacheInvalidator(func(h string) { evicted = append(evicted, h) })

		_, err := c.TransitionMachineIdentity(ctx, 1, 22, MachineActive, 9)
		require.NoError(t, err)
		assert.Empty(t, evicted, "re-activating a machine must not evict any tokens")
		ms.AssertNotCalled(t, "ListMachineIdentityCredentials", mock.Anything, mock.Anything)
		ms.AssertExpectations(t)
	})
}
