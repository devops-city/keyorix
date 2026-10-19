package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// fixedClock is the reference "now" used across the session-TTL tests.
var sessionTestNow = time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)

func newSessionCore(store *MockStorage, access, absolute time.Duration) *KeyorixCore {
	return &KeyorixCore{
		storage:            store,
		now:                func() time.Time { return sessionTestNow },
		passwordPolicy:     DefaultPasswordPolicy(),
		sessionAccessTTL:   access,
		sessionAbsoluteTTL: absolute,
	}
}

// captureCreatedSession records the session handed to CreateSession (so the test
// can assert on the computed expiry fields) and echoes it straight back. The mock
// returns the same pointer, which Run has already populated, so RefreshSession's
// returned session carries the rotated token.
func captureCreatedSession(store *MockStorage) *models.Session {
	captured := &models.Session{}
	store.On("CreateSession", mock.Anything, mock.AnythingOfType("*models.Session")).
		Run(func(args mock.Arguments) {
			*captured = *args.Get(1).(*models.Session)
		}).
		Return(captured, nil)
	return captured
}

// captureRotatedSession records the replacement session handed to RotateSession (so
// the test can assert on the computed expiry fields) and reports the CAS a win,
// echoing the same pointer back as "created". Use for RefreshSession success-path
// tests; the old row's id must equal oldID for the mock to match.
func captureRotatedSession(store *MockStorage, oldID uint) *models.Session {
	captured := &models.Session{}
	store.On("RotateSession", mock.Anything, oldID, mock.AnythingOfType("*models.Session"), mock.Anything).
		Run(func(args mock.Arguments) {
			*captured = *args.Get(2).(*models.Session)
		}).
		Return(captured, true, nil)
	return captured
}

// mintSession with no absolute TTL configured stamps only the access window.
func TestMintSession_AccessTTLOnly(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	captured := captureCreatedSession(store)
	c := newSessionCore(store, 30*time.Minute, 0)

	_, err := c.mintSession(context.Background(), 1, "ua", "ip")
	require.NoError(t, err)

	require.NotNil(t, captured.ExpiresAt)
	require.Equal(t, sessionTestNow.Add(30*time.Minute), *captured.ExpiresAt)
	require.Nil(t, captured.AbsoluteExpiresAt, "no ceiling configured")
}

// mintSession with an absolute TTL stamps both the access window and the ceiling.
func TestMintSession_WithAbsoluteCeiling(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	captured := captureCreatedSession(store)
	c := newSessionCore(store, 30*time.Minute, 12*time.Hour)

	_, err := c.mintSession(context.Background(), 1, "ua", "ip")
	require.NoError(t, err)

	require.Equal(t, sessionTestNow.Add(30*time.Minute), *captured.ExpiresAt)
	require.NotNil(t, captured.AbsoluteExpiresAt)
	require.Equal(t, sessionTestNow.Add(12*time.Hour), *captured.AbsoluteExpiresAt)
}

// A ceiling shorter than one access window is clamped so the first window never
// already overruns the ceiling.
func TestMintSession_CeilingShorterThanAccessClamped(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	captured := captureCreatedSession(store)
	c := newSessionCore(store, 1*time.Hour, 10*time.Minute)

	_, err := c.mintSession(context.Background(), 1, "ua", "ip")
	require.NoError(t, err)

	require.Equal(t, *captured.ExpiresAt, *captured.AbsoluteExpiresAt,
		"ceiling pulled up to the access window")
}

// An unset access TTL falls back to the historic 24h default.
func TestMintSession_DefaultAccessTTL(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	captured := captureCreatedSession(store)
	c := newSessionCore(store, 0, 0)

	_, err := c.mintSession(context.Background(), 1, "ua", "ip")
	require.NoError(t, err)
	require.Equal(t, sessionTestNow.Add(24*time.Hour), *captured.ExpiresAt)
}

// Refreshing within the absolute window carries the ceiling unchanged onto the new
// session and starts a fresh access window. The old session is deleted.
func TestRefreshSession_CarriesCeiling(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	captured := captureRotatedSession(store, 7)
	c := newSessionCore(store, 30*time.Minute, 12*time.Hour)

	ceiling := sessionTestNow.Add(8 * time.Hour) // still within the window
	oldExpiry := sessionTestNow.Add(-5 * time.Minute)
	old := &models.Session{ID: 7, UserID: 1, SessionToken: "old", FamilyID: "fam-1", ExpiresAt: &oldExpiry, AbsoluteExpiresAt: &ceiling}
	store.On("GetSessionAny", mock.Anything, "old").Return(old, nil)
	store.On("GetUser", mock.Anything, uint(1)).Return(&models.User{ID: 1, IsActive: true, AccountState: AccountActive}, nil)

	out, err := c.RefreshSession(context.Background(), "old")
	require.NoError(t, err)
	require.NotEqual(t, "old", out.SessionToken, "token rotated")
	require.Equal(t, "fam-1", captured.FamilyID, "family id carried unchanged")
	require.Equal(t, sessionTestNow.Add(30*time.Minute), *captured.ExpiresAt, "fresh access window")
	require.NotNil(t, captured.AbsoluteExpiresAt)
	require.Equal(t, ceiling, *captured.AbsoluteExpiresAt, "ceiling unchanged")
	store.AssertCalled(t, "RotateSession", mock.Anything, uint(7), mock.Anything, mock.Anything)
}

// The last access window before the ceiling is clamped so it cannot overrun it.
func TestRefreshSession_ClampsLastWindowToCeiling(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	captured := captureRotatedSession(store, 7)
	c := newSessionCore(store, 30*time.Minute, 12*time.Hour)

	ceiling := sessionTestNow.Add(10 * time.Minute) // less than one access window away
	old := &models.Session{ID: 7, UserID: 1, SessionToken: "old", AbsoluteExpiresAt: &ceiling}
	store.On("GetSessionAny", mock.Anything, "old").Return(old, nil)
	store.On("GetUser", mock.Anything, uint(1)).Return(&models.User{ID: 1, IsActive: true, AccountState: AccountActive}, nil)

	_, err := c.RefreshSession(context.Background(), "old")
	require.NoError(t, err)
	require.Equal(t, ceiling, *captured.ExpiresAt, "new window clamped to the ceiling")
}

// Refreshing at or past the ceiling is refused and the stale session is deleted —
// re-authentication is required rather than another rotation.
func TestRefreshSession_RefusedPastCeiling(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newSessionCore(store, 30*time.Minute, 12*time.Hour)

	ceiling := sessionTestNow.Add(-1 * time.Minute) // already past
	old := &models.Session{ID: 7, UserID: 1, SessionToken: "old", AbsoluteExpiresAt: &ceiling}
	store.On("GetSessionAny", mock.Anything, "old").Return(old, nil)
	store.On("DeleteSession", mock.Anything, uint(7)).Return(nil)

	_, err := c.RefreshSession(context.Background(), "old")
	require.Error(t, err)
	require.Contains(t, err.Error(), "re-authentication required")
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
	store.AssertCalled(t, "DeleteSession", mock.Anything, uint(7))
}

// An impersonation session must not be refreshable — otherwise /auth/refresh would
// mint a fresh, full-TTL session for the target with the impersonation attribution
// stripped (laundering).
func TestRefreshSession_RefusesImpersonationSession(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newSessionCore(store, 30*time.Minute, 12*time.Hour)

	admin := uint(9)
	old := &models.Session{ID: 7, UserID: 1, SessionToken: "imp", ImpersonatedBy: &admin}
	store.On("GetSessionAny", mock.Anything, "imp").Return(old, nil)

	_, err := c.RefreshSession(context.Background(), "imp")
	require.Error(t, err)
	require.Contains(t, err.Error(), "impersonation")
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// With no ceiling (legacy behaviour) a session refreshes indefinitely.
func TestRefreshSession_NoCeilingRefreshesForever(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	captured := captureRotatedSession(store, 7)
	c := newSessionCore(store, 24*time.Hour, 0)

	old := &models.Session{ID: 7, UserID: 1, SessionToken: "old"} // AbsoluteExpiresAt nil
	store.On("GetSessionAny", mock.Anything, "old").Return(old, nil)
	store.On("GetUser", mock.Anything, uint(1)).Return(&models.User{ID: 1, IsActive: true, AccountState: AccountActive}, nil)

	_, err := c.RefreshSession(context.Background(), "old")
	require.NoError(t, err)
	require.Equal(t, sessionTestNow.Add(24*time.Hour), *captured.ExpiresAt)
	require.Nil(t, captured.AbsoluteExpiresAt)
}

// A session whose account was deactivated or suspended after issuance must not be
// refreshed into a fresh access window — otherwise a deactivated user keeps a
// self-renewing session. The stale session is deleted and no new one is minted.
func TestRefreshSession_RefusedForInactiveOrBlockedAccount(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		user *models.User
	}{
		{"deactivated", &models.User{ID: 1, IsActive: false, AccountState: AccountActive}},
		{"suspended", &models.User{ID: 1, IsActive: true, AccountState: AccountSuspended}},
		{"deprovisioned", &models.User{ID: 1, IsActive: true, AccountState: AccountDeprovisioned}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := new(MockStorage)
			c := newSessionCore(store, 30*time.Minute, 12*time.Hour)

			ceiling := sessionTestNow.Add(8 * time.Hour) // still within the window
			old := &models.Session{ID: 7, UserID: 1, SessionToken: "old", AbsoluteExpiresAt: &ceiling}
			store.On("GetSessionAny", mock.Anything, "old").Return(old, nil)
			store.On("GetUser", mock.Anything, uint(1)).Return(tc.user, nil)
			store.On("DeleteSession", mock.Anything, uint(7)).Return(nil)

			_, err := c.RefreshSession(context.Background(), "old")
			require.Error(t, err)
			require.Contains(t, err.Error(), "account is not active")
			store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
			store.AssertCalled(t, "DeleteSession", mock.Anything, uint(7))
		})
	}
}

// TestValidateSessionToken_AbsoluteCeilingEnforcedAtBoundary pins that the hard
// absolute-lifetime ceiling is enforced when a session is VALIDATED, independently of the
// clamp RefreshSession/mintSession apply to ExpiresAt. The clamp makes an expired ceiling
// imply an expired access window in normal operation (see the RefreshSession tests above),
// but the ceiling must not DEPEND on every issuer clamping correctly: a session whose access
// window is still open yet whose ceiling has passed (a future non-clamping path, or a
// tampered row) must be rejected at the validation boundary. Self-checking invariant.
func TestValidateSessionToken_AbsoluteCeilingEnforcedAtBoundary(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("past ceiling is rejected even with an open access window", func(t *testing.T) {
		store := new(MockStorage)
		c := newSessionCore(store, time.Hour, 12*time.Hour)
		accessOpen := sessionTestNow.Add(time.Hour)   // access window still valid
		ceilingPast := sessionTestNow.Add(-time.Hour) // absolute ceiling already passed
		store.On("GetSession", ctx, "tok").Return(&models.Session{
			ID: 7, UserID: 2, ExpiresAt: &accessOpen, AbsoluteExpiresAt: &ceilingPast,
		}, nil)

		_, _, err := c.ValidateSessionToken(ctx, "tok")
		require.ErrorContains(t, err, "lifetime exceeded")
		// Fails fast at the boundary — no last-seen write or user lookup for a dead session.
		c.FlushLastUsed(ctx) // the stamp is coalesced: flush so a recorded touch would reach the mock
		store.AssertNotCalled(t, "TouchSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		store.AssertNotCalled(t, "GetUser", mock.Anything, mock.Anything)
	})

	t.Run("a future ceiling still validates", func(t *testing.T) {
		store := new(MockStorage)
		c := newSessionCore(store, time.Hour, 12*time.Hour)
		accessOpen := sessionTestNow.Add(time.Hour)
		ceilingFuture := sessionTestNow.Add(6 * time.Hour)
		store.On("GetSession", ctx, "tok").Return(&models.Session{
			ID: 7, UserID: 2, ExpiresAt: &accessOpen, AbsoluteExpiresAt: &ceilingFuture,
		}, nil)
		store.On("TouchSession", ctx, uint(7), mock.Anything, mock.Anything).Return(nil)
		store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, IsActive: true, AccountState: AccountActive}, nil)
		store.On("GetUserRoles", ctx, uint(2)).Return([]*models.Role{{Name: "viewer"}}, nil)

		user, roles, err := c.ValidateSessionToken(ctx, "tok")
		require.NoError(t, err)
		require.Equal(t, uint(2), user.ID)
		require.Equal(t, []string{"viewer"}, roles)
		c.FlushLastUsed(ctx) // write the coalesced stamp now, not from a timer after the test
	})
}

// A replay of an already-rotated session token (#211) must be detected distinctly
// from ordinary "not found"/expiry — audited as a reuse event, with the whole
// session family (every session descended from the same login) revoked, not just
// silently treated as an unknown token. The client-facing error stays the generic
// "not found or expired" (no oracle distinguishing reuse from a garbage token).
func TestRefreshSession_ReplayOfRotatedTokenDetectedAndFamilyRevoked(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newSessionCore(store, 30*time.Minute, 0)

	rotatedAt := sessionTestNow.Add(-time.Minute)
	old := &models.Session{ID: 7, UserID: 1, SessionToken: "stale", FamilyID: "fam-1", RotatedAt: &rotatedAt, IPAddress: "203.0.113.5"}
	store.On("GetSessionAny", mock.Anything, "stale").Return(old, nil)
	store.On("ListSessionTokenHashesByFamily", mock.Anything, "fam-1").Return([]string{"hash-a", "hash-b"}, nil)
	store.On("DeleteSessionsByFamily", mock.Anything, "fam-1").Return(nil)
	var loggedType string
	store.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { loggedType = args.Get(1).(*models.AuditEvent).EventType }).
		Return(nil)

	_, err := c.RefreshSession(context.Background(), "stale")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found or expired", "the client-facing error stays generic (no oracle)")
	require.Equal(t, EventSessionReuseDetected, loggedType, "a reuse of an already-rotated token must be audited distinctly")
	store.AssertCalled(t, "DeleteSessionsByFamily", mock.Anything, "fam-1")
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "RotateSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// A concurrent-refresh race — two refreshes of the SAME not-yet-rotated token,
// racing the atomic RotateSession CAS — must let only ONE succeed (#211). The
// loser is treated exactly like a reuse-of-an-already-rotated-token replay: audited
// distinctly and the session family revoked, so it can't silently mint a second
// live session from one token use.
func TestRefreshSession_LosingRotationRaceIsTreatedAsReuse(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newSessionCore(store, 30*time.Minute, 0)

	old := &models.Session{ID: 7, UserID: 1, SessionToken: "old", FamilyID: "fam-1"}
	store.On("GetSessionAny", mock.Anything, "old").Return(old, nil)
	store.On("GetUser", mock.Anything, uint(1)).Return(&models.User{ID: 1, IsActive: true, AccountState: AccountActive}, nil)
	// The CAS in RotateSession is what a concurrent racer already won — this call
	// reports the loss (won=false, created=nil), exactly like the local_auth.go
	// implementation would when another goroutine's UPDATE already flipped
	// rotated_at first.
	store.On("RotateSession", mock.Anything, uint(7), mock.AnythingOfType("*models.Session"), mock.Anything).
		Return(nil, false, nil)
	store.On("ListSessionTokenHashesByFamily", mock.Anything, "fam-1").Return([]string{"hash-a"}, nil)
	store.On("DeleteSessionsByFamily", mock.Anything, "fam-1").Return(nil)
	var loggedType string
	store.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { loggedType = args.Get(1).(*models.AuditEvent).EventType }).
		Return(nil)

	_, err := c.RefreshSession(context.Background(), "old")
	require.Error(t, err, "the losing side of a rotation race must not mint a second session")
	require.Equal(t, EventSessionReuseDetected, loggedType)
	store.AssertCalled(t, "DeleteSessionsByFamily", mock.Anything, "fam-1")
}

// TestRefreshSession_FamilyRevokeFailureIsAuditedLoudly is the red-proof for
// handleSessionReuse's silently-swallowed DeleteSessionsByFamily error (Session O,
// O2 item 2): unlike the deactivation-cleanup case, nothing else independently
// blocks a live sibling session here (the account is still active) — a failure to
// revoke the family after reuse was detected leaves an attacker's session live with
// no signal anywhere. Red before the fix: DeleteSessionsByFamily's error was `_ =`,
// so no second audit event was ever written and this test's
// EventSessionReuseFamilyRevokeFailed assertion could never pass.
func TestRefreshSession_FamilyRevokeFailureIsAuditedLoudly(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newSessionCore(store, 30*time.Minute, 0)

	rotatedAt := sessionTestNow.Add(-time.Minute)
	old := &models.Session{ID: 7, UserID: 1, SessionToken: "stale", FamilyID: "fam-1", RotatedAt: &rotatedAt}
	store.On("GetSessionAny", mock.Anything, "stale").Return(old, nil)
	store.On("ListSessionTokenHashesByFamily", mock.Anything, "fam-1").Return([]string{"hash-a"}, nil)
	store.On("DeleteSessionsByFamily", mock.Anything, "fam-1").Return(errors.New("db unavailable"))
	var loggedTypes []string
	store.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) {
			loggedTypes = append(loggedTypes, args.Get(1).(*models.AuditEvent).EventType)
		}).
		Return(nil)

	_, err := c.RefreshSession(context.Background(), "stale")
	require.Error(t, err, "the client-facing error stays generic even when cleanup failed")
	require.Contains(t, loggedTypes, EventSessionReuseDetected)
	require.Contains(t, loggedTypes, EventSessionReuseFamilyRevokeFailed,
		"a failure to revoke a reused session's family must be audited distinctly, not silently swallowed")
}
