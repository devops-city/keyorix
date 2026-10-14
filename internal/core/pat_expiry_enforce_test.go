package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newPATExpiryDB opens a fresh, isolated in-memory SQLite DB for expiry tests.
func newPATExpiryDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "patexpiryenforce_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(
		&models.PersonalAccessToken{},
		&models.Notification{},
	))
	return db
}

// ── IsPATExpired ──────────────────────────────────────────────────────────────

func TestIsPATExpired_NilExpiresAt(t *testing.T) {
	t.Parallel()
	pat := &models.PersonalAccessToken{}
	assert.False(t, IsPATExpired(pat, time.Now()), "nil ExpiresAt → never expired")
}

func TestIsPATExpired_FutureExpiresAt(t *testing.T) {
	t.Parallel()
	future := time.Now().Add(time.Hour)
	pat := &models.PersonalAccessToken{ExpiresAt: &future}
	assert.False(t, IsPATExpired(pat, time.Now()), "future ExpiresAt → not yet expired")
}

func TestIsPATExpired_PastExpiresAt(t *testing.T) {
	t.Parallel()
	past := time.Now().Add(-time.Minute)
	pat := &models.PersonalAccessToken{ExpiresAt: &past}
	assert.True(t, IsPATExpired(pat, time.Now()), "past ExpiresAt → expired")
}

func TestIsPATExpired_ExactlyNow(t *testing.T) {
	t.Parallel()
	// At the boundary: time.After is strict, so ExpiresAt == now is NOT expired.
	now := time.Now()
	pat := &models.PersonalAccessToken{ExpiresAt: &now}
	assert.False(t, IsPATExpired(pat, now), "expires == now → not yet expired (After is strict)")
}

// ── emitPATExpiredNotification ────────────────────────────────────────────────

func TestEmitPATExpiredNotification_CreatesWarningNotification(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)

	pat := &models.PersonalAccessToken{ID: 42, UserID: 7, Name: "my-ci-token"}

	var captured *models.Notification
	ms.On("ListNotifications", ctx, uint(7), true, 200).
		Return([]*models.Notification{}, nil)
	ms.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.Notification) }).
		Return(&models.Notification{ID: 1}, nil)

	c.emitPATExpiredNotification(ctx, pat)

	ms.AssertExpectations(t)
	require.NotNil(t, captured)
	assert.Equal(t, uint(7), captured.UserID)
	assert.Equal(t, NotificationPATExpiredUsed, captured.Type)
	assert.Equal(t, models.NotificationSeverityWarning, captured.Severity)
	assert.Equal(t, patExpiredUsedLink(42), captured.Link)
	assert.Contains(t, captured.Message, "my-ci-token")
}

// TestEmitPATExpiredNotification_UnreadExisting_Skipped is the regression test
// for the notification-spam finding: repeatedly presenting the same expired PAT
// must not create a fresh notification while an unread one for that exact token
// already stands. Before the fix, emitPATExpiredNotification unconditionally
// called CreateNotification — this test's mock has no CreateNotification
// expectation at all, so it would fail loudly (unexpected call) against
// pre-fix code instead of silently passing.
func TestEmitPATExpiredNotification_UnreadExisting_Skipped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)

	pat := &models.PersonalAccessToken{ID: 42, UserID: 7, Name: "my-ci-token"}

	ms.On("ListNotifications", ctx, uint(7), true, 200).
		Return([]*models.Notification{{
			ID:   9,
			Type: NotificationPATExpiredUsed,
			Link: patExpiredUsedLink(42),
		}}, nil)

	c.emitPATExpiredNotification(ctx, pat)

	ms.AssertExpectations(t)
	ms.AssertNotCalled(t, "CreateNotification", mock.Anything, mock.Anything)
}

// TestEmitPATExpiredNotification_UnreadExisting_DifferentToken_StillFires
// confirms dedup is keyed per-token (by ID, not by owner alone): an unread
// standing reminder for a DIFFERENT token owned by the same user must not
// suppress this token's notification (#G22-style token-identity concern).
func TestEmitPATExpiredNotification_UnreadExisting_DifferentToken_StillFires(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)

	pat := &models.PersonalAccessToken{ID: 42, UserID: 7, Name: "my-ci-token"}

	ms.On("ListNotifications", ctx, uint(7), true, 200).
		Return([]*models.Notification{{
			ID:   9,
			Type: NotificationPATExpiredUsed,
			Link: patExpiredUsedLink(43), // a different token
		}}, nil)
	ms.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{ID: 10}, nil)

	c.emitPATExpiredNotification(ctx, pat)

	ms.AssertExpectations(t)
}

func TestEmitPATExpiredNotification_ZeroUserID_NoOp(t *testing.T) {
	t.Parallel()
	// notifyWithSeverity returns immediately when userID == 0; storage must not be
	// called at all.
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)

	pat := &models.PersonalAccessToken{ID: 1, UserID: 0, Name: "orphan"}
	c.emitPATExpiredNotification(ctx, pat) // must not panic or call storage

	ms.AssertNotCalled(t, "CreateNotification", mock.Anything, mock.Anything)
}

// ── ValidatePATToken with expiry → ErrPATExpired ──────────────────────────────

func TestValidatePATToken_ExpiredPAT_ReturnsErrPATExpired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	raw := patPrefix + "expiredtok0test"
	hash := sha256Hex(raw)

	ms := new(MockStorage)
	c := NewKeyorixCore(ms)

	past := time.Now().Add(-time.Hour)
	ms.On("GetPersonalAccessTokenByHash", ctx, hash).
		Return(&models.PersonalAccessToken{ID: 5, UserID: 3, Name: "old-token", ExpiresAt: &past}, nil)
	ms.On("ListNotifications", ctx, uint(3), true, 200).
		Return([]*models.Notification{}, nil)
	ms.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{ID: 99}, nil)

	_, _, _, _, err := c.ValidatePATToken(ctx, raw)

	require.ErrorIs(t, err, ErrPATExpired)
	ms.AssertCalled(t, "CreateNotification", ctx, mock.AnythingOfType("*models.Notification"))
}

// TestValidatePATToken_ExpiredPAT_RepeatedPresentation_OnlyFirstNotifies is the
// end-to-end regression test for the notification-spam finding: an attacker (or
// a stale client) who repeatedly presents the SAME already-expired PAT string at
// the auth boundary must trigger at most one standing notification, not one per
// attempt. Uses a real in-memory-SQLite-backed core (not the mock) so the dedup
// check reads back what CreateNotification actually persisted, exactly as it
// does in production.
func TestValidatePATToken_ExpiredPAT_RepeatedPresentation_OnlyFirstNotifies(t *testing.T) {
	t.Parallel()
	db := newPATExpiryDB(t)
	raw := patPrefix + "repeatedspam0test"
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)

	require.NoError(t, db.Create(&models.PersonalAccessToken{
		ID: 60, UserID: 40, Name: "spammed-token",
		TokenHash: sha256Hex(raw), ExpiresAt: &past, Revoked: false,
	}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	ctx := context.Background()

	// Five rapid-fire presentations of the same expired token, as an attacker
	// replaying a captured (now-worthless-for-access, but still notification-
	// triggering) token string would do.
	for range 5 {
		_, _, _, _, err := c.ValidatePATToken(ctx, raw)
		require.ErrorIs(t, err, ErrPATExpired)
	}

	notes, err := c.storage.ListNotifications(ctx, 40, false, 200)
	require.NoError(t, err)
	var patNotes []*models.Notification
	for _, n := range notes {
		if n.Type == NotificationPATExpiredUsed {
			patNotes = append(patNotes, n)
		}
	}
	require.Len(t, patNotes, 1, "5 rapid repeat presentations of the same expired PAT must yield exactly 1 notification, not 5")

	// The owner reads (dismisses) the standing notification — the same signal
	// every other reminder in this package uses to allow a fresh one later.
	require.NoError(t, c.storage.MarkNotificationRead(ctx, patNotes[0].ID, 40))

	// A further presentation after the standing notification was read must fire
	// a new one: the owner has now seen (and presumably acted on, or chosen to
	// ignore) the first warning, so a renewed attempt is worth re-surfacing.
	_, _, _, _, err = c.ValidatePATToken(ctx, raw)
	require.ErrorIs(t, err, ErrPATExpired)

	notes, err = c.storage.ListNotifications(ctx, 40, false, 200)
	require.NoError(t, err)
	patNotes = nil
	for _, n := range notes {
		if n.Type == NotificationPATExpiredUsed {
			patNotes = append(patNotes, n)
		}
	}
	require.Len(t, patNotes, 2, "presenting again after the standing notification was read must fire a new one")
}

func TestValidatePATToken_ValidNonExpiredPAT_Succeeds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	raw := patPrefix + "validtok12test5"
	hash := sha256Hex(raw)

	ms := new(MockStorage)
	c := NewKeyorixCore(ms)

	future := time.Now().Add(24 * time.Hour)
	ms.On("GetPersonalAccessTokenByHash", ctx, hash).
		Return(&models.PersonalAccessToken{ID: 7, UserID: 2, ExpiresAt: &future}, nil)
	ms.On("GetUser", ctx, uint(2)).
		Return(&models.User{ID: 2, Username: "alice", IsActive: true, AccountState: AccountActive}, nil)
	ms.On("GetUserRoles", ctx, uint(2)).
		Return([]*models.Role{{Name: "project_viewer"}}, nil)

	user, roles, _, _, err := c.ValidatePATToken(ctx, raw)

	require.NoError(t, err)
	assert.Equal(t, uint(2), user.ID)
	assert.Equal(t, []string{"project_viewer"}, roles)
	ms.AssertNotCalled(t, "CreateNotification", mock.Anything, mock.Anything)
}

// ── ListExpiredOwnPATs ────────────────────────────────────────────────────────

func TestListExpiredOwnPATs_ReturnsExpiredNonRevokedTokens(t *testing.T) {
	t.Parallel()
	db := newPATExpiryDB(t)
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	// Only token 1 should appear: expired, non-revoked, owned by user 10.
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 10, TokenHash: "h1", Name: "expired", ExpiresAt: &past, Revoked: false}).Error)
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 2, UserID: 10, TokenHash: "h2", Name: "active", ExpiresAt: &future, Revoked: false}).Error)
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 3, UserID: 10, TokenHash: "h3", Name: "expired-revoked", ExpiresAt: &past, Revoked: true}).Error)
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 4, UserID: 10, TokenHash: "h4", Name: "no-expiry", Revoked: false}).Error)
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 5, UserID: 99, TokenHash: "h5", Name: "other-user", ExpiresAt: &past, Revoked: false}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	tokens, err := c.ListExpiredOwnPATs(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, uint(1), tokens[0].ID)
	assert.Equal(t, "expired", tokens[0].Name)
}

func TestListExpiredOwnPATs_ZeroUserID_Error(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.ListExpiredOwnPATs(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestListExpiredOwnPATs_NoExpiredTokens_ReturnsEmptySlice(t *testing.T) {
	t.Parallel()
	db := newPATExpiryDB(t)
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	future := now.Add(24 * time.Hour)
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 5, TokenHash: "hx1", Name: "active", ExpiresAt: &future, Revoked: false}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	tokens, err := c.ListExpiredOwnPATs(context.Background(), 5)
	require.NoError(t, err)
	assert.Empty(t, tokens)
}

// ── BulkRevokeExpiredOwnPATs ──────────────────────────────────────────────────

func TestBulkRevokeExpiredOwnPATs_RevokesExpiredTokensAndReturnsHashes(t *testing.T) {
	t.Parallel()
	db := newPATExpiryDB(t)
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 20, TokenHash: "rev-hash-1", Name: "exp1", ExpiresAt: &past, Revoked: false}).Error)
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 2, UserID: 20, TokenHash: "rev-hash-2", Name: "exp2", ExpiresAt: &past, Revoked: false}).Error)
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 3, UserID: 20, TokenHash: "rev-hash-3", Name: "active", ExpiresAt: &future, Revoked: false}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	hashes, err := c.BulkRevokeExpiredOwnPATs(context.Background(), 20)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"rev-hash-1", "rev-hash-2"}, hashes)

	// Verify DB: expired tokens are now revoked; active token is untouched.
	var tok1 models.PersonalAccessToken
	require.NoError(t, db.First(&tok1, 1).Error)
	assert.True(t, tok1.Revoked)

	var tok3 models.PersonalAccessToken
	require.NoError(t, db.First(&tok3, 3).Error)
	assert.False(t, tok3.Revoked)
}

func TestBulkRevokeExpiredOwnPATs_ZeroUserID_Error(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.BulkRevokeExpiredOwnPATs(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestBulkRevokeExpiredOwnPATs_NoneExpired_ReturnsNilHashes(t *testing.T) {
	t.Parallel()
	db := newPATExpiryDB(t)
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	future := now.Add(24 * time.Hour)
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 30, TokenHash: "hfut1", Name: "active", ExpiresAt: &future, Revoked: false}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	hashes, err := c.BulkRevokeExpiredOwnPATs(context.Background(), 30)
	require.NoError(t, err)
	assert.Nil(t, hashes)
}
