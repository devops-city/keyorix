package core

// session_cache_hit_liveness_test.go — PERF-FIX-7 (collapse C6).
//
// SessionCacheHitLiveness answers, from one storage read, what the HTTP
// session cache hit used to ask in two calls: AccountUsabilityAndState(user)
// and SessionLiveForToken(session, token). This pins it to those two methods,
// verdicts AND error contract, over every combination of account row and
// session row outcomes (found in each state, absent, storage error), with and
// without a session id, and for a storage failure of the combined read itself.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// liveCheckStore serves GetUser / GetSessionByID from fixed answers and
// forwards GetSessionAuthLiveness to ComposeSessionAuthLiveness over itself,
// unless combinedErr is set (a failure of the combined read itself).
type liveCheckStore struct {
	storage.Storage
	user        *models.User
	userErr     error
	session     *models.Session
	sessionErr  error
	combinedErr error
}

func (s *liveCheckStore) GetUser(context.Context, uint) (*models.User, error) {
	return s.user, s.userErr
}

func (s *liveCheckStore) GetSessionByID(context.Context, uint) (*models.Session, error) {
	return s.session, s.sessionErr
}

func (s *liveCheckStore) GetSessionAuthLiveness(ctx context.Context, userID, sessionID uint) (*storage.SessionAuthLiveness, error) {
	if s.combinedErr != nil {
		return nil, s.combinedErr
	}
	return storage.ComposeSessionAuthLiveness(ctx, s, userID, sessionID), nil
}

func TestSessionCacheHitLiveness_MatchesTheTwoChecks(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Minute), now.Add(time.Hour)
	const token = "tok-live"
	hash := hashSessionTokenForLookup(token)
	errDown := errors.New("connection refused")

	type userCase struct {
		name string
		user *models.User
		err  error
	}
	users := []userCase{
		{"active", &models.User{ID: 7, IsActive: true, AccountState: AccountActive}, nil},
		{"legacy empty state", &models.User{ID: 7, IsActive: true}, nil},
		{"inactive", &models.User{ID: 7, IsActive: false, AccountState: AccountActive}, nil},
		{"suspended", &models.User{ID: 7, IsActive: true, AccountState: AccountSuspended}, nil},
		{"deprovisioned", &models.User{ID: 7, IsActive: true, AccountState: AccountDeprovisioned}, nil},
		{"password reset required", &models.User{ID: 7, IsActive: true, AccountState: AccountPasswordResetRequired}, nil},
		{"pending first login", &models.User{ID: 7, IsActive: true, AccountState: AccountPendingFirstLogin}, nil},
		{"unknown state", &models.User{ID: 7, IsActive: true, AccountState: "bogus"}, nil},
		{"absent / soft-deleted", nil, fmt.Errorf("user not found: %w", storage.ErrUserNotFound)},
		{"storage error", nil, errDown},
	}
	type sessionCase struct {
		name    string
		session *models.Session
		err     error
	}
	sess := func(mut func(*models.Session)) *models.Session {
		s := &models.Session{ID: 3, UserID: 7, SessionToken: hash, ExpiresAt: &future, AbsoluteExpiresAt: &future}
		mut(s)
		return s
	}
	sessions := []sessionCase{
		{"live", sess(func(*models.Session) {}), nil},
		{"no expiry", sess(func(s *models.Session) { s.ExpiresAt, s.AbsoluteExpiresAt = nil, nil }), nil},
		{"another token's row", sess(func(s *models.Session) { s.SessionToken = hashSessionTokenForLookup("other") }), nil},
		{"another user's row, other token", sess(func(s *models.Session) { s.UserID = 8; s.SessionToken = hashSessionTokenForLookup("other") }), nil},
		{"rotated", sess(func(s *models.Session) { s.RotatedAt = &past }), nil},
		{"idle-expired", sess(func(s *models.Session) { s.ExpiresAt = &past }), nil},
		{"absolute-expired", sess(func(s *models.Session) { s.AbsoluteExpiresAt = &past }), nil},
		{"setup-only", sess(func(s *models.Session) { s.SetupOnly = true }), nil},
		{"gone", nil, fmt.Errorf("not found: %w", storage.ErrSessionNotFound)},
		{"storage error", nil, errDown},
	}

	n := 0
	for _, uc := range users {
		for _, sc := range sessions {
			for _, withSession := range []bool{true, false} {
				name := fmt.Sprintf("user=%s/session=%s/with-id=%v", uc.name, sc.name, withSession)
				st := &liveCheckStore{user: uc.user, userErr: uc.err, session: sc.session, sessionErr: sc.err}
				c := NewKeyorixCore(st)
				c.now = func() time.Time { return now }

				wantUsable, wantState, wantAccErr := c.AccountUsabilityAndState(ctx, 7)
				var sid *uint
				var wantLive bool
				var wantSessErr error
				if withSession {
					id := uint(3)
					sid = &id
					wantLive, wantSessErr = c.SessionLiveForToken(ctx, id, token)
				}

				got := c.SessionCacheHitLiveness(ctx, 7, sid, token)
				require.Equal(t, wantAccErr, got.AccountErr, name)
				require.Equal(t, wantUsable, got.AccountUsable, name)
				require.Equal(t, wantState, got.AccountState, name)
				require.Equal(t, withSession, got.SessionChecked, name)
				require.Equal(t, wantSessErr, got.SessionErr, name)
				require.Equal(t, wantLive, got.SessionLive, name)
				n++
			}
		}
	}
	t.Logf("%d combinations equal to AccountUsabilityAndState + SessionLiveForToken", n)
}

// A failure of the combined read is a failed lookup on BOTH halves (the
// cache-hit caller keeps its cached snapshot for each), never a verdict:
// not "unusable", not "not live".
func TestSessionCacheHitLiveness_CombinedReadFailureIsIndeterminateOnBothHalves(t *testing.T) {
	errDown := errors.New("connection refused")
	c := NewKeyorixCore(&liveCheckStore{combinedErr: errDown})
	id := uint(3)
	got := c.SessionCacheHitLiveness(context.Background(), 7, &id, "tok")
	require.ErrorIs(t, got.AccountErr, errDown)
	require.ErrorIs(t, got.SessionErr, errDown)
	require.True(t, got.SessionChecked)
	require.False(t, storage.IsSessionNotFound(got.SessionErr), "a failed read must not look like a definitive \"session gone\"")
}
