package store

// PERF-FIX-7: GetSessionAuthLiveness must answer exactly what GetUser +
// GetSessionByID answer (storage.ComposeSessionAuthLiveness over the same
// store), in every state, in ONE statement; and a failure of that statement
// must be answered by those two reads, with their own errors.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

func sessionAuthBackends() []string {
	if os.Getenv("KEYORIX_TEST_PG_DSN") == "" {
		return []string{"sqlite"}
	}
	return []string{"sqlite", "postgres"}
}

func newSessionAuthTestStorage(t *testing.T, backend string) *LocalStorage {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	var db *gorm.DB
	if backend == "sqlite" {
		var err error
		db, err = gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "sal.db")), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
	} else {
		db = pgOpen(t, pgIsolatedSchemaDSN(t, pgTestDSN(t)))
	}
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}))
	return NewLocalStorage(db)
}

func requireSameSessionAuthLiveness(t *testing.T, want, got *storage.SessionAuthLiveness, msg string) {
	t.Helper()
	require.NotNil(t, got, msg)
	require.Equal(t, want.UserErr == nil, got.UserErr == nil, "%s: user error presence (want %v, got %v)", msg, want.UserErr, got.UserErr)
	if want.UserErr != nil {
		require.Equal(t, want.UserErr.Error(), got.UserErr.Error(), msg)
		require.Equal(t, errors.Is(want.UserErr, storage.ErrUserNotFound), errors.Is(got.UserErr, storage.ErrUserNotFound), msg)
	}
	require.Equal(t, want.User, got.User, "%s: user half", msg)
	require.Equal(t, want.SessionErr == nil, got.SessionErr == nil, "%s: session error presence (want %v, got %v)", msg, want.SessionErr, got.SessionErr)
	if want.SessionErr != nil {
		require.Equal(t, want.SessionErr.Error(), got.SessionErr.Error(), msg)
		require.Equal(t, storage.IsSessionNotFound(want.SessionErr), storage.IsSessionNotFound(got.SessionErr), msg)
	}
	if want.Session == nil || got.Session == nil {
		require.Equal(t, want.Session == nil, got.Session == nil, "%s: session presence", msg)
		return
	}
	w, g := *want.Session, *got.Session
	for _, tp := range []struct {
		name string
		a, b *time.Time
	}{{"rotated_at", w.RotatedAt, g.RotatedAt}, {"expires_at", w.ExpiresAt, g.ExpiresAt}, {"absolute_expires_at", w.AbsoluteExpiresAt, g.AbsoluteExpiresAt}} {
		require.Equal(t, tp.a == nil, tp.b == nil, "%s: %s presence", msg, tp.name)
		if tp.a != nil {
			require.True(t, tp.a.Equal(*tp.b), "%s: %s want %v got %v", msg, tp.name, *tp.a, *tp.b)
		}
	}
	w.RotatedAt, w.ExpiresAt, w.AbsoluteExpiresAt = nil, nil, nil
	g.RotatedAt, g.ExpiresAt, g.AbsoluteExpiresAt = nil, nil, nil
	require.Equal(t, w, g, "%s: session half", msg)
}

// TestGetSessionAuthLiveness_EqualsTheTwoReads crosses every user-row state
// with every session-row state (and user/session pairs that do not belong
// together) and compares the combined read with ComposeSessionAuthLiveness.
func TestGetSessionAuthLiveness_EqualsTheTwoReads(t *testing.T) {
	for _, backend := range sessionAuthBackends() {
		t.Run(backend, func(t *testing.T) {
			ls := newSessionAuthTestStorage(t, backend)
			ctx := context.Background()
			db := ls.db
			// A real zone (core's clock is time.Now, and AbsoluteExpiresAt is
			// not normalised to UTC on save).
			local, err := time.LoadLocation("Europe/Berlin")
			require.NoError(t, err)
			past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
			pastLocal, futureLocal := past.In(local), future.In(local)

			userStates := []struct {
				name string
				mut  func(u *models.User)
			}{
				{"active", func(*models.User) {}},
				{"inactive", func(u *models.User) { u.IsActive = false }},
				{"suspended", func(u *models.User) { u.AccountState = "suspended" }},
				{"deprovisioned", func(u *models.User) { u.AccountState = "deprovisioned" }},
				{"pending_first_login", func(u *models.User) { u.AccountState = "pending_first_login" }},
				{"password_reset_required", func(u *models.User) { u.AccountState = "password_reset_required" }},
				{"legacy empty state", func(u *models.User) { u.AccountState = "" }},
				{"login-locked", func(u *models.User) { u.LoginLockedUntil = &future; u.FailedLoginAttempts = 9 }},
				{"mfa enabled", func(u *models.User) { u.MFAEnabled = true }},
			}
			var users []uint
			for i, us := range userStates {
				u := &models.User{Username: fmt.Sprintf("sal%d", i), UsernameFolded: fmt.Sprintf("sal%d", i), IsActive: true, AccountState: "active"}
				require.NoError(t, db.Create(u).Error)
				us.mut(u)
				require.NoError(t, db.Save(u).Error)
				if u.AccountState == "" {
					require.NoError(t, db.Exec("UPDATE users SET account_state = '' WHERE id = ?", u.ID).Error)
				}
				users = append(users, u.ID)
			}
			deleted := &models.User{Username: "saldeleted", UsernameFolded: "saldeleted", IsActive: true, AccountState: "active"}
			require.NoError(t, db.Create(deleted).Error)
			require.NoError(t, db.Delete(deleted).Error)
			users = append(users, deleted.ID, 999999)

			sessionStates := []struct {
				name string
				mut  func(s *models.Session)
			}{
				{"live", func(*models.Session) {}},
				{"no expiry", func(s *models.Session) { s.ExpiresAt = nil; s.AbsoluteExpiresAt = nil }},
				{"idle-expired", func(s *models.Session) { s.ExpiresAt = &past }},
				{"absolute-expired (non-UTC zone)", func(s *models.Session) { s.AbsoluteExpiresAt = &pastLocal }},
				{"absolute in future (non-UTC zone)", func(s *models.Session) { s.AbsoluteExpiresAt = &futureLocal }},
				{"rotated", func(s *models.Session) { s.RotatedAt = &past }},
				{"setup-only", func(s *models.Session) { s.SetupOnly = true }},
				{"impersonated", func(s *models.Session) { id := users[0]; s.ImpersonatedBy = &id; s.ImpersonationStartedAt = &past }},
			}
			var sessions []uint
			for i, ss := range sessionStates {
				s := &models.Session{UserID: users[i%len(userStates)], SessionToken: fmt.Sprintf("hash-%d", i),
					ExpiresAt: &future, AbsoluteExpiresAt: &future, FamilyID: "f"}
				ss.mut(s)
				require.NoError(t, db.Create(s).Error)
				sessions = append(sessions, s.ID)
			}
			gone := &models.Session{UserID: users[0], SessionToken: "hash-gone"}
			require.NoError(t, db.Create(gone).Error)
			require.NoError(t, db.Delete(gone).Error)
			sessions = append(sessions, gone.ID, 999999)

			n := 0
			for _, uid := range users {
				for _, sid := range sessions {
					want := storage.ComposeSessionAuthLiveness(ctx, ls, uid, sid)
					got, err := readSessionAuthLiveness(ctx, db, uid, sid)
					require.NoError(t, err, "the combined statement itself must succeed (user %d, session %d)", uid, sid)
					requireSameSessionAuthLiveness(t, want, got, fmt.Sprintf("user %d session %d", uid, sid))
					viaMethod, err := ls.GetSessionAuthLiveness(ctx, uid, sid)
					require.NoError(t, err)
					requireSameSessionAuthLiveness(t, want, viaMethod, fmt.Sprintf("method: user %d session %d", uid, sid))
					n++
				}
			}
			t.Logf("%s: %d (user, session) pairs equal to GetUser + GetSessionByID", backend, n)
		})
	}
}

// TestGetSessionAuthLiveness_OneStatement: one statement; the two reads were two.
func TestGetSessionAuthLiveness_OneStatement(t *testing.T) {
	for _, backend := range sessionAuthBackends() {
		t.Run(backend, func(t *testing.T) {
			ls := newSessionAuthTestStorage(t, backend)
			ctx := context.Background()
			u := &models.User{Username: "one", UsernameFolded: "one", IsActive: true, AccountState: "active"}
			require.NoError(t, ls.db.Create(u).Error)
			s := &models.Session{UserID: u.ID, SessionToken: "h"}
			require.NoError(t, ls.db.Create(s).Error)
			counter := countStatements(t, ls.db, "perffix7")
			stmts := counter.during(func() {
				res, err := ls.GetSessionAuthLiveness(ctx, u.ID, s.ID)
				require.NoError(t, err)
				require.NoError(t, res.UserErr)
				require.NoError(t, res.SessionErr)
			})
			require.Len(t, stmts, 1, strings.Join(stmts, "\n"))
			stmts = counter.during(func() { _ = storage.ComposeSessionAuthLiveness(ctx, ls, u.ID, s.ID) })
			require.Len(t, stmts, 2, strings.Join(stmts, "\n"))
		})
	}
}

// TestGetSessionAuthLiveness_StatementFailureFallsBackToTheTwoReads: with one
// of the two tables unreadable the combined statement fails, and the answer is
// the two reads' own: the readable half is reported, the other carries a
// retrieval error that is NOT the not-found sentinel (the cache-hit check
// degrades on it instead of denying).
func TestGetSessionAuthLiveness_StatementFailureFallsBackToTheTwoReads(t *testing.T) {
	for _, backend := range sessionAuthBackends() {
		for _, drop := range []string{"users", "sessions"} {
			t.Run(backend+"/"+drop, func(t *testing.T) {
				ls := newSessionAuthTestStorage(t, backend)
				ctx := context.Background()
				u := &models.User{Username: "fb", UsernameFolded: "fb", IsActive: true, AccountState: "active"}
				require.NoError(t, ls.db.Create(u).Error)
				s := &models.Session{UserID: u.ID, SessionToken: "h"}
				require.NoError(t, ls.db.Create(s).Error)
				require.NoError(t, ls.db.Migrator().DropTable(drop))
				_, err := readSessionAuthLiveness(ctx, ls.db, u.ID, s.ID)
				require.Error(t, err, "precondition: the combined statement fails")

				got, err := ls.GetSessionAuthLiveness(ctx, u.ID, s.ID)
				require.NoError(t, err)
				requireSameSessionAuthLiveness(t, storage.ComposeSessionAuthLiveness(ctx, ls, u.ID, s.ID), got, drop)
				if drop == "users" {
					require.Error(t, got.UserErr)
					require.False(t, errors.Is(got.UserErr, storage.ErrUserNotFound))
					require.NoError(t, got.SessionErr)
				} else {
					require.Error(t, got.SessionErr)
					require.False(t, storage.IsSessionNotFound(got.SessionErr))
					require.NoError(t, got.UserErr)
				}
			})
		}
	}
}
