package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SessionAuthLiveness is GetSessionAuthLiveness's result: the auth-relevant
// columns of one user row and one session row, read together. Each half
// carries exactly what GetUser / GetSessionByID would have returned for it:
// User is set iff UserErr is nil, Session is set iff SessionErr is nil, and the
// errors are those methods' errors (UserErr wraps ErrUserNotFound when the user
// is absent or soft-deleted; SessionErr wraps ErrSessionNotFound when the
// session row is absent).
type SessionAuthLiveness struct {
	User       *SessionAuthUser
	UserErr    error
	Session    *SessionAuthSession
	SessionErr error
}

// SessionAuthUser is the part of a user row the session cache-hit check reads.
type SessionAuthUser struct {
	ID           uint
	IsActive     bool
	AccountState string
}

// SessionAuthSession is the part of a session row the session cache-hit check
// reads. SessionToken is the stored SHA-256 hash, as on models.Session.
type SessionAuthSession struct {
	ID                uint
	UserID            uint
	SessionToken      string
	RotatedAt         *time.Time
	ExpiresAt         *time.Time
	AbsoluteExpiresAt *time.Time
}

// SessionAuthReads is the subset of Storage that ComposeSessionAuthLiveness reads.
type SessionAuthReads interface {
	GetUser(ctx context.Context, id uint) (*models.User, error)
	GetSessionByID(ctx context.Context, id uint) (*models.Session, error)
}

// ComposeSessionAuthLiveness answers GetSessionAuthLiveness from the
// per-statement methods, in the order the session cache-hit check called them
// before PERF-FIX-7: GetUser, then GetSessionByID. Each read's error is kept in
// its own half; neither stops the other (the cache-hit check judged them
// independently).
//
// It is the reference the one-statement implementation is tested against, the
// LocalStorage fallback when that statement fails, and what a Storage wrapper
// that overrides GetUser or GetSessionByID (a test injecting a fault) forwards
// GetSessionAuthLiveness to, so the override still reaches the check.
func ComposeSessionAuthLiveness(ctx context.Context, s SessionAuthReads, userID, sessionID uint) *SessionAuthLiveness {
	out := &SessionAuthLiveness{}
	if u, err := s.GetUser(ctx, userID); err != nil {
		out.UserErr = err
	} else {
		out.User = &SessionAuthUser{ID: u.ID, IsActive: u.IsActive, AccountState: u.AccountState}
	}
	if sess, err := s.GetSessionByID(ctx, sessionID); err != nil {
		out.SessionErr = err
	} else {
		out.Session = &SessionAuthSession{
			ID: sess.ID, UserID: sess.UserID, SessionToken: sess.SessionToken,
			RotatedAt: sess.RotatedAt, ExpiresAt: sess.ExpiresAt, AbsoluteExpiresAt: sess.AbsoluteExpiresAt,
		}
	}
	return out
}
