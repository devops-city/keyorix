// local_session_auth_liveness.go — GetSessionAuthLiveness (PERF-FIX-7,
// collapse C6 of SESSION-PERF-FIX-3's plan).
//
// The HTTP auth middleware's session cache hit (serveAuthCacheHit) re-read two
// rows on every request: the owning account (GetUser, via
// core.AccountUsabilityAndState) and the session row (GetSessionByID, via
// core.SessionLiveForToken). This reads both in ONE statement: a one-row probe
// LEFT JOIN the user row (GetUser's row: soft-deleted rows excluded) LEFT JOIN
// the session row (GetSessionByID's row: sessions are hard-deleted). Both halves
// come from one snapshot.
//
// No cache is involved: neither GetUser nor GetSessionByID is cached, and the
// auth-cache invalidation (core's invalidateTokenCache / evictUserSessionCache)
// is unchanged. When the statement fails (including a schema without one of the
// tables, which some test fixtures migrate), the answer is
// storage.ComposeSessionAuthLiveness over this store: exactly the two reads
// the check made before, with their own errors.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"gorm.io/gorm"
)

// sessionAuthLivenessSQL is the combined statement. The probe derived table
// always yields exactly one row and both joins are on primary keys, so the
// result is exactly one row: user columns NULL when there is no live user row,
// session columns NULL when there is no session row.
const sessionAuthLivenessSQL = `SELECT u.id AS user_id, u.is_active AS user_is_active, u.account_state AS user_account_state,
 s.id AS session_id, s.user_id AS session_user_id, s.session_token AS session_token,
 s.rotated_at AS session_rotated_at, s.expires_at AS session_expires_at, s.absolute_expires_at AS session_absolute_expires_at
FROM (SELECT 1 AS probe) p
LEFT JOIN users u ON u.id = ? AND u.deleted_at IS NULL
LEFT JOIN sessions s ON s.id = ?`

type sessionAuthLivenessRow struct {
	UserID                   *uint
	UserIsActive             *bool
	UserAccountState         *string
	SessionID                *uint
	SessionUserID            *uint
	SessionToken             *string
	SessionRotatedAt         *time.Time
	SessionExpiresAt         *time.Time
	SessionAbsoluteExpiresAt *time.Time
}

// readSessionAuthLiveness runs sessionAuthLivenessSQL and maps each half to
// what GetUser / GetSessionByID would have returned for it.
func readSessionAuthLiveness(ctx context.Context, db *gorm.DB, userID, sessionID uint) (*storage.SessionAuthLiveness, error) {
	var row sessionAuthLivenessRow
	res := db.WithContext(ctx).Raw(sessionAuthLivenessSQL, userID, sessionID).Scan(&row)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected != 1 {
		// Cannot happen for a one-row probe joined on primary keys; never read
		// "absent" out of nothing.
		return nil, fmt.Errorf("session/user snapshot returned %d rows", res.RowsAffected)
	}
	out := &storage.SessionAuthLiveness{}
	if row.UserID == nil {
		out.UserErr = fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), storage.ErrUserNotFound)
	} else {
		u := &storage.SessionAuthUser{ID: *row.UserID}
		if row.UserIsActive != nil {
			u.IsActive = *row.UserIsActive
		}
		if row.UserAccountState != nil {
			u.AccountState = *row.UserAccountState
		}
		out.User = u
	}
	if row.SessionID == nil {
		out.SessionErr = fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), storage.ErrSessionNotFound)
	} else {
		s := &storage.SessionAuthSession{
			ID:                *row.SessionID,
			RotatedAt:         row.SessionRotatedAt,
			ExpiresAt:         row.SessionExpiresAt,
			AbsoluteExpiresAt: row.SessionAbsoluteExpiresAt,
		}
		if row.SessionUserID != nil {
			s.UserID = *row.SessionUserID
		}
		if row.SessionToken != nil {
			s.SessionToken = *row.SessionToken
		}
		out.Session = s
	}
	return out, nil
}

// GetSessionAuthLiveness — see the storage.Storage doc comment and this file's
// header. It never returns an error itself: a failed combined statement is
// answered by the per-statement reads, whose errors land in the result.
func (ls *LocalStorage) GetSessionAuthLiveness(ctx context.Context, userID, sessionID uint) (*storage.SessionAuthLiveness, error) {
	if out, err := readSessionAuthLiveness(ctx, ls.db, userID, sessionID); err == nil {
		return out, nil
	}
	return storage.ComposeSessionAuthLiveness(ctx, ls, userID, sessionID), nil
}
