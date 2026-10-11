// local_auth.go — Session and Personal Access Token / Setup Token operations for
// LocalStorage.
//
// Covers: CreateSession, GetSession, DeleteSession, CleanupExpiredSessions,
// personal access tokens (ADR-027), and setup tokens (ADR-028).
//
// All operations use direct GORM queries. LocalStorage is the sole Storage
// implementation; the former remote (HTTP) equivalent, RemoteStorage, is deleted.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// --- Sessions ---

// hashSessionToken is the at-rest representation of a session token. Sessions, like
// PATs / machine / setup tokens, are stored only as a SHA-256 hash so a database read
// (backup, replica, injection, insider) never yields a live, replayable token. The
// plaintext lives only in the client's possession.
func hashSessionToken(token string) string {
	// codeql[go/weak-sensitive-data-hashing] -- token is a high-entropy random session
	// token, not a password; this is a deterministic lookup hash (needs fast, indexable
	// equality), not credential storage, matching the PAT/machine/setup-token precedent
	// (internal/core/hash.go's sha256Hex) a slow KDF would only protect against guessing a
	// low-entropy secret, which doesn't apply here.
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (ls *LocalStorage) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	// Persist the hash, not the plaintext token. Hand the plaintext back to the caller
	// (it must reach the client) but keep it out of the row; the column holds the hash.
	plaintext := session.SessionToken
	session.SessionToken = hashSessionToken(plaintext)
	// #2701: insert and re-check the owner's liveness in ONE transaction — see
	// CreatePersonalAccessToken's doc comment. Without it a session committed
	// after a suspend's DeleteSessionsForUserExcept swept the table, and became
	// usable again the moment the account was reactivated, up to its own expiry.
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(session).Error; err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		return requireLiveCredentialOwner(tx, session.UserID)
	})
	session.SessionToken = plaintext // restore for the caller (transient, never re-stored)
	if err != nil {
		return nil, err
	}
	return session, nil
}

// GetSession looks up a LIVE session by the hash of the presented token — the row
// stores only the hash. A rotated row (RotatedAt set) is excluded: it must
// authenticate nothing, exactly like a deleted row (#211).
//
// Distinguishes a genuine "no such live session" (gorm.ErrRecordNotFound) from any
// other retrieval failure by wrapping storage.ErrSessionNotFound ONLY for the former
// — mirroring GetSessionByID immediately below, and storage.IsSessionNotFound's own
// doc comment. Previously this wrapped ANY error identically (both under the
// "ErrorNotFound" i18n message), which made every caller's `err != nil` the only
// signal available — core.Logout (internal/core/auth.go) used to collapse a real
// storage failure into the SAME 401 "session not found" response as an ordinary
// already-logged-out token (#2337 fixed the double-logout case but, in doing so,
// also silently swallowed a genuine 5xx into that same 401 — found closing that
// finding properly rather than re-litigating it).
func (ls *LocalStorage) GetSession(ctx context.Context, token string) (*models.Session, error) {
	var session models.Session
	if err := ls.db.WithContext(ctx).
		Where("session_token = ? AND rotated_at IS NULL", hashSessionToken(token)).
		First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), storage.ErrSessionNotFound)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &session, nil
}

// GetSessionAny looks up a session by token hash regardless of rotation state —
// used only by RefreshSession's reuse-detection path (#211), which must tell an
// already-rotated token (a reuse signal) apart from one that never existed.
func (ls *LocalStorage) GetSessionAny(ctx context.Context, token string) (*models.Session, error) {
	var session models.Session
	if err := ls.db.WithContext(ctx).Where("session_token = ?", hashSessionToken(token)).First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Typed like GetSession: RefreshSession tells "no such token" (a counted
			// guess) from a storage failure (no verdict, the slot is released).
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), storage.ErrSessionNotFound)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &session, nil
}

// RotateSession atomically supersedes the session at oldID with newSession, inside
// one DB transaction (#211). The conditional UPDATE's WHERE guard (rotated_at IS
// NULL) is the CAS: under concurrent refreshes of the same token, only the caller
// whose UPDATE matches a still-live row wins (won=true) and gets its replacement
// created in the SAME transaction, so a crash between the two steps can never leave
// an old row marked rotated with no live descendant. The loser's UPDATE matches zero
// rows (won=false, created=nil) — the caller must treat that exactly like an
// out-of-band replay of an already-rotated token.
func (ls *LocalStorage) RotateSession(ctx context.Context, oldID uint, newSession *models.Session, now time.Time) (*models.Session, bool, error) {
	var created *models.Session
	won := false
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.Session{}).
			Where("id = ? AND rotated_at IS NULL", oldID).
			Update("rotated_at", now)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return nil // lost the race / already rotated — won stays false, not an error
		}
		won = true
		plaintext := newSession.SessionToken
		newSession.SessionToken = hashSessionToken(plaintext)
		if err := tx.Create(newSession).Error; err != nil {
			return err
		}
		// #2701: the rotated-in session is a fresh credential row, so it needs
		// the same owner re-check its sibling insert does. The rotation's own
		// CAS on rotated_at serializes it against another rotation, not against
		// a credential sweep.
		if err := requireLiveCredentialOwner(tx, newSession.UserID); err != nil {
			return err
		}
		newSession.SessionToken = plaintext
		created = newSession
		return nil
	})
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return created, won, nil
}

// ListSessionTokenHashesByFamily returns the stored session_token hashes for every
// (live or rotated) session sharing familyID, so the reuse-detection path can evict
// each from the auth cache before deleting them (#211).
func (ls *LocalStorage) ListSessionTokenHashesByFamily(ctx context.Context, familyID string) ([]string, error) {
	var hashes []string
	if err := ls.db.WithContext(ctx).Model(&models.Session{}).
		Where("family_id = ?", familyID).
		Pluck("session_token", &hashes).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return hashes, nil
}

// DeleteSessionsByFamily removes every session sharing familyID — used to revoke
// the whole lineage descended from one login when a refresh-token reuse is
// detected (#211), not just the single replayed row.
func (ls *LocalStorage) DeleteSessionsByFamily(ctx context.Context, familyID string) error {
	if familyID == "" {
		return nil
	}
	if err := ls.db.WithContext(ctx).Where("family_id = ?", familyID).Delete(&models.Session{}).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

func (ls *LocalStorage) GetSessionByID(ctx context.Context, id uint) (*models.Session, error) {
	var session models.Session
	if err := ls.db.WithContext(ctx).First(&session, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Wrap the typed sentinel so callers can distinguish "absent" from a
			// transient failure (SessionLiveForToken's cache-hit deny-vs-fall-back split).
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), storage.ErrSessionNotFound)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &session, nil
}

// ListSessionsByUser returns the user's non-expired sessions, most-recently-seen first.
func (ls *LocalStorage) ListSessionsByUser(ctx context.Context, userID uint) ([]*models.Session, error) {
	// G81 (Session.ExpiresAt): normalize internally — see GetAuditLogs.
	var sessions []*models.Session
	if err := ls.db.WithContext(ctx).
		Where("user_id = ? AND (expires_at IS NULL OR expires_at > ?)", userID, time.Now().UTC()).
		Order(sqlOrderCreatedAtDesc).
		Find(&sessions).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return sessions, nil
}

func (ls *LocalStorage) DeleteSession(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Delete(&models.Session{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return nil
}

// EnforceSessionLimit keeps only the `keep` most-recent sessions for a user and deletes
// the rest, so unbounded logins can't grow the table or enlarge the credential-theft
// blast radius. No-op when the user is at or under the cap.
func (ls *LocalStorage) EnforceSessionLimit(ctx context.Context, userID uint, keep int) error {
	if keep <= 0 {
		return nil
	}
	var keepIDs []uint
	if err := ls.db.WithContext(ctx).Model(&models.Session{}).
		Where("user_id = ?", userID).
		Order(sqlOrderCreatedAtDesc).Limit(keep).Pluck("id", &keepIDs).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if len(keepIDs) < keep {
		return nil // under the cap — nothing to prune
	}
	if err := ls.db.WithContext(ctx).
		Where("user_id = ? AND id NOT IN ?", userID, keepIDs).
		Delete(&models.Session{}).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// DeleteSessionsForUserExcept removes all of the user's sessions except exceptID.
// It also removes impersonation sessions the user STARTED (impersonated_by = userID):
// an impersonation session is keyed to the target's user_id, so without this clause a
// suspend/deactivate/force-logout of the impersonating admin would leave their live
// impersonation session running until its TTL — elevated access outliving the admin.
func (ls *LocalStorage) DeleteSessionsForUserExcept(ctx context.Context, userID, exceptID uint) error {
	result := ls.db.WithContext(ctx).
		Where("(user_id = ? OR impersonated_by = ?) AND id <> ?", userID, userID, exceptID).
		Delete(&models.Session{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return nil
}

// ListSessionTokenHashesForUser returns the stored session_token hashes for every session
// the user owns or is impersonated through, for auth-cache eviction on a state change.
func (ls *LocalStorage) ListSessionTokenHashesForUser(ctx context.Context, userID uint) ([]string, error) {
	var hashes []string
	if err := ls.db.WithContext(ctx).Model(&models.Session{}).
		Where("user_id = ? OR impersonated_by = ?", userID, userID).
		Pluck("session_token", &hashes).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return hashes, nil
}

// TouchSession bumps last_seen_at only if the stored value is older than staleness
// (or NULL), keeping the auth hot path from writing on every request.
//
// #1507: this UpdateColumn write bypasses model hooks too, but unlike
// PersonalAccessToken.LastUsedAt/MachineIdentityCredential.LastUsedAt there is
// no separate consumer to diverge from — the WHERE bound and the SET value
// below both come from this function's own seenAt parameter, in the same
// call. If a future range query on last_seen_at is ever added elsewhere
// (there is none today — verified repo-wide), it would need the same
// call-site normalization the other two #1507 fields document.
func (ls *LocalStorage) TouchSession(ctx context.Context, id uint, seenAt time.Time, staleness time.Duration) error {
	cutoff := seenAt.Add(-staleness)
	return ls.db.WithContext(ctx).Model(&models.Session{}).
		Where("id = ? AND (last_seen_at IS NULL OR last_seen_at < ?)", id, cutoff).
		UpdateColumn("last_seen_at", seenAt).Error
}

// CleanupExpiredSessions hard-deletes all sessions whose expires_at is in the past.
func (ls *LocalStorage) CleanupExpiredSessions(ctx context.Context) error {
	// G81 (Session.ExpiresAt): normalize internally — see GetAuditLogs.
	return ls.db.WithContext(ctx).Where("expires_at < ?", time.Now().UTC()).Delete(&models.Session{}).Error
}

// --- Personal Access Tokens (ADR-027) ---

// CreatePersonalAccessToken inserts a PAT and, in the same transaction, re-reads
// its owning user with lockLiveParent — still active, still in a login-capable
// account_state — rolling back if it is not (#2701, INV-STORE-21).
//
// Every path that revokes a user's credentials (setAccountState's
// blocked-state sweep, DeleteUser, DeprovisionSCIMUser) row-locks the user
// FIRST and only then runs RevokeAllPersonalAccessTokensForUser, which is what
// makes the write-then-check ordering sound here: either the sweep's snapshot
// includes this row, or this re-check blocks on the sweep's lock and then sees
// the blocked state. Without it the INSERT committed with revoked=false after a
// sweep that was audited as complete — and because ReactivateUser revokes
// nothing, the routine suspend → investigate → reactivate sequence handed the
// credential back.
func (ls *LocalStorage) CreatePersonalAccessToken(ctx context.Context, t *models.PersonalAccessToken) (*models.PersonalAccessToken, error) {
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(t).Error; err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		return requireLiveCredentialOwner(tx, t.UserID)
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

// requireLiveCredentialOwner is the shared child-under-live-parent re-check for
// the two credential tables a suspend/deactivate/delete sweeps. It is one
// function rather than two call sites so the predicate — and in particular the
// account_state list — cannot drift between the PAT path and the session path.
//
// loginCapableAccountStates is the SQL counterpart of core.AccountLoginBlocked.
// They are kept in step by TestGlobalAdminLiveAccountStates_MatchAccountLoginBlocked
// (internal/core), which is why this reuses that exact slice rather than
// introducing a second list for the same predicate.
func requireLiveCredentialOwner(tx *gorm.DB, userID uint) error {
	live, err := lockLiveParent(tx, &models.User{},
		"id = ? AND is_active = ? AND account_state IN ?", userID, true, loginCapableAccountStates)
	if err != nil {
		return err
	}
	if !live {
		return fmt.Errorf("%s", i18n.T("ErrorUserNotFound", nil))
	}
	return nil
}

func (ls *LocalStorage) ListPersonalAccessTokensByUser(ctx context.Context, userID uint) ([]*models.PersonalAccessToken, error) {
	var tokens []*models.PersonalAccessToken
	if err := ls.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order(sqlOrderCreatedAtDesc).
		Find(&tokens).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return tokens, nil
}

// ListActivePersonalAccessTokens returns every non-revoked PAT, newest first — the
// deployment-wide token-hygiene view.
func (ls *LocalStorage) ListActivePersonalAccessTokens(ctx context.Context) ([]*models.PersonalAccessToken, error) {
	var tokens []*models.PersonalAccessToken
	if err := ls.db.WithContext(ctx).
		Where("revoked = ?", false).
		Order(sqlOrderCreatedAtDesc).
		Find(&tokens).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return tokens, nil
}

func (ls *LocalStorage) GetPersonalAccessTokenByID(ctx context.Context, id uint) (*models.PersonalAccessToken, error) {
	var t models.PersonalAccessToken
	if err := ls.db.WithContext(ctx).First(&t, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &t, nil
}

// GetPersonalAccessTokenByHash is the auth hot-path lookup (indexed equality on token_hash).
func (ls *LocalStorage) GetPersonalAccessTokenByHash(ctx context.Context, hash string) (*models.PersonalAccessToken, error) {
	var t models.PersonalAccessToken
	if err := ls.db.WithContext(ctx).Where("token_hash = ?", hash).First(&t).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &t, nil
}

// RevokePersonalAccessToken sets revoked = true; does not delete the record.
func (ls *LocalStorage) RevokePersonalAccessToken(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Model(&models.PersonalAccessToken{}).
		Where("id = ?", id).
		Update("revoked", true)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

// RevokeAllPersonalAccessTokensForUser revokes every not-already-revoked PAT belonging to
// the user and returns the revoked tokens' hashes so the caller can evict them from the
// auth cache immediately. Used on a password change/reset: a PAT is a parallel, longer-
// lived credential that must die with the password, or a thief who minted one from a
// stolen session would survive the reset.
func (ls *LocalStorage) RevokeAllPersonalAccessTokensForUser(ctx context.Context, userID uint) ([]string, error) {
	var hashes []string
	if err := ls.db.WithContext(ctx).Model(&models.PersonalAccessToken{}).
		Where("user_id = ? AND revoked = ?", userID, false).
		Pluck("token_hash", &hashes).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if len(hashes) == 0 {
		return nil, nil
	}
	if err := ls.db.WithContext(ctx).Model(&models.PersonalAccessToken{}).
		Where("user_id = ? AND revoked = ?", userID, false).
		Update("revoked", true).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return hashes, nil
}

// TouchPersonalAccessToken bumps last_used_at only when older than staleness (or NULL),
// keeping the auth hot path from writing on every request (mirrors TouchSession).
//
// #1507: this UpdateColumn write bypasses model hooks, so last_used_at is
// whatever Location usedAt itself carries (currently always c.now(), the same
// accessor CountStalePATs (local_hygiene_counts.go) uses to derive its own
// range-query bound) — safe ONLY as long as every last_used_at reader keeps
// using that same source. If a future range query on this column is added
// anywhere using a differently-sourced time (e.g. a raw time.Now().UTC()),
// normalize explicitly at this call site (there is no BeforeSave hook that
// can reach an UpdateColumn write) before trusting the comparison.
func (ls *LocalStorage) TouchPersonalAccessToken(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error {
	cutoff := usedAt.Add(-staleness)
	return ls.db.WithContext(ctx).Model(&models.PersonalAccessToken{}).
		Where("id = ? AND (last_used_at IS NULL OR last_used_at < ?)", id, cutoff).
		UpdateColumn("last_used_at", usedAt).Error
}

const sqlWhereExpiredPAT = "user_id = ? AND revoked = ? AND expires_at IS NOT NULL AND expires_at < ?"

// ListExpiredPATsByUser returns all non-revoked PATs for userID whose ExpiresAt is in
// the past (expired but never explicitly revoked). Ordered newest-created first.
func (ls *LocalStorage) ListExpiredPATsByUser(ctx context.Context, userID uint, now time.Time) ([]*models.PersonalAccessToken, error) {
	// G81 (PersonalAccessToken.ExpiresAt): normalize internally — see GetAuditLogs.
	now = now.UTC()
	var tokens []*models.PersonalAccessToken
	if err := ls.db.WithContext(ctx).
		Where(sqlWhereExpiredPAT, userID, false, now).
		Order(sqlOrderCreatedAtDesc).
		Find(&tokens).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return tokens, nil
}

// BulkRevokeExpiredPATsByUser revokes every non-revoked, expired PAT belonging to
// userID and returns their token hashes so the caller can evict them from the auth cache.
func (ls *LocalStorage) BulkRevokeExpiredPATsByUser(ctx context.Context, userID uint, now time.Time) ([]string, error) {
	// G81 (PersonalAccessToken.ExpiresAt): normalize internally — see GetAuditLogs.
	now = now.UTC()
	var hashes []string
	if err := ls.db.WithContext(ctx).Model(&models.PersonalAccessToken{}).
		Where(sqlWhereExpiredPAT, userID, false, now).
		Pluck("token_hash", &hashes).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if len(hashes) == 0 {
		return nil, nil
	}
	if err := ls.db.WithContext(ctx).Model(&models.PersonalAccessToken{}).
		Where(sqlWhereExpiredPAT, userID, false, now).
		Update("revoked", true).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return hashes, nil
}

// --- Setup Tokens (ADR-028) ---

func (ls *LocalStorage) CreateSetupToken(ctx context.Context, t *models.SetupToken) (*models.SetupToken, error) {
	if err := ls.db.WithContext(ctx).Create(t).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return t, nil
}

// GetSetupTokenByHash is the consumption lookup (indexed equality on token_hash).
func (ls *LocalStorage) GetSetupTokenByHash(ctx context.Context, hash string) (*models.SetupToken, error) {
	var t models.SetupToken
	if err := ls.db.WithContext(ctx).Where("token_hash = ?", hash).First(&t).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &t, nil
}

// GetSetupTokenByID looks up a setup token by primary key -- used by
// KeyorixCore.ExpireSetupTokenByID (#1622) to resolve purpose/subject detail
// for the audit write before an explicit (non-lazy-read) expiry. Unlike
// GetSetupTokenByHash, this distinguishes "no such row" from any other
// storage failure in the wrapped error text: ExpireSetupTokenByID matches on
// it to treat an unknown ID as a no-op (mirroring the raw
// MarkSetupTokenExpired UPDATE's own zero-rows-is-not-an-error semantics)
// while still surfacing a genuine DB failure as an error.
func (ls *LocalStorage) GetSetupTokenByID(ctx context.Context, id uint) (*models.SetupToken, error) {
	var t models.SetupToken
	if err := ls.db.WithContext(ctx).First(&t, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return &t, nil
}

// SupersedeActiveSetupTokens flips every active token for (purpose, email) to
// superseded so a reissue kills the prior link atomically. When projectID is
// non-nil, the flip is additionally restricted to tokens whose InvitationID
// belongs to that project (a subquery against project_invitations) — this is
// how a project-scoped invitation_accept reissue is kept from superseding a
// different project's still-pending invite to the same address
// (CORE-INVITATIONS-003). A nil projectID keeps the original unscoped
// (purpose, email) behavior for callers with no project dimension (global
// invites, account_setup, password_reset_link).
func (ls *LocalStorage) SupersedeActiveSetupTokens(ctx context.Context, purpose, email string, projectID *uint) error {
	q := ls.db.WithContext(ctx).Model(&models.SetupToken{}).
		Where("purpose = ? AND subject_email = ? AND state = ?", purpose, email, "active")
	if projectID != nil {
		q = q.Where("invitation_id IN (?)",
			ls.db.Model(&models.ProjectInvitation{}).Select("id").Where("project_id = ?", *projectID))
	}
	return q.Update("state", "superseded").Error
}

// MarkSetupTokenConsumed transitions active → consumed only if still active. The
// state guard in the WHERE clause makes consumption single-use even under a
// concurrent replay: the second caller matches zero rows and gets false.
func (ls *LocalStorage) MarkSetupTokenConsumed(ctx context.Context, id uint, consumedAt time.Time) (bool, error) {
	result := ls.db.WithContext(ctx).Model(&models.SetupToken{}).
		Where("id = ? AND state = ?", id, "active").
		Updates(map[string]interface{}{"state": "consumed", "consumed_at": consumedAt})
	if result.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return result.RowsAffected == 1, nil
}

// MarkSetupTokenExpired transitions active → expired (lazy expiry on read).
func (ls *LocalStorage) MarkSetupTokenExpired(ctx context.Context, id uint) error {
	return ls.db.WithContext(ctx).Model(&models.SetupToken{}).
		Where("id = ? AND state = ?", id, "active").
		Update("state", "expired").Error
}

// CountSetupTokensSince counts tokens minted for (purpose, email) since a cutoff,
// backing resend throttling and the daily cap.
func (ls *LocalStorage) CountSetupTokensSince(ctx context.Context, purpose, email string, since time.Time) (int64, error) {
	// G81 (SetupToken.CreatedAt): normalize internally — see GetAuditLogs.
	since = since.UTC()
	var n int64
	if err := ls.db.WithContext(ctx).Model(&models.SetupToken{}).
		Where("purpose = ? AND subject_email = ? AND created_at >= ?", purpose, email, since).
		Count(&n).Error; err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return n, nil
}
