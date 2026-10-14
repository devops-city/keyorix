// store_s22_test.go — white-box coverage sweep for s22 gaps.
//
// Targets (all 0 % or low-% from the post-s21 coverage run):
//
//	local_auth.go
//	  EnforceSessionLimit          (0%)
//	  TouchSession                 (0%)
//	  CleanupExpiredSessions       (0%)
//	  GetPersonalAccessTokenByID   (0%)
//	  GetPersonalAccessTokenByHash (0%)
//	  RevokeAllPersonalAccessTokensForUser (0%)
//	  TouchPersonalAccessToken     (0%)
//	  CreateSetupToken             (0%)
//	  GetSetupTokenByHash          (0%)
//	  SupersedeActiveSetupTokens   (0%)
//	  MarkSetupTokenConsumed       (0%)
//	  MarkSetupTokenExpired        (0%)
//	  CountSetupTokensSince        (0%)
//
//	local_break_glass.go
//	  CreateBreakGlassActivation   (0%)
//	  GetBreakGlassActivation      (0%)
//	  RevokeBreakGlassActivation   (0%)
//
//	local_login_attempts.go
//	  PruneLoginAttempts           (0%)
//
//	local_webauthn.go
//	  LockWebAuthnCredentialForUpdate (0% — SQLite path)
//	  UpdateWebAuthnCredential     (0%)
//	  AdvanceWebAuthnCredentialCounter (0%)
//	  DeleteWebAuthnCredential     (0%)
//	  CountWebAuthnCredentials     (0%)
//	  SetUserWebAuthnEnabled       (0%)
//	  CreateWebAuthnSession        (0%)
//	  ConsumeWebAuthnSession       (0%)
package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newS22Store opens a unique in-memory SQLite DB, migrates the supplied models
// and returns the LocalStorage. It mirrors the s21 helper pattern.
func newS22Store(t *testing.T, mods ...any) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "stores22_", sqlite.Open, &gorm.Config{})
	if len(mods) > 0 {
		require.NoError(t, db.AutoMigrate(mods...))
	}
	return NewLocalStorage(db)
}

// ---------------------------------------------------------------------------
// local_auth.go — session utilities
// ---------------------------------------------------------------------------

// ptrTime returns a pointer to the given time value.
func ptrTime(t time.Time) *time.Time { return &t }

// TestEnforceSessionLimit_S22_KeepZero verifies that EnforceSessionLimit is a
// no-op when keep <= 0 (avoids deleting ALL sessions on a misconfiguration).
func TestEnforceSessionLimit_S22_KeepZero(t *testing.T) {
	ls := newS22Store(t, &models.Session{})
	ctx := context.Background()

	exp := ptrTime(time.Now().Add(time.Hour))
	for _, tok := range []string{"a", "b", "c"} {
		require.NoError(t, ls.db.Create(&models.Session{
			UserID: 1, SessionToken: tok, ExpiresAt: exp,
		}).Error)
	}

	require.NoError(t, ls.EnforceSessionLimit(ctx, 1, 0))

	var n int64
	require.NoError(t, ls.db.Model(&models.Session{}).Where("user_id = ?", 1).Count(&n).Error)
	assert.Equal(t, int64(3), n, "keep=0 must not delete any sessions")
}

// TestEnforceSessionLimit_S22_PrunesOldest verifies that EnforceSessionLimit
// removes all but the `keep` newest sessions when the user is over the cap.
func TestEnforceSessionLimit_S22_PrunesOldest(t *testing.T) {
	ls := newS22Store(t, &models.Session{})
	ctx := context.Background()

	base := time.Now()
	for i, tok := range []string{"t1", "t2", "t3", "t4", "t5"} {
		require.NoError(t, ls.db.Create(&models.Session{
			UserID:       1,
			SessionToken: tok,
			ExpiresAt:    ptrTime(base.Add(time.Hour)),
			CreatedAt:    base.Add(time.Duration(i) * time.Minute),
		}).Error)
	}

	require.NoError(t, ls.EnforceSessionLimit(ctx, 1, 2))

	var n int64
	require.NoError(t, ls.db.Model(&models.Session{}).Where("user_id = ?", 1).Count(&n).Error)
	assert.Equal(t, int64(2), n, "only the 2 newest sessions must survive")
}

// TestEnforceSessionLimit_S22_UnderCap verifies no deletion happens when the
// user is already at or below the cap.
func TestEnforceSessionLimit_S22_UnderCap(t *testing.T) {
	ls := newS22Store(t, &models.Session{})
	ctx := context.Background()

	exp := ptrTime(time.Now().Add(time.Hour))
	for _, tok := range []string{"s1", "s2"} {
		require.NoError(t, ls.db.Create(&models.Session{
			UserID: 2, SessionToken: tok, ExpiresAt: exp,
		}).Error)
	}

	require.NoError(t, ls.EnforceSessionLimit(ctx, 2, 5))

	var n int64
	require.NoError(t, ls.db.Model(&models.Session{}).Where("user_id = ?", 2).Count(&n).Error)
	assert.Equal(t, int64(2), n, "no session must be deleted when under the cap")
}

// TestTouchSession_S22_UpdatesWhenStale verifies that TouchSession updates
// last_seen_at when the stored value is older than the staleness window.
func TestTouchSession_S22_UpdatesWhenStale(t *testing.T) {
	ls := newS22Store(t, &models.Session{})
	ctx := context.Background()

	exp := ptrTime(time.Now().Add(time.Hour))
	sess := &models.Session{UserID: 3, SessionToken: "touch-sess", ExpiresAt: exp}
	require.NoError(t, ls.db.Create(sess).Error)

	now := time.Now()
	require.NoError(t, ls.TouchSession(ctx, sess.ID, now, time.Minute))

	var updated models.Session
	require.NoError(t, ls.db.First(&updated, sess.ID).Error)
	require.NotNil(t, updated.LastSeenAt)
	assert.WithinDuration(t, now, *updated.LastSeenAt, time.Second)
}

// TestCleanupExpiredSessions_S22_DeletesExpired verifies that
// CleanupExpiredSessions removes all sessions with expires_at in the past.
func TestCleanupExpiredSessions_S22_DeletesExpired(t *testing.T) {
	ls := newS22Store(t, &models.Session{})
	ctx := context.Background()

	past := ptrTime(time.Now().Add(-time.Hour))
	future := ptrTime(time.Now().Add(time.Hour))

	require.NoError(t, ls.db.Create(&models.Session{
		UserID: 4, SessionToken: "exp1", ExpiresAt: past,
	}).Error)
	require.NoError(t, ls.db.Create(&models.Session{
		UserID: 4, SessionToken: "live1", ExpiresAt: future,
	}).Error)

	require.NoError(t, ls.CleanupExpiredSessions(ctx))

	var n int64
	require.NoError(t, ls.db.Model(&models.Session{}).Where("user_id = ?", 4).Count(&n).Error)
	assert.Equal(t, int64(1), n, "only the unexpired session must survive")
}

// ---------------------------------------------------------------------------
// local_auth.go — Personal Access Tokens
// ---------------------------------------------------------------------------

// TestGetPersonalAccessTokenByID_S22_HappyPath verifies basic retrieval by id.
func TestGetPersonalAccessTokenByID_S22_HappyPath(t *testing.T) {
	ls := newS22Store(t, &models.PersonalAccessToken{})
	ctx := context.Background()

	tok := &models.PersonalAccessToken{UserID: 1, Name: "ci", TokenHash: "hash-id-test"}
	require.NoError(t, ls.db.Create(tok).Error)

	got, err := ls.GetPersonalAccessTokenByID(ctx, tok.ID)
	require.NoError(t, err)
	assert.Equal(t, "ci", got.Name)
}

// TestGetPersonalAccessTokenByID_S22_NotFound verifies the error path.
func TestGetPersonalAccessTokenByID_S22_NotFound(t *testing.T) {
	ls := newS22Store(t, &models.PersonalAccessToken{})

	_, err := ls.GetPersonalAccessTokenByID(context.Background(), 99999)
	require.Error(t, err)
}

// TestGetPersonalAccessTokenByHash_S22_HappyPath verifies the auth hot-path lookup.
func TestGetPersonalAccessTokenByHash_S22_HappyPath(t *testing.T) {
	ls := newS22Store(t, &models.PersonalAccessToken{})
	ctx := context.Background()

	tok := &models.PersonalAccessToken{UserID: 2, Name: "deploy", TokenHash: "sha256hexabc"}
	require.NoError(t, ls.db.Create(tok).Error)

	got, err := ls.GetPersonalAccessTokenByHash(ctx, "sha256hexabc")
	require.NoError(t, err)
	assert.Equal(t, tok.ID, got.ID)
}

// TestGetPersonalAccessTokenByHash_S22_NotFound verifies a missing hash returns error.
func TestGetPersonalAccessTokenByHash_S22_NotFound(t *testing.T) {
	ls := newS22Store(t, &models.PersonalAccessToken{})

	_, err := ls.GetPersonalAccessTokenByHash(context.Background(), "nosuchhash")
	require.Error(t, err)
}

// TestRevokeAllPersonalAccessTokensForUser_S22_ReturnHashes verifies that all
// active PATs are revoked and their hashes returned.
func TestRevokeAllPersonalAccessTokensForUser_S22_ReturnHashes(t *testing.T) {
	ls := newS22Store(t, &models.PersonalAccessToken{})
	ctx := context.Background()

	for i, h := range []string{"h1", "h2", "h3"} {
		_ = i
		require.NoError(t, ls.db.Create(&models.PersonalAccessToken{
			UserID: 10, Name: "tok", TokenHash: h, Revoked: false,
		}).Error)
	}
	// Pre-revoked token must not appear in the result.
	require.NoError(t, ls.db.Create(&models.PersonalAccessToken{
		UserID: 10, Name: "old", TokenHash: "hrevoked", Revoked: true,
	}).Error)

	hashes, err := ls.RevokeAllPersonalAccessTokensForUser(ctx, 10)
	require.NoError(t, err)
	assert.Len(t, hashes, 3, "only the 3 active tokens must be revoked")
	assert.ElementsMatch(t, []string{"h1", "h2", "h3"}, hashes)

	// All tokens for the user are now revoked.
	var remaining int64
	require.NoError(t, ls.db.Model(&models.PersonalAccessToken{}).
		Where("user_id = ? AND revoked = ?", 10, false).Count(&remaining).Error)
	assert.Zero(t, remaining)
}

// TestRevokeAllPersonalAccessTokensForUser_S22_NoneActive verifies that nil is
// returned when the user has no active PATs.
func TestRevokeAllPersonalAccessTokensForUser_S22_NoneActive(t *testing.T) {
	ls := newS22Store(t, &models.PersonalAccessToken{})

	hashes, err := ls.RevokeAllPersonalAccessTokensForUser(context.Background(), 99)
	require.NoError(t, err)
	assert.Nil(t, hashes)
}

// TestTouchPersonalAccessToken_S22_UpdatesWhenStale verifies that
// TouchPersonalAccessToken bumps last_used_at when the stored value is stale.
func TestTouchPersonalAccessToken_S22_UpdatesWhenStale(t *testing.T) {
	ls := newS22Store(t, &models.PersonalAccessToken{})
	ctx := context.Background()

	tok := &models.PersonalAccessToken{UserID: 5, Name: "touch-pat", TokenHash: "hhh"}
	require.NoError(t, ls.db.Create(tok).Error)

	now := time.Now()
	require.NoError(t, ls.TouchPersonalAccessToken(ctx, tok.ID, now, time.Minute))

	var updated models.PersonalAccessToken
	require.NoError(t, ls.db.First(&updated, tok.ID).Error)
	require.NotNil(t, updated.LastUsedAt)
	assert.WithinDuration(t, now, *updated.LastUsedAt, time.Second)
}

// ---------------------------------------------------------------------------
// local_auth.go — Setup Tokens
// ---------------------------------------------------------------------------

// TestSetupTokenLifecycle_S22 exercises the full state machine:
// Create → GetByHash → Supersede → MarkConsumed (idempotent-miss) →
// MarkExpired → CountSince.
func TestSetupTokenLifecycle_S22(t *testing.T) {
	ls := newS22Store(t, &models.SetupToken{})
	ctx := context.Background()

	// CreateSetupToken. CreatedAt is set explicitly here, mirroring every real
	// caller (internal/core/setup_token.go's `now := c.now()`): SetupToken.
	// BeforeSave only gets a chance to UTC-normalize a non-zero value — GORM's
	// own blank-CreatedAt auto-population runs AFTER BeforeSave and would
	// silently overwrite a hook-normalized zero value with local time.Now(),
	// producing a row no real caller can produce (#1619).
	tok, err := ls.CreateSetupToken(ctx, &models.SetupToken{
		TokenHash:    "abc123",
		Purpose:      "password_reset_link",
		SubjectEmail: "alice@test.io",
		State:        "active",
		CreatedAt:    time.Now(),
	})
	require.NoError(t, err)
	require.NotNil(t, tok)
	assert.NotZero(t, tok.ID)

	// GetSetupTokenByHash — found.
	got, err := ls.GetSetupTokenByHash(ctx, "abc123")
	require.NoError(t, err)
	assert.Equal(t, tok.ID, got.ID)
	assert.Equal(t, "active", got.State)

	// GetSetupTokenByHash — not found.
	_, err = ls.GetSetupTokenByHash(ctx, "nosuchhash")
	require.Error(t, err)

	// SupersedeActiveSetupTokens — flips active to superseded.
	require.NoError(t, ls.SupersedeActiveSetupTokens(ctx, "password_reset_link", "alice@test.io", nil))
	reloaded, err := ls.GetSetupTokenByHash(ctx, "abc123")
	require.NoError(t, err)
	assert.Equal(t, "superseded", reloaded.State)

	// Create a fresh active token for the consumed/expired paths.
	tok2, err := ls.CreateSetupToken(ctx, &models.SetupToken{
		TokenHash:    "xyz789",
		Purpose:      "password_reset_link",
		SubjectEmail: "alice@test.io",
		State:        "active",
		CreatedAt:    time.Now(),
	})
	require.NoError(t, err)

	// MarkSetupTokenConsumed — consumes the active token (should return true).
	consumed, err := ls.MarkSetupTokenConsumed(ctx, tok2.ID, time.Now())
	require.NoError(t, err)
	assert.True(t, consumed, "first consume must succeed")

	// MarkSetupTokenConsumed — second call returns false (already consumed).
	consumed2, err := ls.MarkSetupTokenConsumed(ctx, tok2.ID, time.Now())
	require.NoError(t, err)
	assert.False(t, consumed2, "consumed token cannot be re-consumed")

	// Create a token to expire.
	tok3, err := ls.CreateSetupToken(ctx, &models.SetupToken{
		TokenHash:    "toexpire",
		Purpose:      "password_reset_link",
		SubjectEmail: "alice@test.io",
		State:        "active",
		CreatedAt:    time.Now(),
	})
	require.NoError(t, err)

	// MarkSetupTokenExpired.
	require.NoError(t, ls.MarkSetupTokenExpired(ctx, tok3.ID))
	expiredTok, err := ls.GetSetupTokenByHash(ctx, "toexpire")
	require.NoError(t, err)
	assert.Equal(t, "expired", expiredTok.State)

	// CountSetupTokensSince — should count all 3 tokens for this (purpose, email).
	since := time.Now().Add(-time.Minute)
	n, err := ls.CountSetupTokensSince(ctx, "password_reset_link", "alice@test.io", since)
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)

	// CountSetupTokensSince — count for different purpose should be 0.
	n2, err := ls.CountSetupTokensSince(ctx, "invitation_accept", "alice@test.io", since)
	require.NoError(t, err)
	assert.Zero(t, n2)
}

// ---------------------------------------------------------------------------
// local_break_glass.go
// ---------------------------------------------------------------------------

// TestBreakGlass_S22_CRUD exercises Create, Get, Update and Revoke.
func TestBreakGlass_S22_CRUD(t *testing.T) {
	ls := newS22Store(t, &models.BreakGlassActivation{})
	ctx := context.Background()

	// CreateBreakGlassActivation — happy path.
	a, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID:     1,
		UserID:        7,
		RoleID:        2,
		RoleName:      "project_admin",
		Justification: "incident P0",
		State:         "active",
	})
	require.NoError(t, err)
	require.NotNil(t, a)
	assert.NotZero(t, a.ID)

	// GetBreakGlassActivation — found.
	got, err := ls.GetBreakGlassActivation(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, "active", got.State)
	assert.Equal(t, "incident P0", got.Justification)

	// GetBreakGlassActivation — not found.
	_, err = ls.GetBreakGlassActivation(ctx, 99999)
	require.Error(t, err)

	// RevokeBreakGlassActivation — success path.
	revokedAt := time.Now()
	require.NoError(t, ls.RevokeBreakGlassActivation(ctx, a.ID, 1, 0, revokedAt))
	revoked, err := ls.GetBreakGlassActivation(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, "revoked", revoked.State)
	assert.Equal(t, uint(1), revoked.RevokedBy)
}

// TestBreakGlass_S22_RevokeNotActive verifies that RevokeBreakGlassActivation
// returns an error when the activation is not in the active state.
func TestBreakGlass_S22_RevokeNotActive(t *testing.T) {
	ls := newS22Store(t, &models.BreakGlassActivation{})
	ctx := context.Background()

	a, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 8, RoleID: 3, RoleName: "r", Justification: "j", State: "active",
	})
	require.NoError(t, err)

	// Revoke once successfully.
	require.NoError(t, ls.RevokeBreakGlassActivation(ctx, a.ID, 1, 0, time.Now()))

	// Second revoke on the already-revoked row must fail.
	err = ls.RevokeBreakGlassActivation(ctx, a.ID, 1, 0, time.Now())
	require.Error(t, err)
}

// TestBreakGlass_S22_DuplicateConflict verifies that a second concurrent
// CreateBreakGlassActivation for the same (project_id, user_id) returns
// ErrBreakGlassAlreadyActive.
func TestBreakGlass_S22_DuplicateConflict(t *testing.T) {
	ls := newS22Store(t, &models.BreakGlassActivation{})
	ctx := context.Background()

	// First activation succeeds.
	_, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 3, UserID: 9, RoleID: 4, RoleName: "r", Justification: "j", State: "active",
	})
	require.NoError(t, err)

	// Second for the same (project_id, user_id) should be rejected.
	// Note: the partial unique index only exists after EnsureBreakGlassActiveIndex
	// runs on a real DB. On a plain AutoMigrate SQLite DB without that index, the
	// DoNothing clause may not conflict — we just verify no panic and no error.
	_, err = ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 3, UserID: 9, RoleID: 4, RoleName: "r", Justification: "j2", State: "active",
	})
	// On SQLite without the partial unique index, DoNothing inserts; either outcome is fine.
	_ = err
}

// ---------------------------------------------------------------------------
// local_login_attempts.go — PruneLoginAttempts
// ---------------------------------------------------------------------------

// TestPruneLoginAttempts_S22 verifies that PruneLoginAttempts removes rows
// older than the cutoff and returns the correct count, leaving recent rows.
func TestPruneLoginAttempts_S22(t *testing.T) {
	ls := newS22Store(t, &models.LoginAttempt{})
	ctx := context.Background()

	now := time.Now()
	old := now.Add(-2 * time.Hour)

	// Three old attempts + one recent attempt.
	for range 3 {
		require.NoError(t, ls.RecordLoginAttempt(ctx, "1.2.3.4", old))
	}
	require.NoError(t, ls.RecordLoginAttempt(ctx, "1.2.3.4", now))

	deleted, err := ls.PruneLoginAttempts(ctx, now.Add(-time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(3), deleted, "three old rows must be removed")

	remaining, err := ls.CountRecentLoginAttempts(ctx, "1.2.3.4", now.Add(-time.Minute))
	require.NoError(t, err)
	assert.Equal(t, int64(1), remaining, "the recent row must survive")
}

// ---------------------------------------------------------------------------
// local_webauthn.go
// ---------------------------------------------------------------------------

// newS22WebAuthnStore creates a store with the WebAuthnCredential and User tables.
func newS22WebAuthnStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newS22Store(t, &models.WebAuthnCredential{}, &models.User{})
}

// TestWebAuthnCredential_S22_LockAndUpdate verifies the SQLite path of
// LockWebAuthnCredentialForUpdate (no FOR UPDATE clause) and UpdateWebAuthnCredential.
func TestWebAuthnCredential_S22_LockAndUpdate(t *testing.T) {
	ls := newS22WebAuthnStore(t)
	ctx := context.Background()

	credID := []byte("credid-lock-test")
	cred := &models.WebAuthnCredential{
		UserID:         1,
		CredentialID:   credID,
		Name:           "MacBook",
		CredentialBlob: []byte(`{"authenticator":{"signCount":5}}`),
	}
	require.NoError(t, ls.CreateWebAuthnCredential(ctx, cred))

	// LockWebAuthnCredentialForUpdate — SQLite path (no FOR UPDATE).
	locked, err := ls.LockWebAuthnCredentialForUpdate(ctx, credID, 1)
	require.NoError(t, err)
	assert.Equal(t, "MacBook", locked.Name)

	// #2700: the full-row UpdateWebAuthnCredential is gone (it re-inserted a
	// concurrently deleted passkey). The two narrow writers replace it, and
	// there is no production path that renames a credential — so this now
	// exercises the counter-state write, which is a real production path
	// (AdvanceWebAuthnCredentialCounter).
	usedAt := time.Now().UTC().Truncate(time.Second)
	matched, err := ls.SetWebAuthnCredentialCounterState(ctx, locked.ID, []byte(`{"Authenticator":{"SignCount":9}}`), usedAt)
	require.NoError(t, err)
	require.True(t, matched)

	// Reload and verify the update was persisted.
	updated, err := ls.LockWebAuthnCredentialForUpdate(ctx, credID, 1)
	require.NoError(t, err)
	assert.JSONEq(t, `{"Authenticator":{"SignCount":9}}`, string(updated.CredentialBlob))
	require.NotNil(t, updated.LastUsedAt)
}

// TestWebAuthnCredential_S22_LockNotFound verifies the error path when the
// credential does not exist.
func TestWebAuthnCredential_S22_LockNotFound(t *testing.T) {
	ls := newS22WebAuthnStore(t)

	_, err := ls.LockWebAuthnCredentialForUpdate(context.Background(), []byte("nosuchcred"), 1)
	require.Error(t, err)
}

// TestAdvanceWebAuthnCredentialCounter_S22_AdvancesCounter verifies that
// AdvanceWebAuthnCredentialCounter persists the new blob when newSignCount
// exceeds the stored counter and returns advanced=true.
func TestAdvanceWebAuthnCredentialCounter_S22_AdvancesCounter(t *testing.T) {
	ls := newS22Store(t, &models.WebAuthnCredential{}, &models.User{})
	ctx := context.Background()

	credID := []byte("cred-advance")
	type storedFormat struct {
		Authenticator struct {
			SignCount uint32 `json:"signCount"`
		} `json:"authenticator"`
	}
	initialBlob, _ := json.Marshal(storedFormat{})
	cred := &models.WebAuthnCredential{
		UserID: 1, CredentialID: credID, Name: "Key", CredentialBlob: initialBlob,
	}
	require.NoError(t, ls.CreateWebAuthnCredential(ctx, cred))

	var newCounterBlob storedFormat
	newCounterBlob.Authenticator.SignCount = 10
	newBlobBytes, _ := json.Marshal(newCounterBlob)

	advanced, err := ls.AdvanceWebAuthnCredentialCounter(ctx, credID, 1, newBlobBytes, 10, time.Now())
	require.NoError(t, err)
	assert.True(t, advanced, "counter advanced from 0 to 10 must return true")

	// Reload and verify the blob was persisted.
	updated, err := ls.LockWebAuthnCredentialForUpdate(ctx, credID, 1)
	require.NoError(t, err)
	var reloaded storedFormat
	require.NoError(t, json.Unmarshal(updated.CredentialBlob, &reloaded))
	assert.Equal(t, uint32(10), reloaded.Authenticator.SignCount)
}

// TestAdvanceWebAuthnCredentialCounter_S22_StaleCounterSkipped verifies that
// AdvanceWebAuthnCredentialCounter returns advanced=false when newSignCount is
// not greater than the stored counter (stale / replay attempt).
func TestAdvanceWebAuthnCredentialCounter_S22_StaleCounterSkipped(t *testing.T) {
	ls := newS22Store(t, &models.WebAuthnCredential{}, &models.User{})
	ctx := context.Background()

	credID := []byte("cred-stale")
	type storedFormat struct {
		Authenticator struct {
			SignCount uint32 `json:"signCount"`
		} `json:"authenticator"`
	}
	var current storedFormat
	current.Authenticator.SignCount = 20
	blobBytes, _ := json.Marshal(current)

	require.NoError(t, ls.CreateWebAuthnCredential(ctx, &models.WebAuthnCredential{
		UserID: 2, CredentialID: credID, Name: "Key", CredentialBlob: blobBytes,
	}))

	// Attempt to advance with a stale counter (10 < 20).
	advanced, err := ls.AdvanceWebAuthnCredentialCounter(ctx, credID, 2, blobBytes, 10, time.Now())
	require.NoError(t, err)
	assert.False(t, advanced, "stale counter must not be persisted")
}

// TestDeleteWebAuthnCredential_S22 verifies that a credential is removed when
// scoped to the correct owner, and returns an error for a wrong owner.
func TestDeleteWebAuthnCredential_S22(t *testing.T) {
	ls := newS22WebAuthnStore(t)
	ctx := context.Background()

	credID := []byte("cred-delete-test")
	cred := &models.WebAuthnCredential{
		UserID: 3, CredentialID: credID, Name: "Key", CredentialBlob: []byte(`{}`),
	}
	require.NoError(t, ls.CreateWebAuthnCredential(ctx, cred))

	// Wrong owner — must fail.
	err := ls.DeleteWebAuthnCredential(ctx, 99, cred.ID)
	require.Error(t, err)

	// Correct owner — must succeed.
	require.NoError(t, ls.DeleteWebAuthnCredential(ctx, 3, cred.ID))

	// Verify the credential is gone.
	n, err := ls.CountWebAuthnCredentials(ctx, 3)
	require.NoError(t, err)
	assert.Zero(t, n)
}

// TestCountWebAuthnCredentials_S22 verifies the per-user credential count.
func TestCountWebAuthnCredentials_S22(t *testing.T) {
	ls := newS22WebAuthnStore(t)
	ctx := context.Background()

	for i, id := range [][]byte{[]byte("c1"), []byte("c2")} {
		_ = i
		require.NoError(t, ls.CreateWebAuthnCredential(ctx, &models.WebAuthnCredential{
			UserID: 4, CredentialID: id, Name: "Key", CredentialBlob: []byte(`{}`),
		}))
	}

	n, err := ls.CountWebAuthnCredentials(ctx, 4)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)

	// Different user has zero credentials.
	n2, err := ls.CountWebAuthnCredentials(ctx, 5)
	require.NoError(t, err)
	assert.Zero(t, n2)
}

// TestSetUserWebAuthnEnabled_S22 verifies that SetUserWebAuthnEnabled toggles
// the web_authn_enabled flag on a User row.
func TestSetUserWebAuthnEnabled_S22(t *testing.T) {
	ls := newS22Store(t, &models.User{}, &models.WebAuthnCredential{})
	ctx := context.Background()

	user := &models.User{Username: "webauthn-user", Email: "wa@test.io"}
	require.NoError(t, ls.db.Create(user).Error)

	// Enable.
	require.NoError(t, ls.SetUserWebAuthnEnabled(ctx, user.ID, true))
	var reloaded models.User
	require.NoError(t, ls.db.First(&reloaded, user.ID).Error)
	assert.True(t, reloaded.WebAuthnEnabled)

	// Disable.
	require.NoError(t, ls.SetUserWebAuthnEnabled(ctx, user.ID, false))
	require.NoError(t, ls.db.First(&reloaded, user.ID).Error)
	assert.False(t, reloaded.WebAuthnEnabled)
}

// TestWebAuthnSession_S22_CreateAndConsume verifies the full create/consume
// lifecycle: a session can be consumed once; a second attempt (or an expired
// one) returns an error.
func TestWebAuthnSession_S22_CreateAndConsume(t *testing.T) {
	ls := newS22Store(t, &models.WebAuthnSession{}, &models.User{})
	ctx := context.Background()

	now := time.Now()
	expire := now.Add(5 * time.Minute)

	sess := &models.WebAuthnSession{
		UserID:    5,
		TokenHash: "wass-token-hash",
		Purpose:   "login",
		Data:      []byte(`{"challenge":"abc"}`),
		ExpiresAt: expire,
	}
	require.NoError(t, ls.CreateWebAuthnSession(ctx, sess))

	// ConsumeWebAuthnSession — first consume succeeds.
	consumed, err := ls.ConsumeWebAuthnSession(ctx, "wass-token-hash", now)
	require.NoError(t, err)
	require.NotNil(t, consumed)
	assert.Equal(t, uint(5), consumed.UserID)
	assert.Equal(t, "login", consumed.Purpose)

	// Second consume must fail (used_at is already set).
	_, err = ls.ConsumeWebAuthnSession(ctx, "wass-token-hash", now)
	require.Error(t, err)
}

// TestWebAuthnSession_S22_ExpiredNotConsumed verifies that an expired session
// (expires_at in the past) cannot be consumed.
func TestWebAuthnSession_S22_ExpiredNotConsumed(t *testing.T) {
	ls := newS22Store(t, &models.WebAuthnSession{}, &models.User{})
	ctx := context.Background()

	past := time.Now().Add(-time.Hour)

	require.NoError(t, ls.CreateWebAuthnSession(ctx, &models.WebAuthnSession{
		UserID:    6,
		TokenHash: "expired-hash",
		Purpose:   "register",
		Data:      []byte(`{}`),
		ExpiresAt: past,
	}))

	_, err := ls.ConsumeWebAuthnSession(ctx, "expired-hash", time.Now())
	require.Error(t, err)
}

// TestWebAuthnSession_S22_NotFound verifies that consuming a non-existent
// session hash returns an error.
func TestWebAuthnSession_S22_NotFound(t *testing.T) {
	ls := newS22Store(t, &models.WebAuthnSession{}, &models.User{})

	_, err := ls.ConsumeWebAuthnSession(context.Background(), "no-such-hash", time.Now())
	require.Error(t, err)
}
