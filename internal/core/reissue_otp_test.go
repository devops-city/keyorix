package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// REISSUE-1: an administrator issues a new one-time password for an existing user.

const reissueTargetOldPassword = "Tr1cky-Passphrase-For-Tests!"

type reissueFixture struct {
	c      *KeyorixCore
	st     *store.LocalStorage
	admin  *models.User
	target *models.User
}

func newReissueFixture(t *testing.T) *reissueFixture {
	t.Helper()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	admin, err := st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	target, err := c.CreateUser(ctx, &CreateUserRequest{
		Username: "reissue-target", Email: "reissue-target@example.com",
		DisplayName: "Reissue Target", Password: reissueTargetOldPassword,
	})
	require.NoError(t, err)
	return &reissueFixture{c: c, st: st, admin: admin, target: target}
}

func (f *reissueFixture) reload(t *testing.T, id uint) *models.User {
	t.Helper()
	u, err := f.st.GetUser(context.Background(), id)
	require.NoError(t, err)
	return u
}

func (f *reissueFixture) auditDescriptions(t *testing.T, eventType string) []string {
	t.Helper()
	logs, _, err := f.st.GetAuditLogs(context.Background(), &storage.AuditFilter{Actions: []string{eventType}})
	require.NoError(t, err)
	var out []string
	for _, e := range logs {
		out = append(out, e.Description)
	}
	return out
}

func TestReissueOneTimePassword_IssuesAUsableExpiringRestrictedCredential(t *testing.T) {
	f := newReissueFixture(t)
	ctx := context.Background()
	fixed := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	f.c.now = func() time.Time { return fixed }
	f.c.SetOneTimePasswordExpiry(6 * time.Hour)

	res, err := f.c.ReissueOneTimePassword(ctx, f.admin.ID, f.target.ID)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.NotEmpty(t, res.OTPValue)
	assert.Equal(t, f.target.Email, res.Email)
	assert.True(t, res.ExpiresAt.Equal(fixed.Add(6*time.Hour)), "applies the OTP-EXPIRY-1 TTL: %s", res.ExpiresAt)

	u := f.reload(t, f.target.ID)
	assert.Equal(t, AccountPasswordResetRequired, u.AccountState, "same restricted first-login state as a new one-time-password user")
	require.NotNil(t, u.OneTimePasswordExpiresAt)
	assert.True(t, u.OneTimePasswordExpiresAt.Equal(res.ExpiresAt))
	assert.NotContains(t, u.PasswordHash, res.OTPValue)

	// The old password no longer works; the new one does, into the restricted state.
	_, _, err = f.c.Login(ctx, &LoginRequest{Username: "reissue-target", Password: reissueTargetOldPassword})
	require.Error(t, err, "the previous password is superseded")
	_, _, err = f.c.Login(ctx, &LoginRequest{Username: "reissue-target", Password: res.OTPValue})
	require.NoError(t, err, "the reissued one-time password logs in")
}

func TestReissueOneTimePassword_ExpiredAfterTTL(t *testing.T) {
	f := newReissueFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	f.c.now = func() time.Time { return now }

	res, err := f.c.ReissueOneTimePassword(ctx, f.admin.ID, f.target.ID)
	require.NoError(t, err)
	assert.True(t, res.ExpiresAt.Equal(now.Add(DefaultOneTimePasswordExpiry)), "default TTL when none is configured")

	now = now.Add(DefaultOneTimePasswordExpiry + time.Second)
	_, _, err = f.c.Login(ctx, &LoginRequest{Username: "reissue-target", Password: res.OTPValue})
	require.EqualError(t, err, "invalid credentials", "an expired reissued password is refused like a wrong one")
}

func TestReissueOneTimePassword_EndsSessionsAndClearsLockout(t *testing.T) {
	f := newReissueFixture(t)
	ctx := context.Background()

	expires := time.Now().Add(time.Hour)
	for _, tok := range []string{"reissue-sess-a", "reissue-sess-b"} {
		_, err := f.st.CreateSession(ctx, &models.Session{UserID: f.target.ID, SessionToken: tok, CreatedAt: time.Now(), ExpiresAt: &expires})
		require.NoError(t, err)
	}
	_, err := f.st.CreateSession(ctx, &models.Session{UserID: f.admin.ID, SessionToken: "admin-keeps-this", CreatedAt: time.Now(), ExpiresAt: &expires})
	require.NoError(t, err)
	until := time.Now().Add(time.Hour)
	require.NoError(t, f.st.UpdateLoginLockoutState(ctx, f.target.ID, 5, &until, &until, 2))

	var evicted []string
	f.c.SetTokenCacheInvalidator(func(h string) { evicted = append(evicted, h) })

	_, err = f.c.ReissueOneTimePassword(ctx, f.admin.ID, f.target.ID)
	require.NoError(t, err)

	left, err := f.st.ListSessionsByUser(ctx, f.target.ID)
	require.NoError(t, err)
	assert.Empty(t, left, "every existing session of the user ends")
	adminLeft, err := f.st.ListSessionsByUser(ctx, f.admin.ID)
	require.NoError(t, err)
	assert.Len(t, adminLeft, 1, "the acting admin's own session is untouched")
	// CreateSession stores the SHA-256 of the token, and that hash is the auth-cache key.
	hashOf := func(tok string) string { s := sha256.Sum256([]byte(tok)); return hex.EncodeToString(s[:]) }
	assert.Subset(t, evicted, []string{hashOf("reissue-sess-a"), hashOf("reissue-sess-b")}, "revoked sessions leave the auth cache at once")
	assert.NotContains(t, evicted, hashOf("admin-keeps-this"))

	u := f.reload(t, f.target.ID)
	assert.Nil(t, u.LoginLockedUntil, "a locked-out user can use the new password")
}

// PATs: the reissue follows what an admin-forced password reset already does
// (RequirePasswordReset): the account becomes restricted and every PAT is evicted from
// the auth cache so it stops working at once, but PATs are not deleted -- they are
// revoked when the user replaces the one-time password (applyNewPassword).
func TestReissueOneTimePassword_PATsFollowAdminPasswordReset(t *testing.T) {
	f := newReissueFixture(t)
	ctx := context.Background()
	_, err := f.st.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{UserID: f.target.ID, Name: "ci", TokenHash: "pat-hash-1", CreatedAt: time.Now()})
	require.NoError(t, err)
	var evicted []string
	f.c.SetTokenCacheInvalidator(func(h string) { evicted = append(evicted, h) })

	_, err = f.c.ReissueOneTimePassword(ctx, f.admin.ID, f.target.ID)
	require.NoError(t, err)

	assert.Contains(t, evicted, "pat-hash-1", "the PAT is evicted from the auth cache so the restriction applies to it immediately")
	pats, err := f.st.ListPersonalAccessTokensByUser(ctx, f.target.ID)
	require.NoError(t, err)
	require.Len(t, pats, 1)
	assert.False(t, pats[0].Revoked, "same as RequirePasswordReset: not deleted by the reissue itself")
}

func TestReissueOneTimePassword_AuditsActorAndTargetNeverThePassword(t *testing.T) {
	f := newReissueFixture(t)
	ctx := context.Background()

	res, err := f.c.ReissueOneTimePassword(ctx, f.admin.ID, f.target.ID)
	require.NoError(t, err)

	logs, _, err := f.st.GetAuditLogs(ctx, &storage.AuditFilter{Actions: []string{EventUserOneTimePasswordReissued}})
	require.NoError(t, err)
	require.Len(t, logs, 1)
	require.NotNil(t, logs[0].UserID)
	assert.Equal(t, f.admin.ID, *logs[0].UserID, "actor is the administrator")
	assert.Contains(t, logs[0].Description, fmt.Sprintf("user %d", f.target.ID), "target is named")
	assert.Contains(t, logs[0].Description, res.ExpiresAt.UTC().Format(time.RFC3339))

	// The password must appear in no audit row at all.
	all, _, err := f.st.GetAuditLogs(ctx, &storage.AuditFilter{})
	require.NoError(t, err)
	for _, e := range all {
		assert.False(t, strings.Contains(e.Description, res.OTPValue), "audit event %q leaks the password", e.EventType)
	}
}

func TestReissueOneTimePassword_RefusesOwnAccount(t *testing.T) {
	f := newReissueFixture(t)
	ctx := context.Background()
	before := f.reload(t, f.admin.ID)

	_, err := f.c.ReissueOneTimePassword(ctx, f.admin.ID, f.admin.ID)
	require.ErrorIs(t, err, ErrCannotActOnSelf)

	after := f.reload(t, f.admin.ID)
	assert.Equal(t, before.PasswordHash, after.PasswordHash, "nothing was written")
	assert.Equal(t, before.AccountState, after.AccountState)
	assert.Empty(t, f.auditDescriptions(t, EventUserOneTimePasswordReissued))
}

func TestReissueOneTimePassword_RefusesSSOOnlyUser(t *testing.T) {
	f := newReissueFixture(t)
	ctx := context.Background()
	sso, err := f.c.CreateUser(ctx, &CreateUserRequest{
		Username: "sso-user", Email: "sso-user@example.com", DisplayName: "SSO", Password: reissueTargetOldPassword,
	})
	require.NoError(t, err)
	sso.ExternalID = "sso:corp:corp|123" // JIT/SCIM-provisioned, provider-scoped
	_, err = f.st.UpdateUser(ctx, sso)
	require.NoError(t, err)
	before := f.reload(t, sso.ID)

	_, err = f.c.ReissueOneTimePassword(ctx, f.admin.ID, sso.ID)
	require.ErrorIs(t, err, ErrReissueExternalIdentity)

	after := f.reload(t, sso.ID)
	assert.Equal(t, before.PasswordHash, after.PasswordHash, "an SSO user must not gain a local password")
	assert.Equal(t, before.AccountState, after.AccountState)
	assert.Nil(t, after.OneTimePasswordExpiresAt)
}

func TestReissueOneTimePassword_RefusesSuspendedUser(t *testing.T) {
	f := newReissueFixture(t)
	ctx := context.Background()
	require.NoError(t, f.c.SuspendUser(ctx, f.admin.ID, f.target.ID))
	before := f.reload(t, f.target.ID)

	_, err := f.c.ReissueOneTimePassword(ctx, f.admin.ID, f.target.ID)
	require.ErrorIs(t, err, ErrReissueAccountBlocked, "a reissue must not silently reactivate a suspended account")

	after := f.reload(t, f.target.ID)
	assert.Equal(t, AccountSuspended, after.AccountState)
	assert.Equal(t, before.PasswordHash, after.PasswordHash)
}

func TestReissueOneTimePassword_RefusesMissingUserAndNoActor(t *testing.T) {
	f := newReissueFixture(t)
	ctx := context.Background()

	_, err := f.c.ReissueOneTimePassword(ctx, f.admin.ID, 99999)
	require.Error(t, err)
	_, err = f.c.ReissueOneTimePassword(ctx, f.admin.ID, 0)
	require.Error(t, err)
	// actor 0 is a machine/unauthenticated sentinel, never a human decision.
	_, err = f.c.ReissueOneTimePassword(ctx, 0, f.target.ID)
	require.Error(t, err)
}

// An actor who does not outrank the target must not be able to take the target's
// account over by reissuing its password (admin-rank ceiling, same as every other
// mutation of another user's account).
func TestReissueOneTimePassword_AdminRankCeiling(t *testing.T) {
	f := newReissueFixture(t)
	ctx := context.Background()
	// target (no admin rights) tries to reissue the bootstrapped administrator's password.
	before := f.reload(t, f.admin.ID)

	_, err := f.c.ReissueOneTimePassword(ctx, f.target.ID, f.admin.ID)
	require.ErrorIs(t, err, ErrInsufficientAdminAuthority)

	after := f.reload(t, f.admin.ID)
	assert.Equal(t, before.PasswordHash, after.PasswordHash, "no takeover of a higher-privileged account")
	assert.Equal(t, before.AccountState, after.AccountState)
}

func TestReissueOneTimePassword_KeepsAnEnrolledSecondFactor(t *testing.T) {
	f := newReissueFixture(t)
	ctx := context.Background()
	require.NoError(t, f.st.SetUserMFAEnabled(ctx, f.target.ID, true))

	_, err := f.c.ReissueOneTimePassword(ctx, f.admin.ID, f.target.ID)
	require.NoError(t, err)

	assert.True(t, f.reload(t, f.target.ID).MFAEnabled,
		"a reissue must not strip MFA: otherwise a users.write holder could take over an MFA-protected account")
}

// A storage fault on the row lock is not a missing user: the transports map a
// not-found error to 404 / NotFound, so the fault must not carry that sentinel or
// that text (it is a 500 / Internal), and nothing is written. A real missing user
// still carries storage.ErrUserNotFound.
func TestReissueOneTimePassword_LockFaultIsNotUserNotFound(t *testing.T) {
	f := newReissueFixture(t)
	ctx := context.Background()
	before := f.reload(t, f.target.ID)

	base := f.c.storage
	fs := faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
		Method: "LockUserForUpdate", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected: LockUserForUpdate"),
	})
	f.c.storage = fs
	_, err := f.c.ReissueOneTimePassword(ctx, f.admin.ID, f.target.ID)
	f.c.storage = base

	require.True(t, fs.Fired(), "the reissue's row lock must have been reached")
	require.Error(t, err)
	assert.NotErrorIs(t, err, storage.ErrUserNotFound)
	assert.NotContains(t, strings.ToLower(err.Error()), "not found", "a storage fault must not read as a missing user: %v", err)
	after := f.reload(t, f.target.ID)
	assert.Equal(t, before.PasswordHash, after.PasswordHash, "nothing was written")
	assert.Equal(t, before.AccountState, after.AccountState)

	_, err = f.c.ReissueOneTimePassword(ctx, f.admin.ID, 99999)
	require.ErrorIs(t, err, storage.ErrUserNotFound, "a real missing user keeps the typed sentinel")
}
