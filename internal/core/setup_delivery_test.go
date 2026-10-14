package core

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// fakeDeliverer is a controllable CredentialDelivery for tests. When echoLink is set
// it copies the request link into LinkForAdmin (out-of-band behaviour); otherwise it
// returns the configured result verbatim.
type fakeDeliverer struct {
	called   bool
	lastReq  delivery.SetupLinkRequest
	result   delivery.DeliveryResult
	echoLink bool
	err      error
	// done, when non-nil, is closed after DeliverSetupLink returns — lets a test
	// whose caller dispatches delivery in a background goroutine (e.g.
	// RequestPasswordReset, #117) synchronize an assertion with the async work
	// instead of racing it.
	done chan struct{}
}

func (f *fakeDeliverer) DeliverSetupLink(_ context.Context, req delivery.SetupLinkRequest) (delivery.DeliveryResult, error) {
	f.called = true
	f.lastReq = req
	res := f.result
	if f.echoLink {
		res.LinkForAdmin = req.Link
	}
	if f.done != nil {
		defer close(f.done)
	}
	return res, f.err
}

func (f *fakeDeliverer) Name() string { return "fake" }

const testBaseURL = "https://keyorix.test"

func TestResendAccountSetupLink(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	uid := uint(4)
	fixed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)

	newCore := func(d delivery.CredentialDelivery) (*KeyorixCore, *MockStorage) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		c.now = func() time.Time { return fixed }
		c.SetCredentialDelivery(d, testBaseURL)
		anyAudit(ms)
		// S1 (CLI-split inventory #2012): ResendAccountSetupLink now calls the
		// admin-rank ceiling (createdBy=7 != uid=4 in every subtest below), which
		// reads the target's role scopes first -- an ordinary target (no scopes)
		// passes the ceiling trivially, matching every subtest's existing
		// success/failure expectations unchanged.
		ms.On("GetUserRoleScopes", ctx, uid).Return([]Scope{}, nil)
		return c, ms
	}
	user := func() *models.User {
		return &models.User{ID: uid, Email: "new@acme.io", DisplayName: "Dana", AccountState: AccountPendingFirstLogin}
	}

	t.Run("out-of-band returns the built link and audits the display", func(t *testing.T) {
		fake := &fakeDeliverer{echoLink: true, result: delivery.DeliveryResult{Channel: delivery.ChannelOutOfBand}}
		c, ms := newCore(fake)
		ms.On("GetUser", ctx, uid).Return(user(), nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "new@acme.io", fixed.Add(-24*time.Hour)).Return(int64(0), nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "new@acme.io", fixed.Add(-resendMinInterval)).Return(int64(0), nil)
		ms.On("SupersedeActiveSetupTokens", ctx, SetupPurposeAccountSetup, "new@acme.io", (*uint)(nil)).Return(nil)
		ms.On("CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken")).Return(&models.SetupToken{ID: 1}, nil)

		res, err := c.ResendAccountSetupLink(ctx, uid, 7)
		require.NoError(t, err)
		assert.True(t, fake.called)
		assert.Equal(t, delivery.ChannelOutOfBand, res.Channel)
		assert.False(t, res.Delivered)
		assert.True(t, strings.HasPrefix(res.LinkForAdmin, testBaseURL+"/auth/setup/"+setupPrefix),
			"link is base_url + /auth/setup/ + a kx_setup_ token, got %q", res.LinkForAdmin)
		// The out-of-band display is recorded as a human seeing a credential.
		ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
			return e.EventType == "credential.displayed_out_of_band"
		}))
	})

	t.Run("smtp delivery reports delivered with no admin link", func(t *testing.T) {
		fake := &fakeDeliverer{result: delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}}
		c, ms := newCore(fake)
		ms.On("GetUser", ctx, uid).Return(user(), nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "new@acme.io", mock.AnythingOfType("time.Time")).Return(int64(0), nil)
		ms.On("SupersedeActiveSetupTokens", ctx, SetupPurposeAccountSetup, "new@acme.io", (*uint)(nil)).Return(nil)
		ms.On("CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken")).Return(&models.SetupToken{ID: 1}, nil)

		res, err := c.ResendAccountSetupLink(ctx, uid, 7)
		require.NoError(t, err)
		assert.True(t, res.Delivered)
		assert.Empty(t, res.LinkForAdmin)
		// The recipient sees the right link in the email.
		assert.True(t, strings.HasPrefix(fake.lastReq.Link, testBaseURL+"/auth/setup/"))
	})

	t.Run("min-interval throttle blocks a too-soon resend", func(t *testing.T) {
		c, ms := newCore(&fakeDeliverer{})
		ms.On("GetUser", ctx, uid).Return(user(), nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "new@acme.io", fixed.Add(-24*time.Hour)).Return(int64(1), nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "new@acme.io", fixed.Add(-resendMinInterval)).Return(int64(1), nil)

		_, err := c.ResendAccountSetupLink(ctx, uid, 7)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "wait")
		ms.AssertNotCalled(t, "CreateSetupToken", mock.Anything, mock.Anything)
	})

	t.Run("daily-cap throttle blocks once the cap is hit", func(t *testing.T) {
		c, ms := newCore(&fakeDeliverer{})
		ms.On("GetUser", ctx, uid).Return(user(), nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "new@acme.io", fixed.Add(-24*time.Hour)).Return(int64(resendDailyCap), nil)

		_, err := c.ResendAccountSetupLink(ctx, uid, 7)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "limit")
		ms.AssertNotCalled(t, "CreateSetupToken", mock.Anything, mock.Anything)
	})

	t.Run("rejects a suspended account", func(t *testing.T) {
		c, ms := newCore(&fakeDeliverer{})
		ms.On("GetUser", ctx, uid).Return(&models.User{ID: uid, AccountState: AccountSuspended}, nil)
		_, err := c.ResendAccountSetupLink(ctx, uid, 7)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "suspended")
	})
}

func TestProvisionRequiresBaseURL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetCredentialDelivery(&fakeDeliverer{}, "") // no base URL

	req := CreateUserRequest{Username: "dana", Email: "dana@acme.io", DisplayName: "Dana"}
	_, _, err := c.CreateUserWithSetupLink(ctx, &req, 0)
	require.Error(t, err)
	// The HTTP layer maps this to a 400 ConfigError via errors.Is, so the sentinel
	// must survive the i18n-prefixed wrap.
	assert.ErrorIs(t, err, ErrSetupBaseURLRequired)
	ms.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
}

func TestCreateUserWithSetupLink(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	fixed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return fixed }
	c.SetCredentialDelivery(&fakeDeliverer{echoLink: true, result: delivery.DeliveryResult{Channel: delivery.ChannelOutOfBand}}, testBaseURL)
	anyAudit(ms)

	notFound := func() error { return assertNotFoundErr() }
	created := &models.User{ID: 9, Username: "dana", Email: "dana@acme.io", DisplayName: "Dana", AccountState: AccountPendingFirstLogin}

	ms.On("GetUserByUsername", ctx, "dana").Return(nil, notFound())
	ms.On("GetUserByEmail", ctx, "dana@acme.io").Return(nil, notFound())
	// The account is confined to pending_first_login in the SAME create — no separate
	// UpdateUser that could strand an active, unknown-password account on failure.
	ms.On("CreateUser", ctx, mock.MatchedBy(func(u *models.User) bool {
		return u.AccountState == AccountPendingFirstLogin
	})).Return(created, nil)
	ms.On("AddPasswordHistory", ctx, uint(9), mock.AnythingOfType("string"), mock.Anything).Return(nil)
	ms.On("GetRoleByName", ctx, "system_viewer").Return(nil, notFound())
	// The initial provision is throttle-checked too (#183) — a fresh email with no
	// prior tokens clears both checks.
	ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "dana@acme.io", fixed.Add(-24*time.Hour)).Return(int64(0), nil)
	ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "dana@acme.io", fixed.Add(-resendMinInterval)).Return(int64(0), nil)
	ms.On("SupersedeActiveSetupTokens", ctx, SetupPurposeAccountSetup, "dana@acme.io", (*uint)(nil)).Return(nil)
	ms.On("CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken")).Return(&models.SetupToken{ID: 1}, nil)

	user, prov, err := c.CreateUserWithSetupLink(ctx, &CreateUserRequest{
		Username: "dana", Email: "dana@acme.io", DisplayName: "Dana",
	}, 7)
	require.NoError(t, err)
	assert.Equal(t, AccountPendingFirstLogin, user.AccountState, "account is confined until the link is consumed")
	ms.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
	require.NotNil(t, prov)
	assert.True(t, strings.HasPrefix(prov.LinkForAdmin, testBaseURL+"/auth/setup/"+setupPrefix))
}

// TestCreateUserWithSetupLink_ThrottlesCreateDeleteRecreateLoop proves the #183 fix: a
// create→soft-delete→recreate loop against the SAME email must be throttled on the Nth
// attempt within the cooldown window, exactly like an explicit resend — because
// DeleteUser is an unconditional soft delete and GetUserByEmail excludes soft-deleted
// rows, the email is immediately reusable for another CreateUserWithSetupLink call, and
// without this fix each such "recreate" would look like a fresh, unthrottled initial
// provision and send another email with no cooldown and no daily cap.
func TestCreateUserWithSetupLink_ThrottlesCreateDeleteRecreateLoop(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	fixed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return fixed }
	c.SetCredentialDelivery(&fakeDeliverer{echoLink: true, result: delivery.DeliveryResult{Channel: delivery.ChannelOutOfBand}}, testBaseURL)
	anyAudit(ms)

	notFound := func() error { return assertNotFoundErr() }
	req := &CreateUserRequest{Username: "dana", Email: "dana@acme.io", DisplayName: "Dana"}

	// First create→provision succeeds (the recreated user gets a fresh row/ID after the
	// prior one was soft-deleted, but the email — and so the throttle key — is the same).
	ms.On("GetUserByUsername", ctx, "dana").Return(nil, notFound())
	ms.On("GetUserByEmail", ctx, "dana@acme.io").Return(nil, notFound())
	ms.On("CreateUser", ctx, mock.MatchedBy(func(u *models.User) bool {
		return u.AccountState == AccountPendingFirstLogin
	})).Return(&models.User{ID: 20, Username: "dana", Email: "dana@acme.io", AccountState: AccountPendingFirstLogin}, nil).Once()
	ms.On("AddPasswordHistory", ctx, uint(20), mock.AnythingOfType("string"), mock.Anything).Return(nil).Once()
	ms.On("GetRoleByName", ctx, "system_viewer").Return(nil, notFound())
	ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "dana@acme.io", fixed.Add(-24*time.Hour)).Return(int64(0), nil).Once()
	ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "dana@acme.io", fixed.Add(-resendMinInterval)).Return(int64(0), nil).Once()
	ms.On("SupersedeActiveSetupTokens", ctx, SetupPurposeAccountSetup, "dana@acme.io", (*uint)(nil)).Return(nil).Once()
	ms.On("CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken")).Return(&models.SetupToken{ID: 1}, nil).Once()

	_, prov1, err := c.CreateUserWithSetupLink(ctx, req, 7)
	require.NoError(t, err)
	require.NotNil(t, prov1)

	// Simulate the soft-delete: the recreated account is a "new" user again as far as
	// CreateUser's own checks are concerned (GetUserByUsername/Email miss again), but the
	// setup-token store — keyed on the raw email, independent of the user row — now
	// reflects the one token just issued, so the throttle must fire on this second attempt.
	ms.On("GetUserByUsername", ctx, "dana").Return(nil, notFound())
	ms.On("GetUserByEmail", ctx, "dana@acme.io").Return(nil, notFound())
	ms.On("CreateUser", ctx, mock.MatchedBy(func(u *models.User) bool {
		return u.AccountState == AccountPendingFirstLogin
	})).Return(&models.User{ID: 21, Username: "dana", Email: "dana@acme.io", AccountState: AccountPendingFirstLogin}, nil).Once()
	ms.On("AddPasswordHistory", ctx, uint(21), mock.AnythingOfType("string"), mock.Anything).Return(nil).Once()
	ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "dana@acme.io", fixed.Add(-24*time.Hour)).Return(int64(1), nil).Once()
	ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "dana@acme.io", fixed.Add(-resendMinInterval)).Return(int64(1), nil).Once()

	_, prov2, err := c.CreateUserWithSetupLink(ctx, req, 7)
	require.Error(t, err, "the recreate must be throttled by the still-live min-interval window")
	assert.Contains(t, err.Error(), "wait")
	assert.Nil(t, prov2)
	// Throttled means no second setup token was minted and no second email sent.
	ms.AssertNumberOfCalls(t, "CreateSetupToken", 1)
}

func TestCreateUserWithOneTimePassword(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	anyAudit(ms)

	notFound := func() error { return assertNotFoundErr() }
	created := &models.User{ID: 11, Username: "dana", Email: "dana@acme.io", DisplayName: "Dana", AccountState: AccountPasswordResetRequired}

	ms.On("GetUserByUsername", ctx, "dana").Return(nil, notFound())
	ms.On("GetUserByEmail", ctx, "dana@acme.io").Return(nil, notFound())
	// The account is created directly in password_reset_required — the admin holds the
	// first credential, so the user must change it on first login.
	var captured *models.User
	ms.On("CreateUser", ctx, mock.MatchedBy(func(u *models.User) bool {
		return u.AccountState == AccountPasswordResetRequired
	})).Run(func(args mock.Arguments) { captured = args.Get(1).(*models.User) }).Return(created, nil)
	ms.On("AddPasswordHistory", ctx, uint(11), mock.AnythingOfType("string"), mock.Anything).Return(nil)
	ms.On("GetRoleByName", ctx, "system_viewer").Return(nil, notFound())

	user, otp, err := c.CreateUserWithOneTimePassword(ctx, &CreateUserRequest{
		Username: "dana", Email: "dana@acme.io", DisplayName: "Dana",
	}, 7)
	require.NoError(t, err)
	assert.Equal(t, AccountPasswordResetRequired, user.AccountState, "account must change the credential on first login")
	ms.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
	require.NotNil(t, otp)
	assert.Equal(t, "dana@acme.io", otp.Email)
	// The returned OTP satisfies the default policy and is exactly what was hashed and
	// stored — so it actually authenticates (then hits the password-change gate).
	require.NoError(t, DefaultPasswordPolicy().Validate(otp.OTPValue, nil))
	require.NotNil(t, captured)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(captured.PasswordHash), []byte(otp.OTPValue)),
		"the displayed OTP must be the one persisted")
	// The out-of-band display is recorded as a human seeing a credential.
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "credential.displayed_out_of_band" && strings.Contains(e.Description, "one_time_password")
	}))
}

func TestGenerateInitialCredential(t *testing.T) {
	t.Parallel()
	policy := DefaultPasswordPolicy()
	seen := map[string]bool{}
	for range 50 {
		pw, err := GenerateInitialCredential()
		require.NoError(t, err)
		assert.Len(t, pw, otpLength)
		require.NoError(t, policy.Validate(pw, nil), "every generated OTP must satisfy the default password policy")
		assert.False(t, seen[pw], "OTPs must be unique")
		seen[pw] = true
	}
}

// helpers ---------------------------------------------------------------------

// assertNotFoundErr mirrors the real storage "not found" error (wrapping the typed
// storage.ErrUserNotFound sentinel, same as LocalStorage's GetUser/GetUserByEmail/
// GetUserByUsername/etc., #504) so the mock is detected the same way CreateUser's
// "does this user already exist?" probes detect the real thing.
func assertNotFoundErr() error {
	return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), storage.ErrUserNotFound)
}
