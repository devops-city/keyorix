package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

const identityFailClosedTestPassword = "Secret#Passw0rd!"

const totpStepDuration = 30 * time.Second

// newIdentityFailClosedTestHandler builds an AuthHandler over a FaultyStorage-
// wrapped LocalStorage, with MFA enrolled and activated for user "alice" (id 1).
// Each call gets its own private in-memory DB (sqlitetest.Open, a unique
// shared-cache name with the pool capped to one connection) so
// concurrent/sequential test functions in this file never collide over user id
// 1 — and so the detached goSafe audit writes a request dispatches cannot
// collide with this test's own reads over SQLite's shared-cache table locks
// (#2906: "database table is locked", which a busy timeout cannot retry).
// Returns the handler, the fault wrapper (initially unarmed — a pure pass-
// through), the TOTP secret, a clock ONE STEP PAST activation's own code (so
// the caller's first verify code doesn't collide with the step
// ActivateMFA's own anti-replay check already consumed), and the backing
// *gorm.DB so a test can inspect what a request actually left behind in storage.
func newIdentityFailClosedTestHandler(t *testing.T) (*AuthHandler, *faultstorage.FaultyStorage, string, time.Time, *gorm.DB) {
	t.Helper()
	db := sqlitetest.Open(t, "kxidentityfailclosed")
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.MFASecret{}, &models.MFARecoveryCode{}, &models.MFAChallenge{},
		&models.Session{}, &models.AuditEvent{}, &models.MFAStepupToken{}, &models.MFAStepUpGrant{},
		&models.LoginAttempt{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{},
	))

	hash, err := bcrypt.GenerateFromPassword([]byte(identityFailClosedTestPassword), bcrypt.DefaultCost)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "alice", UsernameFolded: "alice", Email: "alice@example.com", EmailFolded: "alice@example.com",
		PasswordHash: string(hash), AccountState: "active",
	}).Error)

	real := store.NewLocalStorage(db)
	fs := faultstorage.NewFaultyStorage(real, nil)
	c := core.NewKeyorixCore(fs)

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))
	c.SetAuthEncryptor(enc)

	activationTime := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c.SetClockForTesting(func() time.Time { return activationTime })

	ctx := context.Background()
	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, activationTime)
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, actCode, identityFailClosedTestPassword, "")
	require.NoError(t, err)

	// Advance one full TOTP step past activation's own code so a verify call
	// using "fixed" below presents a step ActivateMFA's anti-replay check
	// (MarkTOTPStepUsed) never touched.
	fixed := activationTime.Add(totpStepDuration)
	c.SetClockForTesting(func() time.Time { return fixed })

	return NewAuthHandler(c, false), fs, secret, fixed, db
}

func postVerifyMFA(t *testing.T, h *AuthHandler, challenge, code string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"mfa_challenge": challenge, "code": code})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.VerifyMFA(w, req)
	return w
}

// TestVerifyMFA_GetUserPermissionsError_FailsClosed reproduces #2412 (CI fuzzing
// on PR #2392, FuzzStorageFaultOperations input c67f27: "REST POST
// /auth/mfa/verify", fault "GetUserPermissions#1/error", oracle (c)): a storage
// error resolving the user's permissions must not produce a 200 with a live
// session indistinguishable from a legitimate empty-permissions grant.
//
// Confirmed red on the unfixed handler (buildLoginResponse swallowing the
// GetUserIdentity error, `if id, ierr := ...; ierr == nil`): the request still
// returns 200 "Login successful" with Permissions: [] in the body, AND the
// session minted by VerifyMFALogin is left live in storage — a fully
// functional, fully authenticated session an attacker-observed storage blip
// handed out with no indication anything failed.
//
// WHERE the fault now fires changed with #2841, and the end-to-end assertions
// below did NOT: the identity read moved from buildLoginResponse (after
// VerifyMFALogin had already minted a session, which completeLogin then
// revoked) into VerifyMFALogin itself, before its first write. So the
// zero-session assertion that used to prove "the minted session was revoked"
// now proves "no session was ever minted" — a strictly stronger outcome,
// reached without the revoke. #2412's own property, that this request must not
// report success, is unchanged and still the thing under test; the zero-session
// assertion is kept because it holds either way and would catch a regression in
// EITHER mechanism. (The revoke path itself is still live and still covered —
// Login and ConsumeSetup never moved, see buildLoginResponse's own callers.)
func TestVerifyMFA_GetUserPermissionsError_FailsClosed(t *testing.T) {
	h, fs, secret, fixed, db := newIdentityFailClosedTestHandler(t)
	ctx := context.Background()

	ch, err := h.coreService.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	fs.Arm(&faultstorage.FaultSpec{
		Method: "GetUserPermissions", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("simulated: permission lookup unavailable"),
	})

	w := postVerifyMFA(t, h, ch, code)

	// #2888 (#2740 option C): completeLogin no longer writes its own distinct
	// 500 here -- a storage error reached only once the credential was ALREADY
	// confirmed correct must look byte-identical to a wrong credential (401),
	// or the status code itself becomes a correctness oracle during a storage
	// hiccup. "Fail closed" is still the property under test (not 200, no
	// session, no data payload) -- which status represents that is not.
	assert.Equal(t, http.StatusUnauthorized, w.Code, "a GetUserPermissions storage error must fail closed (401, identical to a wrong code), not 200")
	assert.True(t, fs.Fired(), "the armed fault must actually have fired on GetUserPermissions")

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, false, body["success"], "the response must self-report failure, not success")
	assert.NotContains(t, body, "data", "no session/identity payload may be handed back when identity resolution failed")

	// The literal symptom this test guards against is a session surviving as a
	// live, usable grant after a request that reported failure. Before #2841
	// that meant "minted, then revoked by completeLogin"; since #2841 the
	// identity read runs before the mint, so it means "never minted". Either
	// way the row count must be zero — see this test's doc comment.
	var sessionCount int64
	require.NoError(t, db.Model(&models.Session{}).Where("user_id = ?", 1).Count(&sessionCount).Error)
	assert.Zero(t, sessionCount, "no live session may survive a request that reported failure")
}

// TestVerifyMFA_GetUserPermissionsError_FailsClosed_ThenClears confirms the
// fault-clears half of red/green: once the storage fault is gone, a fresh,
// never-before-used code still verifies normally and yields a real, live
// session with populated permissions — the fail-closed path above is not a
// permanent lockout.
func TestVerifyMFA_GetUserPermissionsError_FailsClosed_ThenClears(t *testing.T) {
	h, fs, secret, fixed, db := newIdentityFailClosedTestHandler(t)
	ctx := context.Background()

	// First attempt: fault armed, fails closed (same assertion as above, kept
	// minimal here since it's fully covered by the previous test).
	ch1, err := h.coreService.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	code1, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	fs.Arm(&faultstorage.FaultSpec{
		Method: "GetUserPermissions", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("simulated: permission lookup unavailable"),
	})
	w1 := postVerifyMFA(t, h, ch1, code1)
	require.NotEqual(t, http.StatusOK, w1.Code)

	var sessionCount int64
	require.NoError(t, db.Model(&models.Session{}).Where("user_id = ?", 1).Count(&sessionCount).Error)
	require.Zero(t, sessionCount, "setup: no session may survive the faulted attempt")

	// Second attempt, one TOTP step later (the first step was already consumed
	// by VerifyMFALogin's anti-replay marking, even though the overall request
	// failed) with the fault cleared: a fresh challenge + fresh code must
	// verify normally and leave a live session with real permissions behind.
	fs.Arm(nil)
	laterStep := fixed.Add(30 * time.Second)
	ch2, err := h.coreService.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	code2, err := totp.GenerateCode(secret, laterStep)
	require.NoError(t, err)
	h.coreService.SetClockForTesting(func() time.Time { return laterStep })

	w2 := postVerifyMFA(t, h, ch2, code2)
	require.Equal(t, http.StatusOK, w2.Code, "once the storage fault clears, a fresh correct code must still verify")

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &body))
	data, _ := body["data"].(map[string]interface{})
	require.NotNil(t, data, "expected a data envelope in the success response")
	assert.NotEmpty(t, data["token"], "a successful verify must hand back a session token")

	require.NoError(t, db.Model(&models.Session{}).Where("user_id = ?", 1).Count(&sessionCount).Error)
	assert.Equal(t, int64(1), sessionCount, "the successful second attempt must leave exactly one live session")
}

// TestBuildLoginResponse_IdentityError_PropagatesAndMintsNothing exercises
// buildLoginResponse directly — originally the single function shared by all
// five login-completion handlers, confirming the #2412 fix lived in the one
// place they shared rather than only in VerifyMFA's call site.
//
// Its callers are now Login and ConsumeSetup only: #2841 moved the other three
// (VerifyMFA, FinishWebAuthnLogin, FinishWebAuthnPasswordlessLogin) to resolve
// the identity inside core, before their first write, because each of those
// also writes something user-scoped after minting that completeLogin's
// session-only revoke never undid. So this test now covers two call sites, not
// five; the other three are covered at the core boundary by
// internal/core/login_identity_before_mint_test.go.
func TestBuildLoginResponse_IdentityError_PropagatesAndMintsNothing(t *testing.T) {
	h, fs, _, _, _ := newIdentityFailClosedTestHandler(t)

	fs.Arm(&faultstorage.FaultSpec{
		Method: "GetUserPermissions", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("simulated: permission lookup unavailable"),
	})

	resp, err := h.buildLoginResponse(context.Background(), &models.Session{SessionToken: "irrelevant"}, &models.User{Username: "alice"})
	require.Error(t, err, "a GetUserIdentity failure must propagate as an error, not be swallowed")
	assert.Equal(t, loginResponseBody{}, resp, "an error return must not carry a partially-built response")
}
