// login_completion_identical_response_test.go — the HTTP-level, byte-for-byte
// proof of #2888's rule for the three login handlers
// login_lockout_no_oracle_test.go cannot reach: FinishWebAuthnLogin,
// FinishWebAuthnPasswordlessLogin and ConsumeSetup.
//
// Same comparison as that file: drive the endpoint once with a credential that
// genuinely fails, once with a credential that genuinely succeeds but whose
// completeLogin then faults, and require the two responses to be
// indistinguishable — status, body bytes, headers — plus the same lockout cost
// where the path has one.
//
// The WebAuthn cases need a CRYPTOGRAPHICALLY VALID assertion, which is why
// they live in their own file: the handlers package's existing
// ltWebAuthnCredentialJSON is a hand-rolled fake that can never verify, so the
// NoneES256 spec vectors are reproduced here (the same ones
// internal/core/webauthn_spec_vectors_test.go uses, from go-webauthn's own
// suite) with the relying party configured for their baked-in RPID/origin
// "example.org". Without a verifying assertion there is no post-verdict window
// to fault at all, and the test would prove nothing.
package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// NoneES256 login spec vector, verbatim from go-webauthn's test suite (RPID
// "example.org"), mirroring internal/core/webauthn_spec_vectors_test.go.
const (
	wcAuthenticatorDataHex = "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000"
	wcClientDataJSONHex    = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
	wcSignatureHex         = "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87"
	wcCredentialIDHex      = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4" //nolint:gosec
	wcChallengeHex         = "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408"
	wcCredentialPubKeyHex  = "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
)

func wcHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// wcAssertionJSON returns the raw PublicKeyCredential JSON the HTTP handlers
// accept, plus the base64url challenge it was signed against. With
// tamperSignature the assertion is well-formed but cannot verify — the
// wrong-credential control.
func wcAssertionJSON(t *testing.T, tamperSignature bool) (json.RawMessage, string) {
	t.Helper()
	id := base64.RawURLEncoding.EncodeToString(wcHex(t, wcCredentialIDHex))
	sig := wcHex(t, wcSignatureHex)
	if tamperSignature {
		sig[len(sig)-1] ^= 0xff
	}
	body := map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"response": map[string]any{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(wcHex(t, wcAuthenticatorDataHex)),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(wcHex(t, wcClientDataJSONHex)),
			"signature":         base64.RawURLEncoding.EncodeToString(sig),
		},
	}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	return raw, base64.RawURLEncoding.EncodeToString(wcHex(t, wcChallengeHex))
}

func wcWebAuthnID(userID uint) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(userID))
	return b
}

// newWebAuthnCompletionEnv builds an AuthHandler over a fault-wrapped store,
// with user 1 holding the spec vector's passkey and the lockout policy enabled.
func newWebAuthnCompletionEnv(t *testing.T) (*AuthHandler, *faultstorage.FaultyStorage, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))
	// A NAMED shared-cache in-memory DB, not a bare ":memory:": gorm pools
	// connections, and a bare ":memory:" gives every new connection its own
	// empty database -- which shows up under full-package load as
	// "no such table: sessions" partway through a test.
	dsn := fmt.Sprintf("file:kxwacompletion%d?mode=memory&cache=shared&_timeout=30000", wcDBCounter.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.AuditEvent{},
		&models.MFAChallenge{}, &models.WebAuthnCredential{}, &models.WebAuthnSession{}, &models.Notification{},
		&models.LoginAttempt{}, &models.MFAStepupToken{}, &models.MFAStepUpGrant{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{}))
	// One connection per in-memory DB: a shared-cache SQLite database serves
	// concurrent connections with SQLITE_LOCKED ("database table is locked"),
	// which busy_timeout does not retry. These tests need no concurrency, so
	// capping the pool keeps them from adding contention to a package that
	// already runs a lot of SQLite in parallel.
	if sqlDB, derr := db.DB(); derr == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "alice", UsernameFolded: "alice", Email: "a@b.com", EmailFolded: "a@b.com",
		IsActive: true, AccountState: "active",
	}).Error)

	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	c := core.NewKeyorixCore(fs)
	c.SetLoginLockoutPolicy(core.LoginLockoutPolicy{
		Enabled: true, MaxAttempts: 3, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour,
	})
	rp, err := webauthn.New(&webauthn.Config{
		RPID: "example.org", RPDisplayName: "Keyorix", RPOrigins: []string{"https://example.org"},
	})
	require.NoError(t, err)
	c.SetWebAuthn(rp)

	// The spec vector's credential, with the Flags its authenticatorData
	// actually asserts (a mismatch is its own rejection).
	blob, err := json.Marshal(webauthn.Credential{
		ID:        wcHex(t, wcCredentialIDHex),
		PublicKey: wcHex(t, wcCredentialPubKeyHex),
		Flags:     webauthn.CredentialFlags{UserPresent: true, BackupEligible: true},
	})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.WebAuthnCredential{
		UserID: 1, CredentialID: wcHex(t, wcCredentialIDHex), Name: "yubikey", CredentialBlob: blob,
	}).Error)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("web_authn_enabled", true).Error)
	return NewAuthHandler(c, false), fs, db
}

// wcSeedCeremony inserts a ceremony session row carrying the spec vector's
// challenge, as Begin* would — written directly rather than through core so
// this test needs no testing-only exported method. Mirrors
// seedWebAuthnLoginCeremony in webauthn_finish_storage_error_test.go.
func wcSeedCeremony(t *testing.T, db *gorm.DB, challenge string, userID uint, purpose string) string {
	t.Helper()
	sd := &webauthn.SessionData{Challenge: challenge}
	if purpose != "passwordless" {
		// A DISCOVERABLE login must leave SessionData.UserID empty: the user
		// comes out of the authenticator's userHandle, and a pre-set UserID makes
		// the library reject the ceremony. Every other purpose pins the user.
		sd.UserID = wcWebAuthnID(1)
	}
	data, err := json.Marshal(sd)
	require.NoError(t, err)
	token := fmt.Sprintf("wc-%s-%s", purpose, challenge)
	sum := sha256.Sum256([]byte(token))
	require.NoError(t, db.Create(&models.WebAuthnSession{
		UserID: userID, TokenHash: hex.EncodeToString(sum[:]), Purpose: purpose, Data: data,
		ExpiresAt: time.Now().Add(10 * time.Minute), CreatedAt: time.Now(),
	}).Error)
	return token
}

type httpObservation struct {
	status  int
	body    string
	headers http.Header
	lockout lockoutColumns
}

type lockoutColumns struct {
	failedAttempts int
	locked         bool
	lockoutCount   int
}

func observeHTTP(t *testing.T, db *gorm.DB, w *httptest.ResponseRecorder) httpObservation {
	t.Helper()
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	return httpObservation{
		status: w.Code, body: w.Body.String(), headers: w.Result().Header.Clone(),
		lockout: lockoutColumns{
			failedAttempts: u.FailedLoginAttempts,
			locked:         u.LoginLockedUntil != nil,
			lockoutCount:   u.LoginLockoutCount,
		},
	}
}

func requireIdenticalResponse(t *testing.T, control, probe httpObservation, what string) {
	t.Helper()
	assert.Equal(t, control.status, probe.status, "%s: status differs -- the status code is a correctness oracle", what)
	assert.Equal(t, control.body, probe.body, "%s: body differs byte-for-byte", what)
	assert.Equal(t, control.headers, probe.headers, "%s: headers differ", what)
	assert.Equal(t, control.lockout, probe.lockout, "%s: lockout accounting differs (#2894)", what)
}

// --- POST /auth/webauthn/login/finish ----------------------------------------

func postFinishWebAuthnLogin(t *testing.T, h *AuthHandler, challenge, sessionToken string, cred json.RawMessage) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"mfa_challenge": challenge, "webauthn_session": sessionToken, "credential": cred,
	})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/auth/webauthn/login/finish", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.FinishWebAuthnLogin(w, r)
	return w
}

// TestFinishWebAuthnLogin_CompleteLoginFaultIsIdenticalToAFailedAssertion:
// the fault is on GetUserPermissions, i.e. inside completeLogin's identity
// read — the transport-owned post-verdict window, reached only once the
// assertion has already verified.
func TestFinishWebAuthnLogin_CompleteLoginFaultIsIdenticalToAFailedAssertion(t *testing.T) {
	// Control: a tampered assertion.
	ch, fsc, dbc := newWebAuthnCompletionEnv(t)
	badCred, challenge := wcAssertionJSON(t, true)
	cchal, err := ch.coreService.CreateMFAChallenge(context.Background(), 1)
	require.NoError(t, err)
	ctok := wcSeedCeremony(t, dbc, challenge, 1, "login")
	control := observeHTTP(t, dbc, postFinishWebAuthnLogin(t, ch, cchal, ctok, badCred))
	require.Equal(t, http.StatusUnauthorized, control.status, "control: a tampered assertion must be 401")
	require.False(t, fsc.Fired(), "control: no fault was armed")

	// Probe: a valid assertion, faulted in completeLogin.
	ph, fsp, dbp := newWebAuthnCompletionEnv(t)
	goodCred, challenge2 := wcAssertionJSON(t, false)
	pchal, err := ph.coreService.CreateMFAChallenge(context.Background(), 1)
	require.NoError(t, err)
	ptok := wcSeedCeremony(t, dbp, challenge2, 1, "login")
	fsp.Arm(&faultstorage.FaultSpec{
		Method: "GetUserPermissions", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError,
	})
	w := postFinishWebAuthnLogin(t, ph, pchal, ptok, goodCred)
	require.True(t, fsp.Fired(), "the armed GetUserPermissions fault must have fired -- if not, the assertion never verified and this test proves nothing")
	probe := observeHTTP(t, dbp, w)

	requireIdenticalResponse(t, control, probe, "webauthn-login/completeLogin")

	var sessions int64
	require.NoError(t, dbp.Model(&models.Session{}).Count(&sessions).Error)
	assert.Zero(t, sessions, "the session minted before the identity fault must be revoked")
}

// --- POST /auth/webauthn/passwordless/finish ---------------------------------

func postFinishPasswordless(t *testing.T, h *AuthHandler, sessionToken string, cred json.RawMessage) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"webauthn_session": sessionToken, "credential": cred})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/auth/webauthn/passwordless/finish", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.FinishWebAuthnPasswordlessLogin(w, r)
	return w
}

func TestFinishWebAuthnPasswordlessLogin_CompleteLoginFaultIsIdenticalToAFailedAssertion(t *testing.T) {
	ch, _, dbc := newWebAuthnCompletionEnv(t)
	badCred, challenge := wcAssertionJSONWithUserHandle(t, true)
	ctok := wcSeedCeremony(t, dbc, challenge, 0, "passwordless")
	control := observeHTTP(t, dbc, postFinishPasswordless(t, ch, ctok, badCred))
	require.Equal(t, http.StatusUnauthorized, control.status, "control: a tampered assertion must be 401")

	ph, fsp, dbp := newWebAuthnCompletionEnv(t)
	goodCred, challenge2 := wcAssertionJSONWithUserHandle(t, false)
	ptok := wcSeedCeremony(t, dbp, challenge2, 0, "passwordless")
	fsp.Arm(&faultstorage.FaultSpec{
		Method: "GetUserPermissions", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError,
	})
	w := postFinishPasswordless(t, ph, ptok, goodCred)
	require.True(t, fsp.Fired(), "the armed GetUserPermissions fault must have fired")
	probe := observeHTTP(t, dbp, w)

	requireIdenticalResponse(t, control, probe, "webauthn-passwordless/completeLogin")

	var sessions int64
	require.NoError(t, dbp.Model(&models.Session{}).Count(&sessions).Error)
	assert.Zero(t, sessions, "the session minted before the identity fault must be revoked")
}

// wcAssertionJSONWithUserHandle is wcAssertionJSON plus the userHandle a
// DISCOVERABLE (passwordless) assertion carries — that is how the passwordless
// path resolves which account is logging in.
func wcAssertionJSONWithUserHandle(t *testing.T, tamperSignature bool) (json.RawMessage, string) {
	t.Helper()
	raw, challenge := wcAssertionJSON(t, tamperSignature)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))
	resp, _ := body["response"].(map[string]any)
	resp["userHandle"] = base64.RawURLEncoding.EncodeToString(wcWebAuthnID(1))
	out, err := json.Marshal(body)
	require.NoError(t, err)
	return out, challenge
}

// --- POST /auth/setup/consume ------------------------------------------------

// TestConsumeSetup_CompleteLoginFaultIsIdenticalToADeadToken: the setup-token
// path has no per-account lockout stake (it authenticates a one-shot token, and
// never feeds the failed-login counter on any branch), so the property here is
// the RESPONSE only — but that half matters just as much, because a distinct
// error would confirm that this particular token was genuinely valid.
func TestConsumeSetup_CompleteLoginFaultIsIdenticalToADeadToken(t *testing.T) {
	// Control: a token that does not exist.
	ch, _, dbc := newSetupConsumeCompletionEnv(t)
	control := observeSetupHTTP(t, dbc, postConsumeSetup(t, ch, "no-such-setup-token", "Kx#Vr9$Mn2!Zp4@Qw"))
	require.Equal(t, http.StatusBadRequest, control.status, "control: a dead token must be 400")

	// Probe: a real token and a policy-passing password, faulted in completeLogin.
	ph, fsp, dbp := newSetupConsumeCompletionEnv(t)
	plain := issueAccountSetupToken(t, ph, "bob@example.com")
	fsp.Arm(&faultstorage.FaultSpec{
		Method: "GetUserPermissions", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError,
	})
	w := postConsumeSetup(t, ph, plain, "Kx#Vr9$Mn2!Zp4@Qw")
	require.True(t, fsp.Fired(), "the armed GetUserPermissions fault must have fired -- if not, the token was never actually consumed")
	probe := observeSetupHTTP(t, dbp, w)

	assert.Equal(t, control.status, probe.status, "setup-consume: status differs -- a distinct error confirms the token was valid")
	assert.Equal(t, control.body, probe.body, "setup-consume: body differs byte-for-byte")
	assert.Equal(t, control.headers, probe.headers, "setup-consume: headers differ")

	var sessions int64
	require.NoError(t, dbp.Model(&models.Session{}).Count(&sessions).Error)
	assert.Zero(t, sessions, "the session minted before the identity fault must be revoked")
}

func postConsumeSetup(t *testing.T, h *AuthHandler, token, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"token": token, "password": password})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/auth/setup/consume", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ConsumeSetup(w, r)
	return w
}

// observeSetupHTTP is observeHTTP without the user row: the setup-consume
// control never touches user 1 (its token does not exist), so there is no
// account state to compare.
func observeSetupHTTP(t *testing.T, _ *gorm.DB, w *httptest.ResponseRecorder) httpObservation {
	t.Helper()
	return httpObservation{status: w.Code, body: w.Body.String(), headers: w.Result().Header.Clone()}
}

var (
	wcDBCounter           atomic.Int64
	setupConsumeDBCounter atomic.Int64
)

func newSetupConsumeCompletionEnv(t *testing.T) (*AuthHandler, *faultstorage.FaultyStorage, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))
	dsn := fmt.Sprintf("file:kxsetupconsume%d?mode=memory&cache=shared&_timeout=30000", setupConsumeDBCounter.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Session{}, &models.AuditEvent{}, &models.SetupToken{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.LoginAttempt{}, &models.PasswordHistory{}, &models.Notification{},
	))
	// One connection per in-memory DB: a shared-cache SQLite database serves
	// concurrent connections with SQLITE_LOCKED ("database table is locked"),
	// which busy_timeout does not retry. These tests need no concurrency, so
	// capping the pool keeps them from adding contention to a package that
	// already runs a lot of SQLite in parallel.
	if sqlDB, derr := db.DB(); derr == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	c := core.NewKeyorixCore(fs)
	return NewAuthHandler(c, false), fs, db
}

// issueAccountSetupToken creates a pending_first_login account and an
// account_setup token for it, the state ConsumeSetup is designed to complete.
func issueAccountSetupToken(t *testing.T, h *AuthHandler, email string) string {
	t.Helper()
	ctx := context.Background()
	user, err := h.coreService.CreateUser(ctx, &core.CreateUserRequest{
		Username:     "bob",
		Email:        email,
		DisplayName:  "Bob",
		Password:     "Sd#Tq7$Jw1!Lm8@Ez!seed",
		AccountState: core.AccountPendingFirstLogin,
	})
	require.NoError(t, err)
	uid := user.ID
	res, err := h.coreService.IssueSetupToken(ctx, core.IssueSetupTokenRequest{
		Purpose:       core.SetupPurposeAccountSetup,
		SubjectEmail:  email,
		SubjectUserID: &uid,
		CreatedBy:     0,
	})
	require.NoError(t, err)
	return res.PlainToken
}
