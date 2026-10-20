package faultops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// POST /auth/setup/consume (#3298, AUTH-2 item 1): an account with no second
// factor, so the consume mints a session. It goes through ONE transaction in
// core, so every fault must leave either the full effect or none: the token
// still active, the old password, every PAT live, no session. The
// second-factor shape (an MFA challenge instead of the session) cannot be a
// second catalog op (keys are live routes): it is swept write-by-write in
// internal/core/TestCompleteSetup_FaultAtAnyWriteLeavesNothingAndTheLinkStillWorks
// (mfa=true) and was swept exhaustively here during AUTH-2 (session report).
//
// Setup is deterministic (fixed token, fixed rows): oracle (a) compares this
// world with an independently built reference world, so a random token hash
// would differ in SetupToken on every run (see zz_saml_acs_op_test.go).
const (
	setupConsumeRawToken    = "kxst_fuzz-setup-consume-token-0001"
	setupConsumeNewPassword = "Fuzz!Setup#Consume-2026x"
)

func seedSetupConsumeAccount(ctx context.Context, w *faultWorld, username, raw string, mfa bool) error {
	hash, err := bcrypt.GenerateFromPassword([]byte("Old!Password#Before-2026"), bcrypt.MinCost)
	if err != nil {
		return err
	}
	user := &models.User{
		Username: username, UsernameFolded: username,
		Email: username + "@example.com", EmailFolded: username + "@example.com",
		PasswordHash: string(hash), AccountState: "pending_first_login", IsActive: true,
		MFAEnabled: mfa, // the consume only reads the flag; no TOTP secret is needed until the challenge is answered
	}
	if err := w.db.WithContext(ctx).Create(user).Error; err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(raw))
	uid := user.ID
	return w.db.WithContext(ctx).Create(&models.SetupToken{
		TokenHash: hex.EncodeToString(sum[:]), Purpose: "account_setup",
		SubjectUserID: &uid, SubjectEmail: user.Email, State: "active",
		ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
	}).Error
}

func setupConsumeOp(key, username, raw string, mfa bool) operation {
	return operation{
		Key: key,
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return nil, seedSetupConsumeAccount(ctx, w, username, raw, mfa)
		},
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/auth/setup/consume", map[string]any{
				"token": raw, "password": setupConsumeNewPassword,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	}
}

// setupConsumeDeadTokenRequest is the "wrong credential" for these ops: a
// well-formed link that does not exist. A consume that fails after the token
// was validated must be answered exactly like it (wrongCredentialRequests,
// TestOracleAByDesign_WrongCredentialOutcomesAreReal).
func setupConsumeDeadTokenRequest(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, "/auth/setup/consume", map[string]any{
		"token": "kxst_fuzz-setup-consume-no-such-token", "password": setupConsumeNewPassword,
	})
	if err != nil {
		return opResult{}, err
	}
	return httpResult(st, body), nil
}

func init() {
	wrongCredentialRequests["REST POST /auth/setup/consume"] = setupConsumeDeadTokenRequest
	registerOps("auth_setup_consume",
		setupConsumeOp("REST POST /auth/setup/consume", "fuzzsetup", setupConsumeRawToken, false),
	)
	registerOverrides("auth_setup_consume", map[string]overrideEntry{
		"REST POST /auth/setup/consume": {StatusFuzzed, "AUTH-2 item 1 (#3298): one transaction; failures after the token was validated are by design (oracle_a_by_design_entry_setup_consume_test.go)"},
	})
}
