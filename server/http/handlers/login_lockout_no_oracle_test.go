// login_lockout_no_oracle_test.go — the behavioural half of #2894 (and the
// HTTP-level proof for #2888's response-shape rule).
//
// Every test here is built the same way, because the property is a COMPARISON,
// not an absolute: run the endpoint twice from identical state — once with a
// genuinely WRONG credential (the control), once with the CORRECT credential
// plus an injected storage fault at a point AFTER the credential matched (the
// probe) — and require the two to be indistinguishable in everything the client
// can see or infer:
//
//	status code
//	response body, byte for byte
//	response headers
//	the account's persisted lockout columns (failed_login_attempts,
//	  login_locked_until, login_lockout_count)
//	the per-IP login-attempt rows (the 429 budget)
//
// The lockout columns are the channel #2888 left open and #2894 closes. Each
// run starts at MaxAttempts−1 on purpose: that is where the difference is
// loudest (the control LOCKS the account, and before the fix the probe did not),
// and it is exactly how an attacker would use it — drive the counter to the
// threshold, then spend the last attempt on a candidate password and watch
// whether the account locks.
//
// The audit trail is deliberately NOT part of the comparison: there the two
// cases MUST differ (auth.login_failed vs auth.login_error), and that is
// asserted separately below. It is an operator-only channel.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const (
	lockoutOracleTestPassword = "C0rrect#Horse!Battery"
	// lockoutOracleMaxAttempts mirrors the policy set in the harness below.
	lockoutOracleMaxAttempts = 3
	// lockoutOracleTestIP is httptest.NewRequest's default RemoteAddr host.
	lockoutOracleTestIP = "192.0.2.1"
)

var lockoutOracleDBCounter atomic.Int64

// lockoutOracleEnv is one fully independent server: its own in-memory DB, its
// own core with the lockout policy enabled, and a fault wrapper that starts
// unarmed.
type lockoutOracleEnv struct {
	h  *AuthHandler
	fs *faultstorage.FaultyStorage
	db *gorm.DB
	// totpSecret and clock are set only by newLockoutOracleEnvWithMFA.
	totpSecret string
	clock      time.Time
}

// newLockoutOracleEnv builds an env with user 1 "alice" holding a password and
// NO second factor, so /auth/login alone completes her login.
func newLockoutOracleEnv(t *testing.T) *lockoutOracleEnv {
	t.Helper()
	return newLockoutOracleEnvOver(t, nil)
}

// newLockoutOracleEnvOver is newLockoutOracleEnv with wrap (when non-nil)
// interposed between the fault wrapper and the real storage, for a probe that
// needs a concurrent effect at an exact point inside one storage call.
func newLockoutOracleEnvOver(t *testing.T, wrap func(corestorage.Storage, *gorm.DB) corestorage.Storage) *lockoutOracleEnv {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))

	// A private shared-cache DB per env: these tests all use user id 1, and
	// several run in sequence within one test function.
	dsn := fmt.Sprintf("file:kxlockoutoracle%d?mode=memory&cache=shared&_timeout=30000", lockoutOracleDBCounter.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Session{}, &models.AuditEvent{}, &models.LoginAttempt{},
		&models.MFASecret{}, &models.MFARecoveryCode{}, &models.MFAChallenge{},
		&models.MFAStepupToken{}, &models.MFAStepUpGrant{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.PasswordHistory{},
	))

	// One connection per in-memory DB: a shared-cache SQLite database serves
	// concurrent connections with SQLITE_LOCKED ("database table is locked"),
	// which busy_timeout does not retry. These tests need no concurrency, so
	// capping the pool keeps them from adding contention to a package that
	// already runs a lot of SQLite in parallel.
	if sqlDB, derr := db.DB(); derr == nil {
		sqlDB.SetMaxOpenConns(1)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(lockoutOracleTestPassword), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "alice", UsernameFolded: "alice", Email: "alice@example.com",
		EmailFolded: "alice@example.com", PasswordHash: string(hash), AccountState: "active", IsActive: true,
	}).Error)

	var real corestorage.Storage = store.NewLocalStorage(db)
	if wrap != nil {
		real = wrap(real, db)
	}
	fs := faultstorage.NewFaultyStorage(real, nil)
	c := core.NewKeyorixCore(fs)
	c.SetLoginLockoutPolicy(core.LoginLockoutPolicy{
		Enabled: true, MaxAttempts: lockoutOracleMaxAttempts, Window: time.Hour,
		BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour,
	})
	return &lockoutOracleEnv{h: NewAuthHandler(c, false), fs: fs, db: db}
}

// newLockoutOracleEnvWithMFA is newLockoutOracleEnv plus a real, activated TOTP
// enrolment for user 1, with the clock parked one step past activation's own
// code so the first verify presents a step the anti-replay check has not seen.
func newLockoutOracleEnvWithMFA(t *testing.T) *lockoutOracleEnv {
	t.Helper()
	env := newLockoutOracleEnv(t)
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))
	env.h.coreService.SetAuthEncryptor(enc)

	activation := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	env.h.coreService.SetClockForTesting(func() time.Time { return activation })

	ctx := context.Background()
	_, secret, err := env.h.coreService.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, activation)
	require.NoError(t, err)
	_, err = env.h.coreService.ActivateMFA(ctx, 1, actCode, lockoutOracleTestPassword, "")
	require.NoError(t, err)

	env.totpSecret = secret
	env.clock = activation.Add(30 * time.Second)
	env.h.coreService.SetClockForTesting(func() time.Time { return env.clock })
	// Enrolment itself is a successful re-auth, so it cleared the counter; make
	// that explicit rather than relying on it.
	require.NoError(t, env.db.Model(&models.User{}).Where("id = ?", 1).
		Updates(map[string]any{"failed_login_attempts": 0, "login_locked_until": nil, "login_lockout_count": 0}).Error)
	return env
}

// observation is everything about one request that an attacker can see, plus
// the server-side state they can probe for afterwards.
type observation struct {
	status  int
	body    string
	headers http.Header

	failedAttempts int
	locked         bool
	lockoutCount   int
	loginAttempts  int64
}

func (e *lockoutOracleEnv) observe(t *testing.T, w *httptest.ResponseRecorder) observation {
	t.Helper()
	var u models.User
	require.NoError(t, e.db.First(&u, 1).Error)
	var attempts int64
	require.NoError(t, e.db.Model(&models.LoginAttempt{}).Where("ip = ?", lockoutOracleTestIP).Count(&attempts).Error)
	return observation{
		status: w.Code, body: w.Body.String(), headers: w.Result().Header.Clone(),
		failedAttempts: u.FailedLoginAttempts,
		locked:         u.LoginLockedUntil != nil,
		lockoutCount:   u.LoginLockoutCount,
		loginAttempts:  attempts,
	}
}

// requireIndistinguishable is the single assertion this whole file exists for.
func requireIndistinguishable(t *testing.T, control, probe observation, what string) {
	t.Helper()
	assert.Equal(t, control.status, probe.status, "%s: status code differs -- the response itself is an oracle", what)
	assert.Equal(t, control.body, probe.body, "%s: response body differs byte-for-byte", what)
	assert.Equal(t, control.headers, probe.headers, "%s: response headers differ", what)
	assert.Equal(t, control.failedAttempts, probe.failedAttempts,
		"%s: failed_login_attempts differs -- the LOCKOUT COUNTER is the oracle (#2894)", what)
	assert.Equal(t, control.locked, probe.locked,
		"%s: one run locked the account and the other did not -- whether the account locks answers 'was the credential correct?' (#2894)", what)
	assert.Equal(t, control.lockoutCount, probe.lockoutCount, "%s: login_lockout_count differs", what)
	assert.Equal(t, control.loginAttempts, probe.loginAttempts,
		"%s: the per-IP login-attempt budget was charged differently -- observable by watching when 429s start", what)
}

// --- /auth/login -------------------------------------------------------------

func (e *lockoutOracleEnv) postLogin(t *testing.T, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": "alice", "password": password})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	e.h.Login(w, r)
	return w
}

// driveToThresholdMinusOne spends MaxAttempts-1 wrong passwords, so the NEXT
// counted failure locks the account. Returns with the account unlocked.
func (e *lockoutOracleEnv) driveToThresholdMinusOne(t *testing.T) {
	t.Helper()
	for i := 0; i < lockoutOracleMaxAttempts-1; i++ {
		w := e.postLogin(t, "definitely-not-her-password")
		require.Equal(t, http.StatusUnauthorized, w.Code, "setup attempt %d", i)
	}
	var u models.User
	require.NoError(t, e.db.First(&u, 1).Error)
	require.Equal(t, lockoutOracleMaxAttempts-1, u.FailedLoginAttempts, "setup: expected to be one failure short of the threshold")
	require.Nil(t, u.LoginLockedUntil, "setup: must not be locked yet")
}

// TestLogin_PostVerdictFaultCostsTheSameAsAWrongPassword is the password-login
// case of #2894. Each armed method is a storage call /auth/login makes only
// AFTER bcrypt has already confirmed the password correct:
//
//	CreateSession       -- mintSession, inside core.LoginWithIdentityPending
//	GetUserPermissions  -- the identity read, inside core before the mint (#2844)
//
// so in both the password WAS right, and in both the client gets the same 401
// "Invalid credentials" a wrong password gets (#2888). Before #2894 the account
// was left at 0 failures instead of locked, which told the attacker the
// password was correct just as plainly as a 500 would have.
func TestLogin_PostVerdictFaultCostsTheSameAsAWrongPassword(t *testing.T) {
	for _, method := range []string{"CreateSession", "GetUserPermissions"} {
		t.Run(method, func(t *testing.T) {
			// Control: the last attempt is a genuinely wrong password.
			ctrlEnv := newLockoutOracleEnv(t)
			ctrlEnv.driveToThresholdMinusOne(t)
			control := ctrlEnv.observe(t, ctrlEnv.postLogin(t, "still-not-her-password"))
			require.True(t, control.locked, "control: a wrong password at threshold-1 must lock the account, or this test proves nothing")

			// Probe: the last attempt is the RIGHT password, faulted after the match.
			probeEnv := newLockoutOracleEnv(t)
			probeEnv.driveToThresholdMinusOne(t)
			probeEnv.fs.Arm(&faultstorage.FaultSpec{
				Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError,
			})
			w := probeEnv.postLogin(t, lockoutOracleTestPassword)
			require.True(t, probeEnv.fs.Fired(), "the armed %s fault must actually have fired", method)
			probe := probeEnv.observe(t, w)

			requireIndistinguishable(t, control, probe, "login/"+method)

			// No session may survive either way.
			var sessions int64
			require.NoError(t, probeEnv.db.Model(&models.Session{}).Count(&sessions).Error)
			assert.Zero(t, sessions, "a post-verdict fault must leave no live session")
		})
	}
}

// suspendBeforeCreateSession suspends user 1 (a direct row update, standing in
// for an admin's SuspendUser on another replica) immediately before the real
// CreateSession runs: the interleaving where the suspend lands between Login's
// password check and its session insert.
type suspendBeforeCreateSession struct {
	corestorage.Storage
	db    *gorm.DB
	fired atomic.Bool
}

func (s *suspendBeforeCreateSession) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	if session.UserID == 1 && s.fired.CompareAndSwap(false, true) {
		if err := s.db.Model(&models.User{}).Where("id = ?", 1).Update("account_state", "suspended").Error; err != nil {
			return nil, err
		}
	}
	return s.Storage.CreateSession(ctx, session)
}

// TestLogin_SuspendBetweenPasswordCheckAndSessionInsertCostsTheSameAsAWrongPassword
// is where #2866 and #2894 meet. #2866 (#2701) made CreateSession re-check the
// owner inside its transaction, so a suspend landing after the password matched
// but before the insert is refused there as a STORAGE error, not minted. That is
// a post-verdict failure like any other (#2894): the client must get the exact
// wrong-password response (in particular, nothing that says "suspended" and
// thereby confirms the password), the lockout must be charged exactly as a wrong
// password charges it, it must be audited auth.login_error (not login_failed),
// and no session may exist.
func TestLogin_SuspendBetweenPasswordCheckAndSessionInsertCostsTheSameAsAWrongPassword(t *testing.T) {
	ctrlEnv := newLockoutOracleEnv(t)
	ctrlEnv.driveToThresholdMinusOne(t)
	control := ctrlEnv.observe(t, ctrlEnv.postLogin(t, "still-not-her-password"))
	require.True(t, control.locked, "control: a wrong password at threshold-1 must lock the account, or this test proves nothing")

	var hook *suspendBeforeCreateSession
	probeEnv := newLockoutOracleEnvOver(t, func(real corestorage.Storage, db *gorm.DB) corestorage.Storage {
		hook = &suspendBeforeCreateSession{Storage: real, db: db}
		return hook
	})
	probeEnv.driveToThresholdMinusOne(t)
	// The setup's own auth.login_failed events are async: let them settle so the
	// count below measures only the probe.
	require.Eventually(t, func() bool {
		var n int64
		return probeEnv.db.Model(&models.AuditEvent{}).Where("event_type = ?", "auth.login_failed").Count(&n).Error == nil &&
			n == lockoutOracleMaxAttempts-1
	}, 5*time.Second, 10*time.Millisecond, "setup: one auth.login_failed per wrong password")
	w := probeEnv.postLogin(t, lockoutOracleTestPassword)
	require.True(t, hook.fired.Load(), "the suspend must have landed inside the session insert, after the password matched")
	var u models.User
	require.NoError(t, probeEnv.db.First(&u, 1).Error)
	require.Equal(t, "suspended", u.AccountState, "calibration: the account really is suspended")
	probe := probeEnv.observe(t, w)

	requireIndistinguishable(t, control, probe, "login/suspend-before-insert")
	assert.NotContains(t, w.Body.String(), "suspend", "the response must not name the suspension")

	var sessions int64
	require.NoError(t, probeEnv.db.Model(&models.Session{}).Count(&sessions).Error)
	assert.Zero(t, sessions, "the owner re-check must refuse the insert: no session for a suspended account")

	assert.Equal(t, int64(1), waitForAuditEvent(t, probeEnv.db, "auth.login_error"),
		"a correct password denied by the insert's owner re-check is auth.login_error")
	var failedEvents int64
	require.NoError(t, probeEnv.db.Model(&models.AuditEvent{}).Where("event_type = ?", "auth.login_failed").Count(&failedEvents).Error)
	assert.Equal(t, int64(lockoutOracleMaxAttempts-1), failedEvents,
		"only the setup's wrong passwords are auth.login_failed; the probe must not add one")
}

// TestLogin_CreateMFAChallengeFaultCostsTheSameAsAWrongPassword covers the one
// post-verdict step the TRANSPORT owns: for an account WITH a second factor,
// core returns ErrMFARequired having deliberately left the counter alone, and
// the handler then issues the challenge. If that write fails, the client gets
// the wrong-password 401 -- so the lockout cost has to match too, which is what
// RecordPostVerdictLoginFailure is for.
func TestLogin_CreateMFAChallengeFaultCostsTheSameAsAWrongPassword(t *testing.T) {
	ctrlEnv := newLockoutOracleEnvWithMFA(t)
	ctrlEnv.driveToThresholdMinusOne(t)
	control := ctrlEnv.observe(t, ctrlEnv.postLogin(t, "still-not-her-password"))
	require.True(t, control.locked, "control: a wrong password at threshold-1 must lock the account")

	probeEnv := newLockoutOracleEnvWithMFA(t)
	probeEnv.driveToThresholdMinusOne(t)
	probeEnv.fs.Arm(&faultstorage.FaultSpec{
		Method: "CreateMFAChallenge", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError,
	})
	w := probeEnv.postLogin(t, lockoutOracleTestPassword)
	require.True(t, probeEnv.fs.Fired(), "the armed CreateMFAChallenge fault must actually have fired")
	probe := probeEnv.observe(t, w)

	requireIndistinguishable(t, control, probe, "login/CreateMFAChallenge")
}

// TestLogin_PostVerdictFaultAuditsLoginErrorNotLoginFailed is the other half of
// the pair: the two cases must be IDENTICAL to the client and DISTINGUISHABLE
// to an operator. Before #2894 a mintSession failure after a correct password
// wrote auth.login_failed -- telling whoever reads the audit log that somebody
// guessed a password wrong, when in fact they had it right and the server
// broke.
func TestLogin_PostVerdictFaultAuditsLoginErrorNotLoginFailed(t *testing.T) {
	env := newLockoutOracleEnv(t)
	env.fs.Arm(&faultstorage.FaultSpec{
		Method: "CreateSession", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError,
	})
	w := env.postLogin(t, lockoutOracleTestPassword)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.True(t, env.fs.Fired())
	env.fs.Arm(nil)

	// The audit writes are async (goSafe) on both branches -- deliberately, so
	// neither is measurably slower than the other. Poll briefly.
	errorEvents := waitForAuditEvent(t, env.db, "auth.login_error")
	assert.Equal(t, int64(1), errorEvents, "a storage fault after the password matched must audit auth.login_error")

	var failedEvents int64
	require.NoError(t, env.db.Model(&models.AuditEvent{}).Where("event_type = ?", "auth.login_failed").Count(&failedEvents).Error)
	assert.Zero(t, failedEvents, "it must NOT also be audited as a wrong password -- that hides the real incident")
}

// TestLogin_WrongPasswordStillAuditsLoginFailed is the control for the above:
// the split must not have turned every denial into login_error.
func TestLogin_WrongPasswordStillAuditsLoginFailed(t *testing.T) {
	env := newLockoutOracleEnv(t)
	w := env.postLogin(t, "not-her-password")
	require.Equal(t, http.StatusUnauthorized, w.Code)

	failedEvents := waitForAuditEvent(t, env.db, "auth.login_failed")
	assert.Equal(t, int64(1), failedEvents, "a genuinely wrong password is still auth.login_failed")

	var errorEvents int64
	require.NoError(t, env.db.Model(&models.AuditEvent{}).Where("event_type = ?", "auth.login_error").Count(&errorEvents).Error)
	assert.Zero(t, errorEvents)
}

// waitForAuditEvent polls for an asynchronously-written audit event.
func waitForAuditEvent(t *testing.T, db *gorm.DB, eventType string) int64 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var n int64
	for time.Now().Before(deadline) {
		if err := db.Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error; err == nil && n > 0 {
			return n
		}
		time.Sleep(10 * time.Millisecond)
	}
	return n
}

// --- /auth/mfa/verify --------------------------------------------------------

func (e *lockoutOracleEnv) postVerify(t *testing.T, challenge, code string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"mfa_challenge": challenge, "code": code})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/auth/mfa/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()
	e.h.VerifyMFA(w, r)
	return w
}

// driveMFAToThresholdMinusOne spends MaxAttempts-1 wrong TOTP codes.
func (e *lockoutOracleEnv) driveMFAToThresholdMinusOne(t *testing.T) {
	t.Helper()
	for i := 0; i < lockoutOracleMaxAttempts-1; i++ {
		ch, err := e.h.coreService.CreateMFAChallenge(context.Background(), 1)
		require.NoError(t, err)
		w := e.postVerify(t, ch, "000000")
		require.Equal(t, http.StatusUnauthorized, w.Code, "setup attempt %d: body %s", i, w.Body.String())
	}
	var u models.User
	require.NoError(t, e.db.First(&u, 1).Error)
	require.Equal(t, lockoutOracleMaxAttempts-1, u.FailedLoginAttempts, "setup: one failure short of the threshold")
	require.Nil(t, u.LoginLockedUntil)
}

// TestVerifyMFA_PostVerdictFaultCostsTheSameAsAWrongCode is #2894 for the
// second-factor step, and it is also the test for the RATE-LIMIT SLOT
// (mfa.go's ReleaseLoginAttempt): the probe must keep its reserved
// LoginAttempt row exactly as the wrong-code control does, because releasing it
// only for a correct-code-but-write-failed attempt is itself a side channel --
// observable by watching when the per-IP 429s start. observation.loginAttempts
// carries that, so requireIndistinguishable asserts it alongside the rest.
func TestVerifyMFA_PostVerdictFaultCostsTheSameAsAWrongCode(t *testing.T) {
	// MarkTOTPStepUsed is the anti-replay write, reached only after the code
	// matched: post-verdict too, so it must cost the same as a wrong code,
	// rate-limit slot included (the oracleAByDesignErrors row for
	// /auth/mfa/verify MarkTOTPStepUsed#1/error cites this subtest).
	for _, method := range []string{"CreateSession", "GetUserPermissions", "MarkTOTPStepUsed"} {
		t.Run(method, func(t *testing.T) {
			ctrlEnv := newLockoutOracleEnvWithMFA(t)
			ctrlEnv.driveMFAToThresholdMinusOne(t)
			ctrlCh, err := ctrlEnv.h.coreService.CreateMFAChallenge(context.Background(), 1)
			require.NoError(t, err)
			control := ctrlEnv.observe(t, ctrlEnv.postVerify(t, ctrlCh, "000000"))
			require.True(t, control.locked, "control: a wrong code at threshold-1 must lock the account")

			probeEnv := newLockoutOracleEnvWithMFA(t)
			probeEnv.driveMFAToThresholdMinusOne(t)
			probeCh, err := probeEnv.h.coreService.CreateMFAChallenge(context.Background(), 1)
			require.NoError(t, err)
			code, err := totp.GenerateCode(probeEnv.totpSecret, probeEnv.clock)
			require.NoError(t, err)
			probeEnv.fs.Arm(&faultstorage.FaultSpec{
				Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError,
			})
			w := probeEnv.postVerify(t, probeCh, code)
			require.True(t, probeEnv.fs.Fired(), "the armed %s fault must actually have fired", method)
			probe := probeEnv.observe(t, w)

			requireIndistinguishable(t, control, probe, "mfa-verify/"+method)

			var sessions int64
			require.NoError(t, probeEnv.db.Model(&models.Session{}).Count(&sessions).Error)
			assert.Zero(t, sessions, "a post-verdict fault must leave no live session")
		})
	}
}

// TestVerifyMFA_MintFailureAfterCorrectCodeAuditsLoginError is the audit half
// for the second-factor step. Before #2894 this branch wrote NO audit event at
// all for a mintSession failure: the request got the wrong-code 401 and
// vanished from the trail entirely, so an operator had no way to know a
// correct code had been denied by a storage fault. It now reaches LogAuthError
// (auth.login_error), while the response stays byte-identical to a wrong code.
func TestVerifyMFA_MintFailureAfterCorrectCodeAuditsLoginError(t *testing.T) {
	env := newLockoutOracleEnvWithMFA(t)
	ch, err := env.h.coreService.CreateMFAChallenge(context.Background(), 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(env.totpSecret, env.clock)
	require.NoError(t, err)
	env.fs.Arm(&faultstorage.FaultSpec{
		Method: "CreateSession", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError,
	})
	w := env.postVerify(t, ch, code)
	require.Equal(t, http.StatusUnauthorized, w.Code, "the response must stay the wrong-code 401")
	require.True(t, env.fs.Fired())
	env.fs.Arm(nil)

	errorEvents := waitForAuditEvent(t, env.db, "auth.login_error")
	assert.Equal(t, int64(1), errorEvents,
		"a mintSession failure after a CORRECT code must reach LogAuthError -- previously this branch audited nothing at all")
}

// TestVerifyMFA_PreVerdictFaultStillReleasesItsSlot is the other direction, and
// the reason the slot assertion above cannot simply be "never release": a
// storage error that stopped the check BEFORE any verdict on the code
// (ErrMFAVerificationUnavailable) still releases its slot and answers 503, per
// #2548/CR3. #2894 must not have collapsed that distinction.
func TestVerifyMFA_PreVerdictFaultStillReleasesItsSlot(t *testing.T) {
	env := newLockoutOracleEnvWithMFA(t)
	ch, err := env.h.coreService.CreateMFAChallenge(context.Background(), 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(env.totpSecret, env.clock)
	require.NoError(t, err)
	env.fs.Arm(&faultstorage.FaultSpec{
		Method: "GetMFASecret", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError,
	})
	w := env.postVerify(t, ch, code)
	require.True(t, env.fs.Fired())

	assert.Equal(t, http.StatusServiceUnavailable, w.Code,
		"a fault BEFORE the code was evaluated is still a 503 'retry', not the wrong-code 401")
	var attempts int64
	require.NoError(t, env.db.Model(&models.LoginAttempt{}).Where("ip = ?", lockoutOracleTestIP).Count(&attempts).Error)
	assert.Zero(t, attempts, "a never-evaluated attempt must release its reserved slot")
	var u models.User
	require.NoError(t, env.db.First(&u, 1).Error)
	assert.Zero(t, u.FailedLoginAttempts, "a never-evaluated attempt must not touch the lockout counter")
}
