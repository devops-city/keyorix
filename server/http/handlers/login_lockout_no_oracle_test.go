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
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/middleware"
)

const (
	lockoutOracleTestPassword = "C0rrect#Horse!Battery"
	// lockoutOracleMaxAttempts mirrors the policy set in the harness below.
	lockoutOracleMaxAttempts = 3
	// lockoutOracleTestIP is httptest.NewRequest's default RemoteAddr host.
	lockoutOracleTestIP = "192.0.2.1"
)

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

	// A private DB per env: these tests all use user id 1, and several run in
	// sequence within one test function. sqlitetest caps the pool to one
	// connection (a shared-cache DB answers concurrent connections with
	// SQLITE_LOCKED, which a busy timeout does not retry) and closes it on cleanup.
	db := sqlitetest.OpenWithConfig(t, "kxlockoutoracle", &gorm.Config{})
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Session{}, &models.AuditEvent{}, &models.LoginAttempt{},
		&models.MFASecret{}, &models.MFARecoveryCode{}, &models.MFAChallenge{},
		&models.MFAStepupToken{}, &models.MFAStepUpGrant{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.PasswordHistory{},
	))

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
	return newLockoutOracleEnvWithMFAOver(t, nil)
}

// newLockoutOracleEnvWithMFAOver is newLockoutOracleEnvWithMFA over
// newLockoutOracleEnvOver(t, wrap).
func newLockoutOracleEnvWithMFAOver(t *testing.T, wrap func(corestorage.Storage, *gorm.DB) corestorage.Storage) *lockoutOracleEnv {
	t.Helper()
	env := newLockoutOracleEnvOver(t, wrap)
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
	throughProductionRecovery(e.h.Login).ServeHTTP(w, r)
	return w
}

// throughProductionRecovery wraps a handler in the production
// middleware.Recovery, the outermost layer of the real router, so a PANIC
// fault is answered here exactly as a client would see it (#3267). Without it
// a panic would unwind out of the test instead of producing a response, and
// nobody could show what a panic returns over HTTP. For a request that does
// not panic it changes nothing, so the control and the non-panic probes are
// unaffected.
func throughProductionRecovery(h http.HandlerFunc) http.Handler {
	return middleware.Recovery()(h)
}

// driveToThresholdMinusOne spends MaxAttempts-1 wrong passwords, so the NEXT
// counted failure locks the account. Returns with the account unlocked.
func (e *lockoutOracleEnv) driveToThresholdMinusOne(t *testing.T) {
	t.Helper()
	for i := range lockoutOracleMaxAttempts - 1 {
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
//
// ORPHAN-2: GetUserRoles (the other half of the identity read) and the
// effect-then-error kind of each read are the server/faultops
// oracleAByDesignErrors rows' proving subtests, so every pinned class-A tuple
// has a handler-level parity proof.
//
// #3267: the PANIC kind of the identity read is here too, answered through
// the production Recovery middleware (postLogin). Before the fix it got the
// Recovery 500 and an uncounted lockout, both of which a wrong password never
// gets. #3277: the same for a PANIC in the session insert.
func TestLogin_PostVerdictFaultCostsTheSameAsAWrongPassword(t *testing.T) {
	for _, c := range []struct {
		method string
		kind   faultstorage.FaultKind
	}{
		{"CreateSession", faultstorage.KindError},
		{"GetUserPermissions", faultstorage.KindError},
		{"GetUserRoles", faultstorage.KindError},
		{"GetUserPermissions", faultstorage.KindEffectThenError},
		{"GetUserRoles", faultstorage.KindEffectThenError},
		{"GetUserPermissions", faultstorage.KindPanic},
		{"GetUserRoles", faultstorage.KindPanic},
		{"CreateSession", faultstorage.KindPanic}, // #3277
	} {
		method, kind := c.method, c.kind
		t.Run(method+"/"+kind.String(), func(t *testing.T) {
			// Control: the last attempt is a genuinely wrong password.
			ctrlEnv := newLockoutOracleEnv(t)
			ctrlEnv.driveToThresholdMinusOne(t)
			control := ctrlEnv.observe(t, ctrlEnv.postLogin(t, "still-not-her-password"))
			require.True(t, control.locked, "control: a wrong password at threshold-1 must lock the account, or this test proves nothing")

			// Probe: the last attempt is the RIGHT password, faulted after the match.
			probeEnv := newLockoutOracleEnv(t)
			probeEnv.driveToThresholdMinusOne(t)
			probeEnv.fs.Arm(&faultstorage.FaultSpec{
				Method: method, NthCall: 1, Kind: kind, Err: assert.AnError,
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
//
// #3277 follow-up: the PANIC kind too, through the production Recovery
// middleware (postLogin). Before, it got the Recovery 500 and an uncounted
// lockout, which a wrong password never gets.
func TestLogin_CreateMFAChallengeFaultCostsTheSameAsAWrongPassword(t *testing.T) {
	for _, kind := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic} {
		t.Run(kind.String(), func(t *testing.T) {
			ctrlEnv := newLockoutOracleEnvWithMFA(t)
			ctrlEnv.driveToThresholdMinusOne(t)
			control := ctrlEnv.observe(t, ctrlEnv.postLogin(t, "still-not-her-password"))
			require.True(t, control.locked, "control: a wrong password at threshold-1 must lock the account")

			probeEnv := newLockoutOracleEnvWithMFA(t)
			probeEnv.driveToThresholdMinusOne(t)
			probeEnv.fs.Arm(&faultstorage.FaultSpec{
				Method: "CreateMFAChallenge", NthCall: 1, Kind: kind, Err: assert.AnError,
			})
			w := probeEnv.postLogin(t, lockoutOracleTestPassword)
			require.True(t, probeEnv.fs.Fired(), "the armed CreateMFAChallenge fault must actually have fired")
			probe := probeEnv.observe(t, w)

			requireIndistinguishable(t, control, probe, "login/CreateMFAChallenge/"+kind.String())
		})
	}
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
	return e.serveVerify(t, throughProductionRecovery(e.h.VerifyMFA), challenge, code)
}

// postVerifyUnrecovered calls the handler bare, for a test that asserts what a
// panic carries when it leaves the handler (#3048) rather than what the client
// is answered.
func (e *lockoutOracleEnv) postVerifyUnrecovered(t *testing.T, challenge, code string) *httptest.ResponseRecorder {
	t.Helper()
	return e.serveVerify(t, http.HandlerFunc(e.h.VerifyMFA), challenge, code)
}

func (e *lockoutOracleEnv) serveVerify(t *testing.T, h http.Handler, challenge, code string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"mfa_challenge": challenge, "code": code})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/auth/mfa/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// driveMFAToThresholdMinusOne spends MaxAttempts-1 wrong TOTP codes.
func (e *lockoutOracleEnv) driveMFAToThresholdMinusOne(t *testing.T) {
	t.Helper()
	for i := range lockoutOracleMaxAttempts - 1 {
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
	//
	// ORPHAN-2: GetUserRoles and the effect-then-error kinds are the proving
	// subtests of the server/faultops oracleAByDesignErrors class-A rows.
	//
	// #3267: so are the PANIC kinds of the identity read, answered through the
	// production Recovery middleware (postVerify). Before the fix a panic there
	// got the Recovery 500 (a wrong code never reaches the identity read, so a
	// 500 meant "the code was right"), the lockout went uncounted and nothing
	// was audited, while the TOTP step stayed burned and the slot stayed spent.
	// #3277: the same for a PANIC in the two post-verdict writes, the
	// anti-replay mark and the session insert.
	for _, c := range []struct {
		method string
		kind   faultstorage.FaultKind
	}{
		{"CreateSession", faultstorage.KindError},
		{"GetUserPermissions", faultstorage.KindError},
		{"MarkTOTPStepUsed", faultstorage.KindError},
		{"GetUserRoles", faultstorage.KindError},
		{"GetUserPermissions", faultstorage.KindEffectThenError},
		{"GetUserRoles", faultstorage.KindEffectThenError},
		{"MarkTOTPStepUsed", faultstorage.KindEffectThenError},
		{"GetUserPermissions", faultstorage.KindPanic},
		{"GetUserRoles", faultstorage.KindPanic},
		{"MarkTOTPStepUsed", faultstorage.KindPanic}, // #3277
		{"CreateSession", faultstorage.KindPanic},    // #3277
	} {
		method, kind := c.method, c.kind
		t.Run(method+"/"+kind.String(), func(t *testing.T) {
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
				Method: method, NthCall: 1, Kind: kind, Err: assert.AnError,
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

// TestVerifyMFA_IdentityReadPanicAuditsLoginErrorAndKeepsTheCodeBurned is the
// rest of #3267's decided outcome for a post-verdict identity-read PANIC,
// through the production Recovery middleware: the operator-only audit half
// (auth.login_error, as for the error kind), and the TOTP step reuse
// protection. The code matched, so its step was consumed before the panic and
// must stay consumed: replaying the same code on a fresh challenge is refused.
func TestVerifyMFA_IdentityReadPanicAuditsLoginErrorAndKeepsTheCodeBurned(t *testing.T) {
	for _, method := range []string{"GetUserPermissions", "GetUserRoles"} {
		t.Run(method, func(t *testing.T) {
			env := newLockoutOracleEnvWithMFA(t)
			code, err := totp.GenerateCode(env.totpSecret, env.clock)
			require.NoError(t, err)

			ch, err := env.h.coreService.CreateMFAChallenge(context.Background(), 1)
			require.NoError(t, err)
			env.fs.Arm(&faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindPanic})
			w := env.postVerify(t, ch, code)
			require.True(t, env.fs.Fired(), "the armed %s panic must actually have fired", method)
			env.fs.Arm(nil)
			require.Equal(t, http.StatusUnauthorized, w.Code, "a post-verdict panic must get the wrong-code 401, not the Recovery 500: %s", w.Body.String())

			assert.Equal(t, int64(1), waitForAuditEvent(t, env.db, "auth.login_error"),
				"a post-verdict panic must be audited auth.login_error, like the same fault returned as an error")

			replay, err := env.h.coreService.CreateMFAChallenge(context.Background(), 1)
			require.NoError(t, err)
			w = env.postVerify(t, replay, code)
			assert.Equal(t, http.StatusUnauthorized, w.Code,
				"the code was accepted before the panic, so its TOTP step must stay burned: a replay must be refused")

			var sessions int64
			require.NoError(t, env.db.Model(&models.Session{}).Count(&sessions).Error)
			assert.Zero(t, sessions, "neither the panicked attempt nor the replay may mint a session")
		})
	}
}

// TestVerifyMFA_WritePanicKeepsTheCodeBurned is the rest of #3277's decided
// outcome for a PANIC in a post-verdict write on /auth/mfa/verify, through the
// production Recovery middleware: the audit record the same write's error kind
// writes (mfa.error for the anti-replay mark, auth.login_error for the session
// insert), no session, and the TOTP step. For CreateSession the step was
// consumed before the panic and must stay consumed (the error kind gives it
// back, the panic kind must not: after a panic the absence of the session row
// rests on a best-effort delete), so a replay of the same code is refused.
// MarkTOTPStepUsed's mark never landed here (FaultyStorage panics in place of
// the call), so that code was never accepted; internal/core's
// TestLoginWritePanic_DeniedLikeItsError covers a mark that landed and then
// panicked.
func TestVerifyMFA_WritePanicKeepsTheCodeBurned(t *testing.T) {
	for _, c := range []struct {
		method, auditEvent string
		replayRefused      bool
	}{
		{"MarkTOTPStepUsed", "mfa.error", false},
		{"CreateSession", "auth.login_error", true},
	} {
		t.Run(c.method, func(t *testing.T) {
			env := newLockoutOracleEnvWithMFA(t)
			code, err := totp.GenerateCode(env.totpSecret, env.clock)
			require.NoError(t, err)

			ch, err := env.h.coreService.CreateMFAChallenge(context.Background(), 1)
			require.NoError(t, err)
			env.fs.Arm(&faultstorage.FaultSpec{Method: c.method, NthCall: 1, Kind: faultstorage.KindPanic})
			w := env.postVerify(t, ch, code)
			require.True(t, env.fs.Fired(), "the armed %s panic must actually have fired", c.method)
			env.fs.Arm(nil)
			require.Equal(t, http.StatusUnauthorized, w.Code, "a post-verdict panic must get the wrong-code 401, not the Recovery 500: %s", w.Body.String())
			assert.Empty(t, w.Result().Cookies(), "a denied login sets no session cookie")

			assert.Equal(t, int64(1), waitForAuditEvent(t, env.db, c.auditEvent),
				"a post-verdict %s panic must be audited %s, like the same fault returned as an error", c.method, c.auditEvent)

			var sessions int64
			require.NoError(t, env.db.Model(&models.Session{}).Count(&sessions).Error)
			require.Zero(t, sessions, "the panicked attempt must leave no session")

			replay, err := env.h.coreService.CreateMFAChallenge(context.Background(), 1)
			require.NoError(t, err)
			w = env.postVerify(t, replay, code)
			if c.replayRefused {
				assert.Equal(t, http.StatusUnauthorized, w.Code,
					"the code was accepted before the session insert panicked, so its TOTP step must stay burned: a replay must be refused")
				require.NoError(t, env.db.Model(&models.Session{}).Count(&sessions).Error)
				assert.Zero(t, sessions, "neither the panicked attempt nor the replay may mint a session")
			} else {
				assert.Equal(t, http.StatusOK, w.Code,
					"calibration: the mark never landed, so the code was never accepted and is still good once: %s", w.Body.String())
			}
		})
	}
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
