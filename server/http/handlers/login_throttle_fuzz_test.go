// login_throttle_fuzz_test.go — FuzzLoginThrottleConcurrency (G1, FUZZ-GAPS).
//
// Population: every unauthenticated endpoint sharing the per-IP login-attempt
// budget (core.LoginMaxAttempts / checkLoginRateLimit, auth.go) — Login,
// RefreshToken, VerifyMFA, BeginWebAuthnLogin, FinishWebAuthnLogin,
// BeginWebAuthnPasswordlessLogin, FinishWebAuthnPasswordlessLogin, ConsumeSetup.
//
// PR #1981 (F2) fixed six of these to RESERVE a budget slot immediately after
// checkLoginRateLimit passes and BEFORE the slow credential check, closing a
// check-then-act race. Its own PR body flagged two call sites as "explicitly
// out of scope": ConsumeSetup and BeginWebAuthnPasswordlessLogin shared the
// same checkLoginRateLimit gate but never called reserveLoginAttempt at all —
// so hammering EITHER of those two alone, from one IP, never tripped the
// shared budget no matter how many attempts were made. This harness confirmed
// that gap (see this file's git history for the pre-fix red run) and the fix
// now lives alongside it in auth.go/webauthn.go.
//
// Oracles, all checked from GROUND-TRUTH STORAGE STATE (a direct COUNT against
// the login_attempts table), never by wall-clock timing:
//
//	(a) BUDGET NEVER SILENTLY SKIPPED: every op that reaches its slow
//	    credential-adjacent check (i.e. checkLoginRateLimit did NOT reject it)
//	    reserves EXACTLY one slot — no more (a double-reserve would let the
//	    budget trip early and lock out real traffic) and no fewer (a skipped
//	    reserve is this file's whole reason to exist).
//	(c) BUDGET CONSISTENT ACROSS ENDPOINTS: a single shared per-IP counter
//	    governs all eight endpoints. Once shadow tracking says an IP has
//	    reserved core.LoginMaxAttempts slots, EVERY endpoint (not just the one
//	    that tripped it) must see 429 on its next call from that IP, with no
//	    additional reservation — no endpoint gets its own separate, larger
//	    budget.
//	(b) LOCKOUT NEVER BYPASSED: a per-account-locked account (core's OWN,
//	    per-account brute-force backstop — login_lockout.go, orthogonal to the
//	    per-IP budget above) never obtains a session, even via a genuinely
//	    correct credential. Checked concretely for Login (real bcrypt
//	    password) and VerifyMFA (real TOTP code) — the two endpoints where
//	    constructing a valid credential is practical without also exercising
//	    real WebAuthn/passkey cryptography (that crypto-correctness surface is
//	    a different track's target, not G1's). For the WebAuthn/ConsumeSetup
//	    endpoints this harness never supplies material that could succeed
//	    at all, so oracle (b) is not exercised there; F1 (PR #1981) already
//	    independently confirmed every session-minting completion path
//	    re-checks and clears lockout immediately before minting.
//
// Deterministic by construction: no goroutines, no sleeps, no real
// concurrency. Instead of racing real requests, the fuzz input picks an
// explicit, ordered SEQUENCE of (IP, endpoint) operations and this harness
// runs them one at a time, tracking an independent shadow count per IP. This
// is the "injected/controlled interleaving" this track's spec asks for: it
// reproduces the observable effect of a race (many logically-concurrent
// requests landing against the same shared counter in an adversarial order)
// without any of the flakiness real goroutine scheduling would add — a
// pre-fix ConsumeSetup/BeginWebAuthnPasswordlessLogin op fails oracle (a) the
// same way regardless of what order it appears in the sequence, because the
// bug is structural (the call site never reserves at all), not timing-shaped.
package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const loginThrottleTestPassword = "Secret#Passw0rd!"

const (
	ltPlainUserID uint = 501 // no second factor
	ltTOTPUserID  uint = 502 // TOTP enrolled
)

// ltFixedNow is the pinned clock every fixture uses, so TOTP codes and the
// (fail-open-on-window-only) per-IP budget are both fully deterministic.
var ltFixedNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// ltEndpoint enumerates G1's population, in the same order the spec lists it.
type ltEndpoint int

const (
	epLogin ltEndpoint = iota
	epRefreshToken
	epVerifyMFA
	epBeginWebAuthnLogin
	epFinishWebAuthnLogin
	epBeginWebAuthnPasswordlessLogin
	epFinishWebAuthnPasswordlessLogin
	epConsumeSetup
	numLTEndpoints = 8
)

// ltWebAuthnCredentialJSON is a syntactically-valid, base64url-clean (but
// cryptographically meaningless) assertion response —
// protocol.ParseCredentialRequestResponseBytes accepts it (verified directly
// against the library: a valid base64url id/rawId and a >=37-byte
// authenticatorData are both required, unlike FuzzWebAuthnCredentialResponse's
// own deliberately-malformed "id":"x" seed, which the library actually
// rejects at parse) — so a Finish* handler reaches its reserve call and its
// real, deep verification failure, never the shallow JSON-decode 400 that
// would skip reserve by design.
const ltWebAuthnCredentialJSON = `{"id":"Y3JlZGVudGlhbC1pZC0wMDAx","rawId":"Y3JlZGVudGlhbC1pZC0wMDAx","type":"public-key","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20ifQ","authenticatorData":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJA","signature":"ZmFrZS1zaWduYXR1cmUtYnl0ZXMtbm90LXJlYWwtY3J5cHRv"}}`

// ltIP returns one of three fixed, canonical per-op IPs (bare host — exactly
// what core.CanonicalIP/clientIP store and this file later queries by).
func ltIP(idx int) string {
	return fmt.Sprintf("198.51.100.%d", 10+(idx%3))
}

// buildLoginThrottleFixture builds a real AuthHandler over a real in-memory
// SQLite KeyorixCore: two users (lt-plain with no second factor, lt-totp
// available for real TOTP activation), a pinned clock, and a real, ENABLED
// per-account login-lockout policy with a small MaxAttempts so oracle (b)'s
// sub-check below can trip it without a large burst.
//
// Deliberately does NOT set up a real at-rest encryptor or activate lt-totp's
// TOTP secret here — encryption.Service.Initialize wraps a fresh DEK with a
// deliberately slow KDF, and doing that on every single fuzz execution (most
// of which never touch the MFA branch at all — VerifyMFA's op in the main
// loop below always sends a garbage challenge, which fails identically
// whether or not lt-totp has real MFA activated) measurably starved this
// harness's exec/s. ensureLTTOTPActivated does that setup lazily, only when
// the fuzzed lockoutViaMFA selector actually needs a genuinely valid code.
func buildLoginThrottleFixture(t *testing.T) (*AuthHandler, *core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// A bare ":memory:" DSN gives EACH new connection its own separate, empty
	// database -- gorm's connection pool opening a second connection mid-test
	// would silently see a blank DB (missing every AutoMigrate'd table). Cap to
	// one connection, same as pat_validate_lifecycle_fuzz_test.go's fixture.
	if sqlDB, serr := db.DB(); serr == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.MFASecret{}, &models.MFARecoveryCode{},
		&models.MFAChallenge{}, &models.Session{}, &models.AuditEvent{},
		&models.LoginAttempt{}, &models.SetupToken{},
		&models.WebAuthnCredential{}, &models.WebAuthnSession{},
	))

	hash, err := bcrypt.GenerateFromPassword([]byte(loginThrottleTestPassword), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.User{
		ID: ltPlainUserID, Username: "lt-plain", UsernameFolded: "lt-plain",
		Email: "lt-plain@x.io", EmailFolded: "lt-plain@x.io",
		PasswordHash: string(hash), IsActive: true, AccountState: core.AccountActive,
	}).Error)
	require.NoError(t, db.Create(&models.User{
		ID: ltTOTPUserID, Username: "lt-totp", UsernameFolded: "lt-totp",
		Email: "lt-totp@x.io", EmailFolded: "lt-totp@x.io",
		PasswordHash: string(hash), IsActive: true, AccountState: core.AccountActive,
	}).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetClockForTesting(func() time.Time { return ltFixedNow })
	c.SetLoginLockoutPolicy(core.LoginLockoutPolicy{
		Enabled: true, MaxAttempts: 3, Window: 15 * time.Minute,
		BaseCooldown: time.Hour, MaxCooldown: time.Hour,
	})

	return NewAuthHandler(c, false), c, db
}

// ensureLTTOTPActivated wires a real at-rest encryptor onto c and activates a
// real TOTP secret for lt-totp, returning the base32 secret. Only called from
// the oracle (b) sub-check's MFA branch — see buildLoginThrottleFixture's doc
// for why this is lazy rather than unconditional per-iteration setup.
func ensureLTTOTPActivated(t *testing.T, c *core.KeyorixCore) string {
	t.Helper()
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))
	c.SetAuthEncryptor(enc)

	_, secret, err := c.BeginMFAEnrollment(context.Background(), ltTOTPUserID)
	require.NoError(t, err)
	// Activate using the previous 30s step so the CURRENT step (ltFixedNow) stays
	// available, unused, for the oracle (b) sub-check's real VerifyMFA call
	// (mirrors the established convention in mfa_stepup_handler_test.go).
	actCode, err := totp.GenerateCode(secret, ltFixedNow.Add(-30*time.Second))
	require.NoError(t, err)
	_, err = c.ActivateMFA(context.Background(), ltTOTPUserID, actCode, loginThrottleTestPassword, "")
	require.NoError(t, err)
	return secret
}

// fireLTOp fires one op-code's request at the real handler for ep, from ip,
// using a payload crafted to be well-formed enough to reach that endpoint's
// reserve call site (never a shallow decode/parse 400 that skips it by
// design) while still failing its slow credential check. Returns the HTTP
// status code.
func fireLTOp(t *testing.T, h *AuthHandler, ep ltEndpoint, ip string) int {
	t.Helper()
	method := http.MethodPost
	var body string
	var withBearer bool

	switch ep {
	case epLogin:
		body = `{"username":"lt-plain","password":"wrong-password"}`
	case epRefreshToken:
		withBearer = true
	case epVerifyMFA:
		body = `{"mfa_challenge":"garbage-challenge","code":"000000"}`
	case epBeginWebAuthnLogin:
		body = `{"mfa_challenge":"garbage-challenge"}`
	case epFinishWebAuthnLogin:
		body = fmt.Sprintf(`{"mfa_challenge":"garbage","webauthn_session":"garbage","credential":%s}`, ltWebAuthnCredentialJSON)
	case epBeginWebAuthnPasswordlessLogin:
		// no body
	case epFinishWebAuthnPasswordlessLogin:
		body = fmt.Sprintf(`{"webauthn_session":"garbage","credential":%s}`, ltWebAuthnCredentialJSON)
	case epConsumeSetup:
		body = `{"token":"garbage-setup-token","password":"Xy9!aBcdEfghi"}`
	default:
		t.Fatalf("fireLTOp: unknown endpoint %d", ep)
	}

	req := httptest.NewRequest(method, "/", strings.NewReader(body))
	req.RemoteAddr = ip + ":40000"
	if withBearer {
		req.Header.Set("Authorization", "Bearer garbage-refresh-token")
	}
	w := httptest.NewRecorder()

	switch ep {
	case epLogin:
		h.Login(w, req)
	case epRefreshToken:
		h.RefreshToken(w, req)
	case epVerifyMFA:
		h.VerifyMFA(w, req)
	case epBeginWebAuthnLogin:
		h.BeginWebAuthnLogin(w, req)
	case epFinishWebAuthnLogin:
		h.FinishWebAuthnLogin(w, req)
	case epBeginWebAuthnPasswordlessLogin:
		h.BeginWebAuthnPasswordlessLogin(w, req)
	case epFinishWebAuthnPasswordlessLogin:
		h.FinishWebAuthnPasswordlessLogin(w, req)
	case epConsumeSetup:
		h.ConsumeSetup(w, req)
	}
	return w.Code
}

// ltLoginAttemptCount reads the ground-truth reserved-slot count for ip
// directly off storage — the "instrumentation point" this harness's oracles
// use instead of wall-clock timing.
func ltLoginAttemptCount(t *testing.T, db *gorm.DB, ip string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Where("ip = ?", ip).Count(&n).Error)
	return n
}

// mixedLTSeed is a hand-built interleaving spanning all 3 IPs and all 8
// endpoints (b%3 selects the IP, b/3%8 selects the endpoint), biased to push
// at least one IP's shadow count past core.LoginMaxAttempts (10) so the
// oracle (c) cross-endpoint consistency check actually exercises its
// "already limited" branch, not just the "not yet limited" one.
var mixedLTSeed = []byte{
	0, 3, 6, 9, 12, 15, 18, 21, // one of each endpoint, in order, all on ip0
	1, 4, 7, 10, 13, 16, 19, 22, // same, all on ip1
	2, 5, 8, 11, 14, 17, 20, 23, // same, all on ip2
	0, 3, 6, 9, 12, 15, 18, 21, // second pass on ip0 -- pushes its shadow count past the budget mid-pass
}

func FuzzLoginThrottleConcurrency(f *testing.F) {
	// b -> ipIdx = int(b) % 3, epIdx = int(b/3) % 8
	f.Add([]byte{0, 3, 6, 9, 12, 15, 18, 21}, byte(0)) // one of each endpoint, single IP (b%3==0 throughout)
	// Hammer ConsumeSetup ALONE past the shared budget on ip1 -- b%3==1, b/3%8==7 (epConsumeSetup)
	// requires b in {22, 25, ...}: 22%3=1, 22/3=7 -> ep 7. Use 22 repeated.
	f.Add([]byte{22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22}, byte(0))
	// Hammer BeginWebAuthnPasswordlessLogin ALONE past the shared budget on ip2 --
	// need b%3==2 and b/3%8==5 (epBeginWebAuthnPasswordlessLogin): b=17 -> 17%3=2, 17/3=5. Use 17 repeated.
	f.Add([]byte{17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17}, byte(1))
	f.Add(mixedLTSeed, byte(0))
	f.Add(mixedLTSeed, byte(1))
	f.Add([]byte{}, byte(0)) // empty op sequence -- only the oracle (b) sub-check runs

	f.Fuzz(func(t *testing.T, ops []byte, lockoutViaMFA byte) {
		// Bound wall-clock/DB growth per single execution -- burst size is fuzzed,
		// not unbounded.
		if len(ops) > 40 {
			ops = ops[:40]
		}

		h, c, db := buildLoginThrottleFixture(t)

		shadow := map[string]int{}
		for i, b := range ops {
			ipIdx := int(b) % 3
			ep := ltEndpoint(int(b/3) % numLTEndpoints)
			ip := ltIP(ipIdx)

			priorCount := ltLoginAttemptCount(t, db, ip)

			var status int
			fuzzutil.Guard(t.Fatalf, fmt.Sprintf("op %d endpoint %d", i, ep), func() {
				status = fireLTOp(t, h, ep, ip)
			})

			afterCount := ltLoginAttemptCount(t, db, ip)
			delta := afterCount - priorCount
			if delta < 0 || delta > 1 {
				t.Fatalf("op %d (ip=%s ep=%d): login_attempts row count for this IP changed by %d in one call (must be 0 or 1)",
					i, ip, ep, delta)
			}

			expectedLimited := shadow[ip] >= int(core.LoginMaxAttempts)
			switch {
			case expectedLimited && status != http.StatusTooManyRequests:
				t.Fatalf("BUDGET INCONSISTENT (oracle c): op %d (ip=%s ep=%d) expected 429 -- shadow count %d already "+
					"at/over the shared %d-attempt budget -- but got HTTP %d. This endpoint appears to have its own, "+
					"separate (larger) budget instead of sharing the per-IP one.",
					i, ip, ep, shadow[ip], core.LoginMaxAttempts, status)
			case expectedLimited && delta != 0:
				t.Fatalf("op %d (ip=%s ep=%d): a request the shared budget should have rejected outright still reserved "+
					"a slot (delta=%d, want 0)", i, ip, ep, delta)
			case !expectedLimited && status == http.StatusTooManyRequests:
				t.Fatalf("op %d (ip=%s ep=%d): got 429 before the shared budget (shadow=%d < %d) was exhausted",
					i, ip, ep, shadow[ip], core.LoginMaxAttempts)
			case !expectedLimited && delta != 1:
				t.Fatalf("BUDGET NOT RESERVED (oracle a): op %d (ip=%s ep=%d) reached its slow credential-adjacent check "+
					"(HTTP %d, not rate-limited) but did not reserve a login-attempt budget slot (delta=%d, want 1) -- "+
					"this endpoint can be hammered without ever contributing to the shared per-IP throttle.",
					i, ip, ep, status, delta)
			default:
				shadow[ip]++
			}
		}

		// Oracle (b): a per-account-locked account never obtains a session via a
		// genuinely correct credential, on a dedicated IP untouched by the op loop
		// above (so its own reservations never interact with the shadow counts
		// just checked).
		checkLTAccountLockoutNeverBypassed(t, h, c, db, lockoutViaMFA)
	})
}

// checkLTAccountLockoutNeverBypassed trips lt-plain's per-account lockout
// (MaxAttempts=3, set by buildLoginThrottleFixture) with real wrong-password
// Logins, confirms the lock actually took (ground truth: the User row's own
// LoginLockedUntil column, not an inferred status code), then tries the
// GENUINELY CORRECT password anyway and asserts no session is minted. When
// lockoutViaMFA selects it, the same is repeated for lt-totp using a real,
// currently-valid TOTP code through VerifyMFA instead of Login (lazily
// activating lt-totp's real TOTP secret only on this path — see
// ensureLTTOTPActivated's doc).
func checkLTAccountLockoutNeverBypassed(t *testing.T, h *AuthHandler, c *core.KeyorixCore, db *gorm.DB, lockoutViaMFA byte) {
	t.Helper()
	const ip = "203.0.113.77" // dedicated -- never touched by the op-sequence loop's IPs

	tripLockout := func(username string, portBase int) {
		for i := range 3 {
			body := fmt.Sprintf(`{"username":%q,"password":"definitely-wrong"}`, username)
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			req.RemoteAddr = fmt.Sprintf("%s:%d", ip, portBase+i)
			w := httptest.NewRecorder()
			fuzzutil.Guard(t.Fatalf, "Login (tripping lockout)", func() { h.Login(w, req) })
		}
	}

	if lockoutViaMFA%2 == 1 {
		totpSecret := ensureLTTOTPActivated(t, c)
		tripLockout("lt-totp", 51000)
		var u models.User
		require.NoError(t, db.First(&u, ltTOTPUserID).Error)
		require.NotNil(t, u.LoginLockedUntil, "lt-totp must be locked after 3 wrong passwords (MaxAttempts=3)")

		challenge, err := c.CreateMFAChallenge(context.Background(), ltTOTPUserID)
		require.NoError(t, err)
		code, err := totp.GenerateCode(totpSecret, ltFixedNow)
		require.NoError(t, err)

		body := fmt.Sprintf(`{"mfa_challenge":%q,"code":%q}`, challenge, code)
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.RemoteAddr = ip + ":52000"
		w := httptest.NewRecorder()
		fuzzutil.Guard(t.Fatalf, "VerifyMFA (locked account, correct code)", func() { h.VerifyMFA(w, req) })
		if w.Code == http.StatusOK {
			t.Fatalf("LOCKOUT BYPASS (oracle b): VerifyMFA minted a session for locked account lt-totp using a "+
				"genuinely correct TOTP code (HTTP %d)", w.Code)
		}
		var sessions int64
		require.NoError(t, db.Model(&models.Session{}).Where("user_id = ?", ltTOTPUserID).Count(&sessions).Error)
		if sessions != 0 {
			t.Fatalf("LOCKOUT BYPASS (oracle b): a session row exists for locked account lt-totp after VerifyMFA")
		}
		return
	}

	tripLockout("lt-plain", 50000)
	var u models.User
	require.NoError(t, db.First(&u, ltPlainUserID).Error)
	require.NotNil(t, u.LoginLockedUntil, "lt-plain must be locked after 3 wrong passwords (MaxAttempts=3)")

	body := fmt.Sprintf(`{"username":"lt-plain","password":%q}`, loginThrottleTestPassword)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.RemoteAddr = ip + ":53000"
	w := httptest.NewRecorder()
	fuzzutil.Guard(t.Fatalf, "Login (locked account, correct password)", func() { h.Login(w, req) })
	if w.Code == http.StatusOK {
		t.Fatalf("LOCKOUT BYPASS (oracle b): Login minted a session for locked account lt-plain using the "+
			"genuinely correct password (HTTP %d)", w.Code)
	}
	var sessions int64
	require.NoError(t, db.Model(&models.Session{}).Where("user_id = ?", ltPlainUserID).Count(&sessions).Error)
	if sessions != 0 {
		t.Fatalf("LOCKOUT BYPASS (oracle b): a session row exists for locked account lt-plain after Login")
	}
}
