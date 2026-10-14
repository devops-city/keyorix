// login_rate_limit_reserve_interleaving_test.go — #2816: a DETERMINISTIC test
// of the property TestLogin_ConcurrentBurst_RateLimitBoundsCredentialChecks
// (login_rate_limit_reserve_test.go) only ever tested statistically.
//
// THE PROPERTY. F2 (2026-09-20): every unauthenticated endpoint used to check
// the per-IP login-attempt budget, run the slow credential check
// (bcrypt/TOTP/WebAuthn assertion), and record the attempt only AFTERWARD, and
// only on failure. Since the check and the record straddled the slow step, a
// burst from one IP all read the same under-budget count and all proceeded.
// The fix moves the record (reserveLoginAttempt) BEFORE the slow step, so the
// budget is consumed at ADMISSION time rather than at verdict time.
//
// WHY THE EXISTING TEST FLAKES. It fires 5 rounds x 30 maximally-synchronized
// requests and asserts the AGGREGATE 429 count clears 40. That is a
// statistical proxy: whether a given request in the burst is refused depends on
// how the Go scheduler and the SQLite-backed reserve interleave with bcrypt,
// which under CI load shifts enough to miss the threshold (#2816 records 38
// observed against a threshold of 40). Its own file header says as much
// ("inherently a timing-sensitive property", "noisy enough for a single round
// to flake either way in CI"), and it is already skipped entirely under -race
// for the same reason.
//
// THE THRESHOLD IS NOT LOWERED, HERE OR THERE. This test does not weaken, relax
// or replace that assertion -- it tests the same property by CONSTRUCTION
// instead of by sampling, which makes the threshold irrelevant rather than
// negotiable. The ordering is observed directly: one login request is PARKED
// inside its credential check, and while it is parked -- with not one
// credential check in the process having completed -- the budget is observed to
// have already been consumed. Under the pre-fix ordering nothing is reserved at
// that moment, so both assertions below fail. There is no sampling, no sleep,
// and no scheduler assumption: every wait is a rendezvous on a channel the
// parked call itself signals, and each is bounded so a regression fails loudly
// instead of hanging the package (CLAUDE.md: bound every wait, or a correctly-
// serialized pair hangs the binary).
//
// It also runs under -race, unlike the burst test.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// rendezvousTimeout bounds every wait in this test. Generous on purpose:
// a timeout here detects a hang, it does not enforce speed (CLAUDE.md).
const rendezvousTimeout = 30 * time.Second

// parkedLoginStorage parks GetUserByUsername -- the FIRST storage call
// core.Login makes, inside VerifyPasswordCredentials, and the one that stands
// in for "the slow credential check has begun but not finished". Every other
// method is delegated untouched through the embedded interface.
//
// It signals `entered` and parks BEFORE delegating, so a parked goroutine
// holds no DB connection, no GORM session and no SQLite lock. That matters:
// this package's test DBs are shared-cache in-memory SQLite, and parking
// mid-query would deadlock the probe request's own counter read instead of
// testing anything (CLAUDE.md: a parked replica holds its locks).
type parkedLoginStorage struct {
	coreStorage.Storage
	entered     chan string
	release     chan struct{}
	releaseOnce sync.Once
}

func (p *parkedLoginStorage) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	p.entered <- username
	<-p.release
	return p.Storage.GetUserByUsername(ctx, username)
}

// newParkedLoginStorage registers the release as a t.Cleanup, via sync.Once so
// an explicit release in the happy path and the cleanup cannot double-close.
//
// This is not tidiness. Without it, a require.* failure runs t.FailNow ->
// runtime.Goexit, the explicit close is skipped, and every parked goroutine
// blocks forever -- which is how the first draft of this file behaved under
// its own red proof: it reported the real failure in 0.05s and then hung the
// package until the 15m test timeout. A test that detects a regression but
// hangs while doing it is a worse signal than one that fails.
func newParkedLoginStorage(t *testing.T, capacity int) *parkedLoginStorage {
	t.Helper()
	p := &parkedLoginStorage{
		Storage: freshLocalStorageS12(t),
		entered: make(chan string, capacity),
		release: make(chan struct{}),
	}
	t.Cleanup(p.releaseAll)
	return p
}

func (p *parkedLoginStorage) releaseAll() {
	p.releaseOnce.Do(func() { close(p.release) })
}

// loginRequest builds a well-formed login POST for a username that does not
// exist, from ip. A nonexistent username is deliberate: core's
// VerifyPasswordCredentials returns on the GetUserByUsername error after
// spending a dummy bcrypt compare, so no request in this test ever writes a
// per-ACCOUNT failure row -- the only login-attempt rows are the per-IP
// reservations this test is counting, with no second bookkeeping path to
// confuse the arithmetic.
func loginRequest(t *testing.T, ip string, port int) *http.Request {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"username": "nobody-interleaving-test",
		"password": "wrong-password",
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
	req.RemoteAddr = fmt.Sprintf("%s:%d", ip, port)
	return req
}

// awaitEntered waits for one parked call to announce itself.
func awaitEntered(t *testing.T, p *parkedLoginStorage, what string) {
	t.Helper()
	select {
	case <-p.entered:
	case <-time.After(rendezvousTimeout):
		t.Fatalf("%s never reached the credential check within %s -- if this is a regression rather "+
			"than a hang, the request was refused or errored BEFORE core.Login ran", what, rendezvousTimeout)
	}
}

// TestLogin_ReserveLandsBeforeCredentialCheck_Interleaved is the ordering half:
// with exactly ONE request parked inside its credential check, the IP's budget
// must already show that request's reservation.
func TestLogin_ReserveLandsBeforeCredentialCheck_Interleaved(t *testing.T) {
	const ip = "203.0.113.210"
	parked := newParkedLoginStorage(t, 1)
	c := core.NewKeyorixCore(parked)
	h := NewAuthHandler(c, false)
	ctx := context.Background()

	before, err := parked.CountRecentLoginAttempts(ctx, core.CanonicalIP(ip), time.Now().Add(-core.LoginWindow))
	require.NoError(t, err)

	done := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		h.Login(w, loginRequest(t, ip, 41000))
		done <- w.Code
	}()
	awaitEntered(t, parked, "the parked login request")

	// The assertion. The request is suspended at the START of its credential
	// check: no bcrypt compare has returned, no verdict exists, nothing has
	// failed yet. Its slot must already be consumed.
	during, err := parked.CountRecentLoginAttempts(ctx, core.CanonicalIP(ip), time.Now().Add(-core.LoginWindow))
	require.NoError(t, err)
	require.Equal(t, before+1, during,
		"ORDERING VIOLATED: a login request parked at the start of its credential check had not yet "+
			"consumed a login-attempt slot (count %d -> %d, expected %d). reserveLoginAttempt must run "+
			"BEFORE the slow credential check, not only after it fails, or a concurrent burst from one IP "+
			"all reads the same under-budget count and blows straight through the budget (F2, 2026-09-20)",
		before, during, before+1)

	parked.releaseAll()
	select {
	case code := <-done:
		require.Equal(t, http.StatusUnauthorized, code,
			"the parked request should still complete normally once released")
	case <-time.After(rendezvousTimeout):
		t.Fatal("the parked login request never completed after release")
	}
}

// TestLogin_ExhaustedBudgetRefusesWhileChecksStillInFlight is the effect half:
// the reservations alone -- with every credential check still in flight -- are
// enough to refuse the next request. This is what the burst test was sampling
// for, observed directly.
//
// Requests are dispatched ONE AT A TIME, each parked before the next is sent,
// rather than as a simultaneous burst. That is what makes it deterministic:
// request k passes the rate-limit gate because exactly k-1 slots are reserved
// at that moment, which is a fact about the sequence rather than about the
// scheduler. A simultaneous burst would have some requests refused at the gate
// and never reach the park, which is precisely the per-round noise #2816 is
// about.
func TestLogin_ExhaustedBudgetRefusesWhileChecksStillInFlight(t *testing.T) {
	const ip = "203.0.113.211"
	budget := int(core.LoginMaxAttempts)
	require.Greater(t, budget, 0, "LoginMaxAttempts must be positive for this test to mean anything")

	// capacity budget+1: the probe below must be refused at the gate, but under
	// a regression it reaches the credential check too, and its `entered` send
	// must not block -- that is how the regression is DETECTED rather than how
	// the test hangs.
	parked := newParkedLoginStorage(t, budget+1)
	h := NewAuthHandler(core.NewKeyorixCore(parked), false)

	codes := make(chan int, budget)
	for i := range budget {
		go func(i int) {
			w := httptest.NewRecorder()
			h.Login(w, loginRequest(t, ip, 42000+i))
			codes <- w.Code
		}(i)
		// Rendezvous before dispatching the next one: request i is now parked
		// inside its credential check with its slot already reserved.
		awaitEntered(t, parked, fmt.Sprintf("parked login request %d/%d", i+1, budget))
	}

	// All `budget` slots are reserved and NOT ONE credential check has
	// completed. IsLoginRateLimited trips at n >= LoginMaxAttempts, so the next
	// request from this IP must be refused AT THE GATE -- before core.Login,
	// and therefore before it could ever park.
	//
	// Dispatched on its own goroutine, and awaited as a bounded three-way
	// rendezvous, because under the regression the probe DOES reach the
	// credential check and parks there. Calling h.Login inline would then block
	// the test goroutine itself forever waiting for a 429 that is never coming
	// -- which is exactly what the first draft of this test did.
	probeCode := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		h.Login(w, loginRequest(t, ip, 43000))
		probeCode <- w.Code
	}()

	select {
	case <-parked.entered:
		t.Fatalf("CEILING VIOLATED: %d login requests are admitted and still inside their credential "+
			"checks, so the whole per-IP budget (LoginMaxAttempts=%d) is already spoken for -- yet the "+
			"next request from the same IP was admitted and reached the slow credential check itself. "+
			"The budget must be consumed at admission time, not at verdict time (F2, 2026-09-20)",
			budget, budget)
	case code := <-probeCode:
		require.Equal(t, http.StatusTooManyRequests, code,
			"CEILING VIOLATED: %d login requests are admitted and still inside their credential checks, "+
				"so the whole per-IP budget (LoginMaxAttempts=%d) is already spoken for -- yet the next "+
				"request from the same IP came back HTTP %d instead of 429",
			budget, budget, code)
	case <-time.After(rendezvousTimeout):
		t.Fatalf("the probe neither completed nor reached the credential check within %s", rendezvousTimeout)
	}

	parked.releaseAll()
	for i := range budget {
		select {
		case code := <-codes:
			require.Equal(t, http.StatusUnauthorized, code,
				"every admitted request should complete with 401 once released")
		case <-time.After(rendezvousTimeout):
			t.Fatalf("only %d of %d parked login requests completed after release", i, budget)
		}
	}
}
