// login_rate_limit_reserve_test.go — F2 (2026-09-20) regression: the per-IP
// login-attempt budget (core.LoginMaxAttempts) used to be enforced by
// checking the count, then only recording an attempt AFTER the slow
// credential check (bcrypt/TOTP/WebAuthn assertion) completed, and only on
// failure. A burst of concurrent requests from one IP all observed the SAME
// under-budget count at their check (none of the others had recorded yet),
// all proceeded through the slow verification, and only then recorded —
// letting the burst blow through the budget before the counter ever caught
// up. The fix moves the record (reserveLoginAttempt) to run BEFORE the slow
// step, right after the request is minimally well-formed (decoded), so
// concurrent requests compete for the same reserved slots instead of each
// reading a stale count.
//
// This is inherently a timing-sensitive property — a maximally-synchronized
// concurrent burst can still theoretically race the check-then-reserve pair
// itself (check and reserve are still two separate calls, not one atomic
// operation; see core's own TestConcurrency_LoginRateLimit_TripsAndStaysTripped
// doc, which explicitly does not promise "at most N ever pass" for the raw
// primitives) — a single 30-request round's too-many-requests count varied
// widely run to run in manual testing (pre-fix: 0-9 of 30; post-fix: 8-20 of
// 30 — real signal, but noisy enough for a single round to flake either way
// in CI). Aggregating several independent rounds averages out that
// per-round scheduling noise (each round uses a fresh IP so no round's
// budget carries into the next) while preserving the real distinction: the
// fix changes the SIZE of the exploitable window from "however long the
// slow credential check takes" (bcrypt, deliberately ~tens of
// milliseconds) down to "however long decode takes" (sub-millisecond).
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runLoginBurst fires a synchronized burst of concurrent Login requests
// carrying a WRONG password (so each one that gets past the rate-limit
// check runs the real, deliberately-slow bcrypt compare — including the
// dummy-hash timing-safety path for a nonexistent user, auth.go's
// dummyBcryptHash) from the SAME IP, and returns how many reached the real
// credential check (401) vs. were rate-limited (429).
func runLoginBurst(t *testing.T, h *AuthHandler, ip string, burst int) (unauthorized, tooMany, other int64) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": "nobody-burst-test", "password": "wrong-password"})
	require.NoError(t, err)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range burst {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
			req.RemoteAddr = fmt.Sprintf("%s:%d", ip, 40000+i)
			w := httptest.NewRecorder()
			<-start
			h.Login(w, req)
			switch w.Code {
			case http.StatusUnauthorized:
				atomic.AddInt64(&unauthorized, 1)
			case http.StatusTooManyRequests:
				atomic.AddInt64(&tooMany, 1)
			default:
				atomic.AddInt64(&other, 1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	return unauthorized, tooMany, other
}

// TestLogin_ConcurrentBurst_RateLimitBoundsCredentialChecks drives several
// independent synchronized bursts (each on its own fresh IP, so no round's
// budget carries into the next) through the real handler.
//
// #2816: it no longer asserts the statistical too-many-requests threshold that
// made it flaky — see the note at the end of this function. It now covers the
// load-shape properties only; the ceiling itself is asserted exactly in
// login_rate_limit_reserve_interleaving_test.go.
func TestLogin_ConcurrentBurst_RateLimitBoundsCredentialChecks(t *testing.T) {
	if raceDetectorActive {
		// -race instruments every memory access, slowing execution enough to
		// change the relative timing between the DB-backed reserve and the
		// bcrypt credential check this test depends on — confirmed
		// empirically to flake under -race even against the fixed code. See
		// login_rate_limit_reserve_race_test.go.
		t.Skip("timing-sensitive concurrency test flakes under -race (see comment); the fix itself " +
			"is red/green-verified manually, see docs/findings/2026-09-20-FINDING-login-lockout-mfa-recheck.md")
	}
	h := NewAuthHandler(freshCoreS12(t), false)

	const burst = 30
	const rounds = 5
	require.Greater(t, burst, int(core.LoginMaxAttempts),
		"each round's burst must exceed the budget for this test to mean anything")

	// Warm up the DB connection pool / i18n / goroutine scheduler on a
	// DIFFERENT IP first — an untouched process's very first request can be
	// slow enough (cold caches, lazy init) to distort the timing this test
	// depends on, without that slowness having anything to do with the
	// property under test.
	warmBody, err := json.Marshal(map[string]string{"username": "nobody-warmup", "password": "wrong-password"})
	require.NoError(t, err)
	warmReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(warmBody)))
	warmReq.RemoteAddr = "203.0.113.78:1234"
	h.Login(httptest.NewRecorder(), warmReq)

	var totalUnauthorized, totalTooMany, totalOther int64
	for round := range rounds {
		ip := fmt.Sprintf("203.0.113.%d", 100+round)
		unauthorized, tooMany, other := runLoginBurst(t, h, ip, burst)
		t.Logf("round=%d ip=%s unauthorized(reached credential check)=%d too_many_requests=%d other=%d",
			round, ip, unauthorized, tooMany, other)
		totalUnauthorized += unauthorized
		totalTooMany += tooMany
		totalOther += other
	}

	t.Logf("TOTAL across %d rounds of %d: unauthorized=%d too_many_requests=%d other=%d",
		rounds, burst, totalUnauthorized, totalTooMany, totalOther)
	assert.Zero(t, totalOther, "every response must be either 401 (reached the credential check) or 429 (rate-limited)")
	assert.Less(t, totalUnauthorized, int64(rounds*burst),
		"the rate limiter had no observable effect on any of these bursts at all")

	// #2816: the statistical threshold assertion that used to live here
	//     assert.GreaterOrEqual(t, totalTooMany, int64(40), "CEILING VIOLATED: ...")
	// is GONE, and the ceiling it defended is now asserted EXACTLY, not
	// sampled -- by TestLogin_ExhaustedBudgetRefusesWhileChecksStillInFlight
	// and TestLogin_ReserveLandsBeforeCredentialCheck_Interleaved
	// (login_rate_limit_reserve_interleaving_test.go), which park a request
	// inside its credential check and observe directly that its slot is
	// already consumed. That is the same property, proved by construction.
	//
	// This is NOT a lowered threshold. The threshold was a proxy for the
	// ceiling, calibrated against observed means (8-20 per round of 30 for
	// the fixed ordering, 0-9 for the broken one) -- overlapping
	// distributions, which is why it was never sound: a 5-round aggregate of
	// 40 sits inside the broken ordering's own best case (5*9=45). Under CI
	// load it read 38 against a threshold of 40 and failed unrelated PRs.
	// Replacing an overlapping-distribution proxy with an exact assertion
	// raises the strength of the check; keeping both would just reinstate the
	// flake. Deliberate, and flagged in the PR for the coordinator rather
	// than done quietly.
	//
	// What is deliberately KEPT here, and why this test still earns its place:
	// the two assertions above are not timing-sensitive and are the thing the
	// deterministic tests cannot cover -- they drive a genuinely simultaneous
	// 150-request burst through the real handler and require that every single
	// response is a clean 401 or 429 (no 500, no panic, no torn state), which
	// sequential-dispatch interleaving by construction never exercises.
	t.Logf("ceiling property is asserted exactly by TestLogin_ExhaustedBudgetRefusesWhileChecksStillInFlight; " +
		"this test now covers only the load-shape properties (no 5xx under a simultaneous burst, limiter has effect)")
}
