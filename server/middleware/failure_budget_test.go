package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func budgetRequest(h http.Handler, ip string) int {
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.RemoteAddr = ip + ":1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

// TestFailureBudget_RefusesAfterBurstOfFailures: burst failures are let through,
// the next attempt from the same IP is 429 without running the handler, and another
// IP has its own budget.
func TestFailureBudget_RefusesAfterBurstOfFailures(t *testing.T) {
	var ran atomic.Int32
	h := FailureBudget(3, time.Hour, http.StatusForbidden)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ran.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	for i := range 3 {
		if got := budgetRequest(h, "203.0.113.1"); got != http.StatusForbidden {
			t.Fatalf("failure %d: status %d, want 403", i+1, got)
		}
	}
	if got := budgetRequest(h, "203.0.113.1"); got != http.StatusTooManyRequests {
		t.Fatalf("after the burst: status %d, want 429", got)
	}
	if ran.Load() != 3 {
		t.Fatalf("handler ran %d times, want 3: a refused attempt must not reach the credential check", ran.Load())
	}
	if got := budgetRequest(h, "203.0.113.2"); got != http.StatusForbidden {
		t.Fatalf("another IP: status %d, want its own budget (403)", got)
	}
}

// TestFailureBudget_SuccessesCostNothing: a caller holding the secret is never
// throttled, however often it calls.
func TestFailureBudget_SuccessesCostNothing(t *testing.T) {
	h := FailureBudget(2, time.Hour, http.StatusUnauthorized)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := range 50 {
		if got := budgetRequest(h, "203.0.113.1"); got != http.StatusOK {
			t.Fatalf("success %d: status %d, want 200", i+1, got)
		}
	}
}

// TestFailureBudget_ConcurrentBurstBoundedByBudget: the budget is reserved before
// the handler runs, so N concurrent wrong guesses from one IP run the credential
// check at most burst times, not N.
func TestFailureBudget_ConcurrentBurstBoundedByBudget(t *testing.T) {
	const burst, n = 4, 64
	var ran atomic.Int32
	release := make(chan struct{})
	h := FailureBudget(burst, time.Hour, http.StatusForbidden)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ran.Add(1)
		<-release // hold every admitted request inside the check
		w.WriteHeader(http.StatusForbidden)
	}))
	var wg sync.WaitGroup
	var refused atomic.Int32
	for range n {
		wg.Go(func() {
			if budgetRequest(h, "203.0.113.9") == http.StatusTooManyRequests {
				refused.Add(1)
			}
		})
	}
	deadline := time.Now().Add(5 * time.Second)
	for refused.Load() < n-burst && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	wg.Wait()
	if got := ran.Load(); got != burst {
		t.Fatalf("%d concurrent guesses ran the check %d times, want exactly the budget %d", n, got, burst)
	}
}
