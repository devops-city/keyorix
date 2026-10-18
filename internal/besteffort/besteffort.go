// Package besteffort gives every caller across internal/core, server/http
// and server/grpc one shared way to run a "best-effort, post-commit step" --
// session-limit enforcement, notify fan-out, response enrichment, audit
// emission, dependency events, and the like, where the step's own primary
// write already committed and a failure in the step itself must never turn
// that already-successful operation into a reported failure.
//
// QA-1 (keyorix session reports) found this exact bug shape fixed one call
// site at a time, 12+ times: a function commits a write, then runs a
// non-critical step whose RETURNED error is deliberately discarded (`_ =
// f()`), but a PANIC in that step is NOT recovered, escapes the discard, and
// the caller sees an error (frequently a 500) for an operation that actually
// succeeded. Run and RunRecover below are the one place that panic recovery,
// failure logging and the keyorix_best_effort_failures_total metric live, so
// every call site gets all three instead of re-deriving its own copy (or, as
// happened repeatedly, omitting the panic half of it).
//
// Run is post-commit only, with ONE sanctioned in-transaction shape: the step
// is itself a nested tx.WithTransaction (a SAVEPOINT on PostgreSQL), so a
// failed statement rolls back to the savepoint and cannot abort the enclosing
// transaction (users.CreateUser's baseline-role grant). Any other use inside a
// WithTransaction closure -- including a call to a helper that runs Run, such
// as purgeStepUpGrants -- is a bug: on PostgreSQL a failed statement aborts the
// transaction and the later COMMIT silently becomes a ROLLBACK, while Run hides
// the failure. besteffort_tx_guard_test.go enforces this lexically.
//
// Do NOT use this package for a step that is part of the operation's own
// contract and must fail closed -- e.g. audit-before-disclosure, where a
// secret's value may not be released until its audit write is confirmed
// durable. That must keep failing the operation on error; wrapping it here
// would silently turn a required write into an optional one.
package besteffort

import (
	"context"
	"log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// failuresTotal counts a best-effort step's panic or returned error, by step
// name. It never counts the primary operation the step followed -- only
// this package existing makes that failure visible at all; before it, a
// swallowed error went nowhere and a panic went to the process-wide
// per-request recovery middleware's log line, with no per-step signal to
// alert on.
var failuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "keyorix_best_effort_failures_total",
	Help: "Panics or returned errors from a best-effort step that runs after a commit, by step name. Never counts the primary operation -- only the best-effort step that followed it.",
}, []string{"step"})

// Run executes fn for a best-effort step that follows an already-committed
// write. A panic in fn is recovered; a panic or a returned error is logged
// (never including a secret value -- callers must keep any sensitive detail
// out of the error fn returns, same discipline every audit log line in this
// repo already follows) and counted in keyorix_best_effort_failures_total.
// Neither is returned or otherwise propagated -- Run always returns to the
// caller exactly as if fn had succeeded, because the caller's own result
// already reflects a write that committed before Run was ever called.
//
// Run does not inspect ctx itself (an already-cancelled context does not
// skip fn) -- a best-effort step such as audit emission or notify fan-out is
// expected to still make its attempt even when the inbound request context
// is cancelling, matching every existing best-effort call site this package
// consolidates. A caller whose fn genuinely should skip on cancellation can
// check ctx.Err() inside fn itself.
//
// Run is synchronous: it does not spawn a goroutine, and must not be called
// from inside one that is not already tracked by the caller (use RunRecover
// for a call site that is already running fn in its own detached goroutine,
// e.g. goSafe).
func Run(_ context.Context, step string, fn func() error) {
	defer RunRecover(step)()
	if err := fn(); err != nil {
		recordFailure(step, err)
	}
}

// RunRecover returns the recover-only half of Run, for a call site that is
// already running asynchronously in its own goroutine (a detached `go
// func(){...}()`) and only needs the panic-recovery and metric, not Run's
// synchronous call to fn. Call it as the goroutine's own first deferred
// statement:
//
//	go func() {
//	    defer RunRecover("step-name")()
//	    fn()
//	}()
func RunRecover(step string) func() {
	return func() {
		if r := recover(); r != nil {
			failuresTotal.WithLabelValues(step).Inc()
			log.Printf("SECURITY: best-effort step %q panicked (post-commit, primary operation already succeeded): %v", step, r)
		}
	}
}

func recordFailure(step string, err error) {
	failuresTotal.WithLabelValues(step).Inc()
	log.Printf("best-effort step %q failed (post-commit, primary operation already succeeded): %v", step, err)
}
