// audit_target.go — writing audit events through an explicit storage handle
// (#2676).
//
// Every audit writer in this package funnels through emitAudit, which writes via
// c.storage and then runs the event's off-box side effects (SIEM forward, waking
// live audit tails). That is correct for the overwhelming majority of callers:
// their primary operation has already committed, and the audit row is the last
// thing to happen.
//
// It is not sufficient for a caller whose primary operation and audit row must
// land or roll back TOGETHER — DecideAccessReviewItem's revoke path, where an
// `access_review.revoked` row recording a revocation that did not happen is
// false compliance evidence (see access_review_decide_tx.go). Such a caller
// needs two things emitAudit cannot give it:
//
//  1. the write to go through the TRANSACTION-scoped storage handle, not
//     c.storage, so it participates in the same commit/rollback; and
//  2. the off-box side effects to be HELD BACK until that transaction commits.
//     emitAudit's own doc comment already states the principle this preserves:
//     "do NOT forward a phantom event ... the off-box mirror must reflect the
//     durable chain, not events that never landed." An event forwarded from
//     inside a transaction that then rolls back is exactly such a phantom.
//
// auditTarget carries both. The existing writers are unchanged for every
// existing caller: each keeps its signature and delegates to an `On` variant
// with c.auditNow(), so there is ONE body per writer, not a transaction-aware
// copy of each. (A duplicated set would be the same "second,
// separately-maintained implementation" shape #2496 had to unwind.)
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// auditForwardSink holds the off-box side effects of audit events written
// inside a transaction until Flush is called after a successful commit.
// Deliberately not safe for concurrent use: a transaction is single-threaded by
// construction, and sharing one across goroutines would be a different bug.
type auditForwardSink struct {
	persisted []*models.AuditEvent
	// failClosed makes a write that does not persist (error or panic) a
	// failure of the enclosing mutation instead of a logged best-effort miss:
	// the first such failure is kept in err, and withAuditedMutation returns
	// it so the transaction rolls back (AUDIT-TX-2). false keeps the historical
	// best-effort semantics (DecideAccessReviewItem's revoke path).
	failClosed bool
	err        error
	// owe (BREAKGLASS-OWED-1) makes the target CAPTURE each event instead of
	// appending it: emitAuditOn prepares the event exactly as for a real write and
	// keeps it in owed, and the caller stores those events as pending_audit_events
	// records in its own transaction. Used only when the audit log has just
	// refused the same writes (activateBreakGlassDegraded), so the owed rows are
	// built by the same writers and carry the same attribution.
	owe  bool
	owed []*models.AuditEvent
}

// fail records a write that did not persist, when the sink is fail-closed.
func (s *auditForwardSink) fail(eventType string, cause error) {
	if s == nil || !s.failClosed || s.err != nil {
		return
	}
	s.err = fmt.Errorf("%w: audit event %q: %v", ErrMutationAuditUnavailable, eventType, cause)
}

// Flush runs the deferred side effects, in write order. Call it ONLY after the
// transaction committed; on rollback, drop the sink and call nothing.
//
// A panic in a side effect (a misbehaving forwarder) is recovered per event, as
// emitAudit's own recover does for the inline case: the transaction has already
// committed, so it must not turn a completed operation into a failure.
func (s *auditForwardSink) Flush(c *KeyorixCore) {
	for _, e := range s.persisted {
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Flush runs after the commit with no request context to
					// correlate against; log without a request ID.
					logAuditEmitPanic(context.Background(), e, r)
				}
			}()
			c.afterAuditEventPersisted(e)
		}()
	}
	s.persisted = nil
}

// auditTarget is where an audit write goes: a storage handle, plus the sink that
// defers off-box side effects when that handle is transaction-scoped.
type auditTarget struct {
	st storage.Storage
	// sink is nil for a non-transactional write, meaning "forward inline",
	// which is emitAudit's long-standing behaviour.
	sink *auditForwardSink
}

// auditNow is the ordinary, non-transactional target: write through c.storage
// and forward immediately.
func (c *KeyorixCore) auditNow() auditTarget {
	return auditTarget{st: c.storage}
}

// auditInto is the transactional target: write through tx and defer forwarding
// into sink.
func auditInto(tx storage.Storage, sink *auditForwardSink) auditTarget {
	return auditTarget{st: tx, sink: sink}
}

// emitAuditOn is emitAudit against an explicit target. emitAudit itself is the
// auditNow() case; see its doc comment (service.go) for the panic-safety and
// best-effort-failure reasoning, which is identical here and deliberately not
// restated.
//
// Best-effort is preserved for the transactional case too: a failed audit write
// is logged and reported as not-persisted, never returned as an error, so it
// cannot roll a committed security decision back. That asymmetry is tested
// (TestDecideAccessReviewItem_RevokeAuditWriteFails_DecisionStillCommits).
func (c *KeyorixCore) emitAuditOn(ctx context.Context, tgt auditTarget, event *models.AuditEvent) (persisted bool) {
	if tgt.sink == nil {
		return c.emitAudit(ctx, event)
	}
	defer func() {
		if r := recover(); r != nil {
			logAuditEmitPanic(ctx, event, r)
			tgt.sink.fail(event.EventType, fmt.Errorf("audit write panicked: %v", r))
			persisted = false
		}
	}()
	if c.skipsSuccessfulReadAudit(event) {
		return true
	}
	prepareAuditEventForEmit(ctx, event)
	if tgt.sink.owe {
		tgt.sink.owed = append(tgt.sink.owed, event)
		return true
	}
	if err := tgt.st.LogAuditEvent(ctx, event); err != nil {
		logAuditEmitFailure(ctx, event, err)
		tgt.sink.fail(event.EventType, err)
		return false
	}
	tgt.sink.persisted = append(tgt.sink.persisted, event)
	return true
}
