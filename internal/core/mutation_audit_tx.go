// mutation_audit_tx.go — a security-relevant mutation and its audit row commit
// in ONE transaction (AUDIT-TX-2, the follow-up to AUDIT-MUTATION-TX-1's
// secret_mutation_audit.go).
//
// Role grants, permission changes, role definitions, group memberships and
// group grants, shares, and the other grant-shaped mutations listed in
// INV-CORE-security-mutation-audit-same-tx used to commit first and then append
// their audit row through c.storage. A crash between the two, or an audit log
// that refused the row, left a committed grant with no audit record: REVIEW-1
// found it for AssignUserRole (#3284's oracle comment states it outright).
//
// withAuditedMutation runs the mutation and its audit writes through the same
// transaction-scoped store. The audit target it hands the mutation is
// fail-closed: a write that does not persist (error or panic) becomes
// ErrMutationAuditUnavailable, and the transaction rolls back. Off-box side
// effects (SIEM forward, live-tail wake-up) are held in the sink and run only
// after the commit.
//
// The audit writes must be the LAST statements of the transaction. On
// PostgreSQL the append takes the chain's transaction-scoped advisory lock
// (local_audit_chain.go), held until this transaction ends, which is what keeps
// chain order equal to commit order for a row written inside a business
// transaction; anything run after it only lengthens that hold. On SQLite every
// transaction is BEGIN IMMEDIATE, so the chain head the append reads is already
// the committed head. The transaction-scoped store never inherits
// auditSkipDurableSync (local_transaction.go), so audit_durability=standard does
// not relax the mutation's commit.
//
// Connection budget: callers that hold a named lock (WithNamedLock keeps its
// own Postgres session) open this transaction INSIDE the lock, the order
// access_review_decide_tx.go documents. Everything inside fn must go through
// tx, never c.storage, or the chain needs a third pooled connection.
//
// Revocations do NOT use this (Andrei 2026-10-14: a revocation is never blocked
// by the audit log). They keep their best-effort audit after the commit;
// #3345's owed-audit record + backfill is the follow-up for those once merged.
package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// ErrMutationAuditUnavailable: a security-relevant mutation's audit row could
// not be written, so its transaction rolled back and nothing was changed.
var ErrMutationAuditUnavailable = errors.New("could not record the change in the audit log; nothing was changed, retry")

// errMutationWroteNoAudit is returned when fn committed nothing to the audit
// log. Every caller of withAuditedMutation writes at least one row, so this is
// a programming error (a refactor that dropped the audit call): fail closed
// rather than commit an unaudited grant.
var errMutationWroteNoAudit = errors.New("mutation wrote no audit row")

// withAuditedMutation runs fn in one transaction with a fail-closed audit
// target bound to it. The transaction commits only when fn returns nil AND
// every audit write fn made through tgt persisted (at least one). Off-box audit
// side effects run after the commit.
func (c *KeyorixCore) withAuditedMutation(ctx context.Context, fn func(tx storage.Storage, tgt auditTarget) error) error {
	sink := &auditForwardSink{failClosed: true}
	if err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		if err := fn(tx, auditInto(tx, sink)); err != nil {
			return err
		}
		if sink.err != nil {
			return sink.err
		}
		if len(sink.persisted) == 0 {
			return fmt.Errorf("%w: %w", ErrMutationAuditUnavailable, errMutationWroteNoAudit)
		}
		return nil
	}); err != nil {
		return err
	}
	sink.Flush(c)
	return nil
}

// mutationAuditActorKey tags a request context with the actor a core mutation
// should attribute its in-transaction audit row to (WithMutationAuditActor).
type mutationAuditActorKey struct{}

// WithMutationAuditActor tags ctx so a core mutation whose audit row used to be
// written by its transport after the commit (project and environment create)
// writes that row inside its own transaction instead, attributed to actorID
// (0 = no authenticated principal). The transport must then NOT write the row
// itself. Untagged callers get the mutation with no audit row from core, as
// before.
func WithMutationAuditActor(ctx context.Context, actorID uint) context.Context {
	return context.WithValue(ctx, mutationAuditActorKey{}, actorID)
}

func mutationAuditActorFromContext(ctx context.Context) (uint, bool) {
	a, ok := ctx.Value(mutationAuditActorKey{}).(uint)
	return a, ok
}

// mutationTx runs fn in one transaction: through withAuditedMutation (fail
// closed, at least one audit row) when audited, else as a plain transaction in
// which fn receives a zero auditTarget and must write no audit row.
func (c *KeyorixCore) mutationTx(ctx context.Context, audited bool, fn func(tx storage.Storage, tgt auditTarget) error) error {
	if audited {
		return c.withAuditedMutation(ctx, fn)
	}
	return c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		return fn(tx, auditTarget{})
	})
}
