// local_transaction.go — WithTransaction for the local (DB-backed) store.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"gorm.io/gorm"
)

// WithTransaction runs fn inside a single GORM transaction. fn receives a
// transaction-scoped LocalStorage: every mutation it makes is committed together when
// fn returns nil, and rolled back together if fn returns an error (or panics). The
// transaction-scoped store shares the parent's audit-chain, audit-checkpoint, and
// bootstrap mutexes so an audit append, checkpoint write, or bootstrap seed inside
// the transaction still serializes correctly (ADR-029/#339).
//
// It also shares the parent's read-path cache POINTER but deliberately does NOT
// copy cacheEnabled, so every read inside the transaction goes live. That is
// required, not a tuning choice: a tx-scoped store reads through the
// transaction handle, so it sees uncommitted generations and uncommitted data,
// and publishing those into a cache that outlives the transaction lets a
// rolled-back answer be served once a later committed write reproduces the same
// generation value. See cacheEnabled's doc comment on LocalStorage. Going live
// inside the transaction is also strictly more correct for read-your-own-writes
// — the transaction handle sees its own uncommitted writes, a cache hit would
// not.
func (ls *LocalStorage) WithTransaction(ctx context.Context, fn func(storage.Storage) error) error {
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(&LocalStorage{
			db:                    tx,
			auditChainMu:          ls.auditChainMu,
			auditCheckpointMu:     ls.auditCheckpointMu,
			bootstrapMu:           ls.bootstrapMu,
			namedLockMu:           ls.namedLockMu,
			consumeClockWatermark: ls.consumeClockWatermark,
			rbacClockWatermark:    ls.rbacClockWatermark,
			// auditSkipDurableSync (ADR-112 Amendment 1) is deliberately NOT
			// propagated, and this is a correctness requirement rather than an
			// oversight: a clone's audit append runs logAuditEventDirect inside
			// THIS tx (GORM nests it as a SAVEPOINT), so a `SET LOCAL
			// synchronous_commit = off` issued there would relax the commit
			// durability of the caller's whole transaction — the secret
			// mutation included — not just the audit row. Leaving the field at
			// its zero value keeps that transaction durable.
			// TestWithTransaction_CloneNeverInheritsAuditSkipDurableSync is the
			// guard; a future refactor to a `clone := *ls` whole-struct copy
			// would break it and must re-read this.
			secretMetaCache: ls.secretMetaCache,
			rolePermCache:   ls.rolePermCache,
		})
	})
}
