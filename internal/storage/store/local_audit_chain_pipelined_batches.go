// local_audit_chain_pipelined_batches.go — PERF-HIGHLOAD-1: up to
// auditPipelineDepth Postgres audit batches in flight, so the flusher builds and
// sends batch N+1 while batch N executes and commits
// (docs/specs/audit-pipelined-commits.md).
//
// A batch is sent pipelined only as a one-flight transaction
// (local_audit_chain_one_flight.go). The first batch of a run chains onto the
// armed chain-head cache, as a one-flight commit always did. Every later batch
// chains onto the last row of the batch sent just before it, whose id is not
// known yet (a pending head): its in-transaction check compares the head's
// entry_hash instead (auditInsertCheckSQL), so a batch whose predecessor did not
// commit, or whose head another writer moved, raises and is rolled back. Chain
// positions are assigned before the batch is sent, batches are sent one after
// another from the flusher goroutine, and Postgres runs them one at a time on
// KEYAUDIT, so the chain order is the send order.
//
// Outcomes are handled in send order (each batch waits for its predecessor's
// completion), with the same rules as a serial one-flight attempt: a commit
// updates the cache; a failure that provably wrote nothing is retried through
// the two-flight path, which re-reads the head under the lock, then isolated by
// the bisection (finishAuditBatch); any other failure fails its items. Every
// item gets its batch's result only after that batch's COMMIT was acknowledged,
// or an error. A run ends as soon as the cache epoch moves (a miss, a failure,
// an invalidation): the flusher waits for the batches in flight and commits
// serially until the cache re-arms.
//
// SQLite and a non-pgx Postgres pool never pipeline: their cache never arms
// (INV-STORE-audit-one-flight-commit rule 4), and only an armed cache starts a
// run.
package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// auditPipelineDepth is how many batches may be in flight at once. Postgres
// runs them one at a time on KEYAUDIT, so a second batch is enough to keep the
// flusher's connection busy while the next one is built; a third would only
// wait for the lock, holding a pool connection.
const auditPipelineDepth = 2

// auditInflightBatch is one batch sent pipelined.
type auditInflightBatch struct {
	batch []*auditBatchItem
	epoch uint64
	plan  *auditOneFlightPlan
	// tailHash is the entry_hash of the batch's last row as it was sent, the
	// head the next batch chains onto. Copied before the batch is handed to its
	// goroutine: a retry re-chains the batch's own events.
	tailHash string
	prev     *auditInflightBatch // completed before this one; nil for the first of a run
	sent     chan struct{}       // closed once the flight is on the wire (or could not be sent)
	done     chan struct{}       // closed once the batch's items have their results
}

// auditBatchPipeline is the flusher goroutine's pipeline state. Only the
// flusher goroutine reads or writes its fields; the batches' own goroutines
// touch only their auditInflightBatch and slots.
type auditBatchPipeline struct {
	ls    *LocalStorage
	slots chan struct{} // one token per batch in flight
	epoch uint64        // the cache epoch the current run began under
	tail  *auditInflightBatch
}

// newAuditBatchPipeline returns the pipeline for one flusher run, or nil when
// this store never pipelines (not Postgres, or a depth below two).
func (ls *LocalStorage) newAuditBatchPipeline() *auditBatchPipeline {
	if auditPipelineDepth < 2 || ls.db == nil || ls.db.Dialector.Name() != "postgres" {
		return nil
	}
	return &auditBatchPipeline{ls: ls, slots: make(chan struct{}, auditPipelineDepth)}
}

// commitFlusherBatch commits batch for the flusher: pipelined when it can be,
// otherwise serially once every batch in flight has completed. Every item of
// batch gets exactly one result either way.
func (ls *LocalStorage) commitFlusherBatch(p *auditBatchPipeline, batch []*auditBatchItem) {
	if p.trySend(batch) {
		return
	}
	p.drain()
	deliverAuditBatch(batch, ls.commitAuditBatch(batch))
}

func deliverAuditBatch(batch []*auditBatchItem, errs []error) {
	for i, item := range batch {
		item.done <- errs[i]
	}
}

// drain waits until every batch in flight has completed and ends the run.
func (p *auditBatchPipeline) drain() {
	if p == nil || p.tail == nil {
		return
	}
	<-p.tail.done // completions are in send order: the last one is the last to finish
	p.tail = nil
}

// auditPipelineFits reports whether batch's events fit one INSERT, the only
// shape whose check can chain onto a pending head. Every flusher batch does
// (TestAuditInsertRowsPerStatement_CoversAFullFlusherBatch).
func auditPipelineFits(batch []*auditBatchItem) bool {
	perStmt, err := auditInsertRowsPerStatement(&models.AuditEvent{})
	return err == nil && len(batch) <= perStmt
}

// trySend sends batch pipelined and reports whether it did. It does not when
// no run is open and the cache is not armed, or when the batch cannot be built;
// the caller then commits it serially.
func (p *auditBatchPipeline) trySend(batch []*auditBatchItem) bool {
	if p == nil || !auditPipelineFits(batch) {
		return false
	}
	ls := p.ls
	var head auditChainHead
	if p.tail != nil && ls.auditHead.currentEpoch() == p.epoch {
		head = auditChainHead{hash: p.tail.tailHash, pending: true}
	} else {
		p.drain()
		epoch, cached, armed := ls.auditHead.begin()
		if !armed {
			return false
		}
		head, p.epoch = cached, epoch
	}
	plan, err := ls.prepareAuditOneFlight(batch[0].ctx, batch, head)
	if err != nil {
		// Nothing was sent; the serial commit builds the batch again and
		// reports the error if it persists.
		p.drain()
		return false
	}
	b := &auditInflightBatch{
		batch:    batch,
		epoch:    p.epoch,
		plan:     plan,
		tailHash: plan.tailHash(),
		prev:     p.tail,
		sent:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	p.slots <- struct{}{}
	if head.pending {
		auditPipelinedBatches.Inc()
		ls.auditHead.pipelinedSends.Add(1)
	}
	go p.run(b)
	<-b.sent // the next batch is built only once this one is on the wire
	p.tail = b
	return true
}

// run sends b on a pool connection of its own, reads its results, and once
// b.prev has completed, completes b.
func (p *auditBatchPipeline) run(b *auditInflightBatch) {
	ls := p.ls
	ctx := b.batch[0].ctx
	var last auditChainHead
	beforeCommit := true
	sent := false
	err := ls.withAuditPipelineConn(ctx, func(pc *pgx.Conn) error {
		b.plan.f.send(pc)
		sent = true
		close(b.sent)
		var err error
		last, beforeCommit, err = b.plan.read()
		return err
	})
	if !sent {
		close(b.sent)
	}
	if b.prev != nil {
		<-b.prev.done
	}
	deliverAuditBatch(b.batch, ls.completePipelinedBatch(ctx, b, last, beforeCommit, err))
	close(b.done)
	<-p.slots
}

// completePipelinedBatch turns b's flight outcome into its items' results, as
// commitBatchAttemptPipelined and commitAuditBatch would for a serial
// one-flight attempt.
func (ls *LocalStorage) completePipelinedBatch(ctx context.Context, b *auditInflightBatch, last auditChainHead, beforeCommit bool, err error) []error {
	switch {
	case err == nil:
		ls.auditHead.committedOneFlight(b.epoch, last)
		return ls.finishAuditBatch(b.batch, nil)
	case errors.Is(err, errAuditPipelineUnavailable):
		// Unreachable while only an armed cache starts a run (a non-pgx pool
		// never arms it); kept so such a batch still commits, through the GORM
		// transaction.
		return ls.commitAuditBatch(b.batch)
	case auditOneFlightRolledBack(err, beforeCommit):
		// Nothing was written: the head moved (another writer, or the batch
		// before this one did not commit) or a statement failed. Retry once in
		// two flights, then bisect, as a serial one-flight miss does.
		ls.auditHead.missedOneFlight()
		return ls.finishAuditBatch(b.batch, ls.commitBatchTwoFlights(ctx, b.batch))
	default:
		// May have committed (a lost connection, an error on COMMIT): fail
		// closed, as a serial attempt does.
		ls.auditHead.failed()
		return ls.finishAuditBatch(b.batch, err)
	}
}
