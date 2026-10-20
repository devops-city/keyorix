// audit_owed.go — audit rows owed by an operation that takes effect without waiting
// for the audit log. A plain secret suspend is the one such operation: revocation is
// never blocked or delayed by an audit failure (Andrei, 2026-10-14). Its audit row is
// still never silently lost:
//
//  1. The effect and a pending_audit_events record of the owed row commit in ONE
//     transaction, so the effect can never commit without either its audit row or a
//     durable record of the missing one. If even that record cannot be written, the
//     effect is applied on its own: revocation wins, and the gap is logged.
//  2. The owed row is appended, and the record claimed (deleted), in one transaction
//     with a bounded wait. Success is the normal case and leaves nothing behind.
//  3. Otherwise the failure is loud: a SECURITY log line naming the event, a process
//     counter and the pending count in GET /api/v1/system/info (security.
//     audit_owed_failures / audit_owed_pending, shown as a warning in the web UI),
//     and the record stays for BackfillPendingAuditEvents, which the server runs on
//     a schedule and which writes the row once the audit log accepts writes again.
//
// Exactly once: the claim (a DELETE reporting whether this call removed the row) and
// the append share a transaction, so two writers of the same owed row (the request
// and a backfill pass, or two replicas) cannot both commit it.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// owedAuditWait bounds how long a call whose effect has already committed waits for
// its owed audit row before answering. The effect does not wait at all.
const owedAuditWait = 5 * time.Second

// owedAuditBackfillBatch is how many owed rows one backfill page reads.
const owedAuditBackfillBatch = 100

// owedAuditFailures counts, per process, owed audit rows that could not be written
// when they were due (each one is either pending for the backfill or logged as lost).
var owedAuditFailures atomic.Uint64

var (
	errOwedAuditAlreadyWritten = errors.New("owed audit event already written")
	errOwedAuditRefused        = errors.New("the audit log refused the event")
)

// pendingRecordError marks a failure to write the pending_audit_events record
// itself, as opposed to the effect it accompanies.
type pendingRecordError struct{ err error }

func (e *pendingRecordError) Error() string { return "record owed audit event: " + e.err.Error() }
func (e *pendingRecordError) Unwrap() error { return e.err }

// commitOwingAudit applies effect and then writes event, without ever letting the
// audit log block or fail the effect. It returns effect's error only.
func (c *KeyorixCore) commitOwingAudit(ctx context.Context, effect func(st storage.Storage) error, event *models.AuditEvent) error {
	prepareAuditEventForEmit(ctx, event) // stamp the request's attribution now; a backfill has no request
	var pendingID uint
	encoded, encErr := json.Marshal(event)
	err := encErr
	if encErr == nil {
		err = c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
			if err := effect(tx); err != nil {
				return err
			}
			p := &models.PendingAuditEvent{EventType: event.EventType, Event: string(encoded)}
			if err := tx.CreatePendingAuditEvent(ctx, p); err != nil {
				return &pendingRecordError{err}
			}
			pendingID = p.ID
			return nil
		})
	}
	if err != nil {
		var recErr *pendingRecordError
		if encErr == nil && !errors.As(err, &recErr) {
			return err // the effect itself failed: nothing happened, as before
		}
		// The record of the owed row could not be written. The effect must not depend
		// on it: apply it alone, then still try the audit row below.
		log.Printf("SECURITY: could not record the owed audit event %q (%s) before its effect: %v; applying the effect without that record", event.EventType, event.Description, err)
		pendingID = 0
		if err := effect(c.storage); err != nil {
			return err
		}
	}
	c.writeOwedAudit(ctx, pendingID, event)
	return nil
}

// writeOwedAudit appends event (claiming pendingID when it is non-zero) and makes a
// failure loud. Never returns an error: the effect has already committed.
func (c *KeyorixCore) writeOwedAudit(ctx context.Context, pendingID uint, event *models.AuditEvent) {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), owedAuditWait)
	defer cancel()
	_, err := c.appendOwedAudit(wctx, pendingID, 0, event)
	if err == nil {
		return
	}
	owedAuditFailures.Add(1)
	if pendingID == 0 {
		log.Printf("SECURITY: audit event %q could not be written after its effect committed and is NOT queued for backfill (record it by hand): %s; user=%v secret=%v: %v",
			event.EventType, event.Description, uintOrNil(event.UserID), uintOrNil(event.SecretNodeID), err)
		return
	}
	log.Printf("SECURITY: audit event %q could not be written after its effect committed; queued for backfill as pending audit event %d: %s; user=%v secret=%v: %v",
		event.EventType, pendingID, event.Description, uintOrNil(event.UserID), uintOrNil(event.SecretNodeID), err)
	if rerr := c.storage.RecordPendingAuditEventFailure(context.WithoutCancel(ctx), pendingID, err.Error()); rerr != nil {
		log.Printf("SECURITY: could not note the failure on pending audit event %d: %v", pendingID, rerr)
	}
}

// appendOwedAudit claims pendingID (when non-zero) and appends event in one
// transaction, then forwards the committed row. wrote is false with a nil error when
// the claim found the row already gone: another writer committed it first.
//
// breakGlassActivationID (non-zero for a row owed by a degraded break-glass
// activation, BREAKGLASS-OWED-1) settles that activation in the same transaction
// once this was its last owed row, so "settled" commits iff the row is in the chain.
// The settle runs before the append: the append stays the last statement (on
// PostgreSQL it takes the chain's advisory lock until the transaction ends).
func (c *KeyorixCore) appendOwedAudit(ctx context.Context, pendingID, breakGlassActivationID uint, event *models.AuditEvent) (wrote bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic writing owed audit event: %v", r)
		}
	}()
	sink := &auditForwardSink{}
	err = c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		if pendingID != 0 {
			claimed, err := tx.ClaimPendingAuditEvent(ctx, pendingID)
			if err != nil {
				return err
			}
			if !claimed {
				return errOwedAuditAlreadyWritten
			}
		}
		if breakGlassActivationID != 0 {
			if _, err := tx.SettleBreakGlassOwedAudit(ctx, breakGlassActivationID, time.Now()); err != nil {
				return err
			}
		}
		if !c.emitAuditOn(ctx, auditInto(tx, sink), event) {
			return errOwedAuditRefused
		}
		return nil
	})
	if errors.Is(err, errOwedAuditAlreadyWritten) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	sink.Flush(c)
	return true, nil
}

// BackfillPendingAuditEvents writes every owed audit row, oldest first, and returns
// how many it wrote. It stops at the first row the audit log still refuses (the next
// pass retries it). Each row is written with the time it is recorded and says when
// the operation happened. Safe to run on several replicas at once.
//
// A row owed by a degraded break-glass activation (BREAKGLASS-OWED-1) keeps its
// ORIGINAL event time instead: the chain is ordered by id, not by time (auditverify
// accepts non-monotonic times, edge_clock_audit_test.go), and an emergency
// elevation's record must say when it happened, not when the audit log came back.
// Its description says it was recorded late, and its activation is settled with its
// last row (appendOwedAudit).
func (c *KeyorixCore) BackfillPendingAuditEvents(ctx context.Context) (int, error) {
	written := 0
	var after uint
	for {
		batch, err := c.storage.ListPendingAuditEvents(ctx, after, owedAuditBackfillBatch)
		if err != nil {
			return written, fmt.Errorf("list pending audit events: %w", err)
		}
		for _, p := range batch {
			after = p.ID
			var event models.AuditEvent
			if err := json.Unmarshal([]byte(p.Event), &event); err != nil {
				// Never dropped: it stays pending and visible, and the rest still drain.
				log.Printf("SECURITY: pending audit event %d (%s) cannot be decoded and stays pending: %v", p.ID, p.EventType, err)
				_ = c.storage.RecordPendingAuditEventFailure(ctx, p.ID, "decode: "+err.Error())
				continue
			}
			event.ID = 0
			event.Description = fmt.Sprintf("%s (recorded late: it happened at %s, when the audit log refused the write)",
				event.Description, event.EventTime.UTC().Format(time.RFC3339))
			if p.BreakGlassActivationID == 0 {
				event.EventTime = time.Now()
			}
			wrote, err := c.appendOwedAudit(ctx, p.ID, p.BreakGlassActivationID, &event)
			if err != nil {
				_ = c.storage.RecordPendingAuditEventFailure(ctx, p.ID, err.Error())
				return written, fmt.Errorf("pending audit event %d (%s): %w", p.ID, p.EventType, err)
			}
			if !wrote {
				continue // another replica wrote it
			}
			written++
			log.Printf("Audit backfill: wrote owed audit event %q (pending %d, owed since %s)", p.EventType, p.ID, p.CreatedAt.UTC().Format(time.RFC3339))
		}
		if len(batch) < owedAuditBackfillBatch {
			return written, nil
		}
	}
}

// OwedAuditStatus is the admin-visible state of owed audit rows.
type OwedAuditStatus struct {
	// Pending is how many owed audit rows are not written yet (cluster-wide), or -1
	// when the count could not be read.
	Pending int64 `json:"pending"`
	// Failures is how many owed audit rows this process could not write when due.
	Failures uint64 `json:"failures_since_start"`
}

// OwedAuditStatus reports the owed-audit state for the system status surface.
func (c *KeyorixCore) OwedAuditStatus(ctx context.Context) OwedAuditStatus {
	st := OwedAuditStatus{Pending: -1, Failures: owedAuditFailures.Load()}
	if n, err := c.storage.CountPendingAuditEvents(ctx); err == nil {
		st.Pending = n
	}
	return st
}

func uintOrNil(p *uint) any {
	if p == nil {
		return nil
	}
	return *p
}
