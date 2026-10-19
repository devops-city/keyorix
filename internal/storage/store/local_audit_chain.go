// local_audit_chain.go — tamper-evidence hash chain over audit_events (ADR-029).
//
// Each audit event stores prev_hash (the prior chained event's entry_hash, or a
// genesis constant for the first) and entry_hash = SHA256(canonical(fields) ‖
// prev_hash). Any modification, deletion, insertion, or reordering of audit
// rows breaks the chain and is detected by VerifyAuditChain.
//
// Appends are serialized (process mutex + a Postgres transaction-scoped advisory
// lock) so the read-chain-head + insert critical section is atomic even though
// audit events are emitted from concurrent goroutines.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"crypto/rand"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// auditGenesisHash is the prev_hash of the first chained event. A fixed, visibly
// non-real 64-hex-char constant so the chain has a deterministic anchor.
const auditGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// auditAdvisoryLockKey is the Postgres advisory-lock key guarding audit appends
// across processes (arbitrary constant, namespaced to this use).
const auditAdvisoryLockKey = 0x4B455941_55444954 // "KEYAUDIT"

// auditChainVerifyBatch bounds memory when re-walking the chain.
const auditChainVerifyBatch = 1000

// auditBusyRetryBaseDelay/auditBusyRetryMaxDelay bound LogAuditEvent's SQLite
// busy-retry backoff (#1727) -- see that loop's own doc comment for why it
// exists. Exponential from base, capped at max, jittered by up to half the
// current delay so many goroutines released by the same lock release don't
// all retry in lockstep.
const (
	auditBusyRetryBaseDelay = 20 * time.Millisecond
	auditBusyRetryMaxDelay  = 500 * time.Millisecond
)

// applyAuditCommitDurability is the ONE place storage.database.audit_durability
// (ADR-112 Amendments 1 and 3, docs/specs/fast-audit-mode.md) touches the
// audit-commit path, and the ONLY implementation of the standard level anywhere.
//
// POSTGRES ONLY. Callers must already have established that tx's dialect is
// postgres. There is NO SQLite counterpart, and deliberately never was in a
// shipped build: standard is PostgreSQL-only (Andrei's decision, 2026-10-05)
// and config validation REFUSES TO START a SQLite backend set to standard
// (internal/config's auditDurabilityStandardSQLiteUnsupportedError), so a
// SQLite-backed LocalStorage can never reach this function with skip == true.
// SQLite's own DSN says `_synchronous=FULL` unconditionally and has no other
// branch. See config.DatabaseConfig.AuditDurability for the
// reasons SQLite was rejected (a per-connection pragma would relax every
// table, not just audit; and the measured p99 got worse under concurrency).
//
// skip == false (the strict level) is a strict NO-OP: no
// statement is issued at all, so the strict path is byte-identical to what it
// was before this setting existed — no extra round trip, nothing to regress,
// and nothing that could accidentally override a cluster- or role-level
// synchronous_commit an operator set deliberately.
//
// skip == true issues `SET LOCAL synchronous_commit = off`. Three properties
// make this the right mechanism rather than a bigger one:
//
//   - SET LOCAL is TRANSACTION-scoped: it reverts at COMMIT/ROLLBACK, so it
//     can never leak to the next transaction that borrows this pooled
//     connection. That is what confines the relaxation to the audit
//     transaction and leaves a concurrent secret WRITE committing durably.
//   - synchronous_commit is evaluated AT COMMIT TIME, so setting it from
//     inside the transaction is what actually takes effect for this
//     transaction's commit (it is not a connect-time-only GUC).
//   - The WAL record is still written, in order. Async commit removes the WAIT
//     for the flush, not the write and not the ordering — which is exactly why
//     a crash can only truncate the audit chain's TAIL and can never gap or
//     fork it: recovery replays a valid PREFIX of a single totally-ordered WAL
//     stream, so a surviving row's prev_hash always points at a row that also
//     survived. A synchronous commit elsewhere flushes WAL up to its own LSN
//     and therefore makes every EARLIER async commit durable too, so the
//     inversion ("a later audit row survives while an earlier one is lost")
//     has no mechanism by which to happen. See the spec §5 and
//     TestFastAuditMode_PostgresCrashLosesOnlyATail.
//
// Not parameterised: the value is a fixed literal, never interpolated from
// config or any request, so there is no injection surface here (SET does not
// accept bind parameters in any case).
func applyAuditCommitDurability(tx *gorm.DB, skip bool) error {
	stmt := auditCommitDurabilityStatement(skip)
	if stmt == "" {
		return nil
	}
	return tx.Exec(stmt).Error
}

// auditCommitDurabilityStatement is the statement applyAuditCommitDurability
// runs, for the pipelined Postgres commit (commitBatchAttemptPipelined), which
// queues it in its first flight instead of running it through GORM: "" when
// skip is false (no statement at all), the SET LOCAL above when it is true.
func auditCommitDurabilityStatement(skip bool) string {
	if !skip {
		return ""
	}
	return "SET LOCAL synchronous_commit = off"
}

// isSQLiteBusyErr reports whether err is a SQLite writer-lock contention
// error: the in-process write gate's own timeout, or the driver-native
// SQLITE_BUSY / "database is locked" from the raw busy handler.
//
// The gate's sentinel is checked FIRST, and with errors.Is rather than a
// substring. Once storage.ErrSQLiteWriteContention exists, it is the DOMINANT
// contention error on SQLite — the gate serializes writers in-process, so
// contention is resolved by waiting on a channel and reported as a timeout,
// and SQLITE_BUSY only survives for the paths the gate does not cover
// (autocommit writes, a second *sql.DB handle in the same process). A
// classifier that knows only the driver text would therefore stop recognising
// the common case the moment the gate landed, which is what the coordinator's
// review of #2637 found: the busy-retry budget that exists for exactly this
// condition would no longer apply to it.
//
// The driver-text checks stay, as substrings, for the reason the original
// comment gives: this codebase does not set gorm.Config{TranslateError: true},
// so there is no typed error to match on for the driver's own errors — the
// same approach isUniqueViolation uses (local_memberships.go).
func isSQLiteBusyErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, storage.ErrSQLiteWriteContention) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "SQLITE_BUSY") || strings.Contains(msg, "database is locked")
}

// isBatchGlobalContentionErr reports whether err is a contention failure that
// applies to the BATCH rather than to any item in it, so bisecting to find a
// poisoned item is not just useless but actively harmful. See commitAuditBatch.
//
// That includes a write-gate wait that ended on the caller's ctx instead of on the
// gate's own timer. auditWriteTimeout, sqliteWriteGateMaxWait and the DSN's
// busy_timeout are all 10s and the ctx deadline starts first, so the gate's
// select can legitimately return a wrapped ctx.Err() rather than
// ErrSQLiteWriteContention (#2637 review, Finding 1). Every item of a batch
// shares one fixed deadline shape, so an expired/cancelled ctx is likewise a
// property of the batch, not of an item.
func isBatchGlobalContentionErr(err error) bool {
	return errors.Is(err, storage.ErrSQLiteWriteContention) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled)
}

// ComputeAuditEntryHash is computeAuditEntryHash (the current encoding) for
// callers outside this package that must model the chain exactly — tests of a
// DB-level attacker who rewrites rows and recomputes their hashes. The hash is
// unkeyed by design (ADR-029: forgery resistance comes from the signed
// checkpoints), so exporting it gives an attacker nothing new.
func ComputeAuditEntryHash(e *models.AuditEvent, prevHash string) string {
	return computeAuditEntryHash(e, prevHash)
}

// computeAuditEntryHash hashes an event's semantically meaningful fields plus
// prevHash, in a fixed order, each field preceded by its own big-endian
// uint64 byte length ("length-prefixed" / TLV-style encoding). The DB-assigned
// id is excluded — it is unknown before insert and chain linkage already pins
// position. event_time is encoded as Unix microseconds to round-trip
// identically on Postgres (µs precision) and SQLite.
//
// Length-prefixing (not a delimiter byte) is required for the encoding to be
// injective: several of these fields are free-form strings that can
// legitimately (or, via IngestAuditEventProxy's raw passthrough on
// SQLite-backed deployments — Postgres TEXT columns reject embedded NUL
// outright, so this was only ever live there) contain ANY byte value,
// including a delimiter byte. A single NUL-separated write() (the prior
// scheme) is then non-injective: "a\x00" + "bc" and "a" + "\x00bc" concatenate
// to the identical byte stream and therefore hash identically, even though
// the field values differ — defeating the tamper-evidence guarantee this hash
// chain exists to provide. A length prefix carried out-of-band (as a fixed-
// width binary integer, never as characters that could themselves be part of
// the content) removes that ambiguity regardless of what bytes a field
// contains.
//
// BREAKING CHANGE / no backward compatibility with pre-fix hashes: this
// encoding is NOT the same byte stream the old NUL-delimited scheme produced,
// even for a field that never contained a NUL byte — so the change is a hash-
// format break, not a content-preserving refactor. VerifyAuditChain re-derives
// every row's entry_hash from this same function (see verifyBatchEvents), so
// on any deployment that already has chained audit_events rows written before
// this fix, re-verifying those rows post-upgrade WILL recompute a different
// hash than what is stored and report the chain broken at the first pre-
// upgrade row — indistinguishable, from VerifyAuditChain's callers' point of
// view, from real tampering. There is no per-row encoding-version marker in
// the schema to let verification pick the right algorithm per row (adding one
// is a real schema migration, out of scope here), and the existing retention
// re-anchor mechanism (audit_retention_anchor.go) does not help either — it
// only substitutes the genesis-prevHash requirement for the anchored row, it
// does not skip re-deriving that row's own entry_hash. Coordinating a fix for
// deployments with pre-existing audit history (e.g. a one-time migration that
// re-derives entry_hash/prev_hash for every existing row under this new
// encoding, in ascending id order, before the upgrade takes live traffic) is
// left to the integrating release process; this change intentionally does not
// attempt that migration itself, per this change's own review discussion.
//
// #G799 (go/weak-sensitive-data-hashing, false positive): the query's dataflow
// correctly traces AccountState's AccountPasswordResetRequired constant into
// this function's Description field write, then flags SHA256 as "insecure for
// password hashing" -- but that constant is an account-status ENUM VALUE
// ("this account currently requires a password reset"), not a credential; no
// real password/secret value ever reaches this function. SHA256 is also the
// deliberately correct choice here regardless: this hash is a tamper-evidence
// chain link (integrity, not credential storage/verification), where a fast,
// deterministic, collision-resistant hash is exactly what's wanted -- a slow
// password KDF (bcrypt/argon2/scrypt) on every audit-log write would be a
// severe, pointless performance regression with no security benefit, since
// the threat model here is "detect tampering," not "resist offline brute-
// forcing a stored hash." See the `write` closure below.
func computeAuditEntryHash(e *models.AuditEvent, prevHash string) string {
	h := sha256.New()
	var lenBuf [8]byte
	write := func(s string) {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
		h.Write(lenBuf[:])
		// codeql[go/weak-sensitive-data-hashing]
		h.Write([]byte(s))
	}
	uptr := func(p *uint) string {
		if p == nil {
			return ""
		}
		return strconv.FormatUint(uint64(*p), 10)
	}
	bptr := func(p *bool) string {
		if p == nil {
			return ""
		}
		return strconv.FormatBool(*p)
	}

	write(prevHash)
	write(e.EventType)
	write(uptr(e.UserID))
	write(uptr(e.SecretNodeID))
	write(uptr(e.ProjectID))
	write(e.IPAddress)
	write(e.Description)
	write(bptr(e.Success))
	write(strconv.FormatInt(e.EventTime.UnixMicro(), 10))
	write(e.Diff)
	write(uptr(e.ImpersonatedBy))
	write(uptr(e.ActingAs))
	write(strconv.FormatBool(e.Impersonation))
	write(e.ActorType)
	return hex.EncodeToString(h.Sum(nil))
}

// normalizeAuditEventForHash applies the two GORM-default round-trip fixes
// (ActorType, Success) that must happen BEFORE hashing, on every write path —
// factored out so the batched and direct paths can't drift out of sync on
// this (SESSION-PERF, #2403 follow-up; previously inline in LogAuditEvent).
func normalizeAuditEventForHash(event *models.AuditEvent) {
	// Truncate to microseconds before both hashing and storage so the stored
	// timestamp equals the hashed one on every backend (Postgres timestamptz is
	// µs-precision; an un-truncated nanosecond time would not round-trip).
	event.EventTime = event.EventTime.Truncate(time.Microsecond)

	// Normalize ActorType to the column default ("user", see models.AuditEvent)
	// BEFORE hashing. The hash covers ActorType, but the row is stored via GORM,
	// whose `default:user` tag rewrites an empty value to "user" at insert. Without
	// this, a caller that leaves ActorType unset (e.g. the sharing/impersonation
	// audit helpers) hashes over "" yet persists "user", so VerifyAuditChain later
	// recomputes over the stored "user" and false-fails an untampered chain. Pinning
	// the value here keeps the hashed and stored ActorType identical for every caller.
	if event.ActorType == "" {
		event.ActorType = "user"
	}

	// Same round-trip hazard for Success (`default:true`, models.AuditEvent): the
	// hash covers Success, but GORM rewrites a nil *bool to true at insert. Callers
	// that leave Success unset (every sharing_audit.go helper) would hash over ""
	// yet persist "true", so VerifyAuditChain recomputes over the stored true and
	// false-fails an untampered chain. Pin it to the column default before hashing.
	if event.Success == nil {
		t := true
		event.Success = &t
	}
}

// LogAuditEvent appends an audit event, linking it into the tamper-evidence
// hash chain (ADR-029). See logAuditEventBatched/logAuditEventDirect for which
// path actually runs.
func (ls *LocalStorage) LogAuditEvent(ctx context.Context, event *models.AuditEvent) error {
	return ls.logAuditEvent(ctx, event, nil)
}

// LogAuditEventWithAccessLog is LogAuditEvent plus a secret_access_logs row,
// committed together in the SAME transaction/batch as the audit event
// (SESSION-PERF, #2403 follow-up, item 3) — one fsync covers both rows, and
// they succeed or fail as one unit. accessLog may be nil (equivalent to
// LogAuditEvent); event may never be nil.
func (ls *LocalStorage) LogAuditEventWithAccessLog(ctx context.Context, event *models.AuditEvent, accessLog *models.SecretAccessLog) error {
	return ls.logAuditEvent(ctx, event, accessLog)
}

func (ls *LocalStorage) logAuditEvent(ctx context.Context, event *models.AuditEvent, accessLog *models.SecretAccessLog) (err error) {
	start := time.Now()
	defer func() { observeAuditWrite(start, err) }()
	normalizeAuditEventForHash(event)
	// ls.auditFlusher is nil on a transaction-scoped LocalStorage (see
	// WithTransaction/RemoveGlobalAdminRoleGuarded's clone construction) --
	// batching across to a DIFFERENT, independent transaction would break the
	// atomicity the caller's own WithTransaction is relying on, so that case
	// (unexercised by any real caller today, but kept correct defensively)
	// falls back to the original per-call direct path, same as before this
	// change. Every other caller (the common case -- the root LocalStorage)
	// goes through the batching flusher.
	if ls.auditFlusher == nil {
		return ls.logAuditEventDirect(ctx, event, accessLog)
	}
	return ls.logAuditEventBatched(ctx, event, accessLog)
}

// logAuditEventDirect is LogAuditEvent's ORIGINAL body (pre-#2403-item-3):
// one event (and, now, optionally one access-log row) per transaction, one
// fsync per call, serialized by auditChainMu + a Postgres advisory lock. Used
// only for the transaction-scoped fallback above.
func (ls *LocalStorage) logAuditEventDirect(ctx context.Context, event *models.AuditEvent, accessLog *models.SecretAccessLog) error {
	// #1650: detach from the caller's cancellation before the transaction below runs —
	// see auditWriteContext's doc comment for the full rationale.
	ctx, cancel := auditWriteContext(ctx)
	defer cancel()

	ls.auditChainMu.Lock()
	defer ls.auditChainMu.Unlock()

	// #1727: retry a SQLite writer-lock timeout instead of surfacing it straight to
	// emitAudit, which just logs and drops it. SQLite's own _busy_timeout
	// (factory.go's sqliteBusyTimeoutMillis, 10s) already retries internally once a
	// transaction requests the write lock, but a 30-minute sustained-load
	// measurement (docs/adr-100-mlockall-removal-deployment-swap-control.md) still
	// exhausted that budget 704 times out of ~27k iterations (~2.6%): SQLite's busy
	// handler makes no fairness guarantee across competing connections, so a
	// transaction that starts AFTER the mutation it's auditing (this one, always)
	// can be repeatedly overtaken by new arrivals for the full 10s and never get a
	// turn. auditChainMu above already serializes this transaction against every
	// OTHER audit append; it does nothing against concurrent writers on unrelated
	// tables (secret_nodes, users, ...), which is where the real contention comes
	// from. A short, jittered, bounded-by-ctx backoff loop re-enters the queue on a
	// transient SQLITE_BUSY instead of giving up after one exhausted busy_timeout
	// window -- closing the gap for the dominant real-world case (transient
	// contention, not a genuinely stuck writer) without an unbounded retry storm:
	// ctx already carries auditWriteTimeout's 10s deadline (detached from the
	// caller's own cancellation above), so this loop can never outlive that.
	delay := auditBusyRetryBaseDelay
	for {
		txErr := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			// Cross-process serialization for multi-instance Postgres; no-op on SQLite.
			if tx.Dialector.Name() == "postgres" {
				if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", int64(auditAdvisoryLockKey)).Error; err != nil {
					return err
				}
				if err := applyAuditCommitDurability(tx, ls.auditSkipDurableSync); err != nil {
					return err
				}
				// This append moves the head without the flusher (AUDIT-1FLIGHT-1).
				ls.invalidateAuditChainHead()
			}

			var head struct{ EntryHash string }
			if err := tx.Model(&models.AuditEvent{}).
				Select("entry_hash").
				Order("id DESC").
				Limit(1).
				Scan(&head).Error; err != nil {
				return err
			}
			prev := head.EntryHash
			if prev == "" {
				prev = auditGenesisHash
			}

			// Zero at the start of each attempt (coordinator review, #2420,
			// item 4): a retried attempt reuses this same event/accessLog
			// pointer, and a PRIOR attempt's tx.Create(event) may have
			// already assigned event.ID before accessLog's Create failed
			// and rolled the whole transaction back — without this reset,
			// the retry's tx.Create(event) would run with that stale ID
			// still set, turning an auto-assigned insert into an
			// explicit-primary-key one.
			event.ID = 0
			if accessLog != nil {
				accessLog.ID = 0
			}
			event.PrevHash = prev
			event.EntryHash = computeAuditEntryHash(event, prev)
			if err := tx.Create(event).Error; err != nil {
				return err
			}
			if accessLog != nil {
				return tx.Create(accessLog).Error
			}
			return nil
		})
		if txErr == nil || !isSQLiteBusyErr(txErr) {
			return txErr
		}
		jittered := delay/2 + time.Duration(retryJitterN(int64(delay/2+1)))
		select {
		case <-ctx.Done():
			return txErr
		case <-time.After(jittered):
		}
		if delay *= 2; delay > auditBusyRetryMaxDelay {
			delay = auditBusyRetryMaxDelay
		}
	}
}

// auditQueueCapacity bounds the batching flusher's pending-item channel
// (SESSION-PERF, #2403 follow-up, item 3) — the fix for Phase 1's finding that
// the OLD one-goroutine-per-audit-event design let the backlog of not-yet-
// durable audit entries grow WITHOUT BOUND under load (measured: 918 of 935
// live goroutines blocked on auditChainMu, 10s into a single-client run).
// Once this channel is full, a submitter's send blocks (see submitAuditBatchItem)
// until the flusher drains space — deliberate backpressure: a caller whose
// audit entry can't be queued yet WAITS rather than piling up an unbounded,
// not-yet-durable backlog in memory. Sized well above any single batch
// (auditFlusherMaxBatch) so a burst can queue up without immediately blocking
// senders, while still being a small, fixed, auditable bound.
const auditQueueCapacity = 4096

// auditFlusherMaxBatch bounds how many pending items one flusher iteration
// commits together. Unbounded batching would let an extreme burst hold the
// FIRST queued item's caller waiting indefinitely while the batch keeps
// growing; this caps the wait any one submitter can experience to "however
// long it takes to commit up to this many rows," not "however long the queue
// keeps growing."
const auditFlusherMaxBatch = 256

// auditFlusherIdleTimeout is how long the flusher goroutine waits for a new
// item before exiting (and un-marking itself as running, so the next
// submission starts a fresh one). Keeps this goroutine from leaking forever
// on a LocalStorage that stops being used (every test that creates one, and
// any production instance after its last audit write) — short enough that a
// test binary doesn't accumulate thousands of long-lived blocked goroutines
// across a full suite run, long enough that a production server under
// continuous load essentially never pays the restart cost (a new item almost
// always arrives well within this window).
const auditFlusherIdleTimeout = 200 * time.Millisecond

// auditBatchItem is one pending LogAuditEvent/LogAuditEventWithAccessLog
// submission, queued for the flusher goroutine to commit as part of a batch.
type auditBatchItem struct {
	event      *models.AuditEvent
	accessLog  *models.SecretAccessLog // nil if this submission has no access-log row
	ctx        context.Context         // the (already-detached) context to run the eventual DB work under
	done       chan error              // buffered(1); the flusher sends exactly once, always
	enqueuedAt time.Time               // set by submitAuditBatchItem; feeds keyorix_audit_group_commit_wait_seconds
}

// auditFlusherState is LocalStorage's audit-batching flusher. nil on a
// transaction-scoped LocalStorage (see logAuditEvent's dispatch) — only the
// root LocalStorage returned by NewLocalStorage ever has one.
//
// pending counts submissions that read af.queue under mu and have not yet been
// received by the flusher (PERF-LOWCONC-1): raised under mu before the send,
// lowered when the flusher takes the item (or the send is abandoned). The idle
// exit clears running only under mu with pending == 0, so a send that is still
// on its way can never be left in a channel nobody reads.
type auditFlusherState struct {
	mu      sync.Mutex
	queue   chan *auditBatchItem
	running bool
	pending int
}

// auditBeforeQueueSendHook, when set (tests only), runs in submitAuditBatchItem
// after the submission registered and released af.mu, before it sends: the
// window in which the idle exit used to strand the send.
var auditBeforeQueueSendHook func()

// submitAuditBatchItem hands item to the flusher goroutine (starting one if
// none is currently running) and blocks until item's batch commits,
// returning that batch's error (nil on success). Uses ONLY item.ctx
// (already detached from the caller's own cancellation by
// logAuditEventBatched, via auditWriteContext) for BOTH the wait for a queue
// slot and the wait for the result — never the original caller context.
// This is required, not a stylistic choice: #1650's whole point is that a
// client disconnecting (cancelling the inbound request's context) must never
// turn "the mutation committed" into "committed with zero audit record" —
// using the caller's own ctx here would make a cancelled caller abandon the
// wait early and return ctx.Err() instead of the batch's real outcome, even
// though the write itself (correctly) keeps going to completion underneath.
// TestLogAuditEventImplementations_DetachFromCallerCancellation and
// TestLogAuditEvent_SucceedsWithAlreadyCanceledCallerContext exist
// specifically to catch this regression.
func (ls *LocalStorage) submitAuditBatchItem(item *auditBatchItem) error {
	af := ls.auditFlusher
	item.enqueuedAt = time.Now()
	af.mu.Lock()
	if !af.running {
		af.running = true
		af.queue = make(chan *auditBatchItem, auditQueueCapacity)
		go ls.runAuditFlusher(af)
	}
	af.pending++
	queue := af.queue
	af.mu.Unlock()

	if auditBeforeQueueSendHook != nil {
		auditBeforeQueueSendHook()
	}
	select {
	case queue <- item:
	case <-item.ctx.Done():
		af.mu.Lock()
		af.pending--
		af.mu.Unlock()
		return item.ctx.Err()
	}
	select {
	case err := <-item.done:
		return err
	case <-item.ctx.Done():
		return item.ctx.Err()
	}
}

// runAuditFlusher is the ONE goroutine (per currently-active run; see the
// idle-exit below) that actually commits every batched audit append for this
// LocalStorage — replacing the old design's one-goroutine-per-audit-event
// fan-out with a single serialized writer that batches whatever is currently
// pending into one transaction/one fsync, same as a human reviewer would
// expect "group commit" to mean. Chain order within a batch is exactly the
// order items are drained here — the SAME total-ordering guarantee
// auditChainMu provided before (a single serialization point imposing SOME
// total order on concurrent arrivals, not a claim about real-world causal
// order, which neither design ever provided).
//
// On Postgres, up to auditPipelineDepth batches are in flight at once on one
// connection (commitFlusherBatch, local_audit_chain_pipelined_batches.go);
// their results still reach their items in batch order, each only after its
// own COMMIT. While a batch is in flight and nothing new is queued, the
// flusher reads that batch's result instead of waiting for items, and the
// idle exit ends the run first, so no batch's readers wait on the flusher.
func (ls *LocalStorage) runAuditFlusher(af *auditFlusherState) {
	pipe := ls.newAuditBatchPipeline()
	for {
		var batch []*auditBatchItem
		if pipe.inFlight() {
			select {
			case item := <-af.queue:
				batch = append(batch, item)
			default:
				pipe.completeOldest()
				continue
			}
		} else {
			select {
			case item := <-af.queue:
				batch = append(batch, item)
			case <-time.After(auditFlusherIdleTimeout):
				pipe.shutdown()
				af.mu.Lock()
				// Re-check for a race: a submitter's queue<-item may have
				// succeeded between this timeout firing and acquiring af.mu.
				// A submitter reads af.queue and releases af.mu BEFORE it sends,
				// so an empty queue alone does not mean nobody is about to send:
				// exiting then left that send in a channel nobody read (the next
				// submission makes a new one), and its caller waited out its audit
				// deadline and failed closed (PERF-LOWCONC-1). Exit only when no
				// submission is registered (pending, raised under af.mu before the
				// send); otherwise keep waiting for it.
				select {
				case item := <-af.queue:
					batch = append(batch, item)
					af.mu.Unlock()
				default:
					if af.pending == 0 {
						af.running = false
						af.mu.Unlock()
						return
					}
					af.mu.Unlock()
					continue
				}
			}
		}
		// Linger (SESSION-PERF, #2403/#2420 follow-up, coordinator-requested
		// tuning): after the first item arrives, deliberately wait up to
		// ls.auditFlusherLingerWindow for MORE items to arrive, instead of only
		// ever draining whatever happened to already be buffered at this exact
		// instant. The field defaults to 0 (preserving the original behavior
		// exactly: a non-blocking drain, `default:` fires immediately, no
		// deliberate wait) and is only ever nonzero if a deployment has
		// explicitly set config.DatabaseConfig.AuditFlusherLingerWindow — see
		// that field's doc comment, and PR #2420's body, for why 0 is the
		// shipped default rather than a tuned nonzero value.
		if ls.auditFlusherLingerWindow <= 0 {
		drain:
			for len(batch) < auditFlusherMaxBatch {
				select {
				case item := <-af.queue:
					batch = append(batch, item)
				default:
					break drain
				}
			}
			// While a batch is in flight, a batch too small to be worth its
			// own transaction waits for that one's result and takes what
			// arrived meanwhile (auditPipelineMinBatch).
			if pipe.waitBeforeSending(len(batch)) {
				pipe.completeOldest()
				goto drain
			}
		} else {
			lingerTimer := time.NewTimer(ls.auditFlusherLingerWindow)
		lingerLoop:
			for len(batch) < auditFlusherMaxBatch {
				select {
				case item := <-af.queue:
					batch = append(batch, item)
				case <-lingerTimer.C:
					break lingerLoop
				}
			}
			lingerTimer.Stop()
		}
		af.mu.Lock()
		af.pending -= len(batch)
		af.mu.Unlock()
		observeAuditGroupCommitWait(batch, time.Now())
		ls.commitFlusherBatch(pipe, batch)
	}
}

// auditInsertMaxBindVars is the bind-parameter budget of one multi-row audit
// INSERT. SQLite's SQLITE_MAX_VARIABLE_NUMBER defaults to 32766 (since 3.32;
// modernc.org/sqlite keeps the default) and Postgres' wire protocol allows
// 65535, so the smaller one bounds both dialects.
// TestAuditInsertRowsPerStatement_SQLiteVariableLimitIsReal proves the SQLite
// ceiling is real, and TestCommitBatchAttempt_ChunksAtVariableLimitBoundary
// that a batch on either side of the derived row bound still commits.
const auditInsertMaxBindVars = 32766

// auditInsertSchemaCache backs auditInsertRowsPerStatement's schema.Parse.
var auditInsertSchemaCache sync.Map

// auditInsertRowsPerStatement returns how many rows of model one INSERT may
// carry under auditInsertMaxBindVars. It counts EVERY column of the model,
// the primary key included although GORM leaves a zero one out, so the bound
// stays conservative whichever columns GORM ends up binding.
func auditInsertRowsPerStatement(model any) (int, error) {
	s, err := schema.Parse(model, &auditInsertSchemaCache, schema.NamingStrategy{})
	if err != nil {
		return 0, err
	}
	return auditInsertMaxBindVars / len(s.DBNames), nil
}

// createAuditRowsMultiRow inserts rows with one multi-row INSERT per
// auditInsertRowsPerStatement-sized chunk (one statement for any batch up to
// auditFlusherMaxBatch), in slice order. GORM writes each returned ID back
// onto the matching element.
func createAuditRowsMultiRow[T any](tx *gorm.DB, rows []*T) error {
	if len(rows) == 0 {
		return nil
	}
	perStmt, err := auditInsertRowsPerStatement(rows[0])
	if err != nil {
		return err
	}
	for start := 0; start < len(rows); start += perStmt {
		chunk := rows[start:min(start+perStmt, len(rows))]
		if err := tx.Create(&chunk).Error; err != nil {
			return err
		}
	}
	return nil
}

// checkAuditInsertIDOrder fails the attempt unless the IDs GORM wrote back are
// non-zero and strictly ascending in slice order. See commitBatchAttempt for
// why the hash chain depends on that.
func checkAuditInsertIDOrder(events []*models.AuditEvent) error {
	for i, e := range events {
		if e.ID == 0 || (i > 0 && e.ID <= events[i-1].ID) {
			return fmt.Errorf("audit batch insert: row %d of %d came back with id %d, not in VALUES order", i, len(events), e.ID)
		}
	}
	return nil
}

// commitBatchAttempt runs ONE transaction attempt for batch: reads the
// current chain head, assigns/recomputes prev_hash+entry_hash for every
// item in order, and inserts them all — one fsync for the whole attempt.
//
// On Postgres the transaction is sent as two pipelined flights rather than one
// round trip per statement (PERF-FIX-1, commitBatchAttemptPipelined in
// local_audit_chain_pipeline.go), with the event ids allocated under the lock
// before the INSERT so the id-order check below still runs before COMMIT.
// SQLite, and a Postgres pool that is not pgx, use commitBatchAttemptTx.
//
// The rows go in with one INSERT for all the events and one for all the
// non-nil access logs (PERF-FIX-2), not one statement per item. The hashes
// are still computed first, item by item, exactly as the per-item version
// did, so the chain is byte-identical. What the multi-row form adds is a
// dependency on ID order: VerifyAuditChain walks id ASC and the next attempt
// reads the head as id DESC, so row k of the VALUES list must get a smaller
// id than row k+1, and GORM must map the RETURNING rows back onto the slice
// in that same order (gorm.Scan assigns RETURNING row k to element k). Both
// hold on both dialects: SQLite assigns rowids as it steps through VALUES and
// Postgres calls nextval per VALUES row, and both emit RETURNING rows in that
// processing order (SQLite's documentation leaves the RETURNING order
// unspecified, so this is checked rather than assumed):
//   - checkAuditInsertIDOrder re-checks the write-back on every attempt and
//     fails closed if the returned ids are not strictly ascending (the attempt
//     rolls back and commitAuditBatch bisects, down to single rows that need
//     no ordering);
//   - TestCommitBatchAttempt_MultiRowMatchesPerRow_{SQLite,Postgres} prove the
//     stored rows, ids and hashes equal the per-item path's, that every
//     returned id points at the row with that item's own entry_hash, that the
//     id DESC head is the batch's last item, and that the chain verifies.
//
// A bad row now fails the whole statement rather than only its own one, which
// commitAuditBatch's bisection already handles: it never relied on WHICH
// statement failed, only on the attempt failing, and each half is a fresh
// attempt. TestCommitAuditBatch_RealDBErrorOnOneRowIsolated_{SQLite,Postgres}
// pin that with a genuine database error (a trigger), not a GORM callback.
//
// Zeros each item's event/accessLog ID at the START of this attempt
// (coordinator review, #2420, item 4): tx.Create assigns the DB-generated ID
// onto the Go struct the moment that statement succeeds, which can happen for
// the events INSERT before the access-log INSERT fails and rolls the whole
// transaction back. Without this reset, a retried attempt would insert those
// events with the stale IDs still set from the rolled-back attempt, turning
// what should be a fresh auto-assigned insert into an explicit-primary-key
// insert — wrong on every backend, and on Postgres specifically a correctness
// hazard: that stale ID may not even be the one the sequence would hand out
// next.
func (ls *LocalStorage) commitBatchAttempt(ctx context.Context, batch []*auditBatchItem) error {
	if ls.db.Dialector.Name() == "postgres" {
		err := ls.commitBatchAttemptPipelined(ctx, batch)
		if !errors.Is(err, errAuditPipelineUnavailable) {
			return err
		}
	}
	return ls.commitBatchAttemptTx(ctx, batch)
}

// commitBatchAttemptTx is commitBatchAttempt through a GORM transaction, one
// round trip per statement: SQLite's path (in-process, so a statement costs no
// network flight), and Postgres' only when the pool is not a pgx one (see
// commitBatchAttemptPipelined).
func (ls *LocalStorage) commitBatchAttemptTx(ctx context.Context, batch []*auditBatchItem) error {
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if tx.Dialector.Name() == "postgres" {
			if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", int64(auditAdvisoryLockKey)).Error; err != nil {
				return err
			}
			if err := applyAuditCommitDurability(tx, ls.auditSkipDurableSync); err != nil {
				return err
			}
		}
		var head struct{ EntryHash string }
		if err := tx.Model(&models.AuditEvent{}).
			Select("entry_hash").
			Order("id DESC").
			Limit(1).
			Scan(&head).Error; err != nil {
			return err
		}
		events, accessLogs := chainAuditBatch(batch, head.EntryHash)
		if err := createAuditRowsMultiRow(tx, events); err != nil {
			return err
		}
		if err := checkAuditInsertIDOrder(events); err != nil {
			return err
		}
		return createAuditRowsMultiRow(tx, accessLogs)
	})
}

// chainAuditBatch links batch onto the chain head headHash (genesis when
// empty): it zeros every ID, sets each event's prev_hash and entry_hash in
// batch order, and returns the events and the non-nil access logs in that
// order. Both commit paths call it, so they hash identically.
func chainAuditBatch(batch []*auditBatchItem, headHash string) ([]*models.AuditEvent, []*models.SecretAccessLog) {
	prev := headHash
	if prev == "" {
		prev = auditGenesisHash
	}
	events := make([]*models.AuditEvent, 0, len(batch))
	var accessLogs []*models.SecretAccessLog
	for _, item := range batch {
		item.event.ID = 0
		if item.accessLog != nil {
			item.accessLog.ID = 0
			accessLogs = append(accessLogs, item.accessLog)
		}
		item.event.PrevHash = prev
		item.event.EntryHash = computeAuditEntryHash(item.event, prev)
		prev = item.event.EntryHash
		events = append(events, item.event)
	}
	return events, accessLogs
}

// commitBatchWithBusyRetry attempts batch repeatedly, retrying ONLY on a
// transient SQLite busy error — identical backoff shape to
// logAuditEventDirect's own retry loop (see its doc comment for the full
// rationale: SQLite's busy handler makes no fairness guarantee, so a
// transaction already in the queue can be repeatedly overtaken by new
// arrivals). Returns nil on success, or the final error (a genuine
// non-busy failure, or the last busy error if ctx expired first).
func (ls *LocalStorage) commitBatchWithBusyRetry(ctx context.Context, batch []*auditBatchItem) error {
	delay := auditBusyRetryBaseDelay
	for {
		err := ls.commitBatchAttempt(ctx, batch)
		if err == nil || !isSQLiteBusyErr(err) {
			return err
		}
		jittered := delay/2 + time.Duration(retryJitterN(int64(delay/2+1)))
		select {
		case <-ctx.Done():
			return err
		case <-time.After(jittered):
		}
		if delay *= 2; delay > auditBusyRetryMaxDelay {
			delay = auditBusyRetryMaxDelay
		}
	}
}

// commitAuditBatch commits every item in batch, preferring ONE transaction
// for the whole batch — the group-commit fast path, one fsync for every
// item, identical hashing/locking semantics to the old per-call path
// (computeAuditEntryHash, the Postgres cross-process advisory lock, the
// SQLite busy-retry loop). Returns one error per item, in the SAME order as
// batch (nil = that item's event, and access-log row if any, committed).
//
// A GENUINE (non-busy) failure on a multi-item batch does NOT fail every
// item in the batch (coordinator review, #2420, item 3: "one bad item must
// not fail the batch"). It bisects instead, retrying each half
// independently — a single poisoned item (e.g. one access-log row
// violating a constraint) only ever fails itself, isolated down through
// O(log n) extra transaction attempts, not the N-1 unrelated reads that
// happened to share its batch window. Every surviving item still gets full
// chain-linkage: each sub-batch attempt re-reads the CURRENT chain head
// fresh from the table, so whichever sub-batch commits first (these all run
// sequentially on the one flusher goroutine, never concurrently with each
// other) correctly becomes the next sub-batch's starting point — the same
// "some total order, not a causal-order claim" guarantee the single
// un-split batch always provided.
//
// A batch that fails only because busy-retry exhausted its budget (ctx
// expired under sustained contention) bisects the same way and every leaf
// gets the same outcome (nothing committed, same error) — bisection doesn't
// change that case's result, only adds a few harmless extra attempts.
//
// That last sentence is TRUE ONLY WHEN THE CTX HAS EXPIRED, which is what makes
// each leaf fail instantly. The in-process SQLite write gate (#2637) breaks that
// premise and is therefore excluded explicitly below: the gate gives up after its
// own bound while the item's auditWriteContext deadline can still be live, so
// every leaf of the recursion can queue for the FULL bound again. A 256-item
// batch has ~511 leaves, so a single bounded failure becomes an unbounded serial
// amplification — under precisely the sustained-contention load the gate exists
// to bound. recordAuditFlush also fires once per recursion level, which would
// corrupt keyorix_audit_flusher_batch_size / _flushes_total at exactly the moment
// an operator is looking at them. Found by the coordinator's review of #2637.
func (ls *LocalStorage) commitAuditBatch(batch []*auditBatchItem) []error {
	return ls.commitAuditBatchHeld(nil, batch)
}

// commitAuditBatchHeld is commitAuditBatch on the flusher's held connection
// when held has one (local_audit_chain_pipelined_batches.go): only the
// flusher's own commits pass it, from the flusher goroutine.
func (ls *LocalStorage) commitAuditBatchHeld(held *auditBatchPipeline, batch []*auditBatchItem) []error {
	ctx := withHeldAuditConn(batch[0].ctx, held) // auditWriteContext-derived; every item's ctx carries the same fixed deadline shape
	return ls.finishAuditBatch(held, batch, ls.commitBatchWithBusyRetry(ctx, batch))
}

// finishAuditBatch is commitAuditBatch after batch's first attempt returned
// err: nil fails nothing, a single item gets err, a batch-global contention
// error fails every item, anything else bisects. The pipelined batches'
// completion (local_audit_chain_pipelined_batches.go) enters here with the
// outcome of an attempt it ran itself, so a pipelined batch is retried and
// isolated exactly like one the flusher committed serially.
func (ls *LocalStorage) finishAuditBatch(held *auditBatchPipeline, batch []*auditBatchItem, err error) []error {
	recordAuditFlush(len(batch))
	if err == nil {
		return make([]error, len(batch))
	}
	if len(batch) == 1 {
		return []error{err}
	}
	// A batch-GLOBAL contention failure is not a poisoned item, so there is
	// nothing for a bisection to find: fail the whole batch with the one error.
	// Every caller is already waiting on its own item's done channel and gets the
	// same error it would have got from a leaf, just without the ~511 extra gate
	// waits and the corrupted flush metrics.
	if isBatchGlobalContentionErr(err) {
		errs := make([]error, len(batch))
		for i := range errs {
			errs[i] = err
		}
		return errs
	}
	mid := len(batch) / 2
	left := ls.commitAuditBatchHeld(held, batch[:mid])
	right := ls.commitAuditBatchHeld(held, batch[mid:])
	return append(left, right...)
}

// logAuditEventBatched queues event (and optionally accessLog) with the
// flusher and waits for its batch to commit.
func (ls *LocalStorage) logAuditEventBatched(ctx context.Context, event *models.AuditEvent, accessLog *models.SecretAccessLog) error {
	// #1650: detach from the caller's cancellation before the eventual transaction
	// runs — see auditWriteContext's doc comment. Applied once here (not per-caller)
	// since every batched item shares this same derivation.
	itemCtx, cancel := auditWriteContext(ctx)
	defer cancel()
	item := &auditBatchItem{event: event, accessLog: accessLog, ctx: itemCtx, done: make(chan error, 1)}
	return ls.submitAuditBatchItem(item)
}

// VerifyAuditChain re-walks the hash chain by ascending id in bounded batches.
// A leading run of legacy rows (empty entry_hash, pre-ADR-029) is counted as an
// unchained prefix. From the first chained row, each row's prev_hash must equal
// the running previous entry_hash (genesis for the first) and its entry_hash
// must recompute from its stored fields. The first divergence stops the walk.
//
// anchor, when non-nil, is an ALREADY-AUTHENTICATED re-anchor point (see
// storage.AuditChainAnchor) written by a retention purge that removed the
// original earliest rows. This method trusts it literally — it does not, and
// cannot, re-verify its signature (no signing key at this layer); the caller
// must have done that. When the earliest surviving row's own prev_hash is
// still genesis (the purge only removed the unchained legacy prefix, emptied
// the table, or no purge ever ran), the anchor is superfluous and ignored —
// the walk proceeds exactly as it always has.
func (ls *LocalStorage) VerifyAuditChain(ctx context.Context, anchor *storage.AuditChainAnchor) (*storage.AuditChainVerification, error) {
	return ls.VerifyAuditChainSegment(ctx, storage.AuditChainSegment{Anchor: anchor})
}

// VerifyAuditChainSegment is the walk behind VerifyAuditChain, bounded for the
// incremental verification modes (docs/specs/audit-incremental-verification.md).
// The zero segment is exactly VerifyAuditChain(ctx, nil). See the
// storage.Storage interface doc for the contract.
func (ls *LocalStorage) VerifyAuditChainSegment(ctx context.Context, seg storage.AuditChainSegment) (*storage.AuditChainVerification, error) {
	result := &storage.AuditChainVerification{Valid: true}

	prevHash := auditGenesisHash
	started := false
	var lastID uint
	var headID uint
	firstBatch := seg.AfterID == 0
	anchor := seg.Anchor

	if seg.AfterID > 0 {
		broke, err := ls.pinAuditChainSeed(ctx, seg, result)
		if err != nil || broke {
			return result, err
		}
		prevHash, started, lastID, headID = seg.SeedHash, true, seg.AfterID, seg.AfterID
	}

	walked := 0
	for {
		limit := auditChainVerifyBatch
		if seg.MaxRows > 0 {
			limit = min(limit, seg.MaxRows-walked)
		}
		q := ls.db.WithContext(ctx).Where("id > ?", lastID)
		if seg.ThroughID > 0 {
			q = q.Where("id <= ?", seg.ThroughID)
		}
		if limit <= 0 {
			// The row cap is reached: report whether anything was left unwalked.
			var next []uint
			if err := q.Model(&models.AuditEvent{}).Order("id ASC").Limit(1).Pluck("id", &next).Error; err != nil {
				return nil, err
			}
			result.Truncated = len(next) > 0
			break
		}
		var batch []*models.AuditEvent
		if err := q.Order("id ASC").Limit(limit).Find(&batch).Error; err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			break
		}
		if firstBatch {
			firstBatch = false
			if head := batch[0]; anchor != nil && head.PrevHash != auditGenesisHash {
				if head.EntryHash == "" || head.ID != anchor.RowID ||
					head.PrevHash != anchor.PrevHash || head.EntryHash != anchor.EntryHash {
					brokenChain(result, head.ID,
						"earliest surviving audit row does not match the last retention re-anchor (rows removed outside a sanctioned purge, or the re-anchor is stale)")
					return result, nil
				}
				// The anchor authenticates head's prev_hash as a legitimate chain
				// position established before its predecessors were purged — seed
				// the walk from there instead of requiring genesis.
				prevHash = anchor.PrevHash
				started = true
			}
		}
		newPrev, newHead, newStarted, broke := verifyBatchEvents(batch, prevHash, started, result)
		if broke {
			return result, nil
		}
		prevHash, started = newPrev, newStarted
		if newHead != 0 {
			headID = newHead
		}
		walked += len(batch)
		lastID = batch[len(batch)-1].ID
		if len(batch) < limit {
			break
		}
	}

	// Record the verified head so an external monitor can anchor on it and detect
	// tail-truncation / re-seed (which a self-consistent shorter chain otherwise
	// passes). prevHash holds the last chained entry_hash, or genesis if none.
	result.HeadHash = prevHash
	result.HeadID = headID
	return result, nil
}

// pinAuditChainSeed checks a segment's seed row before the walk continues past
// it: the row must still exist, carry the entry_hash it was certified or last
// verified with, and recompute from its own stored fields. broke reports a
// failure already recorded on result.
func (ls *LocalStorage) pinAuditChainSeed(ctx context.Context, seg storage.AuditChainSegment, result *storage.AuditChainVerification) (broke bool, err error) {
	var seed models.AuditEvent
	err = ls.db.WithContext(ctx).Where("id = ?", seg.AfterID).Take(&seed).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		brokenChain(result, seg.AfterID, fmt.Sprintf(
			"audit event #%d, the certified/verified starting point of this walk, is missing (rows removed outside a sanctioned purge)", seg.AfterID))
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if seed.EntryHash != seg.SeedHash {
		brokenChain(result, seg.AfterID, fmt.Sprintf(
			"audit event #%d hash differs from the value it was certified/verified with (row rewritten)", seg.AfterID))
		return true, nil
	}
	if computeAuditEntryHash(&seed, seed.PrevHash) != seed.EntryHash {
		brokenChain(result, seg.AfterID, fmt.Sprintf(
			"audit event #%d no longer recomputes to its entry_hash, so its contents changed after it was written (event modified)", seg.AfterID))
		return true, nil
	}
	return false, nil
}

// MigrateAuditChainEncoding re-derives entry_hash/prev_hash for every chained
// audit_events row under computeAuditEntryHash's current encoding, in one
// transaction spanning the whole migration (holding the same cross-process
// exclusivity LogAuditEvent uses for its own append, so no concurrently
// appended row can interleave against a partially-migrated chain). See the
// storage.Storage interface doc for the full contract, including why callers
// must still ensure no other process reaches this database concurrently.
func (ls *LocalStorage) MigrateAuditChainEncoding(ctx context.Context, dryRun bool, anchor *storage.AuditChainAnchor) (*storage.AuditChainMigrationResult, error) {
	result := &storage.AuditChainMigrationResult{}

	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if tx.Dialector.Name() == "postgres" {
			if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", int64(auditAdvisoryLockKey)).Error; err != nil {
				return err
			}
			// Re-hashing rewrites the head's entry_hash (AUDIT-1FLIGHT-1).
			ls.invalidateAuditChainHead()
		}

		// Pre-flight, inside the same transaction and before a single row is
		// rewritten. Without it this operation recomputed and overwrote every
		// entry_hash/prev_hash unconditionally, which on a tampered database
		// re-hashed the tampered row exactly like a stale one and left the chain
		// verifying afterwards -- an evidence-erasing write on the one dataset
		// that exists to be evidence. The only trace was the migration event this
		// function appends, which says a migration ran, not what it covered up.
		//
		// Refusing here costs nothing in the legitimate case (the chain is
		// intact, just old-encoded) and is the difference between "we detected
		// tampering" and "we destroyed the proof of it" in the case that matters.
		// The transaction rolls back, so a refusal leaves the database untouched.
		if err := refuseIfAuditChainBroken(tx, anchor); err != nil {
			return err
		}

		prevHash := auditGenesisHash
		started := false
		var lastID uint
		firstBatch := true
		firstChainedID := uint(0)
		firstChainedNewHash := ""
		anchorApplies := false

		for {
			var batch []*models.AuditEvent
			if err := tx.
				Where("id > ?", lastID).
				Order("id ASC").
				Limit(auditChainVerifyBatch).
				Find(&batch).Error; err != nil {
				return err
			}
			if len(batch) == 0 {
				break
			}
			if firstBatch {
				firstBatch = false
				// Mirror VerifyAuditChain's exact applicability rule: only seed from
				// the anchor if the earliest row that WOULD start the chain (first
				// non-empty-entry_hash row) currently carries a non-genesis
				// prev_hash — i.e. a prior purge genuinely moved the chain start.
				for _, e := range batch {
					if e.EntryHash == "" {
						continue
					}
					if anchor != nil && e.PrevHash != auditGenesisHash {
						prevHash = anchor.PrevHash
						anchorApplies = true
					}
					break
				}
			}
			for _, e := range batch {
				if !started {
					if e.EntryHash == "" {
						result.UnchainedRowsSkipped++
						continue
					}
					started = true
					firstChainedID = e.ID
				}
				newHash := computeAuditEntryHash(e, prevHash)
				if e.ID == firstChainedID {
					firstChainedNewHash = newHash
				}
				if e.PrevHash != prevHash || e.EntryHash != newHash {
					if err := tx.Model(&models.AuditEvent{}).Where("id = ?", e.ID).
						Updates(map[string]any{"prev_hash": prevHash, "entry_hash": newHash}).Error; err != nil {
						return err
					}
				}
				prevHash = newHash
				result.HeadID = e.ID
				result.RowsMigrated++
			}
			lastID = batch[len(batch)-1].ID
			if len(batch) < auditChainVerifyBatch {
				break
			}
		}

		result.HeadHash = prevHash
		if anchorApplies && firstChainedID != 0 {
			// The earliest migrated row is the anchor's row; the caller must
			// re-sign the anchor with this row's newly computed entry_hash (its
			// PrevHash is unchanged — it represents an already-purged predecessor
			// that cannot be recomputed under any encoding).
			result.AnchorRowID = firstChainedID
			result.AnchorNewEntryHash = firstChainedNewHash
		}
		if dryRun {
			return errAuditMigrationDryRun
		}
		return nil
	})
	if err != nil && !errors.Is(err, errAuditMigrationDryRun) {
		return nil, err
	}
	return result, nil
}

// refuseIfAuditChainBroken walks the stored chain before MigrateAuditChainEncoding
// rewrites it, and returns an error if any chained row is inconsistent under BOTH
// the current and the pre-#1452 encodings, or if the chain linkage itself is
// broken.
//
// The two checks catch different things and both matter:
//
//   - content: a row whose stored entry_hash matches neither encoding's
//     derivation from its own fields. Its contents changed after it was written.
//   - linkage: a row whose prev_hash does not equal the preceding row's stored
//     entry_hash. A row was inserted, deleted, or reordered -- which re-encoding
//     would silently repair by rewriting prev_hash down the whole chain.
//
// Mixed encodings are explicitly fine (see auditEntryHashMatchesAnyKnownEncoding):
// a deployment that upgraded and took traffic before migrating has honest rows in
// both formats, and refusing that would push operators toward a force flag.
func refuseIfAuditChainBroken(tx *gorm.DB, anchor *storage.AuditChainAnchor) error {
	prevHash := auditGenesisHash
	started := false
	firstBatch := true
	var lastID uint

	for {
		var batch []*models.AuditEvent
		if err := tx.
			Where("id > ?", lastID).
			Order("id ASC").
			Limit(auditChainVerifyBatch).
			Find(&batch).Error; err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		if firstBatch {
			firstBatch = false
			// Same applicability rule the rewrite loop below uses: seed from the
			// retention anchor only when the first chained row carries a
			// non-genesis prev_hash, i.e. a prior purge really did move the
			// chain start.
			for _, e := range batch {
				if e.EntryHash == "" {
					continue
				}
				if anchor != nil && e.PrevHash != auditGenesisHash {
					prevHash = anchor.PrevHash
				}
				break
			}
		}

		for _, e := range batch {
			if !started {
				if e.EntryHash == "" {
					continue // leading unchained (pre-ADR-029) rows
				}
				started = true
			}
			if e.EntryHash == "" {
				return fmt.Errorf("refusing to re-encode the audit chain: event %d has no entry_hash, so "+
					"chain data was removed after it was written. Re-encoding would rewrite the chain around "+
					"this gap and produce a chain that verifies. Investigate before migrating", e.ID)
			}
			if e.PrevHash != prevHash {
				return fmt.Errorf("refusing to re-encode the audit chain: event %d's prev_hash does not link "+
					"to the preceding event, so a row was inserted, deleted, or reordered. Re-encoding "+
					"rewrites prev_hash for every row and would repair this break invisibly. Investigate "+
					"before migrating", e.ID)
			}
			if !auditEntryHashMatchesAnyKnownEncoding(e) {
				return fmt.Errorf("refusing to re-encode the audit chain: event %d's entry_hash matches "+
					"neither the current encoding nor the pre-#1452 one, so its contents changed after it "+
					"was written -- this is not a stale encoding. Re-encoding would re-hash the modified "+
					"contents and leave the chain verifying, destroying the evidence. Investigate before "+
					"migrating", e.ID)
			}
			prevHash = e.EntryHash
		}

		lastID = batch[len(batch)-1].ID
		if len(batch) < auditChainVerifyBatch {
			return nil
		}
	}
}

// errAuditMigrationDryRun is a sentinel used to force MigrateAuditChainEncoding's
// transaction to roll back after computing (but never persisting) its result.
var errAuditMigrationDryRun = errors.New("audit chain migration dry run")

// verifyBatchEvents processes one page of audit events against the running hash chain.
// Returns the new prevHash, the last verified headID, the updated started flag, and
// whether a chain break was detected (in which case result is already marked broken).
func verifyBatchEvents(batch []*models.AuditEvent, prevHash string, started bool, result *storage.AuditChainVerification) (newPrev string, headID uint, newStarted bool, broke bool) {
	for _, e := range batch {
		if !started {
			if e.EntryHash == "" {
				result.UnchainedEvents++
				continue
			}
			started = true
		}
		if e.EntryHash == "" {
			brokenChain(result, e.ID, "missing entry hash on a chained event (chain data removed)")
			return prevHash, headID, started, true
		}
		if e.PrevHash != prevHash {
			brokenChain(result, e.ID, "prev_hash does not link to the preceding event (row inserted, deleted, or reordered)")
			return prevHash, headID, started, true
		}
		if computeAuditEntryHash(e, e.PrevHash) != e.EntryHash {
			// Two different findings share this branch, and saying the wrong one
			// on a compliance screen is not a cosmetic problem. The stored hash
			// can disagree with the recomputed one because the event really was
			// modified, or because the row was hashed under the pre-2026-08-16
			// encoding (#1452 replaced the NUL-delimited derivation with a
			// length-prefixed one) and has not been through
			// MigrateAuditChainEncoding yet. On an upgraded install the second
			// is reached by doing nothing but deploying.
			//
			// Until the frozen legacy encoder existed there was no way to tell
			// them apart, and this said "event modified" for both -- telling an
			// operator, and the Compliance page's "Audit chain verified" tile,
			// that someone had tampered with their audit log after an ordinary
			// upgrade. Now the row is tested against the old encoding and the
			// two are reported as what they are.
			if ComputeAuditEntryHashPre1452(e, e.PrevHash) == e.EntryHash {
				brokenChain(result, e.ID, "this row's entry_hash is valid under the pre-#1452 audit-hash "+
					"encoding but not the current one — the chain has not been re-encoded since the "+
					"2026-08-16 format change. This is an un-migrated upgrade, NOT evidence of tampering: "+
					"run the one-time re-encoding (POST /api/v1/audit/migrate-chain-encoding), which "+
					"refuses if it finds a row that matches neither encoding")
				return prevHash, headID, started, true
			}
			brokenChain(result, e.ID, "entry_hash matches neither the current encoding nor the pre-#1452 "+
				"one, so this event's contents changed after it was written (event modified)")
			return prevHash, headID, started, true
		}
		prevHash = e.EntryHash
		headID = e.ID
		result.ChainedEvents++
	}
	return prevHash, headID, started, false
}

// brokenChain marks a verification result as failed at the given event.
func brokenChain(r *storage.AuditChainVerification, id uint, reason string) *storage.AuditChainVerification {
	r.Valid = false
	idCopy := id
	r.FirstBrokenID = &idCopy
	r.Reason = reason
	return r
}

// retryJitterN returns a uniform value in [0, n) for retry-backoff jitter.
// It reads crypto/rand so no math/rand generator is involved; on a (never
// expected) entropy failure it returns 0, i.e. the minimum backoff.
func retryJitterN(n int64) int64 {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return 0
	}
	return v.Int64()
}
