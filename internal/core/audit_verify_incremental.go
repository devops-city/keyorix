// audit_verify_incremental.go — incremental audit-chain verification
// (docs/specs/audit-incremental-verification.md).
//
// A full walk re-hashes every row, so its cost grows with the audit table and
// it cannot run per request or on every start. This file moves that work, it
// does not drop it:
//
//   - the tail check (§2.2) verifies only what was appended since the latest
//     signed checkpoint, pinning the certified head row;
//   - the rolling cycle (§2.3) re-walks the whole chain in segments, one per
//     scheduler tick, with progress in the signed state (audit_verify_state.go);
//   - a ?full=true job runs the unchanged full walk in the background.
//
// VerifyAuditChain and WriteAuditCheckpoint keep their full-walk semantics; the
// request paths, posture and the scheduler call the functions below instead.
package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Verification statuses (spec §4). Valid is reported only for StatusValid.
const (
	AuditVerifyStatusValid     = "valid"
	AuditVerifyStatusBroken    = "broken"
	AuditVerifyStatusNotProven = "not_proven"
)

// Report modes.
const (
	AuditVerifyModeIncremental = "incremental"
	AuditVerifyModeFull        = "full"
)

// Job states.
const (
	AuditVerifyJobRunning     = "running"
	AuditVerifyJobSucceeded   = "succeeded"
	AuditVerifyJobFailed      = "failed"
	AuditVerifyJobInterrupted = "interrupted"
)

const (
	// auditVerifyRequestTailRows bounds the tail a request walks, well inside
	// the HTTP write timeout. A longer tail is reported not_proven, never valid.
	auditVerifyRequestTailRows = 250_000
	// auditVerifyMinSegmentWidth: a chain of up to this many ids completes a
	// whole cycle every tick (the pre-incremental cost).
	auditVerifyMinSegmentWidth = 100_000
	// DefaultAuditFullVerificationSegments spreads a cycle over a week of daily ticks.
	DefaultAuditFullVerificationSegments = 7
	// auditVerifyJobTimeout bounds a background full walk (generous: a hang
	// detector, not a speed limit).
	auditVerifyJobTimeout = 2 * time.Hour
)

// AuditVerifyJobLockKey admits one ?full=true job across replicas; defined
// with the storage interface so the advisory-lock key uniqueness guard sees it.
const AuditVerifyJobLockKey = storage.AuditVerifyJobLockKey

// ErrAuditVerifyJobNotFound reports an unknown or superseded job id.
var ErrAuditVerifyJobNotFound = errors.New("audit verification job not found")

// ErrAuditVerifyJobsUnavailable: without a signing key a job's state cannot be
// persisted (it would be forgeable). GET /audit/verify is already a full walk
// then, so callers run that instead.
var ErrAuditVerifyJobsUnavailable = errors.New("background audit verification jobs need the checkpoint signing key (encryption enabled)")

// AuditVerifyCoverage states what one tail check walked.
type AuditVerifyCoverage struct {
	CheckpointID  uint `json:"checkpoint_id"`
	TailFromID    uint `json:"tail_from_id"`
	TailThroughID uint `json:"tail_through_id"`
	TailComplete  bool `json:"tail_complete"`
}

// AuditRollingCycle reports a rolling full re-walk in progress.
type AuditRollingCycle struct {
	StartedAt         time.Time `json:"started_at"`
	TargetID          uint      `json:"target_id"`
	VerifiedThroughID uint      `json:"verified_through_id"`
}

// AuditVerifyReport is the verdict GET /audit/verify, gRPC VerifyAuditChain,
// the compliance posture and a full job report. Valid is true only when Status
// is AuditVerifyStatusValid.
type AuditVerifyReport struct {
	Status          string `json:"status"`
	Mode            string `json:"mode"`
	NotProvenReason string `json:"not_proven_reason,omitempty"`
	StateReason     string `json:"state_reason,omitempty"`

	Valid            bool   `json:"valid"`
	ChainedEvents    int64  `json:"chained_events"`
	UnchainedEvents  int64  `json:"unchained_events"`
	HeadID           uint   `json:"head_id"`
	HeadHash         string `json:"head_hash"`
	Checkpointed     bool   `json:"checkpointed"`
	FirstBrokenID    *uint  `json:"first_broken_id,omitempty"`
	Reason           string `json:"reason,omitempty"`
	CheckpointReason string `json:"checkpoint_reason,omitempty"`

	AnchorToken               []byte     `json:"anchor_token,omitempty"`
	AnchoredAt                *time.Time `json:"anchored_at,omitempty"`
	AnchorProvider            string     `json:"anchor_provider,omitempty"`
	AnchorTrustRootConfigured bool       `json:"anchor_trust_root_configured,omitempty"`

	Coverage                      *AuditVerifyCoverage `json:"coverage,omitempty"`
	LastFullVerificationAt        *time.Time           `json:"last_full_verification_at,omitempty"`
	LastFullVerificationStartedAt *time.Time           `json:"last_full_verification_started_at,omitempty"`
	LastFullVerificationThroughID *uint                `json:"last_full_verification_through_id,omitempty"`
	LastFullVerificationSource    string               `json:"last_full_verification_source,omitempty"`
	RollingCycle                  *AuditRollingCycle   `json:"rolling_cycle,omitempty"`
	LastCheckedAt                 *time.Time           `json:"last_checked_at,omitempty"`
}

// AuditVerifyJobStatus is GET /audit/verify/jobs/{id}.
type AuditVerifyJobStatus struct {
	JobID      string             `json:"job_id"`
	State      string             `json:"state"`
	StartedAt  time.Time          `json:"started_at"`
	FinishedAt *time.Time         `json:"finished_at,omitempty"`
	Error      string             `json:"error,omitempty"`
	Result     *AuditVerifyReport `json:"result,omitempty"`
}

// AuditVerifyTickResult summarises one scheduler tick for the log.
type AuditVerifyTickResult struct {
	Checkpoint      *models.AuditCheckpoint
	Written         bool
	SegmentWalked   bool
	VerifiedThrough uint
	CycleTarget     uint
	CycleCompleted  bool
}

// SetAuditIncrementalVerification turns incremental verification on. server
// main calls it when the checkpoint scheduler runs (signing key present, not
// disabled): interval is the tick interval and segments the number of ticks a
// rolling cycle takes. Without it every verification is a full walk.
func (c *KeyorixCore) SetAuditIncrementalVerification(interval time.Duration, segments int) {
	if segments < 1 {
		segments = DefaultAuditFullVerificationSegments
	}
	c.auditVerifyInterval = interval
	c.auditVerifySegments = segments
}

// auditIncrementalEnabled reports whether the incremental modes are configured.
func (c *KeyorixCore) auditIncrementalEnabled() bool {
	return c.AuditCheckpointsAvailable() && c.auditVerifyInterval > 0
}

// auditVerifyMinSegmentWidth returns the minimum segment width in ids.
func (c *KeyorixCore) auditVerifyMinSegmentWidth() uint {
	if c.auditVerifyMinWidth > 0 {
		return c.auditVerifyMinWidth
	}
	return auditVerifyMinSegmentWidth
}

// auditVerifyCycleDuration is how long one rolling cycle takes.
func (c *KeyorixCore) auditVerifyCycleDuration() time.Duration {
	return c.auditVerifyInterval * time.Duration(max(c.auditVerifySegments, 1))
}

// fullAuditVerifyReport wraps a full-walk verdict.
func fullAuditVerifyReport(v *storage.AuditChainVerification) *AuditVerifyReport {
	r := reportFromVerification(v)
	r.Mode = AuditVerifyModeFull
	if v.Valid {
		r.Status = AuditVerifyStatusValid
	} else {
		r.Status = AuditVerifyStatusBroken
	}
	r.Valid = v.Valid
	return r
}

func reportFromVerification(v *storage.AuditChainVerification) *AuditVerifyReport {
	return &AuditVerifyReport{
		ChainedEvents:             v.ChainedEvents,
		UnchainedEvents:           v.UnchainedEvents,
		HeadID:                    v.HeadID,
		HeadHash:                  v.HeadHash,
		Checkpointed:              v.Checkpointed,
		FirstBrokenID:             v.FirstBrokenID,
		Reason:                    v.Reason,
		CheckpointReason:          v.CheckpointReason,
		AnchorToken:               v.AnchorToken,
		AnchoredAt:                v.AnchoredAt,
		AnchorProvider:            v.AnchorProvider,
		AnchorTrustRootConfigured: v.AnchorTrustRootConfigured,
	}
}

// auditTail is one tail check's outcome.
type auditTail struct {
	// base is the checkpoint the check started from; nil when there is no
	// usable one (none yet, an empty/genesis head, or a signature failure).
	base *models.AuditCheckpoint
	// noBaseReason explains a nil base.
	noBaseReason string
	// sigTampered: the latest checkpoint claims the current key version yet
	// fails its signature (tampering, not a rotation).
	sigTampered bool
	v           *storage.AuditChainVerification
	// certified is base.ChainedEvents + tail rows (chained + purged units).
	certified int64
	truncated bool
}

// auditTailCheck runs the tail check (spec §2.2) from the latest checkpoint.
// maxRows bounds the walk (0 = unbounded). It never writes.
func (c *KeyorixCore) auditTailCheck(ctx context.Context, maxRows int, forWrite bool) (*auditTail, error) {
	cp, err := c.storage.LatestAuditCheckpoint(ctx)
	if err != nil {
		return nil, err
	}
	if cp == nil {
		// Every checkpoint row is gone: the signed high-water mark certifies the
		// same (count, head) snapshot, so the tail is checked from it (pinning its
		// head) rather than reporting nothing. The write path does the same: its
		// full-walk fallback checks only the count against the mark, so a chain
		// rewritten through the head plus deleted checkpoint rows would pass it.
		if cp, err = c.authenticatedHighWaterBase(ctx); err != nil {
			return nil, err
		}
	}
	switch {
	case cp == nil:
		return &auditTail{noBaseReason: "no signed checkpoint exists yet"}, nil
	case !c.checkpointSignatureValid(cp):
		t := &auditTail{noBaseReason: fmt.Sprintf("audit checkpoint #%d does not verify under the current signing key", cp.ID)}
		t.sigTampered = cp.KeyVersion == c.auditCkptKeyVersion
		return t, nil
	case cp.HeadID == 0:
		return &auditTail{noBaseReason: fmt.Sprintf("audit checkpoint #%d certified an empty chain", cp.ID)}, nil
	}
	anchor, err := c.loadAuditRetentionAnchor(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load audit chain re-anchor: %w", err)
	}
	purged := anchorPurgedEvents(anchor)
	// Read the high-water floor BEFORE the walk: a checkpoint written by another
	// caller during the walk can only certify rows that existed before it, which
	// this walk then also sees, so the comparison below has no false alarm.
	//
	// The read path is strict like enforceAuditHighWater; the write path keeps
	// writeAuditCheckpointLocked's rules (a mark under a superseded key or a
	// missing mark does not block, and the write re-establishes it).
	floor, found, hwTampered, hwReason, err := c.auditHighWaterFloor(ctx, !forWrite)
	if err != nil {
		return nil, err
	}
	if !forWrite && !found && !hwTampered {
		// A checkpoint exists (cp above), so a missing mark is a rollback attempt
		// (same rule as enforceAuditHighWater).
		hwTampered = true
		hwReason = "audit high-water mark is missing or malformed although signed checkpoints exist — the anti-rollback mark was deleted or tampered with"
	}

	w, err := c.storage.VerifyAuditChainSegment(ctx, storage.AuditChainSegment{
		AfterID: cp.HeadID, SeedHash: cp.HeadHash, MaxRows: maxRows,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify audit chain tail: %w", err)
	}
	t := &auditTail{base: cp, truncated: w.Truncated}
	t.certified = cp.ChainedEvents + w.ChainedEvents
	v := w
	v.ChainedEvents = t.certified - purged
	if !v.Valid && v.FirstBrokenID != nil && *v.FirstBrokenID == cp.HeadID {
		v.Reason = fmt.Sprintf("head of %s: %s", auditBaseLabel(cp), v.Reason)
	}
	v.Checkpointed = true
	switch {
	case hwTampered:
		c.failCheckpoint(v, nil, hwReason)
	case !w.Truncated && t.certified < floor:
		c.failCheckpoint(v, nil,
			fmt.Sprintf("audit trail truncated below the certified high-water mark: %d events were previously certified, only %d are reachable from %s", floor, t.certified, auditBaseLabel(cp)))
	}
	if !w.Truncated && v.Valid {
		c.bumpWatermark(t.certified)
	}
	// The external-anchor check is the read path's (enforceAuditCheckpoint); the
	// write path never refused over it, so a fresh anchored checkpoint can still
	// be written.
	if len(cp.AnchorToken) > 0 && !forWrite {
		v.AnchorToken = cp.AnchorToken
		v.AnchoredAt = cp.AnchoredAt
		v.AnchorProvider = cp.AnchorProvider
		v.AnchorTrustRootConfigured = c.CheckpointAnchorVerifiable()
		if c.checkpointAnchorRoots != nil {
			if _, _, aerr := c.VerifyCheckpointAnchor(cp); aerr != nil {
				c.failCheckpoint(v, nil,
					fmt.Sprintf("audit checkpoint #%d external anchor failed verification against the configured trust root: %v", cp.ID, aerr))
			}
		}
	}
	t.v = v
	return t, nil
}

// authenticatedHighWaterBase returns the signed high-water mark as a tail-check
// base (ID 0), or nil when it is absent or does not authenticate.
func (c *KeyorixCore) authenticatedHighWaterBase(ctx context.Context) (*models.AuditCheckpoint, error) {
	val, ok, err := c.storage.GetSystemMetadata(ctx, auditHighWaterKey)
	if err != nil || !ok {
		return nil, err
	}
	hw, sig, parsed := parseAuditHighWater(val)
	if !parsed || !c.checkpointSigMatches(hw, sig) {
		return nil, nil
	}
	hw.Signature = sig // same canonical bytes as a checkpoint row
	return hw, nil
}

// auditBaseLabel names a tail-check base in messages.
func auditBaseLabel(cp *models.AuditCheckpoint) string {
	if cp.ID == 0 {
		return "the signed high-water mark"
	}
	return fmt.Sprintf("signed checkpoint #%d", cp.ID)
}

// applyAuditStateToReport fills the persisted-state fields and decides the
// status (spec §4). tailBroken/tailComplete describe the check behind r (for
// posture, the last scheduler tail check).
func (c *KeyorixCore) applyAuditStateToReport(r *AuditVerifyReport, st *auditVerifyState, stReason string, tailBroken, tailComplete bool, notProven string) {
	r.Mode = AuditVerifyModeIncremental
	r.StateReason = stReason
	if lf := st.LastFull; lf != nil {
		completed, started, through := lf.CompletedAt, lf.StartedAt, lf.ThroughID
		r.LastFullVerificationAt = &completed
		r.LastFullVerificationStartedAt = &started
		r.LastFullVerificationThroughID = &through
		r.LastFullVerificationSource = lf.Source
		if r.UnchainedEvents == 0 {
			r.UnchainedEvents = lf.UnchainedEvents
		}
	}
	if cy := st.Cycle; cy != nil {
		r.RollingCycle = &AuditRollingCycle{StartedAt: cy.StartedAt, TargetID: cy.TargetID, VerifiedThroughID: cy.SeedID}
	}
	if lc := st.LastCheck; lc != nil {
		at := lc.At
		r.LastCheckedAt = &at
	}

	switch {
	case tailBroken:
		r.Status = AuditVerifyStatusBroken
	case st.Failure != nil:
		r.Status = AuditVerifyStatusBroken
		if r.Reason == "" {
			r.Reason = fmt.Sprintf("a verification failure was recorded at %s (%s): %s",
				st.Failure.DetectedAt.UTC().Format(time.RFC3339), st.Failure.Source, st.Failure.Reason)
		}
		if r.FirstBrokenID == nil {
			r.FirstBrokenID = st.Failure.FirstBrokenID
		}
	case st.LastFull != nil && !st.LastFull.Valid:
		r.Status = AuditVerifyStatusBroken
		if r.Reason == "" {
			r.Reason = "the last full verification failed: " + st.LastFull.Reason
		}
		if r.FirstBrokenID == nil {
			r.FirstBrokenID = st.LastFull.FirstBrokenID
		}
	case notProven != "":
		r.Status = AuditVerifyStatusNotProven
		r.NotProvenReason = notProven
	case stReason != "":
		r.Status = AuditVerifyStatusNotProven
		r.NotProvenReason = stReason
	case st.Rejected != nil:
		r.Status = AuditVerifyStatusNotProven
		r.NotProvenReason = fmt.Sprintf("the persisted verification state was rejected at %s and restarted (%s): nothing is proven until a full verification that started after that completes",
			st.Rejected.At.UTC().Format(time.RFC3339), st.Rejected.Reason)
	case st.LastFull == nil:
		r.Status = AuditVerifyStatusNotProven
		r.NotProvenReason = "no full verification has completed yet: rows before the latest checkpoint head are not proven until the rolling re-walk completes (or run ?full=true)"
	case c.now().Sub(st.LastFull.CompletedAt) > 2*c.auditVerifyCycleDuration():
		r.Status = AuditVerifyStatusNotProven
		r.NotProvenReason = fmt.Sprintf("the last full verification completed at %s, more than two rolling cycles ago",
			st.LastFull.CompletedAt.UTC().Format(time.RFC3339))
	case !tailComplete:
		r.Status = AuditVerifyStatusNotProven
		r.NotProvenReason = "the tail after the latest checkpoint was not fully verified"
	default:
		r.Status = AuditVerifyStatusValid
	}
	r.Valid = r.Status == AuditVerifyStatusValid
}

// VerifyAuditChainIncremental backs GET /audit/verify and gRPC VerifyAuditChain:
// the signed persisted state plus a bounded tail check from the latest
// checkpoint (spec §2.2, §4). Without incremental verification configured it
// is the full walk, as before.
func (c *KeyorixCore) VerifyAuditChainIncremental(ctx context.Context) (*AuditVerifyReport, error) {
	if !c.auditIncrementalEnabled() {
		v, err := c.VerifyAuditChain(ctx)
		if err != nil {
			return nil, err
		}
		return fullAuditVerifyReport(v), nil
	}
	st, stReason, err := c.loadAuditVerifyState(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load audit verification state: %w", err)
	}
	t, err := c.auditTailCheck(ctx, auditVerifyRequestTailRows, false)
	if err != nil {
		return nil, err
	}
	if t.base == nil {
		r := &AuditVerifyReport{Checkpointed: t.sigTampered}
		if t.sigTampered {
			// Mirror enforceAuditCheckpoint: an unverifiable checkpoint under the
			// current key version is a tamper signal.
			r.Reason = t.noBaseReason + " — the checkpoint was tampered with"
			r.CheckpointReason = r.Reason
		}
		c.applyAuditStateToReport(r, st, stReason, t.sigTampered, false,
			t.noBaseReason+": the tail cannot be checked until the checkpoint scheduler writes one")
		return r, nil
	}
	r := reportFromVerification(t.v)
	r.Coverage = &AuditVerifyCoverage{
		CheckpointID: t.base.ID, TailFromID: t.base.HeadID, TailThroughID: t.v.HeadID, TailComplete: !t.truncated,
	}
	notProven := ""
	if t.truncated {
		notProven = fmt.Sprintf("the tail after checkpoint #%d is longer than %d rows; verified through id %d only",
			t.base.ID, auditVerifyRequestTailRows, t.v.HeadID)
	}
	c.applyAuditStateToReport(r, st, stReason, !t.v.Valid, !t.truncated, notProven)
	return r, nil
}

// AuditVerificationStatus backs the compliance posture and evidence pack: the
// persisted state only, no walk (spec §5). Without incremental verification
// configured it is the full walk, as before.
func (c *KeyorixCore) AuditVerificationStatus(ctx context.Context) (*AuditVerifyReport, error) {
	if !c.auditIncrementalEnabled() {
		v, err := c.VerifyAuditChain(ctx)
		if err != nil {
			return nil, err
		}
		return fullAuditVerifyReport(v), nil
	}
	st, stReason, err := c.loadAuditVerifyState(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load audit verification state: %w", err)
	}
	r := &AuditVerifyReport{}
	lc := st.LastCheck
	notProven := ""
	tailBroken := false
	if lc == nil {
		notProven = "the checkpoint scheduler has not recorded a tail check yet"
	} else {
		r.ChainedEvents, r.HeadID, r.HeadHash, r.Checkpointed = lc.ChainedEvents, lc.ThroughID, lc.HeadHash, lc.Checkpointed
		r.Coverage = &AuditVerifyCoverage{CheckpointID: lc.CheckpointID, TailFromID: lc.FromID, TailThroughID: lc.ThroughID, TailComplete: true}
		if !lc.Valid {
			tailBroken = true
			r.FirstBrokenID, r.Reason = lc.FirstBrokenID, lc.Reason
		} else if c.now().Sub(lc.At) > 2*c.auditVerifyInterval {
			notProven = fmt.Sprintf("the last tail check ran at %s, more than two scheduler intervals ago", lc.At.UTC().Format(time.RFC3339))
		}
	}
	c.applyAuditStateToReport(r, st, stReason, tailBroken, lc != nil, notProven)
	return r, nil
}

// WriteAuditCheckpointIncremental backs the scheduler tick and the on-demand
// POST /audit/checkpoint and gRPC WriteAuditCheckpoint: it extends the latest
// signed checkpoint by a tail check (spec §2.2) instead of a full walk, and
// falls back to WriteAuditCheckpoint's full walk when there is no usable
// checkpoint. It refuses while a verification failure is recorded. Without
// incremental verification configured it is WriteAuditCheckpoint.
func (c *KeyorixCore) WriteAuditCheckpointIncremental(ctx context.Context) (*models.AuditCheckpoint, bool, error) {
	if !c.auditIncrementalEnabled() {
		return c.WriteAuditCheckpoint(ctx)
	}
	var newCP *models.AuditCheckpoint
	var failed *auditVerifyFailure
	var rejected *auditVerifyRejection
	err := c.storage.WithAuditCheckpointLock(ctx, func() error {
		// An untrusted state row is replaced by one that records the rejection
		// (not_proven until a later full verification, plus an audit event); the
		// tail check stands on the signed checkpoint alone.
		st, rej, err := c.loadAuditVerifyStateForWrite(ctx)
		if err != nil {
			return fmt.Errorf("failed to load audit verification state: %w", err)
		}
		rejected = rej
		cp, ferr, werr := c.writeIncrementalCheckpointLocked(ctx, st)
		newCP = cp
		if ferr != nil {
			failed = ferr
		}
		if serr := c.saveAuditVerifyState(ctx, st); serr != nil && werr == nil {
			werr = fmt.Errorf("failed to save audit verification state: %w", serr)
		}
		return werr
	})
	c.reportAuditVerifyStateEvents(ctx, rejected, failed)
	if err != nil {
		return nil, false, err
	}
	return newCP, true, nil
}

// writeIncrementalCheckpointLocked is WriteAuditCheckpointIncremental's body.
// The caller holds WithAuditCheckpointLock and saves st afterwards. newFailure
// is non-nil when this call recorded a new sticky failure.
func (c *KeyorixCore) writeIncrementalCheckpointLocked(ctx context.Context, st *auditVerifyState) (cp *models.AuditCheckpoint, newFailure *auditVerifyFailure, err error) {
	now := c.now()
	t, err := c.auditTailCheck(ctx, 0, true)
	if err != nil {
		return nil, nil, err
	}
	if t.base == nil {
		// No usable checkpoint or high-water mark: the unchanged full-walk path
		// (first checkpoint, KEK-provider migration recovery, or a refusal over a
		// tampered one). It is no way around a recorded failure: refuse like the
		// tail path below, so the failure stays until a full verification clears it.
		if st.Failure != nil {
			return nil, nil, auditFailureRefusal(st.Failure)
		}
		started := now
		cp, err := c.writeAuditCheckpointLocked(ctx)
		if err != nil {
			if errors.Is(err, ErrAuditCheckpointRefused) {
				nf := recordAuditVerifyFailure(st, now, auditFullSourceCheckpoint, nil, err.Error())
				st.LastCheck = &auditTailCheck{At: now, Valid: false, Reason: err.Error()}
				return nil, nf, err
			}
			return nil, nil, err
		}
		// A passing full walk proves the whole chain now: record it, clear a
		// rejection recorded before it, and restart the rolling cycle against this
		// head. (No failure is recorded: the refusal above.)
		st.LastFull = &auditFullResult{StartedAt: started, CompletedAt: c.now(), ThroughID: cp.HeadID,
			Source: auditFullSourceCheckpoint, Valid: true}
		clearAuditVerifyMarkers(st, st.Gen, cp.HeadID, true)
		st.Cycle = nil
		st.LastCheck = &auditTailCheck{At: c.now(), Valid: true, CheckpointID: cp.ID, ThroughID: cp.HeadID,
			HeadHash: cp.HeadHash, CertifiedEvents: cp.ChainedEvents, ChainedEvents: cp.ChainedEvents, Checkpointed: true}
		return cp, nil, nil
	}

	v := t.v
	st.LastCheck = &auditTailCheck{At: now, Valid: v.Valid, CheckpointID: t.base.ID, FromID: t.base.HeadID,
		ThroughID: v.HeadID, HeadHash: v.HeadHash, CertifiedEvents: t.certified, ChainedEvents: v.ChainedEvents,
		Checkpointed: true, FirstBrokenID: v.FirstBrokenID, Reason: v.Reason}
	if !v.Valid {
		nf := recordAuditVerifyFailure(st, now, "tail", v.FirstBrokenID, v.Reason)
		return nil, nf, fmt.Errorf("%w a chain that does not verify: %s", ErrAuditCheckpointRefused, v.Reason)
	}
	if st.Failure != nil {
		return nil, nil, auditFailureRefusal(st.Failure)
	}
	newCP := &models.AuditCheckpoint{
		ChainedEvents: t.certified,
		HeadID:        v.HeadID,
		HeadHash:      v.HeadHash,
		KeyVersion:    c.auditCkptKeyVersion,
	}
	newCP.Signature = c.signCheckpoint(newCP)
	if err := c.storage.CreateAuditCheckpoint(ctx, newCP); err != nil {
		return nil, nil, fmt.Errorf("failed to write audit checkpoint: %w", err)
	}
	c.anchorCheckpoint(ctx, newCP)
	c.advanceAuditHighWater(ctx, newCP)
	st.LastCheck.CheckpointID = newCP.ID
	return newCP, nil, nil
}

// auditFailureRefusal is the checkpoint refusal while a failure is recorded.
func auditFailureRefusal(f *auditVerifyFailure) error {
	return fmt.Errorf("%w: a verification failure was recorded at %s (%s: %s) — investigate, then run a full verification (GET /api/v1/audit/verify?full=true)",
		ErrAuditCheckpointRefused, f.DetectedAt.UTC().Format(time.RFC3339), f.Source, f.Reason)
}

// RunAuditVerificationTick is the audit-checkpoint scheduler tick (spec §6): an
// incremental checkpoint write, then one rolling segment. The caller holds the
// HA scheduler lock, so at most one replica advances the cycle.
func (c *KeyorixCore) RunAuditVerificationTick(ctx context.Context) (*AuditVerifyTickResult, error) {
	res := &AuditVerifyTickResult{}
	cp, written, cerr := c.WriteAuditCheckpointIncremental(ctx)
	res.Checkpoint, res.Written = cp, written && cp != nil
	if !c.auditIncrementalEnabled() {
		return res, cerr
	}
	// The segment runs even when the checkpoint was refused: re-walking is how a
	// recorded failure is confirmed, or cleared once the chain verifies again.
	if serr := c.advanceAuditRollingCycle(ctx, res); serr != nil {
		if cerr != nil {
			return res, fmt.Errorf("%w; rolling verification: %v", cerr, serr)
		}
		return res, fmt.Errorf("rolling audit verification: %w", serr)
	}
	return res, cerr
}

// advanceAuditRollingCycle walks one segment of the rolling full re-walk
// (spec §2.3) and saves the progress. The walk runs outside the checkpoint
// lock; only the scheduler tick changes the cycle, so the merge is safe.
func (c *KeyorixCore) advanceAuditRollingCycle(ctx context.Context, res *AuditVerifyTickResult) error {
	st, stReason, err := c.loadAuditVerifyState(ctx)
	if err != nil {
		return err
	}
	if stReason != "" {
		// Untrusted (the tick's checkpoint write normally replaced it already):
		// record the rejection, and start a cycle from that state next tick.
		return c.updateAuditVerifyState(ctx, func(*auditVerifyState) *auditVerifyFailure { return nil })
	}
	cp, err := c.storage.LatestAuditCheckpoint(ctx)
	if err != nil {
		return err
	}
	if cp == nil || cp.HeadID == 0 || !c.checkpointSignatureValid(cp) {
		return nil // nothing signed to walk up to yet
	}
	now := c.now()
	cyc := st.Cycle
	// A cycle older than two cycle durations is restarted rather than resumed:
	// whatever the persisted progress says, every row is re-walked within a
	// bounded time (the same bound after which last_full counts as stale).
	if cyc == nil || now.Sub(cyc.StartedAt) > 2*c.auditVerifyCycleDuration() {
		segs := uint(1)
		if c.auditVerifySegments > 1 {
			segs = uint(c.auditVerifySegments)
		}
		width := (cp.HeadID + segs - 1) / segs
		cyc = &auditVerifyCycle{StartedAt: now, StartedGen: st.Gen, TargetID: cp.HeadID, TargetHash: cp.HeadHash,
			Width: max(width, c.auditVerifyMinSegmentWidth())}
	} else {
		cp2 := *cyc
		cyc = &cp2
	}
	anchor, err := c.loadAuditRetentionAnchor(ctx)
	if err != nil {
		return fmt.Errorf("failed to load audit chain re-anchor: %w", err)
	}
	seg := storage.AuditChainSegment{ThroughID: min(cyc.ScannedThrough+cyc.Width, cyc.TargetID)}
	if cyc.SeedID == 0 || (anchor != nil && anchor.RowID > cyc.SeedID) {
		// Chain start (legacy prefix, genesis or the signed anchor). After a
		// sanctioned purge past the seed, nothing before the anchor exists any more.
		seg.Anchor = anchor
		cyc.SeedID, cyc.SeedHash = 0, ""
	} else {
		seg.AfterID, seg.SeedHash = cyc.SeedID, cyc.SeedHash
	}
	w, err := c.storage.VerifyAuditChainSegment(ctx, seg)
	if err != nil {
		return fmt.Errorf("failed to verify audit chain segment: %w", err)
	}
	res.SegmentWalked = true
	res.CycleTarget = cyc.TargetID

	var completed *auditFullResult
	var failReason string
	var failID *uint
	if !w.Valid {
		failReason, failID = w.Reason, w.FirstBrokenID
	} else {
		if w.HeadID != 0 {
			cyc.SeedID, cyc.SeedHash = w.HeadID, w.HeadHash
		}
		if seg.AfterID == 0 {
			cyc.UnchainedEvents = w.UnchainedEvents // only the chain-start segment sees the legacy prefix
		}
		cyc.ScannedThrough = seg.ThroughID
		res.VerifiedThrough = cyc.SeedID
		if cyc.ScannedThrough >= cyc.TargetID {
			if cyc.SeedID != cyc.TargetID || cyc.SeedHash != cyc.TargetHash {
				failReason = fmt.Sprintf("the rolling re-walk ended at audit event #%d, not on the signed checkpoint head #%d it targets (rows removed or rewritten)",
					cyc.SeedID, cyc.TargetID)
				id := cyc.TargetID
				failID = &id
			} else {
				completed = &auditFullResult{StartedAt: cyc.StartedAt, CompletedAt: now, ThroughID: cyc.TargetID,
					Source: auditFullSourceRolling, Valid: true, UnchainedEvents: cyc.UnchainedEvents}
			}
		}
	}
	return c.updateAuditVerifyState(ctx, func(st *auditVerifyState) *auditVerifyFailure {
		switch {
		case failReason != "":
			st.Cycle = nil
			st.LastFull = &auditFullResult{StartedAt: cyc.StartedAt, CompletedAt: now, ThroughID: cyc.TargetID,
				Source: auditFullSourceRolling, Valid: false, FirstBrokenID: failID, Reason: failReason}
			return recordAuditVerifyFailure(st, now, auditFullSourceRolling, failID, failReason)
		case st.Rejected != nil && st.Rejected.Gen > cyc.StartedGen:
			// The state was rejected and restarted while this segment walked:
			// drop the progress; the next tick starts a cycle from the new state.
		case completed != nil:
			st.Cycle = nil
			st.LastFull = completed
			// Only a failure recorded before this cycle started, at a row it
			// covered, is cleared; a refusal (no row) needs a full job.
			clearAuditVerifyMarkers(st, cyc.StartedGen, cyc.TargetID, true)
			res.CycleCompleted = true
		default:
			st.Cycle = cyc
		}
		return nil
	})
}

// AuditCheckpointFirstTickDelay is how long server start defers the first
// checkpoint tick (spec §6): until the latest authenticated checkpoint is one
// interval old. created_at is not signed, so the delay is clamped to
// [0, interval]: a forged timestamp can postpone the first tick by at most one
// interval.
func (c *KeyorixCore) AuditCheckpointFirstTickDelay(ctx context.Context, interval time.Duration) time.Duration {
	if !c.AuditCheckpointsAvailable() || interval <= 0 {
		return 0
	}
	cp, err := c.storage.LatestAuditCheckpoint(ctx)
	if err != nil || cp == nil || !c.checkpointSignatureValid(cp) {
		return 0
	}
	return min(max(interval-c.now().Sub(cp.CreatedAt), 0), interval)
}

// StartAuditFullVerification starts the ?full=true background job (spec §5)
// and returns its id. When a job is already running (in this process, or on
// another replica per the advisory lock) it returns that job's id with
// started=false.
func (c *KeyorixCore) StartAuditFullVerification(ctx context.Context) (jobID string, started bool, err error) {
	if !c.AuditCheckpointsAvailable() {
		return "", false, ErrAuditVerifyJobsUnavailable
	}
	if !c.auditVerifyJobMu.TryLock() {
		id, _ := c.auditVerifyJobID.Load().(string)
		return id, false, nil
	}
	// Probe the cross-replica lock: held means another replica is running one.
	free, err := c.storage.WithSchedulerLock(ctx, AuditVerifyJobLockKey, func() error { return nil })
	if err != nil {
		c.auditVerifyJobMu.Unlock()
		return "", false, err
	}
	if !free {
		c.auditVerifyJobMu.Unlock()
		st, _, lerr := c.loadAuditVerifyState(ctx)
		if lerr != nil {
			return "", false, lerr
		}
		if st.Job != nil && st.Job.State == AuditVerifyJobRunning {
			return st.Job.ID, false, nil
		}
		return "", false, errors.New("another replica is running a full audit verification")
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		c.auditVerifyJobMu.Unlock()
		return "", false, err
	}
	id := hex.EncodeToString(raw)
	startedAt := c.now()
	var startedGen uint64
	if err := c.updateAuditVerifyState(ctx, func(st *auditVerifyState) *auditVerifyFailure {
		startedGen = st.Gen
		st.Job = &auditVerifyJob{ID: id, State: AuditVerifyJobRunning, StartedAt: startedAt, StartedGen: startedGen}
		return nil
	}); err != nil {
		c.auditVerifyJobMu.Unlock()
		return "", false, err
	}
	c.auditVerifyJobID.Store(id)
	// The job outlives the request: keep the request context's values, drop its
	// cancellation (runAuditFullVerification bounds it with its own timeout).
	go c.runAuditFullVerification(context.WithoutCancel(ctx), id, startedAt, startedGen)
	return id, true, nil
}

// runAuditFullVerification is the job body: the unchanged full walk, run under
// the cross-replica job lock, then recorded in the signed state. startedGen is
// the generation of the save that started it: only failures and rejections
// recorded by then are cleared by a passing walk.
func (c *KeyorixCore) runAuditFullVerification(parent context.Context, id string, startedAt time.Time, startedGen uint64) {
	defer func() {
		c.auditVerifyJobID.Store("")
		c.auditVerifyJobMu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(parent, auditVerifyJobTimeout)
	defer cancel()
	var rep *AuditVerifyReport
	var v *storage.AuditChainVerification
	ran, err := c.storage.WithSchedulerLock(ctx, AuditVerifyJobLockKey, func() error {
		var verr error
		v, verr = c.VerifyAuditChain(ctx)
		return verr
	})
	if err == nil && !ran {
		err = errors.New("another replica started a full audit verification at the same time")
	}
	if err == nil {
		rep = fullAuditVerifyReport(v)
	}
	finished := c.now()
	uerr := c.updateAuditVerifyState(ctx, func(st *auditVerifyState) *auditVerifyFailure {
		job := &auditVerifyJob{ID: id, StartedAt: startedAt, StartedGen: startedGen, FinishedAt: &finished}
		st.Job = job
		if err != nil {
			job.State, job.Error = AuditVerifyJobFailed, clientSafeJobError(err)
			return nil
		}
		job.State, job.Result = AuditVerifyJobSucceeded, rep
		st.LastFull = &auditFullResult{StartedAt: startedAt, CompletedAt: finished, ThroughID: v.HeadID,
			Source: auditFullSourceJob, Valid: v.Valid, FirstBrokenID: v.FirstBrokenID, Reason: v.Reason,
			UnchainedEvents: v.UnchainedEvents}
		if v.Valid {
			clearAuditVerifyMarkers(st, startedGen, v.HeadID, false)
			return nil
		}
		return recordAuditVerifyFailure(st, finished, auditFullSourceJob, v.FirstBrokenID, v.Reason)
	})
	if err != nil {
		log.Printf("audit full verification job %s failed: %v", id, err)
	}
	if uerr != nil {
		log.Printf("audit full verification job %s: failed to record the result: %v", id, uerr)
	}
}

// clientSafeJobError keeps raw storage errors out of the job status body.
func clientSafeJobError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "the full verification exceeded its time limit"
	}
	return "the full verification could not complete (see the server log)"
}

// AuditFullVerificationJob reports a ?full=true job's status. An unknown or
// superseded id is ErrAuditVerifyJobNotFound. A job the state says is running
// but that no process holds the lock for (the process died) is "interrupted".
func (c *KeyorixCore) AuditFullVerificationJob(ctx context.Context, id string) (*AuditVerifyJobStatus, error) {
	st, _, err := c.loadAuditVerifyState(ctx)
	if err != nil {
		return nil, err
	}
	j := st.Job
	if j == nil || id == "" || j.ID != id {
		return nil, ErrAuditVerifyJobNotFound
	}
	out := &AuditVerifyJobStatus{JobID: j.ID, State: j.State, StartedAt: j.StartedAt, FinishedAt: j.FinishedAt, Error: j.Error, Result: j.Result}
	if j.State == AuditVerifyJobRunning {
		if local, _ := c.auditVerifyJobID.Load().(string); local != id {
			free, perr := c.storage.WithSchedulerLock(ctx, AuditVerifyJobLockKey, func() error { return nil })
			// On SQLite the lock always "runs" (single process): not ours → dead.
			if perr == nil && free {
				out.State = AuditVerifyJobInterrupted
			}
		}
	}
	return out, nil
}
