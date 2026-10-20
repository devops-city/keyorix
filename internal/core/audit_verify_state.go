// audit_verify_state.go — the signed, persisted state of incremental audit-chain
// verification (docs/specs/audit-incremental-verification.md §3).
//
// One system_metadata row holds the rolling full re-walk cycle, the last
// completed full verification, the last scheduler tail check, a sticky failure
// and the latest ?full=true job. It is HMAC-signed with the checkpoint signing
// key (KEK-derived, never in the database) under its own domain-separation
// prefix, so a DB-level actor cannot forge "verified" claims, skip segments or
// clear a failure by editing it. A row that is malformed or fails its signature
// is ignored: that can only remove claims (the API then reports not_proven),
// never add them.
//
// A signature alone does not stop an actor with DB write access from putting
// back an OLDER signed row (a replay or rollback) to resume a rolling cycle past
// a row tampered with since, or to erase a recorded failure. Each saved row
// therefore carries a generation (strictly increasing: every save happens under
// WithAuditCheckpointLock) and is bound to the latest checkpoint id and the
// signed high-water count at save time. A row older than the signed checkpoint
// trail, or than a generation this process already saw, is not trusted either.
// A writer that finds an untrusted row does not overwrite it silently: it starts
// over, records the rejection in the new signed row (reported as not_proven until
// a full verification that started after it completes) and appends a
// system.audit_verification_state_rejected event.
package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// auditVerifyStateKey is the system_metadata key of the signed state row.
const auditVerifyStateKey = "audit_verification_state" // #nosec G101 -- metadata key name, not a credential

// auditVerifyStateSep separates the stored fields (\x1f, as the high-water mark
// and the retention anchor: PostgreSQL text rejects NUL).
const auditVerifyStateSep = "\x1f"

// auditVerifyStateDomain prefixes the signed bytes so this HMAC can never verify
// as a checkpoint, high-water or retention-anchor signature (all share the key).
const auditVerifyStateDomain = "auditverify-state-v1\x00"

// Full-verification sources recorded in auditFullResult.Source.
const (
	auditFullSourceRolling    = "rolling"
	auditFullSourceJob        = "job"
	auditFullSourceCheckpoint = "checkpoint-full"
)

// auditVerifyCycle is a rolling full re-walk in progress.
type auditVerifyCycle struct {
	StartedAt time.Time `json:"started_at"`
	// StartedGen is the state generation the cycle was started from: a failure
	// or rejection recorded at or before it existed when the walk began.
	StartedGen uint64 `json:"started_gen"`
	TargetID   uint   `json:"target_id"`
	TargetHash string `json:"target_hash"`
	// SeedID/SeedHash: the last row verified so far (0 = chain start next).
	SeedID   uint   `json:"seed_id"`
	SeedHash string `json:"seed_hash"`
	// ScannedThrough is the id bound the previous segments covered.
	ScannedThrough uint `json:"scanned_through"`
	Width          uint `json:"width"`
	// UnchainedEvents is the legacy prefix the chain-start segment counted.
	UnchainedEvents int64 `json:"unchained_events"`
}

// auditFullResult is a completed full verification (rolling cycle, full job, or
// the checkpoint write's full-walk fallback).
type auditFullResult struct {
	StartedAt       time.Time `json:"started_at"`
	CompletedAt     time.Time `json:"completed_at"`
	ThroughID       uint      `json:"through_id"`
	Source          string    `json:"source"`
	Valid           bool      `json:"valid"`
	FirstBrokenID   *uint     `json:"first_broken_id,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	UnchainedEvents int64     `json:"unchained_events"`
}

// auditTailCheck is the last scheduler tail check.
type auditTailCheck struct {
	At              time.Time `json:"at"`
	Valid           bool      `json:"valid"`
	CheckpointID    uint      `json:"checkpoint_id"`
	FromID          uint      `json:"from_id"`
	ThroughID       uint      `json:"through_id"`
	HeadHash        string    `json:"head_hash"`
	CertifiedEvents int64     `json:"certified_events"`
	ChainedEvents   int64     `json:"chained_events"`
	Checkpointed    bool      `json:"checkpointed"`
	FirstBrokenID   *uint     `json:"first_broken_id,omitempty"`
	Reason          string    `json:"reason,omitempty"`
}

// auditVerifyFailure is a detected break; sticky until a passing full
// verification clears it.
type auditVerifyFailure struct {
	DetectedAt time.Time `json:"detected_at"`
	// Gen is the generation of the save that recorded it. Only a full
	// verification that started after it may clear it (auditFailureCoveredBy).
	Gen           uint64 `json:"gen"`
	Source        string `json:"source"`
	FirstBrokenID *uint  `json:"first_broken_id,omitempty"`
	Reason        string `json:"reason"`
}

// auditVerifyJob is the latest ?full=true background job.
type auditVerifyJob struct {
	ID         string             `json:"id"`
	State      string             `json:"state"` // running | succeeded | failed
	StartedAt  time.Time          `json:"started_at"`
	StartedGen uint64             `json:"started_gen"`
	FinishedAt *time.Time         `json:"finished_at,omitempty"`
	Error      string             `json:"error,omitempty"`
	Result     *AuditVerifyReport `json:"result,omitempty"`
}

// auditVerifyBinding is the signed checkpoint trail a state row was saved
// against. Both only grow: every checkpoint write saves the state in the same
// WithAuditCheckpointLock section, after the checkpoint and the high-water mark.
type auditVerifyBinding struct {
	CheckpointID uint  `json:"checkpoint_id"`
	HighWater    int64 `json:"high_water"`
}

// auditVerifyRejection records that a writer found the persisted state
// untrusted and started over. It keeps the status not_proven until a full
// verification that started after it (Gen) completes valid.
type auditVerifyRejection struct {
	At     time.Time `json:"at"`
	Gen    uint64    `json:"gen"`
	Reason string    `json:"reason"`
}

// auditVerifyState is the whole signed row.
type auditVerifyState struct {
	V int `json:"v"`
	// Gen is strictly increasing across saves; Bind is the trail at save time.
	Gen       uint64                `json:"gen"`
	Bind      auditVerifyBinding    `json:"bind"`
	Rejected  *auditVerifyRejection `json:"rejected,omitempty"`
	Cycle     *auditVerifyCycle     `json:"cycle,omitempty"`
	LastFull  *auditFullResult      `json:"last_full,omitempty"`
	LastCheck *auditTailCheck       `json:"last_check,omitempty"`
	Failure   *auditVerifyFailure   `json:"failure,omitempty"`
	Job       *auditVerifyJob       `json:"job,omitempty"`
}

func (c *KeyorixCore) signAuditVerifyState(payload []byte) string {
	mac := hmac.New(sha256.New, c.auditCkptKey)
	mac.Write([]byte(auditVerifyStateDomain))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// currentAuditVerifyBinding reads the signed checkpoint trail a state row must
// not be older than: the latest checkpoint row's id and the authenticated
// high-water count (0 when the mark is absent or does not verify, which only
// loosens the check; the tail check reports those).
func (c *KeyorixCore) currentAuditVerifyBinding(ctx context.Context) (auditVerifyBinding, error) {
	var b auditVerifyBinding
	cp, err := c.storage.LatestAuditCheckpoint(ctx)
	if err != nil {
		return b, err
	}
	if cp != nil {
		b.CheckpointID = cp.ID
	}
	hw, err := c.authenticatedHighWaterBase(ctx)
	if err != nil {
		return b, err
	}
	if hw != nil {
		b.HighWater = hw.ChainedEvents
	}
	return b, nil
}

// bumpAuditVerifyGen raises the in-process generation floor to gen.
func (c *KeyorixCore) bumpAuditVerifyGen(gen uint64) {
	for {
		seen := c.auditVerifyGenSeen.Load()
		if gen <= seen || c.auditVerifyGenSeen.CompareAndSwap(seen, gen) {
			return
		}
	}
}

// loadAuditVerifyState reads and authenticates the state row. A missing row is
// an empty state with no reason (a fresh or upgraded deployment), unless this
// process already read or wrote one. A row that exists but cannot be trusted
// returns a non-empty reason and a state that claims nothing: empty when it is
// malformed or fails its signature; when it is authentic but older than the
// signed checkpoint trail or than a generation this process saw (a replay or
// rollback), only its generation, sticky failure and job are kept (a failure
// only ever makes the verdict stricter). Only a storage failure is an error.
func (c *KeyorixCore) loadAuditVerifyState(ctx context.Context) (st *auditVerifyState, reason string, err error) {
	st, reason, err = c.loadAuditVerifyStateUnobserved(ctx)
	switch {
	case err != nil:
	case reason != "":
		observeAuditVerifyStateUntrusted(st)
	case c.AuditCheckpointsAvailable():
		c.observeAuditVerifyState(st)
	}
	return st, reason, err
}

// loadAuditVerifyStateUnobserved is loadAuditVerifyState without publishing the
// result to the audit-verify metrics.
func (c *KeyorixCore) loadAuditVerifyStateUnobserved(ctx context.Context) (st *auditVerifyState, reason string, err error) {
	if !c.AuditCheckpointsAvailable() {
		return &auditVerifyState{V: 1}, "", nil
	}
	// The trail is read BEFORE the row: a writer saves the row after the
	// checkpoint it binds to, so a concurrent write can only make the row newer
	// than what was read here, never look stale.
	cur, err := c.currentAuditVerifyBinding(ctx)
	if err != nil {
		return nil, "", err
	}
	val, ok, err := c.storage.GetSystemMetadata(ctx, auditVerifyStateKey)
	if err != nil {
		return nil, "", err
	}
	seen := c.auditVerifyGenSeen.Load()
	if !ok {
		if seen > 0 {
			return &auditVerifyState{V: 1}, fmt.Sprintf("the persisted verification state is missing although this server already read generation %d (deleted or rolled back) and was ignored", seen), nil
		}
		return &auditVerifyState{V: 1}, "", nil
	}
	parts := strings.Split(val, auditVerifyStateSep)
	if len(parts) != 3 || parts[0] != "avs-v1" {
		return &auditVerifyState{V: 1}, "the persisted verification state is malformed and was ignored", nil
	}
	payload, derr := base64.RawURLEncoding.DecodeString(parts[1])
	if derr != nil {
		return &auditVerifyState{V: 1}, "the persisted verification state is malformed and was ignored", nil
	}
	if !hmac.Equal([]byte(c.signAuditVerifyState(payload)), []byte(parts[2])) {
		return &auditVerifyState{V: 1}, "the persisted verification state fails its signature under the current key (tampered, or written before a KEK-provider migration) and was ignored", nil
	}
	var s auditVerifyState
	if jerr := json.Unmarshal(payload, &s); jerr != nil || s.V != 1 {
		return &auditVerifyState{V: 1}, "the persisted verification state is malformed and was ignored", nil
	}
	untrusted := func(why string) (*auditVerifyState, string, error) {
		return &auditVerifyState{V: 1, Gen: s.Gen, Failure: s.Failure, Job: s.Job},
			"the persisted verification state " + why + " (a replayed or rolled-back row) and was ignored", nil
	}
	if s.Gen < seen {
		return untrusted(fmt.Sprintf("is generation %d, older than generation %d this server already read", s.Gen, seen))
	}
	if s.Bind.CheckpointID < cur.CheckpointID || s.Bind.HighWater < cur.HighWater {
		return untrusted(fmt.Sprintf("was saved at checkpoint #%d and high-water %d, older than the signed checkpoint #%d and high-water %d",
			s.Bind.CheckpointID, s.Bind.HighWater, cur.CheckpointID, cur.HighWater))
	}
	c.bumpAuditVerifyGen(s.Gen)
	return &s, "", nil
}

// loadAuditVerifyStateForWrite is loadAuditVerifyState for a writer holding
// WithAuditCheckpointLock. An untrusted row is not silently replaced: the
// returned state records the rejection (non-nil rejected, which the caller
// reports with an audit event after saving). st.Gen is already the generation
// the caller's save carries, so a failure or job recorded now is stamped with it.
func (c *KeyorixCore) loadAuditVerifyStateForWrite(ctx context.Context) (st *auditVerifyState, rejected *auditVerifyRejection, err error) {
	st, reason, err := c.loadAuditVerifyState(ctx)
	if err != nil {
		return nil, nil, err
	}
	st.Gen = max(st.Gen, c.auditVerifyGenSeen.Load()) + 1
	if reason != "" {
		st.Rejected = &auditVerifyRejection{At: c.now(), Gen: st.Gen, Reason: reason}
		rejected = st.Rejected
	}
	return st, rejected, nil
}

// saveAuditVerifyState binds, signs and stores st (no-op without a signing
// key). The caller holds WithAuditCheckpointLock and loaded st with
// loadAuditVerifyStateForWrite.
func (c *KeyorixCore) saveAuditVerifyState(ctx context.Context, st *auditVerifyState) error {
	if !c.AuditCheckpointsAvailable() {
		return nil
	}
	bind, err := c.currentAuditVerifyBinding(ctx)
	if err != nil {
		return err
	}
	st.V = 1
	st.Bind = bind
	payload, err := json.Marshal(st)
	if err != nil {
		return err
	}
	val := strings.Join([]string{"avs-v1", base64.RawURLEncoding.EncodeToString(payload), c.signAuditVerifyState(payload)}, auditVerifyStateSep)
	if err := c.storage.SetSystemMetadata(ctx, auditVerifyStateKey, val); err != nil {
		return err
	}
	c.bumpAuditVerifyGen(st.Gen)
	c.observeAuditVerifyState(st)
	return nil
}

// updateAuditVerifyState is the read-modify-write every state writer uses. It
// holds WithAuditCheckpointLock (cross-replica on PostgreSQL) only for the
// merge, never for a walk. fn returns whether a failure was newly recorded,
// in which case a system.audit_chain_verification_failed event is appended
// after the save (the in-chain record that survives a state rollback).
func (c *KeyorixCore) updateAuditVerifyState(ctx context.Context, fn func(st *auditVerifyState) (newFailure *auditVerifyFailure)) error {
	var failed *auditVerifyFailure
	var rejected *auditVerifyRejection
	err := c.storage.WithAuditCheckpointLock(ctx, func(ctx context.Context) error {
		st, rej, err := c.loadAuditVerifyStateForWrite(ctx)
		if err != nil {
			return err
		}
		rejected = rej
		failed = fn(st)
		return c.saveAuditVerifyState(ctx, st)
	})
	if err != nil {
		return err
	}
	c.reportAuditVerifyStateEvents(ctx, rejected, failed)
	return nil
}

// reportAuditVerifyStateEvents appends the in-chain records of a rejected state
// row and of a newly recorded failure (both after the save).
func (c *KeyorixCore) reportAuditVerifyStateEvents(ctx context.Context, rejected *auditVerifyRejection, failed *auditVerifyFailure) {
	if rejected != nil {
		c.writeAuditEventFailedFull(ctx, "system.audit_verification_state_rejected", nil, nil, nil, "",
			"audit verification state rejected and restarted: "+rejected.Reason)
	}
	if failed != nil {
		c.writeAuditEventFailedFull(ctx, "system.audit_chain_verification_failed", nil, nil, nil, "",
			"audit chain verification failed ("+failed.Source+"): "+failed.Reason)
	}
}

// recordAuditVerifyFailure sets the sticky failure unless one is already
// recorded, returning the failure only when it is new. st comes from
// loadAuditVerifyStateForWrite, so st.Gen is the recording save's generation.
func recordAuditVerifyFailure(st *auditVerifyState, now time.Time, source string, firstBroken *uint, reason string) *auditVerifyFailure {
	if st.Failure != nil {
		return nil
	}
	st.Failure = &auditVerifyFailure{DetectedAt: now, Gen: st.Gen, Source: source, FirstBrokenID: firstBroken, Reason: reason}
	return st.Failure
}

// clearAuditVerifyMarkers applies a passing full verification that started
// after state generation startedGen and verified every row through throughID.
// A failure is cleared only when it was recorded before the walk began and
// names a row the walk covered (a failure without a row id — a refusal — needs
// a full job: requireRowForFailure); a rejection only when it predates the walk.
func clearAuditVerifyMarkers(st *auditVerifyState, startedGen uint64, throughID uint, requireRowForFailure bool) {
	if f := st.Failure; f != nil && f.Gen <= startedGen {
		switch {
		case f.FirstBrokenID != nil && *f.FirstBrokenID <= throughID:
			st.Failure = nil
		case f.FirstBrokenID == nil && !requireRowForFailure:
			st.Failure = nil
		}
	}
	if r := st.Rejected; r != nil && r.Gen <= startedGen {
		st.Rejected = nil
	}
}
