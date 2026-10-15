// secret_read_denial.go -- audit of REFUSED native secret-value reads (#3273,
// ADR-112 Amendment 4: "denied reads stay audited, so probing still leaves a
// trace").
//
// Every refused value read (REST GET /secrets/{id}?include_value=true and
// /secrets/value, POST /projects/{id}/secrets/render, POST /secrets/{id}/copy,
// the environment copy and clone, gRPC GetSecretValue) writes a secret.read
// audit row with Success=false. Its reason class is one of the
// SecretReadDenialReason constants below. insecure_audit_skip_reads never
// skips it: that setting only drops Success=true value reads
// (skipsSuccessfulReadAudit).
//
// How a denial reaches the recorder. A transport that serves a value read puts
// a SecretReadDenialNote on the request context (WithSecretReadDenialNote).
// Whatever refuses the read writes the reason on the note: the route gates
// (server/middleware), the gRPC authorization helper, and the value-read entry
// points in this package (noteValueReadErr). When the request ends refused, the
// transport calls RecordNotedSecretReadDenial once. Render and copy run their
// whole read inside core, so they record directly (recordSecretReadDenial) and
// mark the note as recorded so the transport does not write a second row.
//
// No existence oracle. A caller who may not read a secret gets the same
// response for "does not exist" and "exists, forbidden" (INV-HTTP-08,
// INV-GRPCSVC-02, TMPL-002). The audit row keeps that property for every
// surface a CALLER can see: a forbidden or not_found row carries no
// SecretNodeID and no ProjectID (so neither the caller's own dashboard activity
// nor a project-filtered audit view can tell the two apart), and its
// description names only what the caller supplied. The internal truth (reason,
// resolved secret and project) is in the description's reason= token and in
// Diff, which only audit.read holders see. Both reasons take the same code
// path through the aggregator below, so the write cost does not differ either.
//
// Best-effort, never fail-open. A denial is a denial whether or not its row is
// written: the recorder returns nothing, a write failure is logged (SECURITY:)
// and the caller's refusal stands. It runs only on the denial path; a
// successful read never touches the aggregator or storage here.
//
// Flood protection (the aggregator). Rows are aggregated per (principal, reason
// class, path, target), where path is the value-read route (rest.get_secret,
// grpc.get_secret_value, ...) and target is the secret ID the caller asked
// for, or the reference / project / environment for a route that names no
// secret ID:
//
//   - The first denial of a key is written immediately.
//   - Further denials of that key within secretReadDenialWindow (60s) are
//     counted, not written.
//   - When the window closes (a timer per key), one summary row is written
//     carrying the count, if there was anything to count. The next denial after
//     that opens a new window and is again written immediately.
//
// So one key costs at most two rows per window however many denials arrive.
// Two caps bound a flood that varies the key instead: a principal holds at
// most secretReadDenialPrincipalKeys live keys (further keys fold into that
// principal's per-reason overflow key, target "*"), and the aggregator holds at
// most secretReadDenialMaxKeys keys overall (beyond that, new keys fold into
// the same per-principal overflow key). Every caller here is authenticated, so
// principals are bounded by the identities that exist. The count is kept in
// memory per process: a restart loses the open windows' counts, never a first
// row.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SecretReadDenialReason is the class of a refused value read, recorded as the
// reason= token of the audit row's description and as Diff.reason.
type SecretReadDenialReason string

// Reason classes. The set is closed; ClassifySecretReadDenial maps every error a
// value read can return onto one of them.
const (
	// SecretReadDeniedForbidden: the caller lacks read permission on the secret.
	SecretReadDeniedForbidden SecretReadDenialReason = "forbidden"
	// SecretReadDeniedNotFound: no such secret (or reference, project,
	// environment). The response is the same as for forbidden; only the audit
	// row records which one it was.
	SecretReadDeniedNotFound SecretReadDenialReason = "not_found"
	// SecretReadDeniedOutsideSchedule: outside the secret's access schedule.
	SecretReadDeniedOutsideSchedule SecretReadDenialReason = "outside_schedule"
	// SecretReadDeniedExpired: the secret has expired (or the clock looked
	// stepped back past its expiration, which answers the same way).
	SecretReadDeniedExpired SecretReadDenialReason = "expired"
	// SecretReadDeniedSuspended: the secret is suspended.
	SecretReadDeniedSuspended SecretReadDenialReason = "suspended"
	// SecretReadDeniedMaxReadsExhausted: the secret's max_reads budget is spent.
	SecretReadDeniedMaxReadsExhausted SecretReadDenialReason = "max_reads_exhausted" // #nosec G101 -- audit reason/path label, not a credential
	// SecretReadDeniedClassificationGate: a restricted secret's classification
	// gate (permission, approval or MFA step-up) refused the read.
	SecretReadDeniedClassificationGate SecretReadDenialReason = "classification_gate"
	// SecretReadDeniedMFARequired: the project's MFA policy (ADR-037) refused an
	// interactive session without a second factor.
	SecretReadDeniedMFARequired SecretReadDenialReason = "mfa_required"
	// SecretReadDeniedInternalError: the read failed for a reason that is not a
	// refusal (storage or decryption failure). Recorded with outcome=failed.
	SecretReadDeniedInternalError SecretReadDenialReason = "internal_error"
)

// SecretReadDenialReasons lists every reason class, for tests that must cover
// the whole family.
func SecretReadDenialReasons() []SecretReadDenialReason {
	return []SecretReadDenialReason{
		SecretReadDeniedForbidden, SecretReadDeniedNotFound, SecretReadDeniedOutsideSchedule,
		SecretReadDeniedExpired, SecretReadDeniedSuspended, SecretReadDeniedMaxReadsExhausted,
		SecretReadDeniedClassificationGate, SecretReadDeniedMFARequired, SecretReadDeniedInternalError,
	}
}

// IsBeforeAuthorization reports whether the reason can be returned to a caller
// who has not been shown to have read access. Such a row must not identify the
// secret on any caller-visible column (see the file comment).
func (r SecretReadDenialReason) IsBeforeAuthorization() bool {
	return r == SecretReadDeniedForbidden || r == SecretReadDeniedNotFound || r == SecretReadDeniedInternalError
}

// outcome is "failed" for a read that broke, "denied" for one that was refused.
func (r SecretReadDenialReason) outcome() string {
	if r == SecretReadDeniedInternalError {
		return "failed"
	}
	return "denied"
}

// Value-read paths, recorded as Diff.path and in the description.
const (
	SecretReadPathRESTGet         = "rest.get_secret"
	SecretReadPathRESTByRef       = "rest.get_secret_value_by_ref"
	SecretReadPathRESTRender      = "rest.render"
	SecretReadPathRESTCopy        = "rest.copy"
	SecretReadPathRESTCopyEnv     = "rest.copy_environment"  // #nosec G101 -- audit reason/path label, not a credential
	SecretReadPathRESTCloneEnv    = "rest.clone_environment" // #nosec G101 -- audit reason/path label, not a credential
	SecretReadPathGRPCGetValue    = "grpc.get_secret_value"  // #nosec G101 -- audit reason/path label, not a credential
	secretReadPathRender          = "render"
	secretReadPathCopy            = "copy"
	secretReadDenialOverflowShard = "*"
)

// ClassifySecretReadDenial maps an error returned by a value read onto its
// reason class. The secret-state refusals (ERRMAP-1) match by sentinel; the
// rest by the fixed texts core's permission and lookup errors carry (the same
// texts every transport already branches on).
func ClassifySecretReadDenial(err error) SecretReadDenialReason {
	switch {
	case errors.Is(err, ErrAccessOutsideSchedule):
		return SecretReadDeniedOutsideSchedule
	case errors.Is(err, ErrSecretExpired):
		return SecretReadDeniedExpired
	case errors.Is(err, ErrSecretSuspended):
		return SecretReadDeniedSuspended
	case errors.Is(err, ErrSecretMaxReadsExhausted):
		return SecretReadDeniedMaxReadsExhausted
	case errors.Is(err, ErrSecretRefNotFound):
		return SecretReadDeniedNotFound
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "is restricted:"):
		return SecretReadDeniedClassificationGate
	case strings.Contains(msg, "permission denied"), strings.Contains(msg, "insufficient permissions"),
		strings.Contains(msg, "access denied"), strings.Contains(msg, "not authorized"):
		return SecretReadDeniedForbidden
	case strings.Contains(msg, "not found"):
		return SecretReadDeniedNotFound
	default:
		return SecretReadDeniedInternalError
	}
}

// SecretReadDenialNote collects what refused one value-read request. Safe for
// concurrent use; the zero value is not used (WithSecretReadDenialNote makes one).
type SecretReadDenialNote struct {
	mu        sync.Mutex
	path      string
	reason    SecretReadDenialReason
	subjectID uint
	projectID uint
	recorded  bool
}

type secretReadDenialNoteKey struct{}

// WithSecretReadDenialNote returns ctx carrying a fresh note for one value-read
// request on path. The only cost on the success path is this one allocation.
func WithSecretReadDenialNote(ctx context.Context, path string) (context.Context, *SecretReadDenialNote) {
	n := &SecretReadDenialNote{path: path}
	return context.WithValue(ctx, secretReadDenialNoteKey{}, n), n
}

// Reason is the reason class noted so far, "" when none.
func (n *SecretReadDenialNote) Reason() SecretReadDenialReason {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.reason
}

func secretReadDenialNoteFrom(ctx context.Context) *SecretReadDenialNote {
	n, _ := ctx.Value(secretReadDenialNoteKey{}).(*SecretReadDenialNote)
	return n
}

// NoteSecretReadDenial records reason on ctx's note, if any (the last refusal
// wins). A no-op without a note, so a gate shared with non-value routes may call
// it unconditionally.
func NoteSecretReadDenial(ctx context.Context, reason SecretReadDenialReason) {
	if n := secretReadDenialNoteFrom(ctx); n != nil {
		n.mu.Lock()
		n.reason = reason
		n.mu.Unlock()
	}
}

// NoteSecretReadSubject records which secret the request resolved to (internal
// truth for the audit row's Diff). A no-op without a note or with a nil secret.
func NoteSecretReadSubject(ctx context.Context, secret *models.SecretNode) {
	if secret == nil {
		return
	}
	if n := secretReadDenialNoteFrom(ctx); n != nil {
		n.mu.Lock()
		n.subjectID, n.projectID = secret.ID, secret.ProjectID
		n.mu.Unlock()
	}
}

// noteValueReadErr is the deferred hook on core's value-read entry points: on
// a non-nil error it notes the reason class (and the secret ID, when the entry
// point has one) on ctx's note. Nothing on success.
func noteValueReadErr(ctx context.Context, err error, secretID uint) {
	if err == nil {
		return
	}
	n := secretReadDenialNoteFrom(ctx)
	if n == nil {
		return
	}
	n.mu.Lock()
	n.reason = ClassifySecretReadDenial(err)
	if n.subjectID == 0 {
		n.subjectID = secretID
	}
	n.mu.Unlock()
}

// SecretReadDenialActor is who was refused, as the transport authenticated them.
type SecretReadDenialActor struct {
	UserID   uint // human principal; 0 for a machine identity
	Username string
	IP       string
	UA       string
}

// SecretReadDenialTarget is what the caller asked for: a secret ID, or for a
// route without one a reference / project / environment string.
type SecretReadDenialTarget struct {
	SecretID uint
	Ref      string
}

// secretReadDenialTargetMaxLen caps a caller-supplied reference in the
// aggregation key and on the row, so a long ref cannot inflate the
// aggregator's memory (secretReadDenialMaxKeys keys at most this long).
const secretReadDenialTargetMaxLen = 256

func (t SecretReadDenialTarget) key() string {
	if t.SecretID != 0 {
		return "secret:" + strconv.FormatUint(uint64(t.SecretID), 10)
	}
	return truncateAuditField(t.Ref, secretReadDenialTargetMaxLen)
}

func (t SecretReadDenialTarget) describe() string {
	if t.SecretID != 0 {
		return fmt.Sprintf("secret id %d", t.SecretID)
	}
	return fmt.Sprintf("%q", t.key())
}

// RecordNotedSecretReadDenial writes the audit row for a refused value read the
// transport served with note on its context. fallback is the reason when no
// layer noted one (the transport derives it from its own response: 403 is
// forbidden, 404 not_found). No-op when core already recorded this request
// (render, copy) or when neither a noted reason nor a fallback exists.
func (c *KeyorixCore) RecordNotedSecretReadDenial(ctx context.Context, note *SecretReadDenialNote, actor SecretReadDenialActor, target SecretReadDenialTarget, fallback SecretReadDenialReason) {
	if c == nil || note == nil {
		return
	}
	note.mu.Lock()
	if note.recorded {
		note.mu.Unlock()
		return
	}
	reason := note.reason
	if reason == "" {
		reason = fallback
	}
	if reason == "" {
		note.mu.Unlock()
		return
	}
	note.recorded = true
	d := secretReadDenial{
		path: note.path, reason: reason, actor: actor, target: target,
		subjectID: note.subjectID, projectID: note.projectID,
	}
	note.mu.Unlock()
	c.recordSecretReadDenial(ctx, d)
}

// secretReadDenial is one refused read, as handed to the aggregator.
type secretReadDenial struct {
	path      string
	reason    SecretReadDenialReason
	actor     SecretReadDenialActor
	target    SecretReadDenialTarget
	subjectID uint // the secret the request resolved to, 0 if none
	projectID uint // that secret's project (or the route's project), 0 if none
	// The principal as the request context tagged it; filled by
	// recordSecretReadDenial so a summary written later off a timer keeps it.
	actorType      string
	machineID      uint
	impersonatorID uint
}

// recordSecretReadDenialInCore is recordSecretReadDenial for a read core runs
// end to end (render, copy): it marks ctx's note recorded, so the transport
// does not write a second row for the same request.
func (c *KeyorixCore) recordSecretReadDenialInCore(ctx context.Context, d secretReadDenial) {
	if n := secretReadDenialNoteFrom(ctx); n != nil {
		n.mu.Lock()
		n.recorded = true
		if n.path != "" {
			d.path = n.path
		}
		n.mu.Unlock()
	}
	c.recordSecretReadDenial(ctx, d)
}

// recordSecretReadDenial hands one denial to the aggregator and writes whatever
// row it says is due. Never returns an error: the refusal stands either way.
func (c *KeyorixCore) recordSecretReadDenial(ctx context.Context, d secretReadDenial) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SECURITY: recording a refused secret read panicked (reason=%s path=%s, the read stays refused): %v", d.reason, d.path, r)
		}
	}()
	d.actorType = actorTypeFromContext(ctx)
	if id, ok := machineActorFromContext(ctx); ok {
		d.machineID = id
	}
	if id, ok := impersonatorFromContext(ctx); ok {
		d.impersonatorID = id
	}
	first, summary := c.secretReadDenials().admit(d, time.Now())
	if summary != nil {
		c.writeSecretReadDenialRow(*summary)
	}
	if first != nil {
		c.writeSecretReadDenialRow(*first)
	}
}

// denialRow is one row the aggregator decided to write: the first denial of a
// window (count 1, not aggregated) or a window's summary.
type denialRow struct {
	denial      secretReadDenial
	count       int
	aggregated  bool
	windowStart time.Time
	windowEnd   time.Time
}

// secretReadDenialDiff is the row's structured Diff (audit.read only).
type secretReadDenialDiff struct {
	Outcome           string `json:"outcome"`
	Reason            string `json:"reason"`
	Path              string `json:"path"`
	Target            string `json:"target"`
	RequestedSecretID uint   `json:"requested_secret_id,omitzero"`
	SecretID          uint   `json:"secret_id,omitzero"`
	ProjectID         uint   `json:"project_id,omitzero"`
	Count             int    `json:"count"`
	Aggregated        bool   `json:"aggregated,omitzero"`
	WindowStart       string `json:"window_start,omitempty"`
	WindowEnd         string `json:"window_end,omitempty"`
}

// writeSecretReadDenialRow builds and writes one secret.read Success=false row.
// Best-effort: a failure is logged, never returned.
func (c *KeyorixCore) writeSecretReadDenialRow(row denialRow) {
	d := row.denial
	f := false
	subjectID, projectID := d.subjectID, d.projectID
	if subjectID == 0 {
		subjectID = d.target.SecretID
	}
	// A refusal past authorization is about a secret that exists; name its
	// project on the row when no layer noted it (denial path only).
	if !d.reason.IsBeforeAuthorization() && projectID == 0 && subjectID != 0 {
		if s, err := c.storage.GetSecret(context.Background(), subjectID); err == nil && s != nil {
			projectID = s.ProjectID
		}
	}
	diff := secretReadDenialDiff{
		Outcome: d.reason.outcome(), Reason: string(d.reason), Path: d.path,
		Target: d.target.key(), RequestedSecretID: d.target.SecretID,
		SecretID: d.subjectID, ProjectID: projectID,
		Count: row.count, Aggregated: row.aggregated,
	}
	noun := "User"
	if d.actorType == ActorTypeMachine {
		noun = "Machine identity"
	}
	desc := fmt.Sprintf("%s %s was refused a secret value read (%s) of %s reason=%s outcome=%s",
		noun, d.actor.Username, d.path, d.target.describe(), d.reason, d.reason.outcome())
	if row.aggregated {
		diff.WindowStart = row.windowStart.UTC().Format(time.RFC3339)
		diff.WindowEnd = row.windowEnd.UTC().Format(time.RFC3339)
		desc += fmt.Sprintf(" (%d further refusals aggregated, %s to %s)", row.count, diff.WindowStart, diff.WindowEnd)
	}
	encoded, err := json.Marshal(diff)
	if err != nil {
		encoded = nil
	}
	event := &models.AuditEvent{
		EventType:   "secret.read",
		IPAddress:   d.actor.IP,
		Description: sanitizeAuditText(desc),
		Success:     &f,
		EventTime:   time.Now(),
		Diff:        string(encoded),
		ActorType:   d.actorType,
	}
	if d.actor.UserID != 0 {
		uid := d.actor.UserID
		event.UserID = &uid
	}
	if d.machineID != 0 {
		mid := d.machineID
		event.MachineIdentityID = &mid
	}
	if d.impersonatorID != 0 {
		a := d.impersonatorID
		event.ImpersonatedBy = &a
		event.ActingAs = event.UserID
		event.Impersonation = true
	}
	// Only a refusal the caller could already see past authorization names the
	// secret on the row's columns (see the file comment, "No existence oracle").
	if !d.reason.IsBeforeAuthorization() {
		if subjectID != 0 {
			event.SecretNodeID = &subjectID
		}
		if projectID != 0 {
			event.ProjectID = &projectID
		}
	}
	if !c.emitAudit(context.Background(), event) {
		log.Printf("SECURITY: refused secret read NOT recorded in the audit trail (reason=%s path=%s target=%s count=%d); the read was refused regardless",
			d.reason, d.path, d.target.key(), row.count)
	}
}

// Aggregation bounds (see the file comment).
const (
	secretReadDenialWindow        = time.Minute
	secretReadDenialPrincipalKeys = 50
	secretReadDenialMaxKeys       = 10000
)

type denialKey struct {
	principal string
	reason    SecretReadDenialReason
	path      string
	target    string
}

type denialBucket struct {
	start      time.Time
	suppressed int
	last       secretReadDenial
	timer      *time.Timer
}

// denialAggregator decides, per denial, whether a row is due now. It never does
// I/O itself; the caller writes what admit returns, outside the lock.
type denialAggregator struct {
	mu            sync.Mutex
	window        time.Duration
	principalKeys int
	maxKeys       int
	buckets       map[denialKey]*denialBucket
	perPrincipal  map[string]int
	// flush writes a closed window's summary row. Set by secretReadDenials.
	flush func(denialRow)
}

func newDenialAggregator(window time.Duration, principalKeys, maxKeys int, flush func(denialRow)) *denialAggregator {
	return &denialAggregator{
		window: window, principalKeys: principalKeys, maxKeys: maxKeys,
		buckets: map[denialKey]*denialBucket{}, perPrincipal: map[string]int{},
		flush: flush,
	}
}

// secretReadDenials returns this core's aggregator, creating it on first use.
func (c *KeyorixCore) secretReadDenials() *denialAggregator {
	c.secretReadDenialAggOnce.Do(func() {
		if c.secretReadDenialAgg == nil {
			c.secretReadDenialAgg = newDenialAggregator(secretReadDenialWindow, secretReadDenialPrincipalKeys, secretReadDenialMaxKeys, nil)
		}
		c.secretReadDenialAgg.flush = c.writeSecretReadDenialRow
	})
	return c.secretReadDenialAgg
}

func denialPrincipal(d secretReadDenial) string {
	if d.machineID != 0 {
		return "machine:" + strconv.FormatUint(uint64(d.machineID), 10)
	}
	return "user:" + strconv.FormatUint(uint64(d.actor.UserID), 10)
}

// admit registers one denial at now. first, when non-nil, is the row of a
// denial that opens a window, to write now; summary, when non-nil, is a closed
// window's summary to write before it (a window whose timer had not fired yet).
func (a *denialAggregator) admit(d secretReadDenial, now time.Time) (first, summary *denialRow) {
	principal := denialPrincipal(d)
	key := denialKey{principal: principal, reason: d.reason, path: d.path, target: d.target.key()}
	a.mu.Lock()
	defer a.mu.Unlock()
	b := a.buckets[key]
	if b == nil && (a.perPrincipal[principal] >= a.principalKeys || len(a.buckets) >= a.maxKeys) {
		key.target = secretReadDenialOverflowShard
		d.target = SecretReadDenialTarget{Ref: secretReadDenialOverflowShard}
		b = a.buckets[key]
	}
	if b != nil && now.Sub(b.start) < a.window {
		b.suppressed++
		b.last = d
		return nil, nil
	}
	if b != nil {
		summary = a.closeLocked(key, b)
	}
	nb := &denialBucket{start: now, last: d}
	a.buckets[key] = nb
	a.perPrincipal[principal]++
	nb.timer = time.AfterFunc(a.window, func() { a.expire(key, nb) })
	return &denialRow{denial: d, count: 1}, summary
}

// closeLocked removes b and returns its summary row (nil when nothing was
// suppressed). a.mu must be held.
func (a *denialAggregator) closeLocked(key denialKey, b *denialBucket) *denialRow {
	if a.buckets[key] == b {
		delete(a.buckets, key)
		if a.perPrincipal[key.principal]--; a.perPrincipal[key.principal] <= 0 {
			delete(a.perPrincipal, key.principal)
		}
	}
	if b.timer != nil {
		b.timer.Stop()
	}
	if b.suppressed == 0 {
		return nil
	}
	return &denialRow{
		denial: b.last, count: b.suppressed, aggregated: true,
		windowStart: b.start, windowEnd: b.start.Add(a.window),
	}
}

// expire is the window timer: it closes b (if admit has not already) and
// writes its summary.
func (a *denialAggregator) expire(key denialKey, b *denialBucket) {
	a.mu.Lock()
	if a.buckets[key] != b {
		a.mu.Unlock()
		return
	}
	row := a.closeLocked(key, b)
	flush := a.flush
	a.mu.Unlock()
	if row != nil && flush != nil {
		flush(*row)
	}
}

// flushAll closes every open window now and writes the due summaries. For
// tests, and for an orderly shutdown.
func (a *denialAggregator) flushAll() {
	a.mu.Lock()
	var rows []denialRow
	for key, b := range a.buckets {
		if row := a.closeLocked(key, b); row != nil {
			rows = append(rows, *row)
		}
	}
	flush := a.flush
	a.mu.Unlock()
	if flush == nil {
		return
	}
	for _, row := range rows {
		flush(row)
	}
}

// FlushSecretReadDenials writes the summary rows of every open aggregation
// window now instead of when the window closes. Called on an orderly shutdown so
// counts are not lost, and by tests.
func (c *KeyorixCore) FlushSecretReadDenials() {
	c.secretReadDenials().flushAll()
}
