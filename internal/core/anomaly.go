package core

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AnomalyDetector detects anomalous secret access patterns using statistical baselines
// and, when enabled, an Isolation Forest (ADR-050). Operates on metadata only — secret
// values are never examined.
type AnomalyDetector struct {
	storage  StorageInterface
	ml       MLConfig       // ML pass; disabled by default (see SetMLConfig)
	offHours offHoursPolicy // off_hours rule window; defaults to UTC 22:00–06:00
	// lookback is how far back each pass scans. It must be >= the scheduler interval, or
	// the access logs between (now-lookback) and the prior run go unexamined by any rule
	// — a coverage blind spot when the operator sets a scan cadence longer than the
	// default. Defaults to 1h; SetLookback raises it to match the configured interval.
	lookback time.Duration
	// quarantine is how long an IP/user must have been observed before the live window
	// before buildBaseline trusts it as "known" (#101). Without this, an attacker's IP
	// ages into the baseline after just one lookback interval (as little as 1h) — the
	// very next pass sees it as historical and the new_ip/new_user rules go silent.
	// Requiring sustained presence for `quarantine` before promotion raises the cost of
	// that evasion from one pass to a sustained, repeatedly-observed presence.
	quarantine time.Duration
	// volumeMinCount overrides volumeSpikeMinCount when non-zero (ANOMALY-06).
	volumeMinCount int
	// cumulativeRateFloor is the dailyAvg ceiling below which the 24h cumulative rate
	// rule applies (ANOMALY-06). Defaults to defaultCumulativeRateFloor when zero.
	cumulativeRateFloor float64
	// cumulativeRateMax is the maximum accesses in a 24h window before the
	// cumulative_rate rule fires for low-traffic secrets (ANOMALY-06). Defaults to
	// defaultCumulativeRateMax when zero.
	cumulativeRateMax int
	// lastAuditedOffHours is the off-hours band/timezone last written to the audit
	// log by auditBusinessHoursConfig. ApplyAnomalyConfig re-applies the persisted
	// config (including SetBusinessHours) on every scheduler tick — see
	// server/main.go's "Hotload" comment — so without this, an unchanged persisted
	// config would write a fresh anomaly.business_hours_configured audit event every
	// tick, drowning out genuine changes. nil until the first successful
	// SetBusinessHours call, which is always audited.
	lastAuditedOffHours *auditedOffHours
	// fullSweep disables the incremental candidate filter (every secret is evaluated
	// every pass, the pre-C-PERF-FIXES behaviour). Test-only: the equivalence test runs
	// both modes over identical data and asserts identical alerts.
	fullSweep bool
	// everyAccessDedup sends every per-access alert to CreateAnomalyAlert, settled key
	// or not, each stamped with its own time.Now() (the pre-OPT-READPATH-1 behaviour).
	// Test-only: the equivalence test runs
	// both modes over identical data and asserts identical alert rows.
	everyAccessDedup bool
}

// auditedOffHours is the comparable subset of a SetBusinessHours call's applied
// state, used to detect whether the band/timezone actually changed since the last
// audit write. tz is the canonical location name (offHoursPolicy.loc.String()), not
// the raw caller-supplied string, so "" and "UTC" — which resolve to the same
// location — are treated as the same config rather than a spurious change.
type auditedOffHours struct {
	tz    string
	start int
	end   int
}

// minDetectionLookback is the floor for the per-pass scan window.
const minDetectionLookback = time.Hour

// defaultBaselineQuarantine is how long a newly observed IP/user must have been present
// before buildBaseline promotes it to "known" — see AnomalyDetector.quarantine.
const defaultBaselineQuarantine = 24 * time.Hour

const (
	// defaultCumulativeRateFloor is the dailyAvg threshold below which the 24h
	// cumulative rate rule applies. Secrets with a higher learnt rate already have
	// enough traffic for the per-hour spike rule to work reliably.
	defaultCumulativeRateFloor = 1.0
	// defaultCumulativeRateMax is the absolute access count over a 24h rolling
	// window that triggers a cumulative_rate alert for low-traffic secrets. An
	// attacker reading 9 times/hour evades the per-hour floor (10) indefinitely,
	// but crosses this 24h cumulative threshold in just over two hours.
	defaultCumulativeRateMax = 20
)

// StorageInterface is satisfied by *storage.LocalStorage.
type StorageInterface = interface {
	ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error)
	// PrincipalSecretFirstSeen backs the per-principal breadth-exfiltration pass
	// (#101): see internal/core/storage.Storage's doc comment for the full rationale.
	PrincipalSecretFirstSeen(ctx context.Context, since time.Time) (map[string]map[uint]time.Time, error)
	CreateAnomalyAlert(ctx context.Context, alert *models.AnomalyAlert) error
	ListAnomalyAlerts(ctx context.Context, acknowledged *bool) ([]models.AnomalyAlert, error)
	// LogAuditEvent backs auditBusinessHoursConfig (#144) — a business-hours config
	// change must be on the audit record even though it's applied in-memory here.
	LogAuditEvent(ctx context.Context, event *models.AuditEvent) error
	// ListSecretIDsAccessedSince backs the incremental sweep: only secrets with an
	// access-log row inside the detection horizon are evaluated (see RunDetection).
	ListSecretIDsAccessedSince(ctx context.Context, since time.Time) ([]uint, error)
	// Get/SetSystemMetadata persist the sweep's high-water mark
	// (anomalyHighWaterKey) so a delayed, jittered, or post-downtime pass extends its
	// scan window back to where the last successful pass ended instead of leaving a gap.
	GetSystemMetadata(ctx context.Context, key string) (value string, found bool, err error)
	SetSystemMetadata(ctx context.Context, key, value string) error
}

// anomalyHighWaterKey is the system_metadata key holding the `now` of the last
// fully-successful RunDetection pass (RFC3339Nano, UTC). Shared by every replica —
// the pass itself is single-replica-gated (ADR-039).
const anomalyHighWaterKey = "anomaly_detection_high_water"

// maxDetectionCatchUp caps how far back a pass extends its scan window to reach the
// persisted high-water mark. After a longer outage the remainder of the gap stays
// unexamined (as every gap did before the high-water mark existed) rather than one
// pass replaying days of access logs and flooding admins with stale alerts.
const maxDetectionCatchUp = 24 * time.Hour

// cumulativeRateHorizon is the widest look-back of any per-secret rule
// (cumulative_rate counts the last 24h). The incremental sweep's candidate horizon
// must never be narrower than this, or a secret whose only reads are 1–24h old
// would be skipped and its cumulative_rate alert silently dropped.
const cumulativeRateHorizon = 24 * time.Hour

// SetLookback sets how far back each detection pass scans, flooring it at one hour. The
// scheduler should set this to its scan interval so consecutive passes cover a
// contiguous timeline (a longer cadence must scan a proportionally longer window, else
// the gap between passes is never analysed).
func (d *AnomalyDetector) SetLookback(window time.Duration) {
	if window < minDetectionLookback {
		window = minDetectionLookback
	}
	d.lookback = window
}

// SetBaselineQuarantine overrides how long an IP/user must be observed before the live
// window before it is trusted as "known" baseline (see AnomalyDetector.quarantine). A
// non-positive value disables quarantine (only the live window itself is excluded,
// the pre-#101 behaviour) — accepted as an explicit opt-out, not silently floored.
func (d *AnomalyDetector) SetBaselineQuarantine(window time.Duration) {
	d.quarantine = window
}

// SetVolumeMinCount overrides the absolute floor below which the per-hour volume spike
// detector never fires (ANOMALY-06). Positive values only; non-positive is ignored.
func (d *AnomalyDetector) SetVolumeMinCount(n int) {
	if n > 0 {
		d.volumeMinCount = n
	}
}

// SetCumulativeRateFloor sets the dailyAvg threshold below which the 24h cumulative
// rate rule applies (ANOMALY-06). Positive values only; non-positive is ignored.
func (d *AnomalyDetector) SetCumulativeRateFloor(floor float64) {
	if floor > 0 {
		d.cumulativeRateFloor = floor
	}
}

// SetCumulativeRateMax sets the maximum accesses in a 24h rolling window before the
// cumulative_rate rule fires for low-traffic secrets (ANOMALY-06). Positive values
// only; non-positive is ignored.
func (d *AnomalyDetector) SetCumulativeRateMax(max int) {
	if max > 0 {
		d.cumulativeRateMax = max
	}
}

// NewAnomalyDetector creates a new AnomalyDetector with the ML pass disabled, the
// off-hours window at its UTC 22:00–06:00 default, and the baseline quarantine at its
// 24h default.
func NewAnomalyDetector(storage StorageInterface) *AnomalyDetector {
	return &AnomalyDetector{
		storage:    storage,
		offHours:   defaultOffHoursPolicy(),
		lookback:   minDetectionLookback,
		quarantine: defaultBaselineQuarantine,
	}
}

// SetMLConfig enables (or reconfigures) the Isolation Forest pass. Defaults are
// applied per-pass, so passing a zero-valued config with Enabled=true uses the
// recommended parameters. With Enabled=false (the zero value) only the statistical
// rules run.
func (d *AnomalyDetector) SetMLConfig(cfg MLConfig) {
	d.ml = cfg
}

// offHoursPolicy defines the "off hours" band for the off_hours rule. Hours are
// evaluated in loc, and the band is [start, end) wrapping midnight (e.g. 22→6 means
// 22:00–23:59 plus 00:00–05:59).
type offHoursPolicy struct {
	loc   *time.Location
	start int // off-hours band start hour [0,23]
	end   int // off-hours band end hour [0,23], exclusive
}

// defaultOffHoursPolicy is the legacy hardcoded behaviour: UTC, 22:00–06:00.
func defaultOffHoursPolicy() offHoursPolicy {
	return offHoursPolicy{loc: time.UTC, start: 22, end: 6}
}

// isOffHours reports whether t falls in the off-hours band, evaluated in the policy's
// timezone. A band with start <= end is a normal interval [start, end); start > end is
// a band that wraps midnight.
func (p offHoursPolicy) isOffHours(t time.Time) bool {
	loc := p.loc
	if loc == nil { // zero-value policy → treat as UTC rather than panic in t.In
		loc = time.UTC
	}
	h := t.In(loc).Hour()
	if p.start <= p.end {
		return h >= p.start && h < p.end
	}
	return h >= p.start || h < p.end
}

// validHour reports whether h is a valid clock hour [0,23].
func validHour(h int) bool { return h >= 0 && h <= 23 }

// EventAnomalyBusinessHoursConfigured audits a change to the off_hours rule's
// timezone/band (#144). A degenerate (start == end) or otherwise narrowed band
// silently blinds that rule with no other visible symptom, so the config CHANGE
// itself — not just its effect — must be on the record.
const EventAnomalyBusinessHoursConfigured = "anomaly.business_hours_configured" // #nosec G101 -- audit event type, not a credential

// SetBusinessHours configures the off_hours rule's timezone and band. tz is an IANA
// name ("" = UTC); the off-hours band is [startHour, endHour) wrapping midnight, in
// that timezone. A blank tz keeps UTC, and the band defaults to 22:00–06:00 unless
// overridden. Because 0 is the config zero value AND a valid hour, both hours being 0
// is treated as "unset" (a 0–0 band would be empty) — set the timezone alone and the
// default band is kept. Any other call must supply BOTH hours as a valid, differing
// pair: partial-update callers (e.g. a caller that loads the persisted config and
// only overlays the field it means to change) can otherwise collide an intentionally
// changed hour with the OTHER field's untouched value — including the hardcoded
// default (22/6) when an out-of-range hour is passed for it, since that used to fall
// back to the default silently instead of erroring. Returns an error for an
// unparseable timezone, an out-of-range hour, or a degenerate band (the two hours
// equal, checked on the FINAL merged pair, not just the raw inputs) — a start==end
// band matches no hour in isOffHours, which would silently disable the rule with no
// validation error and no audit trail if allowed through. Any error leaves the prior
// policy unchanged. On success the new band is recorded as an audit event — but only
// the first time it's applied, or when it actually differs from what was last
// audited (see lastAuditedOffHours). ApplyAnomalyConfig calls this on every
// scheduler tick to hot-load the persisted config (server/main.go); without this
// change check, an unchanged config would write a duplicate audit event every tick.
func (d *AnomalyDetector) SetBusinessHours(ctx context.Context, tz string, startHour, endHour int) error {
	p := defaultOffHoursPolicy()
	if tz != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			return fmt.Errorf("anomaly business_hours timezone %q: %w", tz, err)
		}
		p.loc = loc
	}
	if startHour != 0 || endHour != 0 { // both zero = unset → keep the default band
		if !validHour(startHour) {
			return fmt.Errorf("anomaly business_hours: start_hour %d out of range [0,23]", startHour)
		}
		if !validHour(endHour) {
			return fmt.Errorf("anomaly business_hours: end_hour %d out of range [0,23]", endHour)
		}
		p.start = startHour
		p.end = endHour
	}
	// Checked on the final merged band (not the raw inputs) so a start that
	// intentionally matches the OTHER field's still-in-effect value — whether that
	// value came from the hardcoded default above or, before the out-of-range check
	// above existed, from a silently-kept default — is always caught.
	if p.start == p.end {
		return fmt.Errorf("anomaly business_hours: start_hour and end_hour must differ (an equal start/end band is empty and would silently disable the off_hours rule; pass 0,0 to explicitly keep the default band)")
	}
	d.offHours = p
	current := auditedOffHours{tz: p.loc.String(), start: p.start, end: p.end}
	if d.lastAuditedOffHours == nil || *d.lastAuditedOffHours != current {
		d.auditBusinessHoursConfig(ctx, tz, p)
		d.lastAuditedOffHours = &current
	}
	return nil
}

// auditBusinessHoursConfig records the newly-applied off-hours band/timezone as an
// audit event. Called by SetBusinessHours only when the band/timezone actually
// changed since the last audit write (see lastAuditedOffHours), so a caller that
// re-applies the same persisted config on every scheduler tick doesn't spam the
// audit log with identical no-op events. Best-effort: a storage failure here must
// not undo the in-memory policy change SetBusinessHours already applied, but it is
// logged loudly (a missed audit write for a detection-control config change is
// itself a small gap).
func (d *AnomalyDetector) auditBusinessHoursConfig(ctx context.Context, tz string, p offHoursPolicy) {
	if d.storage == nil {
		return
	}
	tzLabel := tz
	if tzLabel == "" {
		tzLabel = "UTC"
	}
	ok := true
	event := &models.AuditEvent{
		EventType: EventAnomalyBusinessHoursConfigured,
		Description: fmt.Sprintf("anomaly off-hours band configured: timezone=%s band=%02d:00-%02d:00",
			tzLabel, p.start, p.end),
		Success:   &ok,
		ActorType: "system",
		EventTime: time.Now(),
	}
	if err := d.storage.LogAuditEvent(ctx, event); err != nil {
		log.Printf("SECURITY: anomaly business-hours config: failed to write audit event: %v", err)
	}
}

// accessBaseline holds statistical baseline for a secret's access patterns.
type accessBaseline struct {
	knownIPs   map[string]bool
	knownUsers map[string]bool
	dailyAvg   float64 // average accesses per day over last 7 days
}

// RunDetection analyses SecretAccessLog over the configured lookback window and emits
// AnomalyAlert rows. Safe to call on a schedule — idempotent per detection window (the
// dedup window absorbs the overlap between passes). It is best-effort per secret but
// returns a non-nil error if any storage operation failed, so the scheduler outcome
// reflects a partial failure rather than silently reporting success.
//
// Incremental sweep (C-PERF-FIXES, Detected-by: PERF-2 performance study). The pass
// used to read two access-log ranges for EVERY active secret, every pass — including
// the pass run at process startup — no matter how few secrets had been touched. It
// now evaluates only the secrets ListSecretIDsAccessedSince reports activity for
// since the detection horizon, min(scanStart, now-24h). That is exactly the set that
// can fire: every per-secret rule needs at least one access-log row in its own
// window (per-access rules and frequency_spike/ml_outlier the scan window,
// cumulative_rate the last 24h), and a secret with no row in either produces no
// alert. TestRunDetection_IncrementalSweepDetectsSameAnomaliesAsFullSweep pins the
// equivalence. If the candidate query fails, the pass falls back to the full sweep
// rather than skipping secrets.
//
// High-water mark: the scan window normally starts at now-lookback, as before. When
// the last fully-successful pass (persisted under anomalyHighWaterKey) ended earlier
// than that — a jittered or delayed first pass after a restart, an outage, or plain
// ticker drift — the window extends back to it (capped at maxDetectionCatchUp), so
// access logs between passes are never left unexamined. frequency_spike still counts
// only the last `lookback` (its threshold is per-window), and the mark advances only
// when the pass had no storage failures.
func (d *AnomalyDetector) RunDetection(ctx context.Context, secrets []models.SecretNode) error {
	now := time.Now().UTC()
	lookback := max(d.lookback, minDetectionLookback)
	lookbackStart := now.Add(-lookback)
	window := d.scanWindowStart(ctx, now, lookbackStart)
	baselineWindow := now.Add(-30 * 24 * time.Hour)

	var failures int
	active, filtered := d.activeSecretIDs(ctx, now, window)
	for _, secret := range secrets {
		if filtered && !active[secret.ID] {
			continue
		}
		failures += d.detectOneSecretAnomalies(ctx, secret, baselineWindow, window, lookbackStart, now)
	}

	// Per-principal aggregate (#101): a principal reading many DIFFERENT secrets it has
	// never touched before is invisible to every rule above — each is scoped to a single
	// secret's own baseline, so the same breadth-exfiltrating principal looks merely
	// "new" to N separate secrets rather than triggering one aggregate signal. Runs once
	// per pass across all secrets, not per secret.
	breadthAlerts, err := detectPrincipalBreadth(ctx, d.storage, now, window, baselineWindow)
	if err != nil {
		failures++
	}
	failures += d.saveAlerts(ctx, breadthAlerts)

	if failures > 0 {
		return fmt.Errorf("anomaly detection completed with %d storage failure(s) — some alerts may not have been recorded", failures)
	}
	// Advance the high-water mark only after a clean pass, so a partially-failed pass's
	// window is re-covered next time rather than skipped.
	if err := d.storage.SetSystemMetadata(ctx, anomalyHighWaterKey, now.Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("anomaly detection: persist high-water mark: %w", err)
	}
	return nil
}

// scanWindowStart returns where this pass's scan window begins: lookbackStart, or the
// persisted high-water mark when that is earlier (floored at now-maxDetectionCatchUp).
// A missing or unreadable mark keeps lookbackStart — the pre-high-water behaviour.
func (d *AnomalyDetector) scanWindowStart(ctx context.Context, now, lookbackStart time.Time) time.Time {
	raw, found, err := d.storage.GetSystemMetadata(ctx, anomalyHighWaterKey)
	if err != nil {
		log.Printf("anomaly detection: could not read high-water mark (%v); scanning the last %s only", err, now.Sub(lookbackStart))
		return lookbackStart
	}
	if !found {
		return lookbackStart
	}
	hw, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		log.Printf("anomaly detection: ignoring unparseable high-water mark %q: %v", raw, err)
		return lookbackStart
	}
	if !hw.Before(lookbackStart) {
		return lookbackStart
	}
	if floor := now.Add(-maxDetectionCatchUp); hw.Before(floor) {
		return floor
	}
	return hw.UTC()
}

// activeSecretIDs returns the set of secrets with any access-log row since the
// detection horizon. filtered is false when the incremental sweep is disabled or the
// candidate query failed — the caller must then evaluate every secret.
func (d *AnomalyDetector) activeSecretIDs(ctx context.Context, now, window time.Time) (map[uint]bool, bool) {
	if d.fullSweep {
		return nil, false
	}
	horizon := now.Add(-cumulativeRateHorizon)
	if window.Before(horizon) {
		horizon = window
	}
	ids, err := d.storage.ListSecretIDsAccessedSince(ctx, horizon)
	if err != nil {
		log.Printf("anomaly detection: candidate-secret query failed (%v); falling back to a full sweep this pass", err)
		return nil, false
	}
	set := make(map[uint]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set, true
}

// detectOneSecretAnomalies runs all anomaly rules for a single secret and returns the
// number of storage failures encountered while saving alerts. window is the scan
// window start (possibly extended back to the high-water mark); lookbackStart bounds
// the frequency_spike count, whose threshold is defined per lookback window.
func (d *AnomalyDetector) detectOneSecretAnomalies(ctx context.Context, secret models.SecretNode, baselineWindow, window, lookbackStart, now time.Time) int {
	// Build 30-day baseline. A secret with NO baseline history (brand new, or unread
	// in 30 days) is NOT skipped — detectAnomalies still flags off-hours access and
	// first-ever new_ip/new_user (severity is scaled down for that case). Skipping was
	// the prior blind spot an attacker targeting a freshly-provisioned secret could exploit.
	baselineLogs, err := d.storage.ListSecretAccessLogs(ctx, secret.ID, baselineWindow)
	if err != nil {
		// #365: log which secret so an operator can distinguish a transient DB hiccup
		// from a genuine coverage gap (the detection window is only ~1h and is never
		// retroactively re-evaluated).
		log.Printf("anomaly detection: baseline access-log read for secret %d: %v — skipping detection for this secret this pass", secret.ID, err)
		return 1
	}
	baseline := buildBaseline(baselineLogs, now, window, d.quarantine)
	recentLogs, err := d.storage.ListSecretAccessLogs(ctx, secret.ID, window)
	if err != nil {
		log.Printf("anomaly detection: detection-window access-log read for secret %d: %v — skipping detection for this secret this pass", secret.ID, err)
		return 1
	}
	failures := 0
	// One storage dedup check per alert key per pass, not one per access row: every
	// per-access alert of this pass carries the pass's `now` as DetectedAt, so they
	// share CreateAnomalyAlert's dedup cutoff, and once one call for a key succeeded
	// (inserted, or found an equivalent alert newer than the cutoff) every later call
	// for that key in this pass would find that row and insert nothing.
	settled := map[anomalyDedupKey]struct{}{}
	for _, accessLog := range recentLogs {
		at := now
		if d.everyAccessDedup {
			at = time.Now().UTC()
		}
		failures += d.saveAlertsOnce(ctx, detectAnomalies(secret, accessLog, baseline, d.offHours, at), settled)
	}
	// The per-window aggregates below keep their pre-high-water inputs: only the
	// lookback slice, even when the scan window was extended for catch-up (identical
	// to recentLogs in the steady state, where window == lookbackStart).
	lookbackLogs := recentLogs
	if window.Before(lookbackStart) {
		lookbackLogs = logsSince(recentLogs, lookbackStart)
	}
	// Per-secret aggregate: a read-volume spike for the window vs. the learned baseline
	// (one alert per secret per pass, not per access).
	if alert := volumeSpikeAlert(secret, len(lookbackLogs), baseline, d.effectiveVolumeMinCount(), now); alert != nil {
		if err := d.storage.CreateAnomalyAlert(ctx, alert); err != nil {
			failures++
		}
	}
	// ANOMALY-06 cumulative rate rule: count accesses over the last 24h from
	// baselineLogs (which covers 30 days) so we catch sustained low-rate exfiltration
	// that stays below the per-hour floor on every individual pass.
	window24h := now.Add(-24 * time.Hour)
	logs24h := logsSince(baselineLogs, window24h)
	// Also include any logs in the current detection window (recentLogs) that fall
	// within the last 24h — the baseline query may exclude the live window on some
	// storage implementations.
	for _, lg := range lookbackLogs {
		if !lg.AccessTime.Before(window24h) {
			logs24h = append(logs24h, lg)
		}
	}
	if alert := cumulativeRateAlert(secret, len(logs24h), baseline, d.effectiveCumulativeRateFloor(), d.effectiveCumulativeRateMax(), now); alert != nil {
		if err := d.storage.CreateAnomalyAlert(ctx, alert); err != nil {
			failures++
		}
	}
	// ML pass (opt-in): score this window's accesses against an Isolation Forest trained
	// on prior history, catching multivariate outliers the single-signal rules miss.
	// Train only on logs BEFORE the window — otherwise the forest learns this window's
	// reads as normal and can't isolate the very accesses it is scoring.
	if d.ml.Enabled {
		failures += d.saveAlertsOnce(ctx, mlOutlierAlerts(secret, logsBefore(baselineLogs, window), recentLogs, d.ml, now), settled)
	}
	return failures
}

// saveAlerts persists a slice of anomaly alerts, returning the number of storage
// failures. Each alert is saved independently so one failure doesn't drop the rest.
func (d *AnomalyDetector) saveAlerts(ctx context.Context, alerts []models.AnomalyAlert) int {
	failures := 0
	for _, alert := range alerts {
		if err := d.storage.CreateAnomalyAlert(ctx, &alert); err != nil {
			failures++
		}
	}
	return failures
}

// anomalyDedupKey is CreateAnomalyAlert's dedup key: an alert with the same key
// detected within anomalyDedupWindow suppresses the insert.
type anomalyDedupKey struct {
	secret               uint
	alertType, actor, ip string
}

// saveAlertsOnce is saveAlerts for alerts that share one DetectedAt (one pass's
// `now`): an alert whose key is in settled is skipped, because a call for that key
// already succeeded this pass and left an equivalent alert newer than the shared
// dedup cutoff, so CreateAnomalyAlert would insert nothing. A failed call does not
// settle its key: the next alert with that key is tried, as before.
func (d *AnomalyDetector) saveAlertsOnce(ctx context.Context, alerts []models.AnomalyAlert, settled map[anomalyDedupKey]struct{}) int {
	failures := 0
	for i := range alerts {
		k := anomalyDedupKey{alerts[i].SecretNodeID, alerts[i].AlertType, alerts[i].AccessedBy, alerts[i].IPAddress}
		if _, ok := settled[k]; ok && !d.everyAccessDedup {
			continue
		}
		if err := d.storage.CreateAnomalyAlert(ctx, &alerts[i]); err != nil {
			failures++
			continue
		}
		settled[k] = struct{}{}
	}
	return failures
}

const (
	// principalBreadthMinNewSecrets is the minimum count of distinct secrets a
	// principal must access in the live window — NONE of which it touched during the
	// 30-day baseline — before a principal_breadth alert fires. Catches breadth
	// exfiltration (many different secrets each read once) that the per-secret rules
	// structurally cannot see.
	principalBreadthMinNewSecrets = 5
	// principalBreadthHighMultiplier: at or above principalBreadthMinNewSecrets times
	// this multiplier, the alert is "high" severity rather than "medium".
	principalBreadthHighMultiplier = 2
)

// detectPrincipalBreadth aggregates access logs by principal (not by secret) over the
// 30-day baseline and flags a principal whose EARLIEST-ever access to an unusually high
// number of secrets falls inside the live scan window — the per-secret rules never see
// this, since each secret only observes "one access from a possibly-new actor." The
// live-window boundary is applied here in Go against a real time.Time, not pushed into
// the storage query's SQL bound — see PrincipalSecretFirstSeen's doc comment for why.
func detectPrincipalBreadth(ctx context.Context, s StorageInterface, now, windowStart, baselineWindow time.Time) ([]models.AnomalyAlert, error) {
	firstSeen, err := s.PrincipalSecretFirstSeen(ctx, baselineWindow)
	if err != nil {
		return nil, err
	}

	var alerts []models.AnomalyAlert
	for principal, secrets := range firstSeen {
		newCount := 0
		// #G43: pick a deterministic representative secret (lowest ID) among the
		// ones that triggered this alert. AlertNewAnomalies resolves the owning
		// project — and therefore which admins to notify in-app — from
		// AnomalyAlert.SecretNodeID; principal_breadth left it unset (there's no
		// single natural owner across many secrets), so every principal_breadth
		// alert silently skipped the in-app admin notification, even though the
		// audit/SIEM event still fired. One representative secret is enough to
		// resolve a real project and get admins notified — it does not need to
		// be exhaustive across every project the principal touched.
		var representativeID uint
		for secretID, t := range secrets {
			if !t.Before(windowStart) { // first ever access to this secret falls in the live window
				newCount++
				if representativeID == 0 || secretID < representativeID {
					representativeID = secretID
				}
			}
		}
		if newCount < principalBreadthMinNewSecrets {
			continue
		}
		severity := "medium"
		if newCount >= principalBreadthMinNewSecrets*principalBreadthHighMultiplier {
			severity = "high"
		}
		alerts = append(alerts, models.AnomalyAlert{
			SecretNodeID: representativeID,
			AlertType:    "principal_breadth",
			Severity:     severity,
			Description: fmt.Sprintf(
				"%s accessed %d distinct secrets with no prior access history in the last scan window — possible breadth exfiltration",
				principal, newCount),
			AccessedBy: principal,
			DetectedAt: now,
		})
	}
	return alerts, nil
}

// logsBefore returns the access logs that occurred strictly before t, preserving
// order. Used to exclude the live detection window from the ML training set so this
// pass's reads don't train the model that is meant to flag them.
func logsBefore(logs []models.SecretAccessLog, t time.Time) []models.SecretAccessLog {
	out := make([]models.SecretAccessLog, 0, len(logs))
	for _, lg := range logs {
		if lg.AccessTime.Before(t) {
			out = append(out, lg)
		}
	}
	return out
}

// logsSince returns the access logs whose AccessTime is at or after t, preserving
// order. Used to compute a 24h rolling count from the already-fetched baseline slice
// without an extra storage query.
func logsSince(logs []models.SecretAccessLog, t time.Time) []models.SecretAccessLog {
	out := make([]models.SecretAccessLog, 0, len(logs))
	for _, lg := range logs {
		if !lg.AccessTime.Before(t) {
			out = append(out, lg)
		}
	}
	return out
}

// baselineMinSeen is the minimum number of times an IP or user must appear in the
// pre-quarantine baseline window before it is promoted to "known." A single occurrence
// is not sufficient — an attacker can generate exactly one historical access and then
// be treated as trusted on every subsequent pass. Requiring N distinct baseline
// observations raises the cost of that poisoning attack from one access to a sustained,
// repeatedly-observed presence spanning the full quarantine period.
const baselineMinSeen = 3

// countBaselineAccesses tallies IP/user occurrences and the 7-day access count
// across the pre-quarantine historical window (before trustCutoff). It is the
// inner counting pass factored out of buildBaseline to keep cognitive complexity low.
func countBaselineAccesses(logs []models.SecretAccessLog, windowStart, trustCutoff, sevenDaysAgo time.Time) (ipCount, userCount map[string]int, recentCount int) {
	ipCount = make(map[string]int)
	userCount = make(map[string]int)
	for _, log := range logs {
		if !log.AccessTime.Before(windowStart) {
			continue
		}
		if !log.AccessTime.Before(trustCutoff) {
			continue
		}
		if log.IPAddress != "" {
			ipCount[log.IPAddress]++
		}
		if log.AccessedBy != "" {
			userCount[log.AccessedBy]++
		}
		if log.AccessTime.After(sevenDaysAgo) {
			recentCount++
		}
	}
	return
}

// buildBaseline computes the statistical baseline from historical access logs,
// EXCLUDING the live detection window [windowStart, now]. The reads being evaluated
// this pass must not seed their own baseline: the baseline query spans 30 days and
// therefore contains the last hour too, so without this exclusion a genuinely new IP
// or user would already appear in knownIPs/knownUsers and the new_ip / new_user rules
// could never fire. Excluding the window also keeps the volume baseline (dailyAvg)
// from inflating itself with the very burst a spike check is meant to catch.
//
// quarantine additionally withholds knownIPs/knownUsers promotion for accesses that,
// while before the live window, are still more recent than `quarantine` (#101): without
// this, an IP/user first observed in pass N is already "known" by pass N+1 — as little
// as one lookback interval later — so an attacker's IP self-poisons the baseline and
// stops triggering new_ip/new_user after a single successful access. Requiring an
// access to predate `windowStart - quarantine`, not just `windowStart`, means an IP/user
// must be observed continuously for the full quarantine period before it is trusted.
//
// ANOMALY-02: a single pre-quarantine access is no longer sufficient to promote an
// IP/user to "known" — it must appear at least baselineMinSeen times. This prevents an
// attacker from generating one carefully-timed historical access to permanently silence
// the new_ip/new_user rules.
//
// dailyAvg counts only accesses that are OUTSIDE the quarantine window (older than
// trustCutoff) to prevent warm-up accesses during quarantine from inflating the volume
// baseline, which would in turn raise the spike threshold and blind the spike detector.
func buildBaseline(logs []models.SecretAccessLog, now, windowStart time.Time, quarantine time.Duration) accessBaseline {
	b := accessBaseline{
		knownIPs:   make(map[string]bool),
		knownUsers: make(map[string]bool),
	}
	sevenDaysAgo := now.Add(-7 * 24 * time.Hour)
	trustCutoff := windowStart.Add(-quarantine)

	ipCount, userCount, recentCount := countBaselineAccesses(logs, windowStart, trustCutoff, sevenDaysAgo)

	// Promote IPs/users that meet the minimum-seen threshold.
	for ip, cnt := range ipCount {
		if cnt >= baselineMinSeen {
			b.knownIPs[ip] = true
		}
	}
	for user, cnt := range userCount {
		if cnt >= baselineMinSeen {
			b.knownUsers[user] = true
		}
	}

	b.dailyAvg = float64(recentCount) / 7.0
	return b
}

// detectAnomalies checks a single access log entry against the baseline.
// newIPAlert returns a new_ip alert when log.IPAddress is unknown to baseline, or nil.
// An empty baseline (no known IPs yet) downgrades to "low" severity: a secret's very
// first access from any IP is unremarkable on its own, but still auditable (#101).
func newIPAlert(secret models.SecretNode, log models.SecretAccessLog, baseline accessBaseline, now time.Time) *models.AnomalyAlert {
	if log.IPAddress == "" || baseline.knownIPs[log.IPAddress] {
		return nil
	}
	severity, desc := "high", fmt.Sprintf("Secret accessed from unrecognised IP address: %s", log.IPAddress)
	if len(baseline.knownIPs) == 0 {
		severity = "low"
		desc = fmt.Sprintf("Secret's first observed access is from IP address %s (no prior baseline to compare against)", log.IPAddress)
	}
	return &models.AnomalyAlert{
		SecretNodeID: secret.ID,
		SecretName:   secret.Name,
		AlertType:    "new_ip",
		Severity:     severity,
		Description:  desc,
		AccessedBy:   log.AccessedBy,
		IPAddress:    log.IPAddress,
		DetectedAt:   now,
	}
}

// newUserAlert returns a new_user alert when log.AccessedBy is unknown to baseline, or nil.
// Same empty-baseline downgrade reasoning as newIPAlert.
func newUserAlert(secret models.SecretNode, log models.SecretAccessLog, baseline accessBaseline, now time.Time) *models.AnomalyAlert {
	if log.AccessedBy == "" || baseline.knownUsers[log.AccessedBy] {
		return nil
	}
	severity, desc := "high", fmt.Sprintf("Secret accessed by user with no prior access history: %s", log.AccessedBy)
	if len(baseline.knownUsers) == 0 {
		severity = "low"
		desc = fmt.Sprintf("Secret's first observed access is by user %s (no prior baseline to compare against)", log.AccessedBy)
	}
	return &models.AnomalyAlert{
		SecretNodeID: secret.ID,
		SecretName:   secret.Name,
		AlertType:    "new_user",
		Severity:     severity,
		Description:  desc,
		AccessedBy:   log.AccessedBy,
		IPAddress:    log.IPAddress,
		DetectedAt:   now,
	}
}

// detectAnomalies returns the per-access alerts for log, stamped DetectedAt now (the
// detection pass's time, so all of one pass's alerts share a dedup cutoff).
func detectAnomalies(secret models.SecretNode, log models.SecretAccessLog, baseline accessBaseline, offHours offHoursPolicy, now time.Time) []models.AnomalyAlert {
	var alerts []models.AnomalyAlert

	// Rule 1: Off-hours access (configurable band + timezone; default 22:00–06:00 UTC).
	if offHours.isOffHours(log.AccessTime) {
		alerts = append(alerts, models.AnomalyAlert{
			SecretNodeID: secret.ID,
			SecretName:   secret.Name,
			AlertType:    "off_hours",
			Severity:     "medium",
			Description:  fmt.Sprintf("Secret accessed outside business hours at %s", log.AccessTime.In(offHours.loc).Format("15:04 MST")),
			AccessedBy:   log.AccessedBy,
			IPAddress:    log.IPAddress,
			DetectedAt:   now,
		})
	}

	// Rule 2: Access from unknown IP — see newIPAlert for the empty-baseline reasoning (#101).
	if a := newIPAlert(secret, log, baseline, now); a != nil {
		alerts = append(alerts, *a)
	}

	// Rule 3: Access by unknown user — same reasoning as Rule 2.
	if a := newUserAlert(secret, log, baseline, now); a != nil {
		alerts = append(alerts, *a)
	}

	return alerts
}

const (
	// volumeSpikeMinCount is the default absolute floor below which a burst is never
	// flagged — avoids false positives on low-traffic secrets where a handful of reads
	// dwarfs a near-zero baseline. Overridable per-deployment via AnomalyConfigRecord.
	volumeSpikeMinCount = 10
	// volumeSpikeMultiplier flags a window whose read count exceeds this many times the
	// secret's learned hourly baseline.
	volumeSpikeMultiplier = 3.0
)

// effectiveVolumeMinCount returns the configurable floor, falling back to the default.
func (d *AnomalyDetector) effectiveVolumeMinCount() int {
	if d.volumeMinCount > 0 {
		return d.volumeMinCount
	}
	return volumeSpikeMinCount
}

// effectiveCumulativeRateFloor returns the configured floor, falling back to the default.
func (d *AnomalyDetector) effectiveCumulativeRateFloor() float64 {
	if d.cumulativeRateFloor > 0 {
		return d.cumulativeRateFloor
	}
	return defaultCumulativeRateFloor
}

// effectiveCumulativeRateMax returns the configured max, falling back to the default.
func (d *AnomalyDetector) effectiveCumulativeRateMax() int {
	if d.cumulativeRateMax > 0 {
		return d.cumulativeRateMax
	}
	return defaultCumulativeRateMax
}

// isVolumeSpike reports whether recentCount reads in the (one-hour) detection window
// is anomalously high versus the secret's learned hourly baseline (dailyAvg / 24).
// Requires both an absolute floor and a multiple of the baseline, so neither a quiet
// secret seeing a few reads nor a busy secret at its normal rate is flagged.
// minCount is the absolute floor (configurable via AnomalyDetector.volumeMinCount).
func isVolumeSpike(recentCount int, baseline accessBaseline, minCount int) bool {
	if recentCount < minCount {
		return false
	}
	hourlyAvg := baseline.dailyAvg / 24.0
	return float64(recentCount) > volumeSpikeMultiplier*hourlyAvg
}

// isCumulativeRateAnomaly reports whether the 24h rolling access count is anomalously
// high for a secret whose learned daily average is below the configured floor. This
// catches the sustained low-rate exfiltration pattern (e.g. 9 reads/hour) that the
// per-hour spike floor misses: 9 reads/hour stays below volumeSpikeMinCount=10 per
// pass, but accumulates to 216 reads in 24h — well above the cumulative threshold.
//
// The rule only applies when dailyAvg < rateFloor so it doesn't interfere with
// high-traffic secrets that already have enough history for the per-hour spike rule.
func isCumulativeRateAnomaly(count24h int, dailyAvg float64, rateFloor float64, rateMax int) bool {
	if dailyAvg >= rateFloor {
		return false // high-traffic secret: per-hour spike rule already covers it
	}
	return count24h > rateMax
}

// volumeSpikeAlert returns a frequency_spike alert when the window's read count is a
// spike versus the baseline, or nil otherwise. The alert is a per-secret aggregate, so
// it carries no single accessor/IP.
func volumeSpikeAlert(secret models.SecretNode, recentCount int, baseline accessBaseline, minCount int, now time.Time) *models.AnomalyAlert {
	if !isVolumeSpike(recentCount, baseline, minCount) {
		return nil
	}
	return &models.AnomalyAlert{
		SecretNodeID: secret.ID,
		SecretName:   secret.Name,
		AlertType:    "frequency_spike",
		Severity:     "medium",
		Description: fmt.Sprintf("Unusual access volume: %d reads in the last hour (baseline ~%.1f/hour)",
			recentCount, baseline.dailyAvg/24.0),
		DetectedAt: now,
	}
}

// cumulativeRateAlert returns a cumulative_rate alert when the 24h access count is
// anomalously high for a low-traffic secret, or nil otherwise.
func cumulativeRateAlert(secret models.SecretNode, count24h int, baseline accessBaseline, rateFloor float64, rateMax int, now time.Time) *models.AnomalyAlert {
	if !isCumulativeRateAnomaly(count24h, baseline.dailyAvg, rateFloor, rateMax) {
		return nil
	}
	return &models.AnomalyAlert{
		SecretNodeID: secret.ID,
		SecretName:   secret.Name,
		AlertType:    "cumulative_rate",
		Severity:     "medium",
		Description: fmt.Sprintf("Sustained access volume: %d reads in the last 24h for a low-traffic secret (baseline ~%.1f/day); possible slow-rate exfiltration",
			count24h, baseline.dailyAvg),
		DetectedAt: now,
	}
}

// ListAlerts returns anomaly alerts. acknowledged filters by state: nil returns
// all, &true only acknowledged, &false only unacknowledged.
func (d *AnomalyDetector) ListAlerts(ctx context.Context, acknowledged *bool) ([]models.AnomalyAlert, error) {
	return d.storage.ListAnomalyAlerts(ctx, acknowledged)
}

// FilterAlerts narrows a set of alerts to those matching the given severity
// (low/medium/high) and/or alert type (off_hours/new_ip/new_user/frequency_spike/
// ml_outlier/principal_breadth).
// An empty string for either is "no constraint", so FilterAlerts(a, "", "") == a.
func FilterAlerts(alerts []models.AnomalyAlert, severity, alertType string) []models.AnomalyAlert {
	if severity == "" && alertType == "" {
		return alerts
	}
	out := make([]models.AnomalyAlert, 0, len(alerts))
	for _, a := range alerts {
		if severity != "" && a.Severity != severity {
			continue
		}
		if alertType != "" && a.AlertType != alertType {
			continue
		}
		out = append(out, a)
	}
	return out
}
