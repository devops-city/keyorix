package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStore records the `since` lower bound of every ListSecretAccessLogs call so a
// test can assert the detection window honors the configured lookback. It returns one
// baseline log so RunDetection proceeds past the empty-history skip.
type captureStore struct {
	sinces       []time.Time
	createErr    error
	createdCount int
	auditCount   int
	meta         map[string]string
}

func (c *captureStore) ListSecretAccessLogs(_ context.Context, _ uint, since time.Time) ([]models.SecretAccessLog, error) {
	c.sinces = append(c.sinces, since)
	// A known user/IP (so new_user/new_ip never fire) at a deterministic OFF-HOURS time
	// (23:00 UTC ∈ the default 22:00–06:00 window), so detectAnomalies always yields
	// exactly one off_hours alert — making the storage-failure path deterministic.
	return []models.SecretAccessLog{{
		AccessedBy: "alice", IPAddress: "10.0.0.1",
		AccessTime: time.Date(2026, 6, 20, 23, 0, 0, 0, time.UTC),
	}}, nil
}
func (c *captureStore) CreateAnomalyAlert(_ context.Context, _ *models.AnomalyAlert) error {
	c.createdCount++
	return c.createErr
}
func (c *captureStore) ListAnomalyAlerts(_ context.Context, _ *bool) ([]models.AnomalyAlert, error) {
	return nil, nil
}
func (c *captureStore) PrincipalSecretFirstSeen(_ context.Context, _ time.Time) (map[string]map[uint]time.Time, error) {
	return nil, nil
}
func (c *captureStore) LogAuditEvent(_ context.Context, _ *models.AuditEvent) error {
	c.auditCount++
	return nil
}

// ListSecretIDsAccessedSince reports secrets 1 and 2 as active — consistent with
// ListSecretAccessLogs above returning a row for every secret — so the incremental
// sweep evaluates exactly the secrets these tests pass in.
func (c *captureStore) ListSecretIDsAccessedSince(_ context.Context, _ time.Time) ([]uint, error) {
	return []uint{1, 2}, nil
}
func (c *captureStore) GetSystemMetadata(_ context.Context, key string) (string, bool, error) {
	v, ok := c.meta[key]
	return v, ok, nil
}
func (c *captureStore) SetSystemMetadata(_ context.Context, key, value string) error {
	if c.meta == nil {
		c.meta = map[string]string{}
	}
	c.meta[key] = value
	return nil
}

// The recent-access scan window must honor the configured lookback (so a longer scan
// cadence scans a proportionally longer window), and be floored at one hour.
func TestRunDetection_ScanWindowHonorsLookback(t *testing.T) {
	t.Run("longer lookback widens the window", func(t *testing.T) {
		store := &captureStore{}
		d := NewAnomalyDetector(store)
		d.SetLookback(6 * time.Hour)
		require.NoError(t, d.RunDetection(context.Background(), []models.SecretNode{{ID: 1}}))

		require.Len(t, store.sinces, 2, "one baseline query + one recent-window query")
		recentSince := store.sinces[1] // the second call uses the lookback window
		gap := time.Now().UTC().Sub(recentSince)
		assert.InDelta(t, (6 * time.Hour).Seconds(), gap.Seconds(), 60, "recent window must span the 6h lookback")
	})

	t.Run("sub-hour lookback is floored at 1h", func(t *testing.T) {
		store := &captureStore{}
		d := NewAnomalyDetector(store)
		d.SetLookback(5 * time.Minute) // below the floor
		require.NoError(t, d.RunDetection(context.Background(), []models.SecretNode{{ID: 1}}))

		gap := time.Now().UTC().Sub(store.sinces[1])
		assert.InDelta(t, time.Hour.Seconds(), gap.Seconds(), 60, "the window floors at 1h")
	})
}

// A storage failure during detection must surface as a non-nil error so the scheduler
// records a partial failure rather than reporting a clean pass.
func TestRunDetection_SurfacesStorageFailure(t *testing.T) {
	store := &captureStore{createErr: assertAnErr}
	d := NewAnomalyDetector(store)
	// The store always yields one off_hours alert, whose insert fails → a surfaced error.
	err := d.RunDetection(context.Background(), []models.SecretNode{{ID: 1, Name: "s"}})
	require.Positive(t, store.createdCount, "the off_hours access must produce an alert to persist")
	require.Error(t, err, "a failed alert insert must surface as a pass error")
}

var assertAnErr = &detectionTestErr{}

type detectionTestErr struct{}

func (*detectionTestErr) Error() string { return "boom" }

// perSecretFailStore fails ListSecretAccessLogs only for a chosen secret ID (on
// whichever call — baseline or recent-window — comes first for that secret), letting
// other secrets in the same RunDetection pass succeed normally. Lets a test tell "one
// secret's read failed" apart from "every read failed".
type perSecretFailStore struct {
	*captureStore
	failSecretID uint
}

func (s *perSecretFailStore) ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error) {
	if secretID == s.failSecretID {
		return nil, assertAnErr
	}
	return s.captureStore.ListSecretAccessLogs(ctx, secretID, since)
}

// #365: a ListSecretAccessLogs failure for one secret must (a) be logged with the
// specific secret ID so an operator can tell a transient hiccup from a genuine gap
// (the detection window is only the last hour and is never retroactively
// re-evaluated), and (b) not block detection for a sibling secret in the same pass.
func TestRunDetection_LogsAndContinuesOnAccessLogReadError(t *testing.T) {
	store := &perSecretFailStore{captureStore: &captureStore{}, failSecretID: 1}
	d := NewAnomalyDetector(store)

	var err error
	logged := captureLog(t, func() {
		err = d.RunDetection(context.Background(), []models.SecretNode{{ID: 1, Name: "broken"}, {ID: 2, Name: "healthy"}})
	})
	require.Error(t, err, "a per-secret read failure must surface as a non-nil pass error, not a silent success")
	assert.Contains(t, err.Error(), "1 storage failure")

	// The healthy secret's baseline+recent calls both went through despite secret 1's
	// failure — RunDetection didn't abort the whole pass.
	assert.GreaterOrEqual(t, len(store.sinces), 2, "the healthy secret's reads still ran")

	assert.Contains(t, logged, "secret 1", "the failing secret's ID must appear in the operator-visible log line")
}

func TestBuildBaseline(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	windowStart := now.Add(-1 * time.Hour) // the live detection window — excluded from the baseline
	// Each trusted IP/user appears baselineMinSeen (3) times so the count-based
	// promotion threshold is met. Mallory's single in-window read must remain excluded.
	logs := []models.SecretAccessLog{
		{IPAddress: "203.0.113.9", AccessedBy: "mallory", AccessTime: now.Add(-30 * time.Minute)}, // inside window → excluded
		// bob: 3 appearances in the 7-day window, all before windowStart
		{IPAddress: "10.0.0.2", AccessedBy: "bob", AccessTime: now.Add(-2 * 24 * time.Hour)},
		{IPAddress: "10.0.0.2", AccessedBy: "bob", AccessTime: now.Add(-3 * 24 * time.Hour)},
		{IPAddress: "10.0.0.2", AccessedBy: "bob", AccessTime: now.Add(-4 * 24 * time.Hour)},
		// alice: 3 appearances, all older than 7 days (outside dailyAvg window)
		{IPAddress: "10.0.0.1", AccessedBy: "alice", AccessTime: now.Add(-20 * 24 * time.Hour)},
		{IPAddress: "10.0.0.1", AccessedBy: "alice", AccessTime: now.Add(-21 * 24 * time.Hour)},
		{IPAddress: "10.0.0.1", AccessedBy: "alice", AccessTime: now.Add(-22 * 24 * time.Hour)},
	}
	// quarantine=0: isolates this test to the live-window exclusion behavior; the
	// quarantine-specific promotion delay is covered separately by
	// TestBuildBaseline_QuarantineWithholdsRecentlySeenIdentities.
	b := buildBaseline(logs, now, windowStart, 0)
	// The in-window read must NOT seed the baseline, else it would mask its own anomaly.
	if b.knownIPs["203.0.113.9"] || b.knownUsers["mallory"] {
		t.Fatalf("in-window read must be excluded from the baseline, got IPs=%v users=%v", b.knownIPs, b.knownUsers)
	}
	if !b.knownIPs["10.0.0.1"] || !b.knownIPs["10.0.0.2"] {
		t.Fatalf("expected historical IPs learned, got %v", b.knownIPs)
	}
	if !b.knownUsers["alice"] || !b.knownUsers["bob"] {
		t.Fatalf("expected historical users learned, got %v", b.knownUsers)
	}
	// Of the pre-window reads, only bob's three entries (-2d, -3d, -4d) are within the
	// last 7 days → recentCount = 3; dailyAvg = 3/7.
	if want := 3.0 / 7.0; b.dailyAvg != want {
		t.Fatalf("dailyAvg = %v, want %v", b.dailyAvg, want)
	}
}

// #101: an IP/user must have been observed for at least `quarantine` before the live
// window, not merely before it, to be trusted as baseline — otherwise a single access
// one lookback interval ago (e.g. 1h) is enough to poison the baseline and silence
// new_ip/new_user for that identity on the very next pass.
//
// ANOMALY-02: additionally requires baselineMinSeen distinct observations before
// promotion — a single pre-quarantine access is no longer sufficient.
func TestBuildBaseline_QuarantineWithholdsRecentlySeenIdentities(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	windowStart := now.Add(-1 * time.Hour)
	quarantine := 24 * time.Hour
	logs := []models.SecretAccessLog{
		// Mallory: 3 accesses that are all within quarantine (2h before window) — must stay quarantined.
		{IPAddress: "203.0.113.9", AccessedBy: "mallory", AccessTime: windowStart.Add(-2 * time.Hour)},
		{IPAddress: "203.0.113.9", AccessedBy: "mallory", AccessTime: windowStart.Add(-3 * time.Hour)},
		{IPAddress: "203.0.113.9", AccessedBy: "mallory", AccessTime: windowStart.Add(-4 * time.Hour)},
		// Alice: 3 accesses, all 48h before the live window — clears the 24h quarantine.
		{IPAddress: "10.0.0.1", AccessedBy: "alice", AccessTime: windowStart.Add(-48 * time.Hour)},
		{IPAddress: "10.0.0.1", AccessedBy: "alice", AccessTime: windowStart.Add(-49 * time.Hour)},
		{IPAddress: "10.0.0.1", AccessedBy: "alice", AccessTime: windowStart.Add(-50 * time.Hour)},
	}
	b := buildBaseline(logs, now, windowStart, quarantine)
	if b.knownIPs["203.0.113.9"] || b.knownUsers["mallory"] {
		t.Fatalf("a recently-first-seen identity must stay quarantined, got IPs=%v users=%v", b.knownIPs, b.knownUsers)
	}
	if !b.knownIPs["10.0.0.1"] || !b.knownUsers["alice"] {
		t.Fatalf("an identity first seen before the quarantine cutoff must be trusted, got IPs=%v users=%v", b.knownIPs, b.knownUsers)
	}
}

func TestLogsBefore(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	cutoff := now.Add(-1 * time.Hour)
	logs := []models.SecretAccessLog{
		{AccessedBy: "old", AccessTime: now.Add(-2 * time.Hour)},      // before cutoff → kept
		{AccessedBy: "edge", AccessTime: cutoff},                      // exactly at cutoff → excluded (strictly before)
		{AccessedBy: "recent", AccessTime: now.Add(-1 * time.Minute)}, // after cutoff → excluded
	}
	got := logsBefore(logs, cutoff)
	if len(got) != 1 || got[0].AccessedBy != "old" {
		t.Fatalf("logsBefore should keep only the pre-cutoff log, got %+v", got)
	}
}

func TestDetectAnomalies(t *testing.T) {
	secret := models.SecretNode{ID: 1, Name: "db"}
	baseline := accessBaseline{
		knownIPs:   map[string]bool{"10.0.0.1": true},
		knownUsers: map[string]bool{"alice": true},
	}

	t.Run("off-hours + new IP + new user all fire", func(t *testing.T) {
		// 03:00 UTC is off-hours; unknown IP + unknown user against a non-empty baseline.
		lg := models.SecretAccessLog{
			IPAddress:  "8.8.8.8",
			AccessedBy: "mallory",
			AccessTime: time.Date(2026, 6, 17, 3, 0, 0, 0, time.UTC),
		}
		got := kindsOf(detectAnomalies(secret, lg, baseline, defaultOffHoursPolicy()))
		for _, want := range []string{"off_hours", "new_ip", "new_user"} {
			if !got[want] {
				t.Errorf("expected %s alert, got %v", want, got)
			}
		}
	})

	t.Run("business-hours known IP+user → no alert", func(t *testing.T) {
		lg := models.SecretAccessLog{
			IPAddress:  "10.0.0.1",
			AccessedBy: "alice",
			AccessTime: time.Date(2026, 6, 17, 14, 0, 0, 0, time.UTC),
		}
		if alerts := detectAnomalies(secret, lg, baseline, defaultOffHoursPolicy()); len(alerts) != 0 {
			t.Fatalf("expected no alerts, got %v", kindsOf(alerts))
		}
	})

	t.Run("empty baseline still flags first-ever access, at low severity (#101)", func(t *testing.T) {
		// A brand-new secret's first-ever access used to be silently waved through with
		// zero novelty signal — exactly the blind spot an attacker deliberately
		// targeting a freshly-provisioned, never-accessed secret would rely on. It must
		// now still surface (auditable), but at "low" severity since there's no
		// established pattern being violated, only an absence of history. Business-hours
		// time so only new_ip/new_user are in play.
		lg := models.SecretAccessLog{
			IPAddress:  "8.8.8.8",
			AccessedBy: "mallory",
			AccessTime: time.Date(2026, 6, 17, 14, 0, 0, 0, time.UTC),
		}
		empty := accessBaseline{knownIPs: map[string]bool{}, knownUsers: map[string]bool{}}
		alerts := detectAnomalies(secret, lg, empty, defaultOffHoursPolicy())
		got := kindsOf(alerts)
		for _, want := range []string{"new_ip", "new_user"} {
			if !got[want] {
				t.Errorf("expected %s alert against an empty baseline, got %v", want, got)
			}
		}
		for _, a := range alerts {
			if a.Severity != "low" {
				t.Errorf("expected low severity for a first-ever access with no baseline, got %s alert at %s", a.AlertType, a.Severity)
			}
		}
	})
}

// The off-hours decision must be evaluated in the configured timezone: the same
// instant can be off-hours in UTC but business hours elsewhere. This is the bug the
// hardcoded-UTC rule had on non-UTC deployments.
func TestOffHoursPolicy(t *testing.T) {
	la, err := time.LoadLocation("America/Los_Angeles")
	require.NoError(t, err)

	// 2026-06-17 01:00 UTC == 2026-06-16 18:00 PDT (UTC-7 in summer).
	instant := time.Date(2026, 6, 17, 1, 0, 0, 0, time.UTC)

	if !defaultOffHoursPolicy().isOffHours(instant) {
		t.Errorf("01:00 UTC must be off-hours under the UTC 22–6 default")
	}
	pacific := offHoursPolicy{loc: la, start: 22, end: 6}
	if pacific.isOffHours(instant) {
		t.Errorf("18:00 PDT (same instant) must NOT be off-hours under a Pacific 22–6 band")
	}

	// A non-wrapping band [9,17) is a normal interval.
	day := offHoursPolicy{loc: time.UTC, start: 9, end: 17}
	if !day.isOffHours(time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("12:00 must fall inside a non-wrapping [9,17) band")
	}
	if day.isOffHours(time.Date(2026, 6, 17, 20, 0, 0, 0, time.UTC)) {
		t.Errorf("20:00 must fall outside a non-wrapping [9,17) band")
	}
}

func TestSetBusinessHours(t *testing.T) {
	d := NewAnomalyDetector(nil)

	ctx := context.Background()

	// Timezone only: the default 22–6 band is kept (both hours 0 = unset).
	require.NoError(t, d.SetBusinessHours(ctx, "America/New_York", 0, 0))
	assert.Equal(t, "America/New_York", d.offHours.loc.String())
	assert.Equal(t, 22, d.offHours.start)
	assert.Equal(t, 6, d.offHours.end)

	// Custom band applied.
	require.NoError(t, d.SetBusinessHours(ctx, "UTC", 20, 7))
	assert.Equal(t, 20, d.offHours.start)
	assert.Equal(t, 7, d.offHours.end)

	// Invalid timezone: error, and the prior policy is left unchanged.
	before := d.offHours
	require.Error(t, d.SetBusinessHours(ctx, "Not/AZone", 1, 2))
	assert.Equal(t, before, d.offHours, "an invalid timezone must not mutate the policy")

	// #144: a degenerate non-zero start==end band matches no hour in isOffHours,
	// silently disabling the rule — must be rejected, and the prior policy kept.
	before = d.offHours
	err := d.SetBusinessHours(ctx, "UTC", 9, 9)
	require.Error(t, err, "an equal, non-zero start/end band must be rejected")
	assert.Contains(t, err.Error(), "must differ")
	assert.Equal(t, before, d.offHours, "a rejected degenerate band must not mutate the policy")
}

// TestSetBusinessHours_PartialUpdateCollision covers wave6/G05: a partial-update
// caller (e.g. one that fetches the persisted config and overlays only the field it
// means to change) can supply one genuinely valid hour that happens to numerically
// collide with the OTHER field's still-in-effect value. The pre-fix bug only checked
// startHour==endHour on the RAW inputs when BOTH independently passed validHour, so
// an out-of-range value on the untouched field slipped past that check, silently fell
// back to the hardcoded default (22 start / 6 end), and could collide with the
// explicitly-supplied field to produce a degenerate, zero-width band with no error.
func TestSetBusinessHours_PartialUpdateCollision(t *testing.T) {
	ctx := context.Background()

	// startHour=6 collides with the hardcoded default endHour (6) once endHour is
	// out of range and silently falls back to that default.
	t.Run("valid start collides with default end via out-of-range end", func(t *testing.T) {
		d := NewAnomalyDetector(nil)
		before := d.offHours
		err := d.SetBusinessHours(ctx, "", 6, -1)
		require.Error(t, err, "an out-of-range end_hour must be rejected, not silently defaulted")
		assert.Equal(t, before, d.offHours, "a rejected config must not mutate the policy")
	})

	// endHour=22 collides with the hardcoded default startHour (22) once startHour is
	// out of range and silently falls back to that default.
	t.Run("valid end collides with default start via out-of-range start", func(t *testing.T) {
		d := NewAnomalyDetector(nil)
		before := d.offHours
		err := d.SetBusinessHours(ctx, "", 99, 22)
		require.Error(t, err, "an out-of-range start_hour must be rejected, not silently defaulted")
		assert.Equal(t, before, d.offHours, "a rejected config must not mutate the policy")
	})

	// The legitimate "explicitly disabled/keep default" state — both hours 0 — must
	// still work: this is the one deliberate way to request the default band, distinct
	// from an accidental collision, and must not be broken by the stricter validation.
	t.Run("both zero still explicitly keeps the default band", func(t *testing.T) {
		d := NewAnomalyDetector(nil)
		err := d.SetBusinessHours(ctx, "", 0, 0)
		require.NoError(t, err)
		assert.Equal(t, 22, d.offHours.start)
		assert.Equal(t, 6, d.offHours.end)
	})

	// A genuinely valid, non-colliding, fully-supplied pair must still be accepted.
	t.Run("valid distinct pair is accepted", func(t *testing.T) {
		d := NewAnomalyDetector(nil)
		err := d.SetBusinessHours(ctx, "", 6, 18)
		require.NoError(t, err)
		assert.Equal(t, 6, d.offHours.start)
		assert.Equal(t, 18, d.offHours.end)
	})
}

// TestSetBusinessHours_AuditsOnlyOnChange is the findings-core-2/core-anomaly.json#1
// regression: ApplyAnomalyConfig re-applies the persisted off-hours config via
// SetBusinessHours on every scheduler tick (server/main.go's "Hotload" comment), and
// SetBusinessHours previously wrote an anomaly.business_hours_configured audit event
// unconditionally on every successful call -- so an unchanged persisted config wrote
// a fresh, identical audit event every tick, defeating the event's change-tracking
// purpose and growing the audit table without bound. Repeated calls with the SAME
// band/timezone must audit exactly once; a genuine change must still audit again.
func TestSetBusinessHours_AuditsOnlyOnChange(t *testing.T) {
	store := &captureStore{}
	d := NewAnomalyDetector(store)
	ctx := context.Background()

	// The very first call has no prior known state and must be audited.
	require.NoError(t, d.SetBusinessHours(ctx, "UTC", 20, 7))
	assert.Equal(t, 1, store.auditCount)

	// Repeated calls with the SAME config (simulating ApplyAnomalyConfig's
	// per-scheduler-tick hotload) must NOT audit again.
	for range 4 {
		require.NoError(t, d.SetBusinessHours(ctx, "UTC", 20, 7))
	}
	assert.Equal(t, 1, store.auditCount, "an unchanged band/timezone must not re-audit on every hotload tick")

	// A genuine band change must audit again.
	require.NoError(t, d.SetBusinessHours(ctx, "UTC", 21, 7))
	assert.Equal(t, 2, store.auditCount)

	// A timezone-only change (same hours) is also a genuine change.
	require.NoError(t, d.SetBusinessHours(ctx, "America/New_York", 21, 7))
	assert.Equal(t, 3, store.auditCount)

	// "" and "UTC" resolve to the same canonical location and must NOT be treated
	// as a change from one another.
	d2 := NewAnomalyDetector(store)
	require.NoError(t, d2.SetBusinessHours(ctx, "UTC", 0, 0))
	assert.Equal(t, 4, store.auditCount)
	require.NoError(t, d2.SetBusinessHours(ctx, "", 0, 0))
	assert.Equal(t, 4, store.auditCount, "\"\" and \"UTC\" resolve to the same location and must not re-audit")
}

func TestVolumeSpike(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	secret := models.SecretNode{ID: 1, Name: "db"}

	// Busy secret: dailyAvg 240 → hourlyAvg 10. Threshold = 3×10 = 30, floor 10.
	busy := accessBaseline{dailyAvg: 240}
	if isVolumeSpike(25, busy, volumeSpikeMinCount) {
		t.Error("25 reads vs a 10/hour baseline should NOT be a spike (≤ 3×)")
	}
	if !isVolumeSpike(40, busy, volumeSpikeMinCount) {
		t.Error("40 reads vs a 10/hour baseline should be a spike (> 3×)")
	}

	// Quiet secret: tiny baseline, but the absolute floor prevents flagging a few reads.
	quiet := accessBaseline{dailyAvg: 1}
	if isVolumeSpike(9, quiet, volumeSpikeMinCount) {
		t.Error("9 reads is below the absolute floor and must not flag")
	}
	if !isVolumeSpike(12, quiet, volumeSpikeMinCount) {
		t.Error("12 reads on a near-zero baseline should flag (floor met, far above 3×)")
	}

	// volumeSpikeAlert wraps the decision and carries no single accessor/IP.
	if a := volumeSpikeAlert(secret, 25, busy, volumeSpikeMinCount, now); a != nil {
		t.Errorf("expected nil alert below threshold, got %+v", a)
	}
	a := volumeSpikeAlert(secret, 40, busy, volumeSpikeMinCount, now)
	if a == nil || a.AlertType != "frequency_spike" || a.SecretNodeID != 1 {
		t.Fatalf("expected a frequency_spike alert for secret 1, got %+v", a)
	}
	if a.AccessedBy != "" || a.IPAddress != "" {
		t.Errorf("aggregate spike alert should carry no accessor/IP, got by=%q ip=%q", a.AccessedBy, a.IPAddress)
	}
}

func TestFilterAlerts(t *testing.T) {
	alerts := []models.AnomalyAlert{
		{AlertType: "off_hours", Severity: "medium"},
		{AlertType: "new_ip", Severity: "high"},
		{AlertType: "frequency_spike", Severity: "medium"},
		{AlertType: "new_user", Severity: "high"},
	}

	// No constraint returns the input unchanged.
	assert.Len(t, FilterAlerts(alerts, "", ""), 4)

	// Severity only.
	high := FilterAlerts(alerts, "high", "")
	assert.Len(t, high, 2)
	for _, a := range high {
		assert.Equal(t, "high", a.Severity)
	}

	// Type only.
	spikes := FilterAlerts(alerts, "", "frequency_spike")
	require.Len(t, spikes, 1)
	assert.Equal(t, "frequency_spike", spikes[0].AlertType)

	// Both must match (AND).
	assert.Empty(t, FilterAlerts(alerts, "high", "frequency_spike"), "high + frequency_spike matches nothing here")
	require.Len(t, FilterAlerts(alerts, "medium", "off_hours"), 1)
}

func kindsOf(alerts []models.AnomalyAlert) map[string]bool {
	m := map[string]bool{}
	for _, a := range alerts {
		m[a.AlertType] = true
	}
	return m
}

// ANOMALY-02: a single pre-quarantine access must NOT promote an IP/user to "known."
// The attacker must appear at least baselineMinSeen times before the trust promotion fires.
func TestBuildBaseline_SingleAccessDoesNotTrust(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	windowStart := now.Add(-1 * time.Hour)
	// One access, well outside the quarantine window. Under the old (boolean) logic this
	// would immediately promote "attacker" to "known" — the very attack being mitigated.
	logs := []models.SecretAccessLog{
		{IPAddress: "1.2.3.4", AccessedBy: "attacker", AccessTime: windowStart.Add(-48 * time.Hour)},
	}
	b := buildBaseline(logs, now, windowStart, 24*time.Hour)
	if b.knownIPs["1.2.3.4"] {
		t.Fatalf("a single pre-quarantine access must NOT promote the IP to 'known' (needs %d occurrences, got 1)", baselineMinSeen)
	}
	if b.knownUsers["attacker"] {
		t.Fatalf("a single pre-quarantine access must NOT promote the user to 'known' (needs %d occurrences, got 1)", baselineMinSeen)
	}

	// Two accesses: still below the threshold.
	logs = append(logs, models.SecretAccessLog{
		IPAddress: "1.2.3.4", AccessedBy: "attacker", AccessTime: windowStart.Add(-50 * time.Hour),
	})
	b = buildBaseline(logs, now, windowStart, 24*time.Hour)
	if b.knownIPs["1.2.3.4"] || b.knownUsers["attacker"] {
		t.Fatalf("two accesses must still be below the baselineMinSeen=%d threshold", baselineMinSeen)
	}

	// Exactly baselineMinSeen accesses: must promote now.
	logs = append(logs, models.SecretAccessLog{
		IPAddress: "1.2.3.4", AccessedBy: "attacker", AccessTime: windowStart.Add(-52 * time.Hour),
	})
	b = buildBaseline(logs, now, windowStart, 24*time.Hour)
	if !b.knownIPs["1.2.3.4"] {
		t.Fatalf("at baselineMinSeen=%d occurrences the IP must be trusted, got knownIPs=%v", baselineMinSeen, b.knownIPs)
	}
	if !b.knownUsers["attacker"] {
		t.Fatalf("at baselineMinSeen=%d occurrences the user must be trusted, got knownUsers=%v", baselineMinSeen, b.knownUsers)
	}
}

// ANOMALY-06: the 24h cumulative rate rule must fire when a low-traffic secret
// receives more than the configured threshold of accesses in a rolling 24h window,
// even when each individual hour stays below the per-hour spike floor.
func TestCumulativeRateAnomaly(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	secret := models.SecretNode{ID: 42, Name: "quiet-secret"}

	// Zero dailyAvg: this secret is normally never accessed.
	zeroAvg := accessBaseline{dailyAvg: 0}

	// At or below the max: no alert.
	if isCumulativeRateAnomaly(defaultCumulativeRateMax, zeroAvg.dailyAvg, defaultCumulativeRateFloor, defaultCumulativeRateMax) {
		t.Errorf("exactly at the max (%d) must not fire", defaultCumulativeRateMax)
	}
	// One over the max: must fire.
	if !isCumulativeRateAnomaly(defaultCumulativeRateMax+1, zeroAvg.dailyAvg, defaultCumulativeRateFloor, defaultCumulativeRateMax) {
		t.Errorf("count=%d (max+1) on a zero-avg secret must fire the cumulative rule", defaultCumulativeRateMax+1)
	}

	// A secret with dailyAvg >= floor must NOT be flagged by the cumulative rule —
	// the per-hour spike rule covers it.
	highAvg := accessBaseline{dailyAvg: defaultCumulativeRateFloor} // exactly at the floor
	if isCumulativeRateAnomaly(100, highAvg.dailyAvg, defaultCumulativeRateFloor, defaultCumulativeRateMax) {
		t.Errorf("a secret at or above the floor (dailyAvg=%.1f) must not be subject to the cumulative rule", highAvg.dailyAvg)
	}

	// cumulativeRateAlert wrapper: must return a cumulative_rate alert.
	a := cumulativeRateAlert(secret, defaultCumulativeRateMax+1, zeroAvg, defaultCumulativeRateFloor, defaultCumulativeRateMax, now)
	if a == nil {
		t.Fatal("cumulativeRateAlert must return an alert when the threshold is exceeded")
	}
	if a.AlertType != "cumulative_rate" {
		t.Errorf("AlertType = %q, want cumulative_rate", a.AlertType)
	}
	if a.SecretNodeID != 42 {
		t.Errorf("alert not attributed to the secret: %+v", a)
	}
	// Below threshold: must return nil.
	if cumulativeRateAlert(secret, 5, zeroAvg, defaultCumulativeRateFloor, defaultCumulativeRateMax, now) != nil {
		t.Error("below threshold must not produce an alert")
	}
}

// ANOMALY-02 + ANOMALY-06 (configurable volume floor): verify that SetVolumeMinCount
// overrides the default floor, allowing detection of bursts below volumeSpikeMinCount.
func TestVolumeSpike_ConfigurableFloor(t *testing.T) {
	baseline := accessBaseline{dailyAvg: 0}
	// Default floor: 9 reads must not flag.
	if isVolumeSpike(9, baseline, volumeSpikeMinCount) {
		t.Error("9 reads below default floor must not flag")
	}
	// With a lower configurable floor of 5, 7 reads must flag (>> 3× near-zero avg).
	if !isVolumeSpike(7, baseline, 5) {
		t.Error("7 reads above a custom floor of 5 must flag on a near-zero baseline")
	}
}
