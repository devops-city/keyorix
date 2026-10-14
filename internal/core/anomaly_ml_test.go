package core

import (
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestMLConfigWithDefaults(t *testing.T) {
	t.Parallel()
	// #101: an unset seed is drawn from crypto/rand, not the fixed constant 1 — assert
	// it's positive and non-deterministic across calls, not a specific value.
	got := MLConfig{Enabled: true}.withDefaults()
	if got.Threshold != 0.60 || got.NumTrees != 100 || got.SampleSize != 256 || got.Seed <= 0 {
		t.Fatalf("defaults not applied: %+v", got)
	}
	got2 := MLConfig{Enabled: true}.withDefaults()
	if got.Seed == got2.Seed {
		t.Fatalf("two unset-seed defaults collided (seed=%d) — the seed must not be a fixed constant", got.Seed)
	}

	// Out-of-range values are corrected; valid ones are kept.
	got = MLConfig{Enabled: true, Threshold: 1.5, NumTrees: -3, SampleSize: 0, Seed: -1}.withDefaults()
	if got.Threshold != 0.60 || got.NumTrees != 100 || got.SampleSize != 256 || got.Seed <= 0 {
		t.Fatalf("out-of-range not corrected: %+v", got)
	}
	got = MLConfig{Enabled: true, Threshold: 0.8, NumTrees: 50, SampleSize: 128, Seed: 9}.withDefaults()
	if got.Threshold != 0.8 || got.NumTrees != 50 || got.SampleSize != 128 || got.Seed != 9 {
		t.Fatalf("valid values must be preserved: %+v", got)
	}
}

// buildBaselineLogs synthesises a believable 30-day access history with a graduated
// frequency distribution: a dominant service account "app" from two IPs during
// business hours, plus a rare-but-known human "alice" (~5%) from her own IP. This is
// the distribution the rules cannot fully reason about — "alice" is known, so the
// new_user rule never fires for her.
func buildBaselineLogs(n int, start time.Time) []models.SecretAccessLog {
	logs := make([]models.SecretAccessLog, 0, n)
	for i := range n {
		user, ip := "app", "10.0.0.1"
		if i%3 == 0 {
			ip = "10.0.0.2"
		}
		if i%20 == 0 { // alice ~5% of accesses, always from her own (rare) IP
			user, ip = "alice", "10.0.0.3"
		}
		day := time.Duration(i%30) * 24 * time.Hour
		hour := time.Duration(9+(i%9)) * time.Hour // business hours 09:00–17:00
		logs = append(logs, models.SecretAccessLog{
			AccessedBy: user,
			IPAddress:  ip,
			AccessTime: start.Add(-day).Truncate(24 * time.Hour).Add(hour),
		})
	}
	return logs
}

// TestMLOutlierAlertsFlagsRareKnownActor is the headline value-add: a known-but-rare
// actor at a normal business hour is flagged, while the dominant actor's identical-
// pattern access is not. Crucially the new_user/new_ip rules stay silent here (alice
// and her IP are both in the baseline), so this is a detection the rules cannot make.
func TestMLOutlierAlertsFlagsRareKnownActor(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	secret := models.SecretNode{ID: 7, Name: "prod-db"}
	baseline := buildBaselineLogs(160, now)

	recent := []models.SecretAccessLog{
		{AccessedBy: "alice", IPAddress: "10.0.0.3", AccessTime: time.Date(2026, 6, 22, 14, 0, 0, 0, time.UTC)}, // rare, known → outlier
		{AccessedBy: "app", IPAddress: "10.0.0.1", AccessTime: time.Date(2026, 6, 22, 14, 0, 0, 0, time.UTC)},   // normal → no alert
	}
	alerts := mlOutlierAlerts(secret, baseline, recent, MLConfig{Enabled: true, Seed: 1}, now)
	if len(alerts) != 1 {
		t.Fatalf("expected exactly 1 ml_outlier (the rare actor), got %d: %+v", len(alerts), alerts)
	}
	a := alerts[0]
	if a.AlertType != "ml_outlier" {
		t.Errorf("AlertType = %q, want ml_outlier", a.AlertType)
	}
	if a.SecretNodeID != 7 || a.SecretName != "prod-db" {
		t.Errorf("alert not attributed to the secret: %+v", a)
	}
	if a.AccessedBy != "alice" || a.IPAddress != "10.0.0.3" {
		t.Errorf("alert should carry the outlier accessor/IP, got by=%q ip=%q", a.AccessedBy, a.IPAddress)
	}
	if a.Severity != "medium" {
		t.Errorf("a rare-but-known actor should be medium severity, got %q", a.Severity)
	}
}

// TestMLOutlierAlertsHighSeverityForStranger confirms a brand-new actor+IP (which the
// rules also catch) scores into the high-severity band, so the ML signal corroborates
// rather than contradicts the rules.
func TestMLOutlierAlertsHighSeverityForStranger(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	secret := models.SecretNode{ID: 7, Name: "prod-db"}
	baseline := buildBaselineLogs(160, now)

	recent := []models.SecretAccessLog{
		{AccessedBy: "mallory", IPAddress: "8.8.8.8", AccessTime: time.Date(2026, 6, 22, 3, 0, 0, 0, time.UTC)},
	}
	alerts := mlOutlierAlerts(secret, baseline, recent, MLConfig{Enabled: true, Seed: 1}, now)
	if len(alerts) != 1 {
		t.Fatalf("expected the stranger to be flagged, got %d alerts", len(alerts))
	}
	if alerts[0].Severity != "high" {
		t.Errorf("a brand-new actor+IP should be high severity, got %q", alerts[0].Severity)
	}
}

func TestMLOutlierAlertsNoFalsePositiveOnNormal(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	secret := models.SecretNode{ID: 7, Name: "prod-db"}
	baseline := buildBaselineLogs(160, now)

	// Several accesses indistinguishable from the dominant baseline pattern.
	recent := []models.SecretAccessLog{
		{AccessedBy: "app", IPAddress: "10.0.0.1", AccessTime: time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)},
		{AccessedBy: "app", IPAddress: "10.0.0.2", AccessTime: time.Date(2026, 6, 22, 15, 0, 0, 0, time.UTC)},
	}
	alerts := mlOutlierAlerts(secret, baseline, recent, MLConfig{Enabled: true, Seed: 1}, now)
	if len(alerts) != 0 {
		t.Fatalf("normal-pattern accesses must not be flagged, got %d: %+v", len(alerts), alerts)
	}
}

func TestMLOutlierAlertsSkipsSparseBaseline(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	secret := models.SecretNode{ID: 7, Name: "prod-db"}
	baseline := buildBaselineLogs(mlMinTrainSamples-1, now) // below the training floor
	recent := []models.SecretAccessLog{
		{AccessedBy: "mallory", IPAddress: "8.8.8.8", AccessTime: time.Date(2026, 6, 22, 3, 0, 0, 0, time.UTC)},
	}
	if alerts := mlOutlierAlerts(secret, baseline, recent, MLConfig{Enabled: true}, now); alerts != nil {
		t.Fatalf("ML must abstain on a sparse baseline, got %+v", alerts)
	}
}

func TestMLOutlierAlertsEmptyRecent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	secret := models.SecretNode{ID: 7, Name: "prod-db"}
	baseline := buildBaselineLogs(160, now)
	if alerts := mlOutlierAlerts(secret, baseline, nil, MLConfig{Enabled: true}, now); alerts != nil {
		t.Fatalf("no recent accesses → no alerts, got %+v", alerts)
	}
}
