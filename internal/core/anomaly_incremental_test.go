package core

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// countingAnomalyStore is a real SQLite LocalStorage that counts the per-secret
// access-log reads RunDetection makes, so a test can see how many secrets a pass
// actually evaluated.
type countingAnomalyStore struct {
	perSecretReads atomic.Int64
}

func newCountingAnomalyStore(db *gorm.DB) (*hookStore, *countingAnomalyStore) {
	s := &countingAnomalyStore{}
	return hooked(store.NewLocalStorage(db), &storeHooks{
		ListSecretAccessLogs: func(next storage.Storage, ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error) {
			s.perSecretReads.Add(1)
			return next.ListSecretAccessLogs(ctx, secretID, since)
		},
	}), s
}

func newAnomalyTestDB(t testing.TB) *gorm.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "anomaly.db") + "?_busy_timeout=10000&_journal_mode=WAL"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretAccessLog{},
		&models.AnomalyAlert{}, &models.AuditEvent{}, &models.SystemMetadata{}))
	return db
}

func accessLog(id uint, who, ip string, at time.Time) models.SecretAccessLog {
	return models.SecretAccessLog{SecretNodeID: id, AccessedBy: who, IPAddress: ip, Action: "read", AccessTime: at}
}

// seedAnomalyScenario builds one dataset that trips every detection rule, plus a
// population of idle secrets that trip none. Returns the secrets to pass to
// RunDetection and the number of idle ones.
func seedAnomalyScenario(t testing.TB, db *gorm.DB, now time.Time, idle int) []models.SecretNode {
	t.Helper()
	var secrets []models.SecretNode
	var logs []models.SecretAccessLog
	known := func(id uint) { // alice@10.0.0.1, steady history 3–20 days ago: a trusted baseline, dailyAvg < 1
		for d := 3; d <= 20; d += 3 {
			logs = append(logs, accessLog(id, "alice", "10.0.0.1", now.Add(-time.Duration(d)*24*time.Hour)))
		}
	}
	add := func(id uint, name string) {
		secrets = append(secrets, models.SecretNode{ID: id, ProjectID: 1, Name: name, Status: "active", IsSecret: true})
	}

	// Idle secrets: history only, nothing in the last 24h. No rule can fire for them.
	for i := 1; i <= idle; i++ {
		add(uint(i), fmt.Sprintf("idle-%d", i))
		known(uint(i))
	}
	base := uint(idle + 100)

	add(base+1, "new-ip") // new_ip
	known(base + 1)
	logs = append(logs, accessLog(base+1, "alice", "203.0.113.7", now.Add(-20*time.Minute)))

	add(base+2, "new-user") // new_user
	known(base + 2)
	logs = append(logs, accessLog(base+2, "mallory", "10.0.0.1", now.Add(-15*time.Minute)))

	add(base+3, "spike") // frequency_spike: 15 reads in the window over a ~0/hour baseline
	known(base + 3)
	for i := range 15 {
		logs = append(logs, accessLog(base+3, "alice", "10.0.0.1", now.Add(-time.Duration(2+i)*time.Minute)))
	}

	// cumulative_rate ONLY: 25 reads 2–20h ago, none in the live 1h window. This is the
	// case a naive "only secrets touched since the last run" filter would drop.
	add(base+4, "slow-exfil")
	known(base + 4)
	for i := range 25 {
		logs = append(logs, accessLog(base+4, "alice", "10.0.0.1", now.Add(-2*time.Hour-time.Duration(i)*40*time.Minute)))
	}

	add(base+5, "off-hours") // off_hours (the test sets the band to cover `now`)
	known(base + 5)
	logs = append(logs, accessLog(base+5, "alice", "10.0.0.1", now.Add(-10*time.Minute)))

	// principal_breadth: eve's first-ever reads of 6 distinct secrets, all in the window.
	for j := range uint(6) {
		id := base + 10 + j
		add(id, fmt.Sprintf("breadth-%d", j))
		known(id)
		logs = append(logs, accessLog(id, "eve", "10.0.0.1", now.Add(-5*time.Minute)))
	}

	require.NoError(t, db.CreateInBatches(&secrets, 500).Error)
	require.NoError(t, db.CreateInBatches(&logs, 500).Error)
	return secrets
}

type alertKey struct {
	secret         uint
	typ, actor, ip string
}

func alertKeys(t testing.TB, db *gorm.DB) []alertKey {
	t.Helper()
	var rows []models.AnomalyAlert
	require.NoError(t, db.Find(&rows).Error)
	out := make([]alertKey, 0, len(rows))
	for _, r := range rows {
		out = append(out, alertKey{r.SecretNodeID, r.AlertType, r.AccessedBy, r.IPAddress})
	}
	sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i]) < fmt.Sprint(out[j]) })
	return out
}

func newScenarioDetector(t testing.TB, s StorageInterface, now time.Time) *AnomalyDetector {
	t.Helper()
	d := NewAnomalyDetector(s)
	h := now.Hour()
	require.NoError(t, d.SetBusinessHours(context.Background(), "UTC", (h+23)%24, (h+2)%24))
	return d
}

// TestRunDetection_IncrementalSweepDetectsSameAnomaliesAsFullSweep is the guard for
// the C-PERF-FIXES incremental sweep: over identical data, the incremental pass must
// record exactly the alerts the pre-change full sweep records — every rule type,
// including cumulative_rate for a secret with no access in the live window — while
// evaluating only the secrets that had activity in the detection horizon.
func TestRunDetection_IncrementalSweepDetectsSameAnomaliesAsFullSweep(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	const idle = 200

	run := func(full bool) ([]alertKey, int64) {
		db := newAnomalyTestDB(t)
		secrets := seedAnomalyScenario(t, db, now, idle)
		st, s := newCountingAnomalyStore(db)
		d := newScenarioDetector(t, st, now)
		d.fullSweep = full
		require.NoError(t, d.RunDetection(ctx, secrets))
		return alertKeys(t, db), s.perSecretReads.Load()
	}

	fullAlerts, fullReads := run(true)
	incAlerts, incReads := run(false)

	// Non-vacuity: the dataset really trips every rule under the full sweep.
	types := map[string]bool{}
	for _, k := range fullAlerts {
		types[k.typ] = true
	}
	for _, want := range []string{"new_ip", "new_user", "frequency_spike", "cumulative_rate", "off_hours", "principal_breadth"} {
		require.True(t, types[want], "scenario must trip %s under the full sweep (got %v)", want, types)
	}

	assert.Equal(t, fullAlerts, incAlerts, "the incremental sweep must detect exactly the same anomalies as the full sweep")

	// And it must actually be incremental: the 200 idle secrets are never read.
	active := int64(len(seedAnomalyScenarioActiveIDs()))
	assert.Equal(t, 2*int64(idle)+2*active, fullReads, "full sweep: two per-secret reads for every secret")
	assert.Equal(t, 2*active, incReads, "incremental sweep: two per-secret reads only for secrets active in the horizon")
}

// seedAnomalyScenarioActiveIDs is the number of non-idle secrets seedAnomalyScenario
// creates (5 single-rule secrets + 6 breadth secrets), as a slice for readability.
func seedAnomalyScenarioActiveIDs() []int { return make([]int, 11) }

// A candidate-query failure must fall back to the full sweep, never skip secrets.
func failingCandidateStore(inner *hookStore) *hookStore {
	h := *inner.h
	h.ListSecretIDsAccessedSince = func(storage.Storage, context.Context, time.Time) ([]uint, error) {
		return nil, fmt.Errorf("boom")
	}
	return hooked(inner.Storage, &h)
}

func TestRunDetection_CandidateQueryFailureFallsBackToFullSweep(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	db := newAnomalyTestDB(t)
	secrets := seedAnomalyScenario(t, db, now, 20)
	counting, s := newCountingAnomalyStore(db)
	d := newScenarioDetector(t, failingCandidateStore(counting), now)
	require.NoError(t, d.RunDetection(ctx, secrets))
	assert.Equal(t, int64(2*len(secrets)), s.perSecretReads.Load(), "every secret evaluated")
	var n int64
	slowExfil := uint(20 + 100 + 4) // seedAnomalyScenario's cumulative_rate-only secret
	require.NoError(t, db.Model(&models.AnomalyAlert{}).
		Where("alert_type = ? AND secret_node_id = ?", "cumulative_rate", slowExfil).Count(&n).Error)
	assert.Equal(t, int64(1), n, "the window-idle secret's cumulative_rate alert is still recorded")
}

// TestRunDetection_HighWaterMarkClosesTheGapBetweenPasses: a pass that starts later
// than one lookback after the previous successful pass (a jittered first pass after
// restart, an outage) must still examine the access logs in between. Before the
// high-water mark, a new-IP read 2h ago with a 1h lookback was never evaluated by any
// pass.
func TestRunDetection_HighWaterMarkClosesTheGapBetweenPasses(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	seed := func(db *gorm.DB) []models.SecretNode {
		sec := models.SecretNode{ID: 7, ProjectID: 1, Name: "gap", Status: "active", IsSecret: true}
		require.NoError(t, db.Create(&sec).Error)
		var logs []models.SecretAccessLog
		for d := 3; d <= 20; d += 3 {
			logs = append(logs, accessLog(7, "alice", "10.0.0.1", now.Add(-time.Duration(d)*24*time.Hour)))
		}
		logs = append(logs, accessLog(7, "alice", "198.51.100.9", now.Add(-2*time.Hour)))
		require.NoError(t, db.Create(&logs).Error)
		return []models.SecretNode{sec}
	}
	newIPAlerts := func(db *gorm.DB) int64 {
		var n int64
		require.NoError(t, db.Model(&models.AnomalyAlert{}).Where("alert_type = ? AND ip_address = ?", "new_ip", "198.51.100.9").Count(&n).Error)
		return n
	}

	t.Run("no high-water mark: lookback window only (control)", func(t *testing.T) {
		db := newAnomalyTestDB(t)
		secrets := seed(db)
		d := NewAnomalyDetector(store.NewLocalStorage(db))
		require.NoError(t, d.RunDetection(ctx, secrets))
		assert.Equal(t, int64(0), newIPAlerts(db), "control: the 2h-old read is outside a fresh install's 1h window")
	})

	t.Run("high-water mark 3h ago: window extends back to it", func(t *testing.T) {
		db := newAnomalyTestDB(t)
		secrets := seed(db)
		ls := store.NewLocalStorage(db)
		require.NoError(t, ls.SetSystemMetadata(ctx, anomalyHighWaterKey, now.Add(-3*time.Hour).Format(time.RFC3339Nano)))
		d := NewAnomalyDetector(ls)
		require.NoError(t, d.RunDetection(ctx, secrets))
		assert.Equal(t, int64(1), newIPAlerts(db), "the read between the last pass and this one must be evaluated")

		raw, found, err := ls.GetSystemMetadata(ctx, anomalyHighWaterKey)
		require.NoError(t, err)
		require.True(t, found)
		hw, err := time.Parse(time.RFC3339Nano, raw)
		require.NoError(t, err)
		assert.WithinDuration(t, time.Now(), hw, time.Minute, "a clean pass advances the mark to its own start")
	})

	t.Run("catch-up is capped at maxDetectionCatchUp", func(t *testing.T) {
		store := &captureStore{meta: map[string]string{anomalyHighWaterKey: now.Add(-72 * time.Hour).Format(time.RFC3339Nano)}}
		d := NewAnomalyDetector(store)
		require.NoError(t, d.RunDetection(ctx, []models.SecretNode{{ID: 1}}))
		require.Len(t, store.sinces, 2)
		assert.InDelta(t, maxDetectionCatchUp.Seconds(), time.Since(store.sinces[1]).Seconds(), 60)
	})

	t.Run("a pass with storage failures does not advance the mark", func(t *testing.T) {
		old := now.Add(-3 * time.Hour).Format(time.RFC3339Nano)
		store := &captureStore{createErr: assertAnErr, meta: map[string]string{anomalyHighWaterKey: old}}
		d := NewAnomalyDetector(store)
		require.Error(t, d.RunDetection(ctx, []models.SecretNode{{ID: 1}}))
		assert.Equal(t, old, store.meta[anomalyHighWaterKey], "the failed pass's window must be re-covered next time")
	})
}
