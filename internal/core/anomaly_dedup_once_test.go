package core

// anomaly_dedup_once_test.go — OPT-READPATH-1: a detection pass sends one
// CreateAnomalyAlert (one dedup count + transaction) per alert key, not one per
// access row in the window. Under a steady read load every read of the window is
// an access row, so the pass used to cost one anomaly_alerts count per read.

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// createCountingStore counts CreateAnomalyAlert calls per alert type and fails
// the first call for each key in failFirst.
type createCountingStore struct {
	*store.LocalStorage
	mu        sync.Mutex
	calls     map[string]int
	failFirst map[string]bool // dedupKeyString of the key
}

func dedupKeyString(secret uint, typ, actor, ip string) string {
	return fmt.Sprintf("%d|%s|%s|%s", secret, typ, actor, ip)
}

func (s *createCountingStore) CreateAnomalyAlert(ctx context.Context, a *models.AnomalyAlert) error {
	s.mu.Lock()
	s.calls[a.AlertType]++
	k := dedupKeyString(a.SecretNodeID, a.AlertType, a.AccessedBy, a.IPAddress)
	fail := s.failFirst[k]
	delete(s.failFirst, k)
	s.mu.Unlock()
	if fail {
		return fmt.Errorf("injected CreateAnomalyAlert failure")
	}
	return s.LocalStorage.CreateAnomalyAlert(ctx, a)
}

func newCreateCountingStore(db *gorm.DB) *createCountingStore {
	return &createCountingStore{LocalStorage: store.NewLocalStorage(db), calls: map[string]int{}, failFirst: map[string]bool{}}
}

// TestRunDetection_OneDedupCheckPerAlertKey is the statement count: a hot secret
// read R times in the window by one new principal from one new IP, off hours,
// yields three per-access alert keys (off_hours, new_ip, new_user). The pass must
// call CreateAnomalyAlert once per key: 3, not 3*R.
func TestRunDetection_OneDedupCheckPerAlertKey(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	const reads = 200
	db := newAnomalyTestDB(t)
	secret := models.SecretNode{ID: 7, ProjectID: 1, Name: "hot", Status: "active", IsSecret: true}
	require.NoError(t, db.Create(&secret).Error)
	logs := make([]models.SecretAccessLog, 0, reads)
	for i := range reads {
		logs = append(logs, accessLog(secret.ID, "machine:9", "198.51.100.4", now.Add(-time.Duration(i+1)*10*time.Second)))
	}
	require.NoError(t, db.CreateInBatches(&logs, 500).Error)

	s := newCreateCountingStore(db)
	d := newScenarioDetector(t, s, now)
	require.NoError(t, d.RunDetection(ctx, []models.SecretNode{secret}))

	perAccess := s.calls["off_hours"] + s.calls["new_ip"] + s.calls["new_user"]
	t.Logf("per-access CreateAnomalyAlert calls for %d reads: %d (calls by type %v)", reads, perAccess, s.calls)
	assert.Equal(t, 3, perAccess, "one dedup check per alert key per pass, not one per access row")
	var n int64
	require.NoError(t, db.Model(&models.AnomalyAlert{}).Where("secret_node_id = ?", secret.ID).
		Where("alert_type IN ?", []string{"off_hours", "new_ip", "new_user"}).Count(&n).Error)
	assert.Equal(t, int64(3), n, "the three per-access alerts are recorded")
}

// dedupMatrixRow is the part of an alert row the equivalence compares (everything
// but id and detected_at, which differs by the pass's runtime between the modes).
type dedupMatrixRow struct {
	secret                         uint
	typ, actor, ip, severity, desc string
}

// seedDedupMatrix builds secrets whose window reads cover every per-access rule,
// several principals and IPs per secret (known and unknown to the baseline),
// pre-existing alerts that do (40m old) and do not (3h old) suppress, and returns
// the keys whose first CreateAnomalyAlert call is to fail.
func seedDedupMatrix(t *testing.T, db *gorm.DB, now time.Time) ([]models.SecretNode, []string) {
	t.Helper()
	var (
		secrets   []models.SecretNode
		logs      []models.SecretAccessLog
		existing  []models.AnomalyAlert
		failFirst []string
	)
	actors := []string{"alice", "bob", "machine:3"}
	ips := []string{"10.0.0.1", "203.0.113.9", "198.51.100.4"}
	for id := uint(1); id <= 12; id++ {
		secrets = append(secrets, models.SecretNode{ID: id, ProjectID: 1, Name: fmt.Sprintf("m-%d", id), Status: "active", IsSecret: true})
		if id%3 != 0 { // baseline: alice@10.0.0.1 known; every third secret has none
			for d := 3; d <= 20; d += 3 {
				logs = append(logs, accessLog(id, "alice", "10.0.0.1", now.Add(-time.Duration(d)*24*time.Hour)))
			}
		}
		for i := range int(id) * 7 { // window reads, interleaved principals and IPs
			logs = append(logs, accessLog(id, actors[(i+int(id))%len(actors)], ips[(i/2+int(id))%len(ips)],
				now.Add(-time.Duration(i+1)*13*time.Second)))
		}
		switch id % 4 {
		case 1: // an equivalent alert 40m old: suppresses new_ip from 203.0.113.9 by bob
			existing = append(existing, models.AnomalyAlert{SecretNodeID: id, SecretName: "m", AlertType: "new_ip", Severity: "high",
				Description: "pre-existing", AccessedBy: "bob", IPAddress: "203.0.113.9", DetectedAt: now.Add(-40 * time.Minute)})
		case 2: // 3h old: outside the dedup window, suppresses nothing
			existing = append(existing, models.AnomalyAlert{SecretNodeID: id, SecretName: "m", AlertType: "off_hours", Severity: "medium",
				Description: "pre-existing", AccessedBy: "alice", IPAddress: "10.0.0.1", DetectedAt: now.Add(-3 * time.Hour)})
		case 3:
			failFirst = append(failFirst, dedupKeyString(id, "off_hours", "bob", "198.51.100.4"),
				dedupKeyString(id, "new_user", "machine:3", "10.0.0.1"))
		}
	}
	require.NoError(t, db.CreateInBatches(&secrets, 500).Error)
	require.NoError(t, db.CreateInBatches(&logs, 500).Error)
	require.NoError(t, db.CreateInBatches(&existing, 500).Error)
	return secrets, failFirst
}

// TestRunDetection_DedupOnceEquivalence: over identical data, the pass that skips
// settled keys records exactly the alert rows (and reports exactly the failures)
// the pass that checks every access row against storage records.
func TestRunDetection_DedupOnceEquivalence(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	run := func(everyAccess bool) ([]dedupMatrixRow, string, map[string]int) {
		db := newAnomalyTestDB(t)
		secrets, failFirst := seedDedupMatrix(t, db, now)
		s := newCreateCountingStore(db)
		for _, k := range failFirst {
			s.failFirst[k] = true
		}
		d := newScenarioDetector(t, s, now)
		d.everyAccessDedup = everyAccess
		errText := ""
		if err := d.RunDetection(ctx, secrets); err != nil {
			errText = err.Error()
		}
		var alerts []models.AnomalyAlert
		require.NoError(t, db.Find(&alerts).Error)
		rows := make([]dedupMatrixRow, 0, len(alerts))
		for _, a := range alerts {
			rows = append(rows, dedupMatrixRow{a.SecretNodeID, a.AlertType, a.AccessedBy, a.IPAddress, a.Severity, a.Description})
		}
		sort.Slice(rows, func(i, j int) bool { return fmt.Sprint(rows[i]) < fmt.Sprint(rows[j]) })
		return rows, errText, s.calls
	}
	before, beforeErr, beforeCalls := run(true)
	after, afterErr, afterCalls := run(false)

	types := map[string]bool{}
	for _, r := range before {
		types[r.typ] = true
	}
	for _, want := range []string{"off_hours", "new_ip", "new_user"} {
		require.True(t, types[want], "matrix must trip %s (got %v)", want, types)
	}
	require.NotEmpty(t, beforeErr, "matrix must exercise the injected failures")
	assert.Equal(t, before, after, "same alert rows")
	assert.Equal(t, beforeErr, afterErr, "same failures reported")
	t.Logf("CreateAnomalyAlert calls: every access row %v, once per key %v", beforeCalls, afterCalls)
	assert.Less(t, afterCalls["off_hours"], beforeCalls["off_hours"])
}

// BenchmarkRunDetection_HotSecret is one steady-state detection pass over a hot
// secret read 2 000 times in the window (its alerts already recorded), checking
// every access row against storage versus once per alert key.
func BenchmarkRunDetection_HotSecret(b *testing.B) {
	for _, mode := range []struct {
		name        string
		everyAccess bool
	}{{"every-access-row", true}, {"once-per-key", false}} {
		b.Run(mode.name, func(b *testing.B) {
			ctx := context.Background()
			now := time.Now().UTC()
			db := newAnomalyTestDB(b)
			secret := models.SecretNode{ID: 7, ProjectID: 1, Name: "hot", Status: "active", IsSecret: true}
			require.NoError(b, db.Create(&secret).Error)
			logs := make([]models.SecretAccessLog, 0, 2000)
			for i := range 2000 {
				logs = append(logs, accessLog(secret.ID, "machine:9", "198.51.100.4", now.Add(-time.Duration(i+1)*time.Second)))
			}
			require.NoError(b, db.CreateInBatches(&logs, 500).Error)
			d := newScenarioDetector(b, store.NewLocalStorage(db), now)
			d.everyAccessDedup = mode.everyAccess
			require.NoError(b, d.RunDetection(ctx, []models.SecretNode{secret})) // records the alerts
			b.ResetTimer()
			for range b.N {
				require.NoError(b, d.RunDetection(ctx, []models.SecretNode{secret}))
			}
		})
	}
}
