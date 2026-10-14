package siem

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDelivery records delivered event IDs and can be toggled to fail.
type fakeDelivery struct {
	mu        sync.Mutex
	failing   bool
	delivered []uint
}

func (d *fakeDelivery) deliver(_ context.Context, e *models.AuditEvent) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failing {
		return assertErr
	}
	d.delivered = append(d.delivered, e.ID)
	return nil
}

func (d *fakeDelivery) setFailing(v bool) { d.mu.Lock(); d.failing = v; d.mu.Unlock() }
func (d *fakeDelivery) count() int        { d.mu.Lock(); defer d.mu.Unlock(); return len(d.delivered) }

var assertErr = &deliveryError{}

type deliveryError struct{}

func (*deliveryError) Error() string { return "siem down" }

func TestSpool_PersistsAndReplaysOnRecovery(t *testing.T) {
	dir := t.TempDir()
	d := &fakeDelivery{failing: true}
	// Long interval so we drive replay() manually and avoid timing flakiness.
	s, err := newSpool(dir, time.Hour, d.deliver)
	require.NoError(t, err)
	t.Cleanup(s.close)

	// Spool two events while the SIEM is "down".
	tr := true
	s.add(&models.AuditEvent{ID: 1, EventType: "secret.read", Success: &tr})
	s.add(&models.AuditEvent{ID: 2, EventType: "secret.updated", Success: &tr})

	spoolPath := filepath.Join(dir, spoolFileName)
	_, statErr := os.Stat(spoolPath)
	require.NoError(t, statErr, "events must be persisted to the spool file")

	// A replay while still failing must keep both events (nothing delivered).
	s.replay()
	assert.Equal(t, 0, d.count())
	_, statErr = os.Stat(spoolPath)
	require.NoError(t, statErr, "a failed replay must retain the backlog")

	// SIEM recovers — the next replay drains the backlog and removes the file.
	d.setFailing(false)
	s.replay()
	assert.ElementsMatch(t, []uint{1, 2}, d.delivered)
	_, statErr = os.Stat(spoolPath)
	assert.True(t, os.IsNotExist(statErr), "a fully-drained spool must delete its file")
}

func TestSpool_DiscardsUnparseableLine(t *testing.T) {
	dir := t.TempDir()
	d := &fakeDelivery{}
	s, err := newSpool(dir, time.Hour, d.deliver)
	require.NoError(t, err)
	t.Cleanup(s.close)

	// A corrupt line must not wedge the spool forever.
	require.NoError(t, os.WriteFile(filepath.Join(dir, spoolFileName), []byte("not json\n"), 0o600))
	s.replay()
	_, statErr := os.Stat(filepath.Join(dir, spoolFileName))
	assert.True(t, os.IsNotExist(statErr), "an unparseable backlog must be cleared, not retried forever")
}

// The spool is bounded: once at its size cap, further adds are dropped (counted) rather
// than growing the file unbounded during a sustained SIEM outage.
func TestSpool_CapBoundsGrowth(t *testing.T) {
	dir := t.TempDir()
	d := &fakeDelivery{failing: true}
	s, err := newSpool(dir, time.Hour, d.deliver)
	require.NoError(t, err)
	t.Cleanup(s.close)
	s.maxBytes = 200 // tiny cap for the test

	tr := true
	for i := range 50 {
		s.add(&models.AuditEvent{ID: uint(i + 1), EventType: "secret.read", Success: &tr})
	}
	info, statErr := os.Stat(filepath.Join(dir, spoolFileName))
	require.NoError(t, statErr)
	// The cap is checked before each append, so the file can exceed it by at most one line.
	assert.Less(t, info.Size(), int64(600), "spool must not grow unbounded past its cap")
}

// A SIEM dir mode is tightened even if it pre-exists with looser perms.
func TestSpool_TightensExistingDirPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.Chmod(dir, 0o755)) // defeat umask
	d := &fakeDelivery{}
	s, err := newSpool(dir, time.Hour, d.deliver)
	require.NoError(t, err)
	t.Cleanup(s.close)
	info, statErr := os.Stat(dir)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), "spool dir must be tightened to 0700")
}

// replay must not lose an event add()ed concurrently during a (slow) delivery: the
// reconcile preserves lines appended after the snapshot. Here delivery of the snapshot
// succeeds (file would be removed) while a new event is added mid-replay; it must survive.
func TestSpool_ConcurrentAddDuringReplayNotLost(t *testing.T) {
	dir := t.TempDir()
	tr := true
	d := &fakeDelivery{}
	// deliver hook adds a second event the first time it runs, simulating a concurrent
	// add() arriving while the snapshot is being delivered.
	var once sync.Once
	var sp *spool
	d2 := &fakeDelivery{}
	hook := func(ctx context.Context, e *models.AuditEvent) error {
		once.Do(func() { sp.add(&models.AuditEvent{ID: 99, EventType: "late", Success: &tr}) })
		return d2.deliver(ctx, e)
	}
	s, err := newSpool(dir, time.Hour, hook)
	require.NoError(t, err)
	sp = s
	// Stop the background replay loop up front so ONLY the controlled replay below runs.
	// Otherwise the loop's periodic/initial replay races the manual one — two concurrent
	// deliveries appending to d2.delivered and a TOCTOU on the spool file — which made this
	// test flaky in CI. close() only stops the goroutine; add()/replay() remain usable.
	s.close()

	s.add(&models.AuditEvent{ID: 1, EventType: "secret.read", Success: &tr})
	s.replay() // delivers ID 1; ID 99 is add()ed mid-delivery and must not be lost

	_ = d
	// The invariant: the event added concurrently during a delivery is never LOST — it is
	// either still in the spool (retained for the next replay) or already delivered by a
	// subsequent replay. (newSpool's background loop makes the exact split nondeterministic;
	// the guarantee is no-loss.) Before the lock-free reconcile, an add() during replay
	// would also have DEADLOCKED on the held mutex — reaching this point at all proves the
	// lock isn't held across delivery.
	deliveredLate := false
	for _, id := range d2.delivered {
		if id == 99 {
			deliveredLate = true
		}
	}
	inSpool := false
	if data, rerr := os.ReadFile(filepath.Join(dir, spoolFileName)); rerr == nil {
		inSpool = bytes.Contains(data, []byte("\"late\""))
	}
	assert.True(t, deliveredLate || inSpool, "the concurrently-added event must be retained or delivered, never lost")
}

// replay() must serialize against itself: two overlapping callers (e.g. the background
// loop's own initial replay racing a manually-triggered one, as happened intermittently
// in CI for TestSpool_PersistsAndReplaysOnRecovery) must not each independently snapshot
// and deliver the same undelivered lines, which would double-deliver every event.
func TestSpool_ConcurrentReplayCallsDoNotDoubleDeliver(t *testing.T) {
	dir := t.TempDir()
	tr := true
	d := &fakeDelivery{}
	// Slow delivery widens the window in which a second, concurrent replay() could race
	// the first if replay() weren't serialized against itself.
	hook := func(ctx context.Context, e *models.AuditEvent) error {
		time.Sleep(10 * time.Millisecond)
		return d.deliver(ctx, e)
	}
	s, err := newSpool(dir, time.Hour, hook)
	require.NoError(t, err)
	s.close() // stop the background loop; drive replay() manually and concurrently below

	s.add(&models.AuditEvent{ID: 1, EventType: "secret.read", Success: &tr})
	s.add(&models.AuditEvent{ID: 2, EventType: "secret.updated", Success: &tr})

	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			s.replay()
		})
	}
	wg.Wait()

	assert.ElementsMatch(t, []uint{1, 2}, d.delivered, "each event must be delivered exactly once despite concurrent replay() callers")
}

// TestSpool_ReplaySkipsOnlyOversizedLine is #G56: a line past maxSpoolLineBytes used
// to make bufio.Scanner stop entirely, silently dropping every legitimate event after
// it in the file on the next rewrite. Now only the oversized line itself is skipped
// (logged + counted) — a well-formed event AFTER it in the same file must still be
// replayed.
func TestSpool_ReplaySkipsOnlyOversizedLine(t *testing.T) {
	dir := t.TempDir()
	d := &fakeDelivery{}
	s, err := newSpool(dir, time.Hour, d.deliver)
	require.NoError(t, err)
	s.close() // stop the background loop; drive replay() manually below

	// A well-formed line, an oversized line, then ANOTHER well-formed line — the
	// oversized line sits in the middle so a "stops at first failure" bug would
	// provably lose event 2 as well as the oversized one.
	tr := true
	s.add(&models.AuditEvent{ID: 1, EventType: "secret.read", Success: &tr})
	oversized := bytes.Repeat([]byte("x"), 5<<20) // 5 MiB > 4 MiB cap
	f, err := os.OpenFile(filepath.Join(dir, spoolFileName), os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = f.Write(append(oversized, '\n'))
	require.NoError(t, err)
	require.NoError(t, f.Close())
	s.add(&models.AuditEvent{ID: 2, EventType: "secret.read", Success: &tr})

	var logBuf bytes.Buffer
	prevOut := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(prevOut) })

	corruptBefore := testutil.ToFloat64(siemForwards.WithLabelValues(outcomeSpoolCorrupt))

	s.replay()

	assert.Contains(t, logBuf.String(), "oversized spool line", "the oversized line must be logged loudly, not silently dropped")
	assert.Equal(t, float64(1), testutil.ToFloat64(siemForwards.WithLabelValues(outcomeSpoolCorrupt))-corruptBefore)
	assert.ElementsMatch(t, []uint{1, 2}, d.delivered, "both well-formed events must survive replay despite the oversized line between them")
}
