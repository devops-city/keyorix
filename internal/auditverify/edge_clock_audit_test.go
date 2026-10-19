package auditverify

// edge_clock_audit_test.go -- EDGE-1 "no NTP": audit entries are ordered by the
// hash chain (row id, prev_hash -> entry_hash), not by their timestamps. A
// device whose clock was wrong when it wrote some entries, or was corrected
// between two of them, must still verify VALID. If anyone ever adds a
// "timestamps must not go backwards" check here, every unattended device that
// ever had its clock set would report a broken audit trail -- and the answer to
// "was this tampered with" would become "it depends on NTP". This pins that the
// verifier does not do that, and that it also does not mistake a rewritten
// timestamp for a clock correction.

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// seedChainWithTimes writes one chained secret.read per time, in that order,
// into a fresh database and returns its path.
func seedChainWithTimes(t *testing.T, times []time.Time) (path string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "audit.db")
	seedEmptySchema(t, path)
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	tr := true
	prev := GenesisHash
	for i, ts := range times {
		row := &AuditEventRow{EventType: "secret.read", IPAddress: "10.0.0.1", Description: "clock test", Success: &tr, EventTime: ts, ActorType: "user"}
		hash := ComputeEntryHash(row, prev)
		_, err := db.Exec(`INSERT INTO audit_events
			(event_type, ip_address, description, success, event_time, diff, impersonation, actor_type, prev_hash, entry_hash)
			VALUES (?,?,?,?,?,?,?,?,?,?)`,
			row.EventType, row.IPAddress, row.Description, tr, row.EventTime, "", false, row.ActorType, prev, hash)
		require.NoError(t, err, "row %d", i)
		prev = hash
	}
	return path
}

func verifyPath(t *testing.T, path string) *Result {
	t.Helper()
	db, err := OpenSQLiteReadOnly(path)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	res, err := Verify(context.Background(), db, Options{})
	require.NoError(t, err)
	return res
}

func TestVerify_ChainWithNonMonotonicTimestampsIsValid(t *testing.T) {
	good := time.Date(2027, 6, 1, 10, 0, 0, 0, time.UTC)
	path := seedChainWithTimes(t, []time.Time{
		good,
		good.Add(-time.Hour),   // clock corrected backwards
		time.Unix(0, 0).UTC(),  // booted at the epoch with no RTC
		time.Unix(60, 0).UTC(), // still the epoch
		time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), // RTC ahead
		good.Add(time.Hour),                         // and back to the real time
	})
	res := verifyPath(t, path)
	require.Equal(t, VerdictValid, res.Verdict, "timestamp order must not influence the verdict: %+v", res)
}

// Red control: the verdict above is not vacuous. Rewriting one entry's
// timestamp -- the thing a tamperer would do to hide when something happened --
// is still caught, because the timestamp is inside the entry hash.
func TestVerify_RewrittenTimestampIsStillBroken(t *testing.T) {
	good := time.Date(2027, 6, 1, 10, 0, 0, 0, time.UTC)
	path := seedChainWithTimes(t, []time.Time{good, good.Add(time.Minute), good.Add(2 * time.Minute)})

	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE audit_events SET event_time = ? WHERE id = 2`, good.Add(-48*time.Hour))
	require.NoError(t, err)
	require.NoError(t, db.Close())

	require.Equal(t, VerdictBroken, verifyPath(t, path).Verdict)
}
