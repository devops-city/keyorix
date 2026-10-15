// fast_audit_mode_postgres_crash_test.go — the crash requirement of
// storage.database.audit_durability on PostgreSQL (ADR-112 Amendments 1 and 3,
// docs/specs/fast-audit-mode.md §S3), at both levels: standard may lose only a
// TAIL of acknowledged audit entries, strict loses none, and the chain
// verifies after the crash at both.
//
// WHY THIS NEEDS ITS OWN GATE, AND WHY IT CAN NEVER RUN IN CI. On SQLite the
// database lives in this process, so a kill -9 of the test's own worker is a
// genuine crash of the thing holding the data. On Postgres it is not: killing
// the Keyorix process does nothing to the database server, and the spec says
// so explicitly (a Keyorix process crash loses nothing). The only event that
// can lose an async commit on Postgres is the POSTMASTER dying with WAL still
// in its shared buffers — so testing the claim means killing the postmaster,
// which means controlling the database server's lifecycle. That is outside
// what a `go test ./...` run may assume, so this test is gated on the operator
// explicitly naming a disposable container:
//
//	docker run -d --name kx-crash-pg -e POSTGRES_PASSWORD=pg -p 32790:5432 postgres:16
//	KX_FASTAUDIT_PG_CRASH_CONTAINER=kx-crash-pg \
//	KEYORIX_TEST_PG_DSN="host=localhost port=32790 user=postgres password=pg dbname=postgres sslmode=disable" \
//	  go test ./internal/storage/store/ -run 'TestFastAuditMode_PostgresCrashLosesOnlyATail|TestAuditDurabilityStrict_PostgresCrashLosesNothing' -v
//
// A fixed published port matters: `docker start` re-rolls a `-p 0:5432`
// mapping, so the reconnect after the restart would hit a port nothing is
// listening on. The first attempt at this test failed exactly that way.
//
// Verification class for docs/security-closures.tsv purposes: MANUAL. This
// test skips in every automated environment by construction, and a skip here
// is correct rather than a failure. The run that matters is recorded in this
// change's PR body with its real output.
package store

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// TestFastAuditMode_PostgresCrashLosesOnlyATail writes async-committed audit
// events, SIGKILLs the postmaster WHILE writes are in flight, restarts it, and
// asserts the two things the mode promises:
//
//   - whatever was lost is a clean TAIL of the written order, never a gap in
//     the middle;
//   - the hash chain still verifies.
//
// The kill has to land mid-write, not after the loop. Postgres's WAL writer
// flushes every wal_writer_delay (200ms by default), so a kill a moment after
// the last write finds nothing at risk — the first version of this test killed
// after the loop and lost 0 of 640 rows, which looks like a pass but proves
// nothing about tail loss. The positive control below turns that outcome into
// a visible "this run proved nothing" rather than a silent green.
func TestFastAuditMode_PostgresCrashLosesOnlyATail(t *testing.T) {
	runPostgresAuditCrash(t, true, "fastaudit_pgcrash")
}

// TestAuditDurabilityStrict_PostgresCrashLosesNothing is the strict level's
// promise under the same crash: every acknowledged audit write survives a
// SIGKILL of the postmaster mid-write (the commit waited for the disk sync
// before acknowledging), and the chain verifies.
func TestAuditDurabilityStrict_PostgresCrashLosesNothing(t *testing.T) {
	runPostgresAuditCrash(t, false, "strictaudit_pgcrash")
}

// runPostgresAuditCrash writes audit events at the given level, SIGKILLs the
// postmaster mid-write, restarts it and checks what survived: at standard a
// clean tail may be lost, at strict nothing may be.
func runPostgresAuditCrash(t *testing.T, standard bool, schema string) {
	t.Helper()
	container := os.Getenv("KX_FASTAUDIT_PG_CRASH_CONTAINER")
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if container == "" || dsn == "" {
		t.Skip("needs KX_FASTAUDIT_PG_CRASH_CONTAINER and KEYORIX_TEST_PG_DSN -- see this file's header " +
			"for the exact invocation. Skipping is the correct outcome in any automated run: this test kills " +
			"a database server.")
	}

	ctx := context.Background()

	openDB := func() *gorm.DB {
		var db *gorm.DB
		var err error
		// Generous: a restarted Postgres replays WAL before accepting
		// connections, and this is deliberately a crash recovery.
		for range 120 {
			db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
			if err == nil {
				var one int
				if probeErr := db.Raw("SELECT 1").Scan(&one).Error; probeErr == nil {
					return db
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Fatalf("could not connect to %q within 60s: %v", dsn, err)
		return nil
	}

	db := openDB()
	require.NoError(t, db.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, db.Exec("CREATE SCHEMA "+schema).Error)
	require.NoError(t, db.Exec("SET search_path TO "+schema).Error)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1) // one session, so the search_path above holds for every statement
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))

	ls := NewLocalStorage(db)
	ls.SetAuditSkipDurableSync(standard)

	killed := make(chan struct{})
	go func() {
		time.Sleep(1500 * time.Millisecond)
		// #nosec G204 -- the container name comes from an env var the operator
		// running this test set themselves, in a test that refuses to run
		// without it. There is no untrusted input anywhere in this process.
		out, kerr := exec.Command("docker", "kill", container).CombinedOutput()
		t.Logf("docker kill (mid-write): %s (err=%v)", strings.TrimSpace(string(out)), kerr)
		close(killed)
	}()

	// Write until the dead server has rejected several attempts in a row. A
	// failed write is deliberately NOT acknowledged — fail-closed means the
	// caller saw an error, so nothing is owed for it.
	var acked []string
	consecutiveFailures := 0
	for n := 1; consecutiveFailures < 3; n++ {
		desc := fmt.Sprintf("pgcrash:%06d", n)
		tr := true
		if logErr := ls.LogAuditEvent(ctx, &models.AuditEvent{
			EventType: "fastaudit_pgcrash.write", Description: desc, Success: &tr,
			EventTime: time.Now(), ActorType: "system",
		}); logErr != nil {
			consecutiveFailures++
			continue
		}
		consecutiveFailures = 0
		acked = append(acked, desc)
	}
	<-killed
	t.Logf("acknowledged %d audit writes (standard=%v) before the postmaster died", len(acked), standard)
	require.NotEmpty(t, acked, "nothing was ever acknowledged -- the harness is broken, not the mode")

	// #nosec G204 -- same env-var-supplied container name as above.
	startOut, startErr := exec.Command("docker", "start", container).CombinedOutput()
	t.Logf("docker start: %s (err=%v)", strings.TrimSpace(string(startOut)), startErr)
	require.NoError(t, startErr, "could not restart the database server")

	db2 := openDB()
	require.NoError(t, db2.Exec("SET search_path TO "+schema).Error)
	sqlDB2, err := db2.DB()
	require.NoError(t, err)
	sqlDB2.SetMaxOpenConns(1)

	var rows []models.AuditEvent
	require.NoError(t, db2.Where("description LIKE ?", "pgcrash:%").Order("id").Find(&rows).Error)
	present := make(map[string]bool, len(rows))
	for _, r := range rows {
		present[r.Description] = true
	}
	t.Logf("after the crash: %d of %d acknowledged rows survived (lost %d)",
		len(present), len(acked), len(acked)-len(present))

	firstMissing := -1
	for i, desc := range acked {
		have := present[desc]
		if !have && firstMissing < 0 {
			firstMissing = i
			continue
		}
		require.Falsef(t, have && firstMissing >= 0,
			"GAP, not a tail: acknowledged write #%d survived the postmaster crash but #%d, written "+
				"EARLIER, did not. Async commit may lose a TAIL of audit entries; it may never lose one from "+
				"the middle. If this fires, the WAL-prefix reasoning in docs/specs/fast-audit-mode.md §5 is "+
				"wrong and the mode is not safe to ship.", i, firstMissing)
	}

	if !standard {
		require.Equalf(t, -1, firstMissing,
			"strict: acknowledged write #%d (and %d after it) did not survive the postmaster crash. At strict "+
				"the audit commit waits for the disk sync before it is acknowledged, so no acknowledged entry "+
				"may ever be lost.", firstMissing, len(acked)-firstMissing-1)
		t.Logf("strict: all %d acknowledged writes survived the postmaster crash", len(acked))
	} else if firstMissing < 0 {
		// Not a failure, but not evidence either. Say so loudly rather than
		// reporting a green that means nothing.
		t.Logf("NOTE: nothing was lost in this run, so it did NOT exercise tail loss -- the WAL writer had "+
			"already flushed everything by the time the kill landed. The chain assertion below still holds, "+
			"but re-run (or shorten the pre-kill delay below %v) for evidence about the lost-tail case.",
			1500*time.Millisecond)
	} else {
		t.Logf("lost a clean TAIL of %d/%d acknowledged writes starting at #%d -- no gap, exactly as the "+
			"spec's WAL-prefix argument predicts", len(acked)-firstMissing, len(acked), firstMissing)
	}

	ls2 := NewLocalStorage(db2)
	v, err := ls2.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	require.Truef(t, v.Valid,
		"the audit chain does not verify after a postmaster crash (standard=%v): reason=%q "+
			"firstBrokenID=%v. Lost tail entries are permitted at standard; a broken chain never is.",
		standard, v.Reason, v.FirstBrokenID)
	t.Logf("VerifyAuditChain after crash recovery: VALID over %d surviving rows", len(rows))
}
