//go:build e2e

package e2e

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestLockLoss_Postgres (LOCKLOSS-SESSION-1): a real keyorix-server on
// PostgreSQL, direct connection (storage.database.pooler unset, so every lock
// is a session lock), whose process-wide advisory lock is ended by
// pg_terminate_backend (a failover, a network partition and a PostgreSQL
// restart look the same to the holder). The server must notice, shut down
// gracefully and exit 1, instead of serving on beside an admin command or a
// second single-writer server. pg-gated like TestAPISmoke_Postgres; each case
// gets a database of its own.
func TestLockLoss_Postgres(t *testing.T) {
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set -- skipping the PostgreSQL lock-loss test")
	}
	dbPassword := os.Getenv("KEYORIX_TEST_PG_PASSWORD")
	if dbPassword == "" {
		dbPassword = parseLibpqDSN(dsn)["password"]
	}
	if dbPassword == "" {
		dbPassword = "keyorix-e2e-smoke"
	}
	serverBin, _ := harness.BuildBinaries(t)

	for _, tc := range []struct {
		name, extraDB string
		// lockBackend selects the backend to terminate: the one holding the lock.
		lockBackend string
		wantLog     string
	}{
		{
			name:        "presence",
			lockBackend: `SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted AND classid = 0 AND objid = 872342 AND objsubid = 1 AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`,
			wantLog:     "serverguard presence lock: the connection holding the advisory lock is gone, so the lock is lost",
		},
		{
			name:        "single_writer",
			extraDB:     "    single_writer: true\n",
			lockBackend: `SELECT holder_pid FROM keyorix_sole_writer`,
			wantLog:     "single_writer holder lock: the connection holding the advisory lock is gone, so the lock is lost",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dbDSN := lockLossDatabase(t, dsn, "keyorix_lockloss_"+strings.ReplaceAll(tc.name, "_", ""))
			backend := harness.DBBackend{
				Name:        "postgres",
				ConfigExtra: fmt.Sprintf("storage:\n  type: postgres\n  database:\n%s%s  encryption:\n    enabled: true\n    dek_path: keys/dek.key\n    salt_path: keys/kek.salt\n", pgDatabaseYAML(dbDSN), tc.extraDB),
				ExtraEnv:    []string{"KEYORIX_DB_PASSWORD=" + dbPassword},
				NoMFAReason: "this test never logs in",
			}
			srv := harness.StartServer(t, serverBin, backend)
			t.Cleanup(srv.Close)

			db, err := sql.Open("pgx", dbDSN)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			ctx := context.Background()
			var pid int
			if err := db.QueryRowContext(ctx, tc.lockBackend).Scan(&pid); err != nil {
				t.Fatalf("find the %s lock backend: %v", tc.name, err)
			}
			// Healthy: the server keeps running across several liveness checks.
			select {
			case <-srv.Exited():
				t.Fatalf("the server exited while its %s lock was held:\n%s", tc.name, readLog(srv))
			case <-time.After(6 * time.Second):
			}

			var ok bool
			if err := db.QueryRowContext(ctx, "SELECT pg_terminate_backend($1)", pid).Scan(&ok); err != nil || !ok {
				t.Fatalf("pg_terminate_backend(%d): ok=%v err=%v", pid, ok, err)
			}
			killed := time.Now()
			select {
			case <-srv.Exited():
			case <-time.After(60 * time.Second):
				t.Fatalf("the %s lock was lost but the server kept running:\n%s", tc.name, readLog(srv))
			}
			log := readLog(srv)
			if code := srv.Cmd.ProcessState.ExitCode(); code != 1 {
				t.Fatalf("exit code after a lost %s lock = %d, want 1:\n%s", tc.name, code, log)
			}
			for _, want := range []string{tc.wantLog, "shutting down so", "All servers shut down gracefully"} {
				if !strings.Contains(log, want) {
					t.Fatalf("server log has no %q:\n%s", want, log)
				}
			}
			t.Logf("%s: exited 1 %s after pg_terminate_backend(%d)", tc.name, time.Since(killed).Round(100*time.Millisecond), pid)
		})
	}
}

// lockLossDatabase creates database name (dropped at cleanup) on base's server
// and returns base pointed at it.
func lockLossDatabase(t *testing.T, base, name string) string {
	t.Helper()
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	ctx := context.Background()
	if _, err := admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
		t.Fatalf("drop %s: %v", name, err)
	}
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	fields := strings.Fields(base)
	for i, f := range fields {
		if strings.HasPrefix(f, "dbname=") {
			fields[i] = "dbname=" + name
			return strings.Join(fields, " ")
		}
	}
	return base + " dbname=" + name
}

func readLog(srv *harness.Server) string {
	b, err := os.ReadFile(srv.LogPath)
	if err != nil {
		return fmt.Sprintf("(read %s: %v)", srv.LogPath, err)
	}
	return string(b)
}
