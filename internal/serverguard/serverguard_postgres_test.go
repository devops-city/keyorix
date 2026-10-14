package serverguard

import (
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// pgTestDSN returns the KEYORIX_TEST_PG_DSN base DSN, skipping the test (not
// failing it) when unset -- matching internal/storage's own convention
// (postgres_pk_rebuild_helpers_test.go's pgTestDSN).
func pgTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — skipping Postgres server-presence guard test")
	}
	return dsn
}

func pgCfg(t *testing.T) *config.Config {
	return &config.Config{
		Storage: config.StorageConfig{
			Type:     "postgres",
			Database: config.DatabaseConfig{DSN: pgTestDSN(t)},
		},
	}
}

func TestPostgres_ProbeRunning_FalseWhenNoServer(t *testing.T) {
	cfg := pgCfg(t)
	running, detail, err := ProbeRunning(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if running {
		t.Fatalf("expected running=false with no server, got true (detail=%q)", detail)
	}
}

func TestPostgres_ProbeRunning_TrueWhileServerHoldsPresence(t *testing.T) {
	cfg := pgCfg(t)
	presence, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	defer presence.Release() //nolint:errcheck

	running, detail, err := ProbeRunning(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !running {
		t.Fatal("expected running=true while a server holds the presence advisory lock")
	}
	if detail == "" {
		t.Fatal("expected a non-empty detail message")
	}
}

func TestPostgres_ProbeRunning_FalseAfterServerReleases(t *testing.T) {
	cfg := pgCfg(t)
	presence, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	if err := presence.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	running, _, err := ProbeRunning(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if running {
		t.Fatal("expected running=false after the server released its presence lock")
	}
}

// parseLibpqDSN parses a libpq keyword/value DSN ("host=... user=... password=...") into a
// map, just enough to let TestPostgres_AcquireExclusive_AuthFailureIsNotLockHeld mutate the
// password without needing its own separate connection config -- mirrors the format CI's
// e2e-nightly sets for KEYORIX_TEST_PG_DSN (scripts/e2e/api_smoke_test.go's own documented
// convention). A URI-form DSN ("postgres://...") isn't handled -- this test's own
// KEYORIX_TEST_PG_DSN must use the keyword/value form for it to target the real host/port.
func parseLibpqDSN(dsn string) map[string]string {
	out := map[string]string{}
	for tok := range strings.FieldsSeq(dsn) {
		kv := strings.SplitN(tok, "=", 2)
		if len(kv) == 2 {
			out[kv[0]] = strings.Trim(kv[1], `'"`)
		}
	}
	return out
}

// TestPostgres_AcquireExclusive_AuthFailureIsNotLockHeld reproduces #2362 exactly: a real
// Postgres server, reachable, but with a wrong password (SQLSTATE 28P01) -- as opposed to
// TestPostgres_AcquireExclusive_ConnectFailureIsNotLockHeld's unreachable-host case. Either
// way, IsLockHeld must be false: presence was never actually determined.
func TestPostgres_AcquireExclusive_AuthFailureIsNotLockHeld(t *testing.T) {
	fields := parseLibpqDSN(pgTestDSN(t))
	if fields["host"] == "" || fields["user"] == "" {
		t.Skip("KEYORIX_TEST_PG_DSN is not in keyword/value form -- cannot target its real host with a mutated password")
	}
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "postgres",
			Database: config.DatabaseConfig{
				Host: fields["host"], Port: fields["port"], Name: fields["dbname"],
				User: fields["user"], Password: "wrong-" + fields["password"] + "-definitely-not-it", SSLMode: "disable",
			},
		},
	}
	_, err := AcquireExclusive(cfg)
	if err == nil {
		t.Fatal("expected AcquireExclusive to fail with a wrong password")
	}
	if IsLockHeld(err) {
		t.Fatalf("expected IsLockHeld(err) == false for an auth failure, got true: %v", err)
	}
}

// TestPostgres_AcquireExclusive_ConflictsWithAnotherExclusive_IsLockHeld is the Postgres
// counterpart to TestSQLite_AcquireExclusive_ConflictsWithAnotherExclusive: a genuine
// lock-held failure, as opposed to the auth/connect-failure tests above, must satisfy
// IsLockHeld.
func TestPostgres_AcquireExclusive_ConflictsWithAnotherExclusive_IsLockHeld(t *testing.T) {
	cfg := pgCfg(t)
	first, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("first AcquireExclusive: %v", err)
	}
	defer first.Release() //nolint:errcheck

	_, err = AcquireExclusive(cfg)
	if err == nil {
		t.Fatal("expected a second concurrent AcquireExclusive to fail")
	}
	if !IsLockHeld(err) {
		t.Fatalf("expected IsLockHeld(err) == true for a genuine lock conflict, got: %v", err)
	}
}

func TestPostgres_MultipleServerReplicas_ShareCoexist(t *testing.T) {
	// Multiple server replicas sharing one Postgres database (ADR-039 HA)
	// must not conflict on the SHARED presence lock — only the admin
	// commands' EXCLUSIVE probe treats that as contention.
	cfg := pgCfg(t)
	p1, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("first AcquirePresence: %v", err)
	}
	defer p1.Release() //nolint:errcheck

	p2, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("second AcquirePresence (concurrent shared holder / HA replica) unexpectedly failed: %v", err)
	}
	defer p2.Release() //nolint:errcheck
}
