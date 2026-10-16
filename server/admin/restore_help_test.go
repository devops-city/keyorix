package admin

import (
	"strings"
	"testing"
)

// TestRestoreHelp_DoesNotClaimPostgresUnsupported pins the operator-facing help to
// the behaviour: runAdminRestore admits PostgreSQL targets (backup_restore_postgres_test.go
// restores into a real database), and docs/SELF_HOSTING.md tells operators to do it.
// The help used to say "Only local/sqlite storage is supported as a restore TARGET
// today; restoring into Postgres is H4", which sent operators to a workaround for a
// path that works. Found by scripts/drills/backup-restore.sh (PROD-OPS-1).
func TestRestoreHelp_DoesNotClaimPostgresUnsupported(t *testing.T) {
	long := restoreCmd.Long
	for _, stale := range []string{"Only local/sqlite", "restoring into Postgres is H4"} {
		if strings.Contains(long, stale) {
			t.Errorf("admin restore --help still carries the stale claim %q", stale)
		}
	}
	if !strings.Contains(long, "PostgreSQL") {
		t.Errorf("admin restore --help does not say that PostgreSQL targets are supported")
	}
}
