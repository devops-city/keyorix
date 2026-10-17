package http

// readpath_statement_count_test.go — OPT-READPATH-1.
//
// The statement count of one audited secret read, measured on the wire: every
// pool the replica opened (GORM, the native read pool, the audit flusher) talks
// to PostgreSQL through a pgwirecount proxy, so a statement issued anywhere in
// the request, or by background work the request started, is counted.
//
// What it pins, for a warm machine-token value read without single_writer: ONE
// statement before the audit write. That statement is the live credential
// re-check (INV-MW-02) with the node stamp, the trigger proofs, the machine's
// roles and the role->permission generation folded into it
// (local_folded_credential.go). It cannot go: the credential re-check is what
// makes a revocation on any replica visible to the next request on this one.
// The audit write that follows is the audit flusher's own business; it is
// logged, not pinned here.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgwirecount"
	"github.com/keyorixhq/keyorix/server/http/handlers"
)

// rcWorld is an svWorld whose replica reaches PostgreSQL through a counting proxy.
func rcWorld(t *testing.T) (*svWorld, *pgwirecount.Proxy) {
	t.Helper()
	cfg := svStorageConfig(t, "postgres")
	proxy, dsn := pgwirecount.Start(t, cfg.Storage.Database.DSN)
	cfg = &config.Config{Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: dsn}}}
	return newSVWorldFromConfig(t, "postgres", 1, cfg), proxy
}

// rcRead is one value read by principal, counted, background work included.
func rcRead(t *testing.T, w *svWorld, proxy *pgwirecount.Proxy, principal string, sec *models.SecretNode, want string) ([]pgwirecount.Statement, int) {
	t.Helper()
	return proxy.Count(func() {
		got := w.read(t, w.a, "rest-include-value", principal, sec)
		require.Equal(t, want, got.Value, got.String())
		handlers.DrainBackgroundGoroutines()
		core.DrainBackgroundGoroutines()
	})
}

// rcReadStatements is the statements before the audit write's transaction.
func rcReadStatements(stmts []pgwirecount.Statement) []pgwirecount.Statement {
	for i, s := range stmts {
		if strings.EqualFold(strings.TrimSpace(s.SQL), "BEGIN") {
			return stmts[:i]
		}
	}
	return stmts
}

func rcLog(t *testing.T, label string, stmts []pgwirecount.Statement, roundTrips int) {
	t.Helper()
	t.Logf("%s: %d statements (%d before the audit write), %d round trips", label, len(stmts), len(rcReadStatements(stmts)), roundTrips)
	for i, s := range stmts {
		t.Logf("  %d: %.160s", i+1, strings.Join(strings.Fields(s.SQL), " "))
	}
}

// TestReadPathStatementCount: a warm audited machine value read (the hot secret
// of a steady read load) issues one statement before its audit write. The human
// session read is logged for comparison.
func TestReadPathStatementCount(t *testing.T) {
	w, proxy := rcWorld(t)
	sec, val := w.newSecret(t, nil)
	for _, principal := range []string{"machine", "human"} {
		t.Run(principal, func(t *testing.T) {
			for range 3 { // token cache, read-path caches, fold marks
				rcRead(t, w, proxy, principal, sec, val)
			}
			stmts, rt := rcRead(t, w, proxy, principal, sec, val)
			rcLog(t, principal+" warm read", stmts, rt)
			require.NotEmpty(t, stmts, "the proxy must see the request's statements")
			if principal == "machine" {
				reads := rcReadStatements(stmts)
				require.Len(t, reads, 1, "warm machine read: one statement before the audit write")
				assert.Contains(t, reads[0].SQL, "machine_identity_credentials c", "the one statement is the live credential re-check")
				assert.Contains(t, reads[0].SQL, "secret_nodes n", "with the node read folded into it")
			}
		})
	}
}
