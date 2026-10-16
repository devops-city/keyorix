package core

// secret_mutation_audit_durability_postgres_test.go — AUDIT-MUTATION-TX-1 and
// ADR-112 Amendment 3: at audit_durability standard only the audit chain's own
// commits skip the disk-sync wait; a transaction that carries a secret mutation
// commits durably even though its audit row is now inside it.
//
// The probe is a GORM callback on the mutation's own pool: every audit_events
// INSERT that runs in a transaction which has already written secret_nodes or
// secret_versions runs `SHOW synchronous_commit` on that same transaction, at
// that moment — after the audit append issued whatever it issues and before the
// COMMIT. Every such probe must read "on". Red if the transaction-scoped store
// inherited auditSkipDurableSync (local_transaction.go): the append's
// `SET LOCAL synchronous_commit = off` would then read back "off" here.

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

type syncCommitProbe struct {
	mu         sync.Mutex
	mutationTx map[gorm.ConnPool]bool
	readings   []string
}

func (p *syncCommitProbe) register(t *testing.T, db *gorm.DB) {
	t.Helper()
	isSecretTable := func(s string) bool { return s == "secret_nodes" || s == "secret_versions" }
	mark := func(tx *gorm.DB) {
		if isSecretTable(tx.Statement.Table) || strings.Contains(tx.Statement.SQL.String(), "secret_nodes") {
			p.mu.Lock()
			p.mutationTx[tx.Statement.ConnPool] = true
			p.mu.Unlock()
		}
	}
	probe := func(tx *gorm.DB) {
		if tx.Statement.Table != "audit_events" {
			return
		}
		p.mu.Lock()
		inMutation := p.mutationTx[tx.Statement.ConnPool]
		p.mu.Unlock()
		if !inMutation {
			return
		}
		var v string
		if err := tx.Statement.ConnPool.QueryRowContext(tx.Statement.Context, "SHOW synchronous_commit").Scan(&v); err != nil {
			v = "probe error: " + err.Error()
		}
		p.mu.Lock()
		p.readings = append(p.readings, v)
		p.mu.Unlock()
	}
	cb := db.Callback()
	require.NoError(t, cb.Create().Before("gorm:create").Register("sma:mark-create", mark))
	require.NoError(t, cb.Update().Before("gorm:update").Register("sma:mark-update", mark))
	require.NoError(t, cb.Delete().Before("gorm:delete").Register("sma:mark-delete", mark))
	require.NoError(t, cb.Raw().Before("gorm:raw").Register("sma:mark-raw", mark))
	require.NoError(t, cb.Create().Before("gorm:create").Register("sma:probe-audit", probe))
}

func (p *syncCommitProbe) take() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.readings
	p.readings = nil
	return r
}

func TestSecretMutationAudit_StandardDurabilityNeverRelaxesTheMutationCommit(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	f := newCTAReviewOn(t, func() *gorm.DB { return pgOpen(t, dsn) })
	db := pgOpen(t, dsn)

	var clusterDefault string
	require.NoError(t, db.Raw("SHOW synchronous_commit").Scan(&clusterDefault).Error)
	require.Equal(t, "on", clusterDefault, "the test cluster must commit durably by default, or this proves nothing")

	p := &syncCommitProbe{mutationTx: map[gorm.ConnPool]bool{}}
	p.register(t, db)
	ls := localstore.NewLocalStorage(db)
	ls.SetAuditSkipDurableSync(true) // audit_durability: standard
	fs := faultstorage.NewFaultyStorage(ls, nil)
	w := &smaWorld{t: t, f: f, db: db, fs: fs, c: NewKeyorixCore(fs), ctx: WithSecretMutationAudit(context.Background(),
		SecretMutationAudit{UserID: f.adminID, Username: "admin", IP: "198.51.100.8", UserAgent: "sma-durability"})}

	for _, k := range smaKinds() {
		t.Run(k.name, func(t *testing.T) {
			id, name := k.prepare(w, "dur-"+k.name)
			p.take() // drop the readings of prepare's own mutations
			got, err := k.mutate(w, id, name)
			require.NoError(t, err)
			require.EqualValues(t, 1, w.auditRows(k.eventType, got))
			readings := p.take()
			require.NotEmpty(t, readings, "%s: no audit row was appended inside the mutation's transaction — the probe saw nothing to check", k.name)
			for _, v := range readings {
				require.Equal(t, "on", v,
					"%s: the transaction carrying the secret mutation would commit with synchronous_commit=%q at standard", k.name, v)
			}
		})
	}
}
