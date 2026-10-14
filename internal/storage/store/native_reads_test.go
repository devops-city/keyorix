package store

// Golden tests for the native read pool (native_reads.go): each statement's
// answer on the pool is reflect.DeepEqual to its answer through database/sql
// and gorm (time zones, nil vs zero pointers and NULLs included), for every row
// shape and for missing rows, on Postgres (KEYORIX_TEST_PG_DSN). The text and
// callback tests run everywhere.

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// attachNativeReadPool gives a Postgres test store the native pool the factory
// gives a production one, on the same DSN.
func attachNativeReadPool(t *testing.T, ls *LocalStorage) {
	t.Helper()
	d, ok := ls.db.Dialector.(*postgres.Dialector)
	require.True(t, ok, "%T", ls.db.Dialector)
	pool, err := pgxpool.New(context.Background(), d.DSN)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	ls.SetNativeReadPool(pool)
}

// pgOnly returns the Postgres backend or skips.
func pgOnly(t *testing.T) string {
	t.Helper()
	for _, b := range principalPermBackends(t) {
		if b == "postgres" {
			return b
		}
	}
	t.Skip("KEYORIX_TEST_PG_DSN not set: the native pool is Postgres only")
	return ""
}

// distinctIDs starts every id sequence the read-path statements bind at its own
// offset, so a bind that lands on the wrong placeholder reads another row
// instead of the same id by coincidence (every fresh table starts at 1).
func distinctIDs(t *testing.T) func(*LocalStorage) {
	return func(ls *LocalStorage) {
		t.Helper()
		require.NoError(t, ls.db.AutoMigrate(&models.MachineIdentityCredential{}))
		for i, table := range []string{"projects", "environments", "machine_identities", "roles", "permissions", "secret_nodes", "machine_identity_credentials"} {
			require.NoError(t, ls.db.Exec("SELECT setval(pg_get_serial_sequence(?, 'id'), ?)", table, (i+1)*100).Error, table)
		}
	}
}

// viaDriver runs fn once through database/sql / gorm (no pool) and once on the
// native pool, and returns both answers.
func viaDriver[T any](t *testing.T, ls *LocalStorage, fn func() T) (classic, native T) {
	t.Helper()
	pool := ls.nativeReads
	require.NotNil(t, pool, "precondition: the Postgres fixture has a native pool")
	ls.nativeReads = nil
	classic = fn()
	ls.nativeReads = pool
	native = fn()
	return classic, native
}

type credAnswer struct {
	cred    *models.MachineIdentityCredential
	state   string
	handled bool
	err     error
}

func (a credAnswer) errText() string {
	if a.err == nil {
		return ""
	}
	return a.err.Error()
}

func TestNativeReads_CredentialLookupMatchesDatabaseSQL(t *testing.T) {
	ls, _ := newPrincipalPermStorage(t, pgOnly(t))
	require.NoError(t, ls.db.AutoMigrate(&models.MachineIdentityCredential{}))
	w := ppWorld{t: t, ls: ls}
	ctx := context.Background()
	mid := w.machine(w.project())
	at := time.Date(2026, 3, 4, 5, 6, 7, 891011000, time.FixedZone("x", 2*3600))
	lookup := func(hash string) func() credAnswer {
		return func() credAnswer {
			c, s, h, err := ls.getMachineIdentityCredentialWithIdentityStateByHashRaw(ctx, hash)
			return credAnswer{c, s, h, err}
		}
	}

	for i, shape := range []struct{ lastUsed, expires bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		hash := w.name("native-hash")
		cred := &models.MachineIdentityCredential{
			MachineIdentityID: mid, Name: hash, TokenHash: hash, TokenPrefix: "kx_",
			AllowedCIDRs: strings.Repeat(`["10.0.0.0/8"]`, i%2), Revoked: i == 3,
			CreatedAt: at.Add(time.Duration(i) * time.Hour), Classification: []string{"", "internal"}[i%2],
		}
		if shape.lastUsed {
			lu := at.Add(time.Minute)
			cred.LastUsedAt = &lu
		}
		if shape.expires {
			ex := at.Add(48 * time.Hour)
			cred.ExpiresAt = &ex
		}
		require.NoError(t, ls.db.Create(cred).Error)
		classic, native := viaDriver(t, ls, lookup(hash))
		require.NoError(t, classic.err)
		require.Equal(t, classic, native, "shape %+v", shape)
	}

	// No such credential: the same wrapped sql.ErrNoRows, the same text.
	classic, native := viaDriver(t, ls, lookup("no-such-hash"))
	require.True(t, native.handled)
	require.ErrorIs(t, native.err, sql.ErrNoRows)
	require.NotErrorIs(t, native.err, pgx.ErrNoRows, "the pgx sentinel never leaks to callers")
	require.Equal(t, classic.errText(), native.errText())
	require.Equal(t, classic.cred, native.cred)

	// A NULL in a NOT-NULL-in-practice column fails both ways, never as a no-row.
	for _, col := range []string{"created_at", "allowed_c_id_rs", "classification"} {
		hash := w.name("native-null-" + col)
		require.NoError(t, ls.db.Create(&models.MachineIdentityCredential{
			MachineIdentityID: mid, Name: hash, TokenHash: hash, CreatedAt: at,
		}).Error)
		require.NoError(t, ls.db.Exec("UPDATE machine_identity_credentials SET "+col+" = NULL WHERE token_hash = ?", hash).Error)
		classic, native := viaDriver(t, ls, lookup(hash))
		require.Error(t, classic.err, col)
		require.Error(t, native.err, col)
		require.False(t, errors.Is(native.err, sql.ErrNoRows), col)
		require.Equal(t, classic.handled, native.handled, col)
		require.Nil(t, native.cred, col)
	}
}

// requireNativePrefetchMatches compares one node-stamp case.
func requireNativePrefetchMatches(t *testing.T, ls *LocalStorage, c prefetchScanCase, wantRows int) {
	t.Helper()
	ctx := context.Background()
	q := readPathPrefetchSQL(nodeTriggerExistsExpr(ls.db), c.want)
	type answer struct {
		rows []readPathPrefetchRow
		err  error
	}
	classic, native := viaDriver(t, ls, func() answer {
		rows, err := ls.readPathPrefetchRows(ctx, q, c.args(), c.want)
		return answer{rows, err}
	})
	require.NoError(t, classic.err, c.name)
	require.Len(t, classic.rows, wantRows, "%s: precondition, row count", c.name)
	require.Equal(t, classic, native, c.name)
}

func TestNativeReads_NodeStampMatchesGorm(t *testing.T) {
	w := newPrefetchWorldWith(t, pgOnly(t), distinctIDs(t))
	ctx := context.Background()
	base := prefetchScanCase{trigger: SecretNodeCacheEpochTrigger, machine: w.machine, scope: w.scope, secret: w.secret.ID}

	for _, want := range []bool{true, false} {
		c := base
		c.want, c.name = want, "one role, schedule with times"
		requireNativePrefetchMatches(t, w.ls, c, 1)
	}
	c := base
	c.want, c.trigger, c.name = true, "no_such_trigger", "trigger absent"
	requireNativePrefetchMatches(t, w.ls, c, 1)
	c = base
	c.want, c.machine, c.name = true, w.machine2(), "no role: role_id NULL"
	requireNativePrefetchMatches(t, w.ls, c, 1)

	second := w.role(false, w.ppWorld.perm())
	require.NoError(t, w.ls.AssignMachineRole(ctx, w.machine, second.ID, w.scope))
	c = base
	c.want, c.name = true, "two roles"
	requireNativePrefetchMatches(t, w.ls, c, 2)

	bare, err := w.ls.CreateSecret(ctx, &models.SecretNode{
		Name: w.name("native-bare"), ProjectID: w.scope.ProjectID, EnvironmentID: w.scope.EnvironmentID, Status: "active",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	c = base
	c.want, c.secret, c.name = true, bare.ID, "no schedule, no versions: NULL schedule, zero aggregates"
	requireNativePrefetchMatches(t, w.ls, c, 2)

	// Versions with read counts: the SUM aggregate is numeric on Postgres.
	for i := 2; i <= 3; i++ {
		_, err = w.ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: w.secret.ID, VersionNumber: i, ReadCount: i * 7, CreatedAt: time.Now()})
		require.NoError(t, err)
	}
	c = base
	c.want, c.name = true, "several versions with read counts"
	requireNativePrefetchMatches(t, w.ls, c, 2)

	require.NoError(t, w.ls.db.Where("key = ?", rolePermissionsGenerationKey).Delete(&models.SystemMetadata{}).Error)
	c = base
	c.want, c.name = true, "no generation row: generation NULL"
	requireNativePrefetchMatches(t, w.ls, c, 2)

	require.NoError(t, w.ls.db.Model(&models.SecretNode{}).Where("id = ?", bare.ID).Update("deleted_at", time.Now()).Error)
	c = base
	c.want, c.secret, c.name = true, bare.ID, "soft-deleted node: no row"
	requireNativePrefetchMatches(t, w.ls, c, 0)
	c = base
	c.want, c.secret, c.name = true, 1<<40, "no such node: no row"
	requireNativePrefetchMatches(t, w.ls, c, 0)
}

type foldedAnswer struct {
	cred  *models.MachineIdentityCredential
	state string
	node  *foldedNodeState
	ok    bool
}

func TestNativeReads_FoldedCredentialMatchesGorm(t *testing.T) {
	w := newFoldWorldWith(t, pgOnly(t), distinctIDs(t))
	ctx := context.Background()
	w.gateReads(ctx) // warm the node cache
	folded := func(hash string, want bool) func() foldedAnswer {
		return func() foldedAnswer {
			pf := storage.ReadPathPrefetchFrom(storage.NewReadPathPrefetchFolding(ctx, w.machine, want, w.secret.ID))
			c, s, n, ok := w.ls.getMachineCredentialFolded(ctx, hash, pf, w.secret.ID)
			return foldedAnswer{c, s, n, ok}
		}
	}
	check := func(name, hash string, wantOK, wantNode bool) {
		t.Helper()
		for _, want := range []bool{true, false} {
			classic, native := viaDriver(t, w.ls, folded(hash, want))
			require.Equal(t, wantOK, classic.ok, "%s: precondition", name)
			require.Equal(t, wantNode, classic.node != nil, "%s: precondition, node found", name)
			require.Equal(t, classic, native, "%s (schedule/version %v)", name, want)
		}
	}

	check("one role, schedule, credential with expiry", w.hash, true, true)

	second := w.role(false, w.ppWorld.perm())
	require.NoError(t, w.ls.AssignMachineRole(ctx, w.machine, second.ID, w.scope))
	var cred models.MachineIdentityCredential
	require.NoError(t, w.ls.db.Where("token_hash = ?", w.hash).First(&cred).Error)
	lu := time.Now().Add(-time.Minute)
	cred.LastUsedAt, cred.ExpiresAt, cred.Revoked = &lu, nil, true
	require.NoError(t, w.ls.db.Save(&cred).Error)
	check("two roles, last used, no expiry, revoked", w.hash, true, true)

	check("no such credential: the plain statement answers", "no-such-hash", false, false)

	require.NoError(t, w.ls.db.Exec("DELETE FROM secret_nodes WHERE id = ?", w.secret.ID).Error)
	check("node gone: credential only, node columns NULL", w.hash, true, false)
}

// The gorm callbacks registered on ls.db see the native statements as they saw
// the gorm ones (same count, same SQL), and an error a callback sets fails the
// native statement as it failed the gorm one.
func TestNativeReads_GormCallbacksSeeTheStatement(t *testing.T) {
	w := newFoldWorld(t, pgOnly(t))
	ctx := context.Background()
	w.gateReads(ctx)
	var seen []string
	var inject error
	require.NoError(t, w.ls.db.Callback().Row().After("gorm:row").Register("native-test:observe", func(db *gorm.DB) {
		seen = append(seen, db.Statement.SQL.String())
		if inject != nil {
			_ = db.AddError(inject)
		}
	}))
	cached, ok := w.ls.secretMetaCache.getNode(w.secret.ID)
	require.True(t, ok)
	run := func() (bool, bool) {
		pf := storage.ReadPathPrefetchFrom(storage.NewReadPathPrefetchFolding(ctx, w.machine, true, w.secret.ID))
		_, _, _, foldOK := w.ls.getMachineCredentialFolded(ctx, w.hash, pf, w.secret.ID)
		_, _, _, stampOK := w.ls.readNodeStampPrefetching(ctx, pf, w.secret.ID, cached.node)
		return foldOK, stampOK
	}
	type answer struct {
		seen             []string
		foldOK, stampOK  bool
		injectedFoldOK   bool
		injectedStampOK  bool
		injectedStatemts int
	}
	classic, native := viaDriver(t, w.ls, func() answer {
		seen, inject = nil, nil
		var a answer
		a.foldOK, a.stampOK = run()
		a.seen = seen
		seen, inject = nil, errors.New("injected")
		a.injectedFoldOK, a.injectedStampOK = run()
		a.injectedStatemts = len(seen)
		return a
	})
	require.Len(t, classic.seen, 2, "precondition: gorm saw both statements")
	require.True(t, classic.foldOK && classic.stampOK)
	require.False(t, classic.injectedFoldOK || classic.injectedStampOK, "precondition: an injected error fails both")
	require.Equal(t, classic, native)
}

// nativeSQL numbers the placeholders exactly as gorm's Postgres dialector does,
// for every shape of both read-path statements.
func TestNativeSQL_NumbersEveryPlaceholder(t *testing.T) {
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: stdlib.OpenDB(pgx.ConnConfig{})}),
		&gorm.Config{Logger: logger.Discard, DryRun: true, DisableAutomaticPing: true})
	require.NoError(t, err)
	expr := nodeTriggerExistsExpr(db)
	require.Contains(t, expr, "pg_trigger", "precondition: the Postgres trigger proof")
	for _, want := range []bool{true, false} {
		for _, q := range []string{readPathPrefetchSQL(expr, want), foldedCredentialSQL(expr, want)} {
			n := strings.Count(q, "?")
			args := make([]any, n)
			for i := range args {
				args[i] = i
			}
			gormText := db.Raw(q, args...).Statement.SQL.String()
			require.Equal(t, gormText, nativeSQL(q))
			require.NotContains(t, nativeSQL(q), "?")
			require.Contains(t, nativeSQL(q), "$"+strconv.Itoa(n))
			require.NotContains(t, nativeSQL(q), "$"+strconv.Itoa(n+1))
		}
	}
}

// A transaction-scoped store never reads on the native pool: its statements
// must see the transaction's snapshot.
func TestNativeReads_NeverInsideATransaction(t *testing.T) {
	ls, _ := newPrincipalPermStorage(t, pgOnly(t))
	require.NotNil(t, ls.nativeReads, "precondition")
	require.NoError(t, ls.WithTransaction(context.Background(), func(s storage.Storage) error {
		tx, ok := s.(*LocalStorage)
		require.True(t, ok)
		require.Nil(t, tx.nativeReads)
		return nil
	}))
}

// The dry run is skipped only while ls.db's Row callback chain is the one it
// had when the pool was attached; registering, replacing or removing a Row
// callback afterwards turns it back on. Pins that the chain is readable on
// this gorm version (if it were not, every statement would be observed, which
// is safe but costs the CPU this file saves).
func TestNativeReads_DryRunOnlyWhenACallbackWasRegistered(t *testing.T) {
	ls, _ := newPrincipalPermStorage(t, "sqlite")
	ls.SetNativeReadPool(nil)
	require.True(t, ls.nativeRowChainKnown, "gorm's Row callback chain must be readable")
	require.False(t, ls.observedByCallbacks(), "nothing registered since the pool was attached")

	cb := ls.db.Callback().Row()
	require.NoError(t, cb.After("gorm:row").Register("native-test:count", func(*gorm.DB) {}))
	require.True(t, ls.observedByCallbacks(), "registered")
	ls.SetNativeReadPool(nil)
	require.NoError(t, cb.Replace("native-test:count", func(*gorm.DB) {}))
	require.True(t, ls.observedByCallbacks(), "replaced")
	ls.SetNativeReadPool(nil)
	require.NoError(t, cb.Remove("native-test:count"))
	require.True(t, ls.observedByCallbacks(), "removed")

	// Unreadable chain: always observed.
	ls.nativeRowChainKnown = false
	require.True(t, ls.observedByCallbacks())
}
