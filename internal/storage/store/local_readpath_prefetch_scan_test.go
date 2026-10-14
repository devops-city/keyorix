package store

// The combined read-path statement is scanned by hand (scanReadPathPrefetchRows)
// instead of gorm's Raw(...).Scan(&rows). These tests are the golden check: for
// every row shape the statement can return, the hand scan yields exactly the
// rows gorm's reflection scan yields (reflect.DeepEqual, so time zones and nil
// vs zero pointers count), on SQLite and, with KEYORIX_TEST_PG_DSN, Postgres.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type prefetchScanCase struct {
	name    string
	trigger string
	machine uint
	scope   storage.Scope
	secret  uint
	want    bool
}

func (c prefetchScanCase) args() []any {
	args := []any{c.trigger, c.machine, c.scope.ProjectID, c.scope.EnvironmentID, rolePermissionsGenerationKey}
	if c.want {
		args = append(args, c.secret)
	}
	return append(args, c.secret)
}

// requireHandScanMatchesGorm runs one case both ways and compares.
func requireHandScanMatchesGorm(t *testing.T, ls *LocalStorage, c prefetchScanCase, wantRows int) {
	t.Helper()
	ctx := context.Background()
	q := readPathPrefetchSQL(nodeTriggerExistsExpr(ls.db), rolePermGenerationExpr(ls.db, "gen"), c.want)
	var viaGorm []readPathPrefetchRow
	require.NoError(t, ls.db.WithContext(ctx).Raw(q, c.args()...).Scan(&viaGorm).Error, c.name)
	got, err := ls.readPathPrefetchRows(ctx, q, c.args(), c.want)
	require.NoError(t, err, c.name)
	require.Len(t, viaGorm, wantRows, "%s: precondition, gorm row count", c.name)
	if len(viaGorm) == 0 {
		require.Empty(t, got, c.name)
		return
	}
	require.Equal(t, viaGorm, got, c.name)
}

func TestReadPathPrefetchScan_MatchesGormScan(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newPrefetchWorld(t, backend)
			ctx := context.Background()
			base := prefetchScanCase{trigger: SecretNodeCacheEpochTrigger, machine: w.machine, scope: w.scope, secret: w.secret.ID}

			// Schedule row with times, one role, generation present.
			for _, want := range []bool{true, false} {
				c := base
				c.want, c.name = want, "one role"
				requireHandScanMatchesGorm(t, w.ls, c, 1)
			}

			// The trigger proof false (no trigger by that name).
			c := base
			c.want, c.trigger, c.name = true, "no_such_trigger", "trigger absent"
			requireHandScanMatchesGorm(t, w.ls, c, 1)

			// No role at the scope: one row, role_id NULL.
			c = base
			c.want, c.machine, c.name = true, w.machine2(), "no role"
			requireHandScanMatchesGorm(t, w.ls, c, 1)

			// Two roles: two rows repeating the node, schedule and versions columns.
			second := w.role(false, w.ppWorld.perm())
			require.NoError(t, w.ls.AssignMachineRole(ctx, w.machine, second.ID, w.scope))
			c = base
			c.want, c.name = true, "two roles"
			requireHandScanMatchesGorm(t, w.ls, c, 2)

			// A secret with no schedule and no versions: NULL schedule columns, zero aggregates.
			bare, err := w.ls.CreateSecret(ctx, &models.SecretNode{
				Name: w.name("pf-bare"), ProjectID: w.scope.ProjectID, EnvironmentID: w.scope.EnvironmentID, Status: "active",
				CreatedAt: time.Now(), UpdatedAt: time.Now(),
			})
			require.NoError(t, err)
			c = base
			c.want, c.secret, c.name = true, bare.ID, "no schedule"
			requireHandScanMatchesGorm(t, w.ls, c, 2)

			// No role->permission generation row: generation NULL.
			require.NoError(t, w.ls.db.Where("key = ?", rolePermissionsGenerationKey).Delete(&models.SystemMetadata{}).Error)
			c = base
			c.want, c.name = true, "no generation row"
			requireHandScanMatchesGorm(t, w.ls, c, 2)

			// Soft-deleted node: no row at all.
			require.NoError(t, w.ls.db.Model(&models.SecretNode{}).Where("id = ?", bare.ID).Update("deleted_at", time.Now()).Error)
			c = base
			c.want, c.secret, c.name = true, bare.ID, "deleted node"
			requireHandScanMatchesGorm(t, w.ls, c, 0)
		})
	}
}

// The stored statement text is per shape: a later call returns the text for its
// own shape, never another's.
func TestReadPathPrefetchSQL_OneTextPerShape(t *testing.T) {
	a := readPathPrefetchSQL("EXISTS (SELECT 1)", "gen.value", true)
	b := readPathPrefetchSQL("EXISTS (SELECT 1)", "gen.value", false)
	require.NotEqual(t, a, b)
	require.Equal(t, a, readPathPrefetchSQL("EXISTS (SELECT 1)", "gen.value", true))
	require.Equal(t, b, readPathPrefetchSQL("EXISTS (SELECT 1)", "gen.value", false))
	require.NotEqual(t, a, readPathPrefetchSQL("EXISTS (SELECT 2)", "gen.value", true))
	require.Contains(t, a, "sched_updated_at")
	require.NotContains(t, b, "sched_updated_at")
}

// Both read-path statements share one text cache: each shape of each
// statement has its own text, and the folded one never answers for the
// node-stamp one (or the reverse).
func TestFoldedCredentialSQL_OneTextPerShape(t *testing.T) {
	for _, want := range []bool{true, false} {
		f := foldedCredentialSQL("EXISTS (SELECT 1)", "gen.value", want)
		require.Equal(t, f, foldedCredentialSQL("EXISTS (SELECT 1)", "gen.value", want))
		require.NotEqual(t, f, readPathPrefetchSQL("EXISTS (SELECT 1)", "gen.value", want))
		require.NotEqual(t, f, foldedCredentialSQL("EXISTS (SELECT 1)", "gen.value", !want))
		require.Equal(t, want, strings.Contains(f, "sched_updated_at"))
		// The credential columns are the plain statement's, in its order.
		plain := strings.TrimSpace(credentialLookupRawQuery)
		require.True(t, strings.HasPrefix(f, plain[:strings.Index(plain, "\nFROM")]+", "), f)
	}
}

// Each statement's binds are built in the order its text expects: one bind
// per placeholder, the node-stamp binds exactly the golden scan test's
// documented order, and the folded statement the same node binds with the
// LEFT JOIN's secret id after the trigger name and the token hash last.
func TestReadPathSQL_BindOrder(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newPrefetchWorld(t, backend)
			expr := nodeTriggerExistsExpr(w.ls.db)
			genExpr := rolePermGenerationExpr(w.ls.db, "gen")
			node := &models.SecretNode{ProjectID: w.scope.ProjectID, EnvironmentID: w.scope.EnvironmentID}
			for _, want := range []bool{true, false} {
				pf := storage.ReadPathPrefetchFrom(storage.NewReadPathPrefetch(context.Background(), w.machine, want))
				c := prefetchScanCase{trigger: SecretNodeCacheEpochTrigger, machine: w.machine, scope: w.scope, secret: w.secret.ID, want: want}

				nodeArgs := readPathPrefetchArgs(pf, w.secret.ID, node)
				require.Equal(t, c.args(), nodeArgs)
				require.Equal(t, strings.Count(readPathPrefetchSQL(expr, genExpr, want), "?"), len(nodeArgs))

				folded := foldedCredentialArgs(pf, w.secret.ID, node, "hash")
				require.Equal(t, strings.Count(foldedCredentialSQL(expr, genExpr, want), "?"), len(folded))
				wantFolded := append([]any{SecretNodeCacheEpochTrigger, w.secret.ID}, nodeArgs[1:len(nodeArgs)-1]...)
				require.Equal(t, append(wantFolded, "hash"), folded)
			}
		})
	}
}
