// break_glass_review_pg_test.go — PostgreSQL-only: proves
// ReviewBreakGlassActivation's conditional UPDATE (reviewed_at IS NULL) is a
// genuine single-winner race gate under REAL concurrent connections, not
// just the single-goroutine-against-one-*gorm.DB-handle shape a SQLite test
// can only approximate (the exact class of gap this repo's own lessons
// (CLAUDE.md: "a test fixture that cannot structurally exercise the property
// it asserts proves nothing") call out — see
// TestConcurrency_BootstrapSystem_CrossReplicaExactlyOneAdmin's history for
// the worked example this mirrors).
package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/require"
)

var breakGlassReviewPgModels = []any{&models.BreakGlassActivation{}}

// TestReviewBreakGlassActivation_Postgres_ConcurrentReviewsExactlyOneWins
// fires N concurrent reviews at the SAME activation, each from its own real
// Postgres connection (via its own *LocalStorage over the shared schema, not
// a shared in-process handle), and asserts exactly one succeeds — the rest
// must all get storage.ErrBreakGlassAlreadyReviewed, never a silent
// overwrite of the first reviewer's attribution.
func TestReviewBreakGlassActivation_Postgres_ConcurrentReviewsExactlyOneWins(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(breakGlassReviewPgModels...))

	activation, err := localstore.NewLocalStorage(setupDB).CreateBreakGlassActivation(context.Background(), &models.BreakGlassActivation{
		ProjectID: 1, UserID: 10, RoleID: 3, RoleName: "editor", State: BreakGlassActive,
	})
	require.NoError(t, err)

	const racers = 8
	var wg sync.WaitGroup
	errs := make([]error, racers)
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			db := pgOpen(t, dsn)
			ls := localstore.NewLocalStorage(db)
			errs[i] = ls.ReviewBreakGlassActivation(context.Background(), activation.ID, uint(100+i),
				"concurrent reviewer racing for the win", time.Now().UTC())
		}(i)
	}
	wg.Wait()

	successes := 0
	for _, e := range errs {
		if e == nil {
			successes++
		}
	}
	require.Equal(t, 1, successes, "exactly one concurrent review must succeed, got %d (errs: %v)", successes, errs)

	var got models.BreakGlassActivation
	require.NoError(t, setupDB.First(&got, activation.ID).Error)
	require.NotZero(t, got.ReviewedBy, "the winning reviewer's attribution must be recorded")
}
