// local_readpath_prefetch_trigger_disabled_test.go — PERF-TESTS-1: the
// combined (prefetching) read statement proves the cache_epoch trigger in the
// same query as the stamp. A trigger that still exists but is DISABLED
// (tgenabled = 'D') never fires, so the stamp stops moving: that must be a
// cache MISS on this path, not a stale hit. Postgres only (SQLite has no
// disabled-trigger state).
package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestReadPathPrefetch_TriggerDisabledWhileWarmIsAMissNotAStaleHit(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		if backend != "postgres" {
			continue
		}
		t.Run(backend, func(t *testing.T) {
			w := newPrefetchWorld(t, backend)
			ctx := context.Background()
			w.gateReads(ctx)
			_, cached := w.ls.secretMetaCache.getNode(w.secret.ID)
			require.True(t, cached, "the entry must be warm")

			require.NoError(t, w.ls.db.Exec("ALTER TABLE secret_nodes DISABLE TRIGGER "+SecretNodeCacheEpochTrigger).Error)
			require.NoError(t, w.ls.db.Model(&models.SecretNode{}).Where("id = ?", w.secret.ID).
				UpdateColumn("status", "suspended").Error)

			pctx := storage.NewReadPathPrefetch(ctx, w.machine, true)
			node, err := w.ls.GetSecret(pctx, w.secret.ID)
			require.NoError(t, err)
			require.Equal(t, "suspended", node.Status, "a warm entry was served after its trigger was disabled")
		})
	}
}
