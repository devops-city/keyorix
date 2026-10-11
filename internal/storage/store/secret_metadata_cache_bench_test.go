// secret_metadata_cache_bench_test.go — microbenchmark for the read-path
// metadata cache (PERF-3, docs/specs/read-path-caching.md): cache hit (warm,
// repeat GetSecret on the same unchanged secret) vs cache miss (every call
// forced cold by evicting the entry first). Not a substitute for the
// pve01 before/after harness numbers (the actual claim this PR makes),
// just a quick local sanity check that a hit is cheaper than a miss at all.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func BenchmarkGetSecret_CacheHit(b *testing.B) {
	ls := newCacheTestStorage(b)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if err != nil {
		b.Fatal(err)
	}
	if _, err := ls.GetSecret(ctx, created.ID); err != nil { // warm once
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ls.GetSecret(ctx, created.ID); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetSecret_CacheMiss(b *testing.B) {
	ls := newCacheTestStorage(b)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ls.secretMetaCache.evictNode(created.ID) // force a live read every iteration
		if _, err := ls.GetSecret(ctx, created.ID); err != nil {
			b.Fatal(err)
		}
	}
}
