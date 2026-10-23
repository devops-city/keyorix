// secret_metadata_cache_bench_test.go — microbenchmark for the read-path
// metadata cache (PERF-3, docs/specs/read-path-caching.md): cache hit (warm,
// repeat GetSecret on the same unchanged secret) vs cache miss (every call
// forced cold by evicting the entry first). Not a substitute for the
// pve01 before/after harness numbers (the actual claim this PR makes),
// just a quick local sanity check that a hit is cheaper than a miss at all.
package store

import (
	"context"
	"fmt"
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

// benchLatestVersionSecret creates a secret with n versions, the shape a
// rotation-heavy secret has: the generation check aggregates over every one of
// them (COUNT/MAX/SUM over secret_versions), so a hit and a miss both scale with n.
func benchLatestVersionSecret(b *testing.B, ls *LocalStorage, n int) uint {
	b.Helper()
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if err != nil {
		b.Fatal(err)
	}
	for v := 1; v <= n; v++ {
		if _, err := ls.CreateSecretVersion(ctx, &models.SecretVersion{
			SecretNodeID: created.ID, VersionNumber: v, EncryptedValue: []byte("ct"), CreatedAt: time.Now(),
		}); err != nil {
			b.Fatal(err)
		}
	}
	return created.ID
}

func BenchmarkGetLatestSecretVersion_CacheHit(b *testing.B) {
	for _, n := range []int{1, 100} {
		b.Run(fmt.Sprintf("versions=%d", n), func(b *testing.B) {
			ls := newCacheTestStorage(b)
			ctx := context.Background()
			id := benchLatestVersionSecret(b, ls, n)
			if _, err := ls.GetLatestSecretVersion(ctx, id); err != nil { // warm once
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := ls.GetLatestSecretVersion(ctx, id); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkGetLatestSecretVersion_CacheMiss(b *testing.B) {
	for _, n := range []int{1, 100} {
		b.Run(fmt.Sprintf("versions=%d", n), func(b *testing.B) {
			ls := newCacheTestStorage(b)
			ctx := context.Background()
			id := benchLatestVersionSecret(b, ls, n)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ls.secretMetaCache.evictNode(id) // drops the cached version too: two queries every iteration
				if _, err := ls.GetLatestSecretVersion(ctx, id); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
