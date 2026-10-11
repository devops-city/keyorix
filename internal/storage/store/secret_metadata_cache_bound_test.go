package store

import (
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Review of #2764: the cache was three plain maps for the process lifetime, and
// setVersion kept EncryptedValue ciphertext for every secret ever read. These
// tests pin the bound (size and age) on every map.

func boundTestCache(max int, ttl time.Duration, clock *time.Time) *secretMetadataCache {
	c := newSecretMetadataCache()
	c.maxEntries = max
	c.ttl = ttl
	c.now = func() time.Time { return *clock }
	return c
}

func TestSecretMetadataCache_SizeIsCapped(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	const max = 8
	c := boundTestCache(max, time.Hour, &clock)
	for i := uint(1); i <= max*4; i++ {
		c.setNode(i, nodeGeneration{}, &models.SecretNode{})
		c.setVersion(i, versionsGeneration{}, &models.SecretVersion{EncryptedValue: []byte("ct")})
		c.setSchedule(i, secretScheduleCacheEntry{hasSchedule: true, schedule: &models.SecretAccessSchedule{}})
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.nodes) > max || len(c.versions) > max || len(c.schedules) > max {
		t.Fatalf("cache exceeded cap %d: nodes=%d versions=%d schedules=%d",
			max, len(c.nodes), len(c.versions), len(c.schedules))
	}
}

func TestSecretMetadataCache_CapDoesNotEvictAnOverwrittenKey(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	c := boundTestCache(2, time.Hour, &clock)
	c.setVersion(1, versionsGeneration{}, nil)
	c.setVersion(2, versionsGeneration{}, nil)
	c.setVersion(2, versionsGeneration{count: 1}, nil) // overwrite at cap: no eviction
	if _, ok := c.getVersion(1); !ok {
		t.Fatal("overwriting an existing key at the cap evicted an unrelated entry")
	}
	if e, ok := c.getVersion(2); !ok || e.generation.count != 1 {
		t.Fatalf("overwrite lost: ok=%v entry=%+v", ok, e)
	}
}

func TestSecretMetadataCache_EntriesExpire(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	c := boundTestCache(100, time.Minute, &clock)
	c.setNode(1, nodeGeneration{}, &models.SecretNode{})
	c.setVersion(1, versionsGeneration{}, &models.SecretVersion{EncryptedValue: []byte("ct")})
	c.setSchedule(1, secretScheduleCacheEntry{hasSchedule: true, schedule: &models.SecretAccessSchedule{}})

	clock = clock.Add(30 * time.Second)
	if _, ok := c.getNode(1); !ok {
		t.Fatal("anti-vacuity: a fresh node entry must hit")
	}
	if _, ok := c.getVersion(1); !ok {
		t.Fatal("anti-vacuity: a fresh version entry must hit")
	}
	if _, ok := c.getSchedule(1); !ok {
		t.Fatal("anti-vacuity: a fresh schedule entry must hit")
	}

	clock = clock.Add(time.Minute)
	if _, ok := c.getNode(1); ok {
		t.Fatal("expired node entry served")
	}
	if _, ok := c.getVersion(1); ok {
		t.Fatal("expired version entry (ciphertext) served")
	}
	if _, ok := c.getSchedule(1); ok {
		t.Fatal("expired schedule entry served")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.nodes)+len(c.versions)+len(c.schedules) != 0 {
		t.Fatal("expired entries were not dropped on read (ciphertext still resident)")
	}
}

// Concurrent fill/read/evict at the cap, under -race: the bound must hold and
// nothing may race. (The stamp-before-data ordering and the tx-scoped
// never-writes rule are pinned by the rollback/rotation tests; the nil-store
// cases by cache_enabled_guard_test.go. This test covers the new eviction
// path those do not reach.)
func TestSecretMetadataCache_BoundHoldsUnderConcurrency(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	const max = 16
	c := boundTestCache(max, time.Hour, &clock)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				id := uint(g*1000 + i)
				c.setVersion(id, versionsGeneration{}, &models.SecretVersion{})
				c.getVersion(id)
				c.setNode(id, nodeGeneration{}, &models.SecretNode{})
				c.setSchedule(id, secretScheduleCacheEntry{hasSchedule: true})
				if i%50 == 0 { // sparse, so evictions don't mask growth
					c.evictNode(id - 1)
					c.evictSchedule(id - 1)
				}
			}
		}(g)
	}
	wg.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.nodes) > max || len(c.versions) > max || len(c.schedules) > max {
		t.Fatalf("cap %d exceeded: %d/%d/%d", max, len(c.nodes), len(c.versions), len(c.schedules))
	}
}
