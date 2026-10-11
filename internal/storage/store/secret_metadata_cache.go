// secret_metadata_cache.go — the read-path metadata cache (PERF-3,
// docs/specs/read-path-caching.md): an in-process, per-LocalStorage-instance
// cache for the three rows GetSecret/GetLatestSecretVersion/
// GetSecretAccessSchedule fetch on every secret read. A cache hit still
// issues one live, indexed generation-check query — it never trusts an
// in-memory value against a write it hasn't independently observed from the
// database. This mirrors server/middleware/auth.go's tokenCache design
// principle (see that file's own header and server/middleware/INVARIANTS.md
// INV-MW-01..11): cache the expensive, mostly-static DATA, never the
// revocation/authorization DECISION — nothing here changes what
// AuthorizeSecret/AuthorizePrincipal decide, only how cheaply the data they
// and the handler read is served.
//
// # One rule, three signals
//
// A generation must change whenever ANY column of the cached value changes.
// A timestamp does not satisfy that, and both of its failure modes were found
// live on this PR's own CI: updated_at is advanced only by writers that go
// through GORM's auto-timestamp callback (so UpdateColumn silently does not
// move it), and two writes landing in one stored microsecond tie.
//
//   - secret_nodes: cache_epoch, a per-row counter maintained by a DATABASE
//     TRIGGER (store.EnsureSecretNodeCacheEpoch). The database bumps it on
//     every update, so Save(), Updates(), UpdateColumn() and raw SQL are all
//     covered with no Go code to forget — and the stamp is ONE int64, so the
//     check is a single indexed PK lookup. Chosen after three Go-side
//     mechanisms each turned out to have a hole; see that function's doc
//     comment. If the trigger is absent (a trigger-less restore, a
//     bare-AutoMigrate test schema) the stamp would be frozen, so the node
//     cache is disabled outright rather than trusted — see
//     SecretNodeCacheEpochTriggerPresent.
//   - secret_versions, for GetLatestSecretVersion: (count, max(version_number),
//     sum(read_count)) over the secret's own versions — content-derived, no
//     clock. A new version moves count and max immediately, a purge moves
//     count, and a read_count increment moves the sum. Deliberately NOT a
//     second trigger: this table has no residual tie risk that a trigger would
//     close, except the one named below, and a second column+trigger doubles
//     the migration surface for it. (An earlier attempt borrowed
//     secret_nodes.updated_at and had CreateSecretVersion bump it; that was
//     reverted because it put a second UPDATE inside rotation's transaction and
//     made invalidation depend on timestamp RESOLUTION, which
//     storeNextSecretVersion's retry loop re-entered fast enough to tie —
//     TestConcurrency_RotateSecret_NoDuplicateVersionNumbers, red in CI.)
//   - secret_access_schedules: the schedule row's own (updated_at + the whole
//     access policy), read in the SAME query as the row. Also deliberately not
//     a trigger: the row is tiny, so covering every policy column costs nothing
//     and leaves NO residual gap — a tie then means the two schedules are the
//     same policy, and serving the cached one is correct.
//
// Known gap, named rather than left implicit: internal/encryption/sweep.go's
// DEK rotation sweep rewrites secret_versions.encrypted_value without changing
// count, max(version_number) or sum(read_count), so a warm latest-version entry
// can outlive a rewrap. That sweep runs only under the exclusive key lock
// (ADR-010, RotateDEKWithSweep), the operator-triggered stopped-server class,
// and its failure mode is a decrypt error against a retired key — fail-closed,
// not a disclosure. A secret_versions.cache_epoch trigger with a
// SUM(cache_epoch) term would close it; recommended as a follow-up rather than
// bundled here.
//
// Deliberately a FIELD on *LocalStorage, not a package-level global: a
// package-level cache would be silently shared across every LocalStorage
// instance in one test binary, which would make a cross-replica Postgres
// test (two LocalStorage instances, two *gorm.DB pools, one shared schema —
// see postgres_contention_helpers_test.go) pass regardless of whether the
// DB-generation invalidation actually works, the same hazard that file's own
// header documents for a single shared storage.Storage. Each NewLocalStorage
// call gets its own fresh cache; WithTransaction's tx-scoped copy shares its
// parent's pointer (same as auditChainMu etc.) — reads inside a transaction
// go through the SAME *gorm.DB handle doing the generation check, so an
// uncommitted write earlier in that transaction is correctly visible
// (read-your-own-writes), and nothing here weakens that.
package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// nodeGeneration is the generation signal for a cached secret_nodes row: the
// row's own cache_epoch, and nothing else.
//
// cache_epoch is maintained by a DATABASE TRIGGER
// (EnsureSecretNodeCacheEpoch, secret_node_cache_epoch.go), which bumps it on
// EVERY update to the row — Save(), Updates(), UpdateColumn() and raw SQL
// alike, with no Go code to forget and nothing for a new writer to opt into.
// That is what lets this be one int64 instead of the row's whole content: the
// three earlier attempts each had a hole the trigger does not (see that
// function's doc comment for updated_at-misses-UpdateColumn, the
// SetColumn-is-a-no-op-under-Save() GORM hook, and the per-write-site bump),
// and the content-derived stamp that did work made the stamp read nearly as
// wide as the row, costing the cache most of its point.
//
// IS a field on models.SecretNode (CacheEpoch, gorm:"<-:false"), so AutoMigrate
// creates the column everywhere — but read-only to GORM, so no Go write can set
// it even by accident, and on Postgres the BEFORE trigger overwrites whatever a
// client sent regardless. Only the TRIGGER is not something AutoMigrate can
// create, which is why EnsureSecretNodeCacheEpoch exists.
//
// A monotonically-increasing per-row counter also cannot TIE the way a
// timestamp can (two writers inside one stored microsecond produced the same
// updated_at, which is why the content-derived stamp existed at all), and it
// cannot repeat after a hard delete and ID re-creation either — see
// TestCacheEpoch_HardDeletedIDIsNeverReissued for the proof rather than the
// assumption.
type nodeGeneration struct {
	cacheEpoch int64
}

// scheduleGeneration is the schedule row's own (updated_at + the whole access
// policy). Same reasoning as nodeGeneration: updated_at can tie between two
// writes in one stored tick, and an access schedule is a read gate, so the
// non-clock component here is the policy itself — a tie then means the two
// schedules ARE the same policy, and serving the cached one is correct.
// AllowedDays/StartHour/EndHour/Timezone are the complete set of policy
// columns on models.SecretAccessSchedule, machine-checked by
// TestScheduleGeneration_CoversEveryPersistedScheduleField.
type scheduleGeneration struct {
	updatedAtUnixNano int64
	allowedDays       string
	startHour         int
	endHour           int
	timezone          string
}

func scheduleGenerationOf(s *models.SecretAccessSchedule) scheduleGeneration {
	return scheduleGeneration{
		updatedAtUnixNano: s.UpdatedAt.UnixNano(),
		allowedDays:       s.AllowedDays,
		startHour:         s.StartHour,
		endHour:           s.EndHour,
		timezone:          s.Timezone,
	}
}

// versionsGeneration is the generation signal for a cached "latest version of
// secret N": derived from the version rows themselves, with no timestamp in
// it, because secret_versions has no updated_at column and because a
// timestamp's resolution is not a safe invalidation boundary for a table
// written in a tight retry loop (see this file's header). Plain `==`
// comparable by construction.
type versionsGeneration struct {
	count            int64
	maxVersionNumber int64
	sumReadCount     int64
}

type secretNodeCacheEntry struct {
	generation nodeGeneration
	node       *models.SecretNode
	storedAt   time.Time
}

// secretVersionCacheEntry is its own entry, in its own map, rather than two
// more fields on secretNodeCacheEntry: the two halves are validated against
// DIFFERENT generation signals now (secret_nodes columns vs the
// secret_versions aggregate), so they cannot share one stamp. That also
// retires the mergeNode/mergeVersion pair, which existed only to stop
// GetSecret and GetLatestSecretVersion from clobbering each other's half of
// one shared entry.
//
// hasVersion distinguishes "this generation has no version row" (a cached
// negative, latestVersion nil) from "nothing cached yet".
type secretVersionCacheEntry struct {
	generation    versionsGeneration
	hasVersion    bool
	latestVersion *models.SecretVersion
	storedAt      time.Time
}

type secretScheduleCacheEntry struct {
	generation  scheduleGeneration
	hasSchedule bool
	schedule    *models.SecretAccessSchedule
	storedAt    time.Time
}

// secretMetadataCache is the whole cache: three independently
// generation-checked maps, one per generation signal.
//
// EVERY method tolerates a nil receiver, and every one of them fails CLOSED
// when it is nil: readers report a miss, writers and evictors no-op. A
// transaction-derived store is built as a bare &LocalStorage{db: tx} literal in
// several places (local_rbac.go's clone among them), which leaves this field
// nil, and the evictors are reached from shared write paths regardless of
// whether the store caches. Nil-safety here is the panic backstop only — the
// POLICY that a tx-derived store must not read or write the cache is enforced
// separately and structurally by TestCacheEnabled* in
// cache_enabled_guard_test.go, because a silent no-op is not a
// substitute for a missing cacheEnabled check.
type secretMetadataCache struct {
	mu        sync.Mutex
	nodes     map[uint]secretNodeCacheEntry
	versions  map[uint]secretVersionCacheEntry
	schedules map[uint]secretScheduleCacheEntry

	maxEntries int              // per map
	ttl        time.Duration    // per entry, measured from its store
	now        func() time.Time // injectable for tests
}

const (
	// secretMetaCacheMaxEntries caps EACH of the three maps (review of #2764,
	// modelled on server/middleware/auth.go's maxTokenCacheEntries). Keys are
	// real secret IDs, so this is not about a flood; it bounds memory — and the
	// resident ciphertext in the versions map, which must keep EncryptedValue
	// because every GetLatestSecretVersion caller consumes it — against vault size.
	secretMetaCacheMaxEntries = 10_000
	// secretMetaCacheTTL bounds how long any entry (ciphertext included) can sit
	// in process memory. It is a memory/exposure bound ONLY: correctness never
	// depends on it, every hit is still validated against its live generation.
	secretMetaCacheTTL = 5 * time.Minute
)

func newSecretMetadataCache() *secretMetadataCache {
	return &secretMetadataCache{
		nodes:      make(map[uint]secretNodeCacheEntry),
		versions:   make(map[uint]secretVersionCacheEntry),
		schedules:  make(map[uint]secretScheduleCacheEntry),
		maxEntries: secretMetaCacheMaxEntries,
		ttl:        secretMetaCacheTTL,
		now:        time.Now,
	}
}

func (c *secretMetadataCache) getNode(id uint) (secretNodeCacheEntry, bool) {
	if c == nil {
		return secretNodeCacheEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.nodes[id]
	if ok && c.expired(e.storedAt) {
		delete(c.nodes, id)
		return secretNodeCacheEntry{}, false
	}
	return e, ok
}

func (c *secretMetadataCache) setNode(id uint, generation nodeGeneration, node *models.SecretNode) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.nodes[id]; !exists {
		makeRoom(c.nodes, c.maxEntries)
	}
	c.nodes[id] = secretNodeCacheEntry{generation: generation, node: node, storedAt: c.now()}
}

// evictNode and evictSchedule tolerate a nil receiver on purpose. A
// transaction-derived store is built as a bare &LocalStorage{db: tx} literal in
// several places (local_rbac.go's WithTransaction clone among them), which
// leaves secretMetaCache nil — and those stores DO reach eviction, because
// eviction is called from the shared write paths. Returning instead of
// panicking is also the correct semantic, not just the safe one: a store with
// no cache has nothing to evict.
func (c *secretMetadataCache) evictNode(id uint) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.nodes, id)
	delete(c.versions, id)
}

func (c *secretMetadataCache) getVersion(secretNodeID uint) (secretVersionCacheEntry, bool) {
	if c == nil {
		return secretVersionCacheEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.versions[secretNodeID]
	if ok && c.expired(e.storedAt) {
		delete(c.versions, secretNodeID) // drops the resident ciphertext too
		return secretVersionCacheEntry{}, false
	}
	return e, ok
}

func (c *secretMetadataCache) setVersion(secretNodeID uint, generation versionsGeneration, version *models.SecretVersion) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.versions[secretNodeID]; !exists {
		makeRoom(c.versions, c.maxEntries)
	}
	c.versions[secretNodeID] = secretVersionCacheEntry{generation: generation, hasVersion: true, latestVersion: version, storedAt: c.now()}
}

func (c *secretMetadataCache) getSchedule(secretNodeID uint) (secretScheduleCacheEntry, bool) {
	if c == nil {
		return secretScheduleCacheEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.schedules[secretNodeID]
	if ok && c.expired(e.storedAt) {
		delete(c.schedules, secretNodeID)
		return secretScheduleCacheEntry{}, false
	}
	return e, ok
}

func (c *secretMetadataCache) setSchedule(secretNodeID uint, e secretScheduleCacheEntry) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.schedules[secretNodeID]; !exists {
		makeRoom(c.schedules, c.maxEntries)
	}
	e.storedAt = c.now()
	c.schedules[secretNodeID] = e
}

// expired reports whether an entry stored at t is past the TTL. Caller holds
// c.mu. An expired entry is a miss and is deleted by the reader. An entry nobody
// reads again stays until the cap evicts it (see makeRoom), so the TTL bounds
// how long an entry can be SERVED and the cap bounds how much can be resident.
func (c *secretMetadataCache) expired(t time.Time) bool {
	return c.now().Sub(t) >= c.ttl
}

// makeRoom evicts one arbitrary entry when m is at the cap, so the insert that
// follows keeps len(m) <= max. Arbitrary (Go map iteration order) rather than
// LRU: every hit is generation-validated, so which entry is dropped affects
// only hit rate, never correctness, and O(1) eviction keeps the write path off
// a scan. Caller holds c.mu and only calls it for a key not already present.
func makeRoom[V any](m map[uint]V, max int) {
	if max <= 0 {
		max = 1
	}
	for len(m) >= max {
		for k := range m {
			delete(m, k)
			break
		}
	}
}

func (c *secretMetadataCache) evictSchedule(secretNodeID uint) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.schedules, secretNodeID)
}

// liveVersionsGeneration reads the aggregate generation of secretNodeID's
// version rows in one indexed query (secret_versions is indexed on
// secret_node_id). Unlike the node and schedule signals it has no "found"
// notion: a secret with no versions legitimately aggregates to the zero
// generation, and that zero is itself a valid stamp — GetLatestSecretVersion
// caches the "no version exists" answer under it, and the first
// CreateSecretVersion moves count and max(version_number) off zero. An error
// is still fail-closed: the caller treats it as a miss and caches nothing.
func liveVersionsGeneration(ctx context.Context, db *gorm.DB, secretNodeID uint) (versionsGeneration, error) {
	var row struct {
		Cnt    int64
		MaxVer int64
		SumRc  int64
	}
	err := db.WithContext(ctx).Model(&models.SecretVersion{}).
		Select("COUNT(*) AS cnt, COALESCE(MAX(version_number), 0) AS max_ver, COALESCE(SUM(read_count), 0) AS sum_rc").
		Where(sqlWhereSecretNodeID, secretNodeID).Take(&row).Error
	if err != nil {
		return versionsGeneration{}, err
	}
	return versionsGeneration{count: row.Cnt, maxVersionNumber: row.MaxVer, sumReadCount: row.SumRc}, nil
}

// liveScheduleGeneration is the schedule table's stamp-only read, used ONLY to
// validate a warm entry; the entry itself is stamped with the row's own values
// read in the same query as the row (GetSecretAccessSchedule), so there is no
// read-data-then-read-stamp window. SecretAccessSchedule has no soft-delete
// column, so "not found" here always means DeleteSecretAccessSchedule actually
// removed the row.
//
// The stamp is updated_at PLUS the whole access policy, so two schedule writes
// landing in one stored timestamp tick cannot tie unless they are the same
// policy — see scheduleGeneration.
func liveScheduleGeneration(ctx context.Context, db *gorm.DB, secretNodeID uint) (scheduleGeneration, bool, error) {
	var row models.SecretAccessSchedule
	err := db.WithContext(ctx).Model(&models.SecretAccessSchedule{}).
		Select("updated_at", "allowed_days", "start_hour", "end_hour", "timezone").
		Where(sqlWhereSecretNodeID, secretNodeID).Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return scheduleGeneration{}, false, nil
		}
		return scheduleGeneration{}, false, err
	}
	return scheduleGenerationOf(&row), true, nil
}
