# Read-path cache ordering: making stale-cache bugs structurally impossible (GUARD-6)

Spec for GUARD-6. Companion to [`read-path-caching.md`](read-path-caching.md), which specified
*which* rows PERF-3 caches and *why* that is safe. This spec is about the one mistake every
such cache can make, and about replacing "remember not to make it" with a mechanism that
fails when someone does.

## 1. The bug class

A generation-validated read cache has three moving parts:

- **G** — a cheap, indexed *generation* (stamp) read: `secret_nodes.updated_at`,
  `system_metadata['role_permissions_generation']`.
- **V** — the expensive *data* load: the row, the latest version, the `role_permissions` join.
- the cache itself, mapping a key to `(G, V)`.

A **miss** must read both and store them together; a **hit** must re-read G live and serve the
cached V only when the fresh G equals the stored one. That shape is correct — but only under one
ordering constraint, and nothing in the shape itself enforces it.

```
            BUGGY: data first, stamp second          CORRECT: stamp first, data second
  t0        v := load()                              g := readGen()        -> G_before
  t1        <a write commits>                        <a write commits>
  t2        g := readGen()  -> G_after               v := load()           -> V_after
  t3        cache[k] = (G_after, v)   <- V_before!   cache[k] = (G_before, V_after)
```

In the buggy ordering the entry is **born self-consistent and wrong**: the next hit reads
`G_after` live, it equals the stored stamp, so the pre-change `V_before` is served — and keeps
being served, not for a bounded TTL but *until some unrelated write bumps that generation
again*. There is no TTL here to put a ceiling on it.

In the correct ordering the worst case is an entry stamped `G_before` holding `V_after`:
pessimistically stale, so the next hit's live `G_after` does not match, the entry never hits,
and the only cost is a wasted map slot. **The failure is asymmetric** — one ordering fails
open and silently, the other fails to a cache miss.

Found twice, in the same review pass, in the two PERF-3 caches:

| Site | Effect | Proving test |
|---|---|---|
| `RoleSetHasPermission` (#2767) | a revoked permission kept authorizing | `TestRoleSetHasPermission_RevokeDuringResolveIsNotCachedStale` |
| `GetLatestSecretVersion` (#2764) | a rotated secret kept returning its pre-rotation version | `TestGetLatestSecretVersion_RotationDuringResolveIsNotCachedStale` |

Both were written independently, by the same author, days apart, each with a full test file
including cross-replica Postgres cases — and both got the ordering wrong. That is the signal
this spec responds to: the ordering is not hard to state, it is hard to *notice*, because
nothing about the buggy code looks wrong and every test that does not race a write through the
window passes. PERF-7 plans a third cache (secret values). Catching this a third time by review
is not a plan.

### 1.1 The sibling bug class, found while fixing these two: a stamp that does not move

Ordering is necessary but not sufficient. A correctly-ordered cache is still wrong if the
stamp **does not change when a cached column changes** — and both PERF-3 caches had that
defect too, found in #2764/#2767's own CI and fixed there (`4b31a9d6`, `34495c0d`):

- `secret_nodes.updated_at` alone misses `TryIncrementSecretNodeReadCount`, whose
  `UpdateColumn` write bypasses GORM's auto-timestamp callback. A warm entry served
  `read_count=0` forever, and `RotateSecret`'s `GetSecret` → mutate → `Save()` wrote that
  stale zero back — a fresh budget for a burn-after-N-reads secret. The node stamp is now
  `secret_nodes.cache_epoch`, maintained by a database trigger — see §1.1.1, which supersedes
  the `(updated_at, read_count)` and content-derived stamps this document originally
  described for this cache.
- the latest-version cache borrowed `secret_nodes.updated_at`, so **no** version writer moved
  it; the mitigation (bump it from `CreateSecretVersion`) made invalidation depend on the
  stored timestamp's *resolution*, and `storeNextSecretVersion`'s retry loop re-entered fast
  enough to tie — it re-read its own stale cached answer and burned all 20 attempts against
  the unique index. Fixed by deriving the stamp from the version rows themselves:
  `(count, max(version_number), sum(read_count))`, no clock in it.
- `role_permissions`' stamp was `time.Now().UnixNano()` plus a random suffix: correct for
  invalidation, but *nondeterministic*, which broke `FuzzStorageFaultOperations`' state
  oracles (they compare `system_metadata` between a fault-free reference run and a faulted
  run; `Value` is a string and is compared byte-for-byte). Fixed by making it a monotonic
  integer the database increments inside one `UPDATE`.

Three rules fall out, and §2 builds them into the helper's contract rather than restating
them:

1. **Derive the stamp from something every writer moves.** A timestamp is a stamp only for
   writers that advance it; enumerate the ones that do not (`UpdateColumn`/`UpdateColumns` and
   raw SQL) and either cover them or make them unreachable. For a wide, frequently-written
   table the answer is a trigger-maintained counter, not an enumeration — §1.1.1.
2. **No clock in a stamp for a table written in a tight loop.** Resolution ties are
   indistinguishable from "nothing changed".
3. **A stamp must be deterministic.** A clock- or randomness-derived stamp is invisible to
   every state-comparison oracle in this repo, which means it silently disables them.

#### 1.1.1 For a wide row, the stamp is a trigger-maintained counter, not derived content

**Decision (Andrei, 2026-10-05). Code lands with #2764; this section is the normative rule from
now on.** `secret_nodes` gained `cache_epoch BIGINT NOT NULL DEFAULT 0`, bumped by a database
trigger on every UPDATE. The node cache's generation is that column alone.

Rule 1 above says "derive the stamp from the cached columns". Taken literally for a 25-column
row, that produces a stamp whose read costs as much as the row read it was meant to avoid:

| node stamp | cache hit | cache miss (the row read) |
|---|---|---|
| `updated_at` only (incorrect — misses `UpdateColumn`) | 6.0–6.5 µs | 23.3–23.9 µs |
| all 25 persisted columns (correct, but) | **24.6–25.5 µs** | 23.1–23.5 µs |
| `cache_epoch` trigger (correct) | 6.6–7.4 µs | 24.3–25.7 µs |

A hit that costs *more than a miss* is a pessimisation wearing a cache's name. So for a wide
row the rule is: **make the database maintain a single integer that moves on every write**, and
stamp on that.

Every Go-side alternative was tried first and has a hole:

- `updated_at` misses `UpdateColumn`/`UpdateColumns`, which bypass GORM's auto-timestamp
  callback. That is the original bug.
- a `BeforeUpdate` hook calling `SetColumn` is **silently a no-op for a full-struct `Save()`**,
  which is what `UpdateSecret` uses.
- bumping it at each write site requires every current and future writer to remember, raw
  `db.Exec` included: opt-in correctness, this codebase's recurring defect shape.

A trigger has none of them: `Save()`, `Updates()`, `UpdateColumn()` and raw SQL are covered
identically, with no Go code to forget. Keep the column **read-only to GORM** (`gorm:"<-:false"`)
— a full-struct `Save()` of a stale struct would otherwise roll the stamp *backwards*, which is
worse than not bumping it, because an entry stamped with the higher value starts matching again.

Two dialect forms, both load-bearing: Postgres gets a BEFORE UPDATE trigger assigning
`NEW.cache_epoch`; SQLite **cannot** (a SQLite trigger body may only run
INSERT/UPDATE/DELETE/SELECT, never assign to `NEW`), so it gets an AFTER UPDATE trigger issuing
a nested single-row UPDATE with `WHEN NEW.cache_epoch = OLD.cache_epoch` as the recursion guard.

**A stamp a trigger maintains must be probed for, and its absence must disable the cache.** A
database with the *column* but not the *trigger* has a stamp frozen at 0 forever, so every hit
serves the row as first read — indefinitely, with no error and no symptom. That is not
hypothetical: it is what every bare-`AutoMigrate` test schema looks like, and
`pg_restore --disable-triggers` or a schema-only restore produces it in production.
`SecretNodeCacheEpochTriggerPresent` checks for it and the cache is **disabled** when it is
absent. Any new trigger-stamped cache owes the same fail-closed probe, and any test fixture
building its own schema owes the `EnsureSecretNodeCacheEpoch` call — a cache test against a
triggerless schema passes against an *uncached* path, which is a vacuous pass, not a green one.
That exact vacuity was found in this spec's own race harness (§4): 13 rows were passing with no
cache in play.

**Where content-derived stamps are still right.** Not everything needs a trigger, and adding one
costs a column, a trigger pair, an upgrade path and a fail-closed probe per table:

- `secret_access_schedules` — the row is small enough that the stamp covers the *whole* policy
  (`allowed_days`, `start_hour`, `end_hour`, `timezone`) at no cost, leaving no residual gap: a
  tie implies an identical policy, so serving the cached one is correct.
- `secret_versions` — the aggregate `(count, max(version_number), sum(read_count),
  sum(cache_epoch))` has no clock in it. The one writer that rewrites `encrypted_value` in place,
  the DEK-rotation sweep, moves none of the first three terms, so it raises `cache_epoch` on every
  row it rewrites, in its own transaction (DEK-SWEEP-CACHE-1; STORAGE-2 had decided the gap safe
  and pinned it, which this replaces). A plain column set by its one writer, not a trigger:
  nothing else rewrites the ciphertext, and
  `TestSecretVersionCiphertextWriters_AreOnlyTheSweep` fails if something starts to. The term
  rides in the aggregate the hit already issues, so the read path gains no statement, and the
  ordering rule of section 1 is untouched (generation first, then the row). Another replica learns
  of the rewrap the same way it learns of a new version: its next hit reads the changed
  aggregate. Pinned by `TestDEKSweepCache_*` and `TestSingleWriter_DEKSweepVsLatestVersionCache`.

The test: **is the row wide enough that reading a content stamp approaches reading the row?** If
yes, trigger. If no, derive from content and state the residual gap.

### 1.2 The one legitimate exception

When G is a **column of the very row V consists of** — `secret_access_schedules.updated_at` and
the schedule row itself — a single query returns both, atomically, as of one snapshot. There is
no window between them to commit a write into, so the ordering constraint does not apply. This
is not a loophole to be argued for case by case: it gets its own, separately named helper, so
that "this site is the same-row case" is a thing the code *says*, not a thing a reviewer has to
re-derive.

## 2. Item 1 — correct by construction: one helper

New file `internal/storage/store/read_path_cache.go`. Every read-path cache in the package goes
through it; there is exactly one place where a cache entry can be written.

### 2.1 The cache container

```go
// genCache is the only cache type in internal/storage/store. Entries can be
// written ONLY by cachedRead/cachedReadSameRow in this file — enforced by
// read_path_cache_guard_test.go, not by convention.
type genCache[K comparable, G cacheGeneration, V any] struct { ... }

func (c *genCache[K, G, V]) get(k K) (genCacheEntry[G, V], bool) // read-only
func (c *genCache[K, G, V]) store(k K, stamp G, v V)             // helper-only
func (c *genCache[K, G, V]) drop(k K)                            // helper-only
```

Generic over key, value and generation type, per the brief. Per-`*LocalStorage`-instance,
never a package-level global — PERF-3's own reason stands and is unchanged: a package-global
cache would make the two-pool cross-replica Postgres tests pass whether or not DB-generation
invalidation works at all.

### 2.2 The generation type is constrained, not just `comparable`

```go
type cacheGeneration interface {
	comparable
	isCacheGeneration()
}
```

`comparable` alone would admit `time.Time`, which is a trap: `time.Time` **is** comparable, so
`G == G` compiles, but `==` on it also compares the monotonic reading and the `*time.Location`
pointer — so two reads of the same column can compare unequal (`time.Time.Equal` is the only
correct comparison, and `Equal` cannot be expressed through `==`). A cache whose stamps never
compare equal never hits: a pure performance failure, invisible to every correctness test,
which is exactly the kind of thing that survives for a year. The marker method makes
`time.Time` *not satisfy the constraint*, so that mistake does not compile. Verified: a
constraint interface embedding `comparable` plus a marker method compiles, and a struct with a
value-receiver marker satisfies it.

Each site declares its own generation type, carrying the stamp §1.1 says it needs. Where a
timestamp still appears it is canonicalised to `int64` nanoseconds on the way in (Postgres
stores `timestamptz` at microsecond precision, so the read-back value is stable, and this loses
nothing the column did not already lose) — which is also what makes these types `comparable` at
all. **These are the four types as they exist in the code**, not an illustration:

```go
type nodeGeneration struct{ cacheEpoch int64 } // secret_nodes — the trigger counter, §1.1.1

type versionsGeneration struct{ count, maxVersionNumber, sumReadCount int64 } // secret_versions

type scheduleGeneration struct { // secret_access_schedules — updated_at AND the whole policy
	updatedAtUnixNano int64
	allowedDays       string
	startHour, endHour int
	timezone          string
}

type rolePermGeneration struct{ counter string } // system_metadata, a monotonic integer as text
```

Two of them are deliberately not what an earlier draft of this document described, and the
differences are the point rather than tidying:

- `nodeGeneration` is `cacheEpoch` **alone** — not `(updated_at, read_count)`. `updated_at` is
  not a stamp for a writer that bypasses GORM's auto-timestamp callback, and widening it to
  cover every column measured *slower than not caching at all*; see §1.1.1.
- `scheduleGeneration` carries the **whole access policy**, not `updated_at` alone, so two
  schedule writes landing in one stored timestamp tick cannot tie unless they are the same
  policy — in which case serving the cached one is correct. That is what makes this signal have
  no residual gap, and it is affordable only because the row is small.

### 2.3 `cachedRead` — the cross-row case

```go
func cachedRead[K comparable, G cacheGeneration, V any](
	ctx context.Context,
	cache *genCache[K, G, V],
	key K,
	gen func(context.Context) (G, bool, error),
	load func(context.Context) (V, error),
) (V, error)
```

Contract, in order, with no path that can reorder it:

1. **The generation is read first, always** — before the cache is even consulted, and therefore
   unconditionally before `load`. One read serves both the hit check and the store stamp.
2. **A hit is served only on a fresh, successful, equal generation read.** `gen` returning an
   error, or `found == false` (the row is gone / soft-deleted), is a **miss** — never "assume
   unchanged". Fail closed: the cache is strictly an optimisation over a path that must behave
   identically with the cache deleted.
3. On a miss, `load` runs and its result is returned.
4. **The entry is stored only when the generation read succeeded and found a row**, under the
   stamp read in step 1. Never under a stamp read after `load`; there is no code path that
   reads a stamp after `load`.
5. **`load` returning an error drops the key** and propagates the error. Dropping is always
   safe (it costs a future miss, nothing else) and it is what makes "the row was deleted"
   stop being served.

`load` returning a *nil pointer with no error* is how a call site caches a confirmed negative
("this generation has no latest version"), preserving PERF-3's existing `hasVersion` behaviour
without a second mechanism.

**`found` is about the GENERATION, not about the data** — worth stating, because steps 2 and 4
otherwise read as forbidding exactly that negative. The two are independent:

| | `gen` returns | `load` returns | result |
|---|---|---|---|
| secret has no versions | `found == true`, the zero aggregate | `nil`, no error | **cached negative** |
| secret row is gone / soft-deleted | `found == false` | not reached | **miss, nothing stored** |

`liveVersionsGeneration` has no not-found notion at all: a secret with no version rows
legitimately aggregates to `(0, 0, 0)`, and that zero is a perfectly good stamp — the first
`CreateSecretVersion` moves `count` and `max(version_number)` off it. So steps 2 and 4 never
fire for the empty-versions case, and the cached negative is stored under a real stamp like any
other value. `found == false` is reserved for signals that genuinely have a row to miss
(`readLiveNodeStamp`, `liveScheduleGeneration`), where it means the thing being stamped no
longer exists and nothing may be served or stored for it.

### 2.4 `cachedReadSameRow` — the exception, made explicit

```go
func cachedReadSameRow[K comparable, G cacheGeneration, V any](
	ctx context.Context,
	cache *genCache[K, G, V],
	key K,
	gen func(context.Context) (G, bool, error),       // cheap stamp-only read, validates a HIT
	load func(context.Context) (V, G, error),          // one query: the row AND its own stamp
) (V, error)
```

Identical except that the stored stamp comes from `load`'s own return value, because it is a
column of the row `load` returned. A caller cannot accidentally use this variant for a
cross-row generation: it would have to produce a stamp from the loaded row, and for
`GetLatestSecretVersion` (stamp on `secret_nodes`, data in `secret_versions`) there is none to
produce.

### 2.5 Call sites moved onto the helper

| Method | Variant | Key | Generation | Data |
|---|---|---|---|---|
| `GetSecret` | `cachedReadSameRow` | secret id | `secret_nodes.cache_epoch` (trigger-maintained, §1.1.1) | the `secret_nodes` row |
| `GetLatestSecretVersion` | `cachedRead` | secret id | `(count, max(version_number), sum(read_count))` over `secret_versions` | newest `secret_versions` row |
| `GetSecretAccessSchedule` | `cachedReadSameRow` | secret node id | `secret_access_schedules.updated_at` **plus the whole access policy** | the schedule row |
| `RoleSetHasPermission` | `cachedRead` | `(sorted(roleIDs), permission)` | `system_metadata['role_permissions_generation']`, a monotonic integer the database increments in one `UPDATE` | the `role_permissions` join |

`GetSecret`'s stamp read additionally re-proves, **in the same query**, that the `cache_epoch`
trigger still exists, and treats its absence as a miss. Without that, a database that loses the
trigger has a stamp frozen at a constant, which compares equal forever — the cache would serve
every warm row as of first read, indefinitely, with no error. See §1.1.1.

**Acceptance criterion: behaviour is identical.** PERF-3's existing cache test files
(`secret_metadata_cache_test.go`, `role_permission_cache_test.go`, both `*_cross_replica_postgres_test.go`,
both `*_bench_test.go`) run **unchanged**, including the accessors they reach into
(`ls.secretMetaCache.getNode`, `ls.getCachedSecret`, `ls.rolePermCache.get`,
`ls.getCachedRolePermission`, `rolePermKey`). A refactor that needed its own tests edited to
pass would not be a refactor.

Two honest qualifications on that criterion, because it is otherwise stated more strongly than
the code supports:

- Those accessors survive, but they do **not** touch a `genCache` directly — that is precisely
  what §3's rule B forbids, and a "thin read-only wrapper over `genCache`" would violate it.
  They route through the sanctioned read-only API (`peekCachedEntry`, `cachedHit`,
  `cachedEntryCount`), which is what keeps the `cacheEnabled` check on the single path through
  `probe`.
- "Unchanged" covers the *refactor*. It does not cover test files that changed for reasons of
  their own in the same series — the rollback tests gained positive controls (they asserted only
  that something is NOT served, so every one of them passed with the cache switched off), and the
  stamp-coverage tests were repointed at the trigger when the node stamp became `cache_epoch`.
  Those are changes to what the tests *prove*, not changes made to keep them passing.

Two incidental simplifications fall out and are called out because they are behaviour-adjacent:

- `secretMetadataCache`'s `mergeNode`/`mergeVersion` pair — which existed to stop `GetSecret`
  and `GetLatestSecretVersion` from clobbering each other's half of one shared map entry —
  disappears: node and latest-version become two independently stamped `genCache`s keyed on the
  same id. Each half was already independently generation-validated, so no validation is lost;
  what is lost is the merge logic, which was the only reason two writers shared one entry.
- "No schedule exists" stays uncached, as PERF-3 specified (there is no row to read a stamp
  from, so a negative cannot be validated). With `cachedReadSameRow` this is not a special case
  any more: a not-found `load` has no stamp to store, so nothing is stored.

### 2.6 Non-goals

- No TTL, no push invalidation (LISTEN/NOTIFY), no shared/cross-process cache. Unchanged from
  `read-path-caching.md` §PR-1, for the same reasons.
- No change to any authorization decision, to what any method returns, or to which callers are
  allowed. This is a refactor plus a guard.
- `V` is not deep-copied by the helper. Defensive copies stay at the call sites, exactly as
  today; the helper documents the contract ("store a value the caller will not mutate, return a
  copy").

## 3. Item 2 — the no-bypass guard

`internal/storage/store/read_path_cache_guard_test.go`, in the style of the existing structural
guards (`internal/core/atomicity_guard_test.go`, `check_then_act_lock_guard_test.go`,
`internal/storage/store/g81_guard_test.go`): parse the package's AST, derive the thing being
checked from the code, fail on a violation.

**It must not be a hardcoded list of today's method names.** Per this repo's own standing
lesson — an enumeration is only as complete as the idioms it knows about, five instances and
counting — the guard *derives* its target set and *states* which shapes it recognises:

1. **Cache types** = types declared in package `store` whose name ends in `Cache`
   (case-insensitive) and whose struct has at least one map-typed or `*genCache` field.
2. **Mutating methods** = methods on those types whose body writes a receiver field: an
   assignment to `r.f` or `r.f[k]`, or `delete(r.f, k)`. Derived from the AST, so
   `set`/`merge*`/`store`/`evict*`/anything-else-named is covered without naming it.
3. **Violation** = a call to any such method from any file other than `read_path_cache.go`,
   `_test.go` files included.
4. **The naming loophole is closed by a second check**: any type in the package carrying both a
   mutex field and a map field, but *not* named `*Cache`, fails with "name it `…Cache` or
   explain it here" plus a reasoned allowlist. On `main` today that allowlist has exactly one
   entry — `namedLockRegistry` (`map[string]*namedLockEntry`, a lock registry, not a read
   cache); the other three mutex-bearing types in the package (`clockWatermark`,
   `auditFlusherState`, `namedLockEntry`) hold no map and so are not candidates at all. Without
   this check, renaming a cache type is enough to escape rule 1 — and a guard you can escape by
   renaming is not a guard.

The guard's doc comment states explicitly what it does **not** catch: a cache built on a bare
map field of `LocalStorage` with no wrapper type at all, and any cache outside package `store`.
Naming a check for what it verifies, and writing down what it doesn't, is the standing rule
here.

**Red/green.** Two layers, because the brief asks for the second and the first is what keeps
working after today:

- `TestReadPathCacheGuard_Fixtures`: the checker runs over `fstest.MapFS` fixtures — a clean
  package (green), a package with a direct `set()` call outside the helper (red), a renamed
  cache type (red), a mutex+map type not named `*Cache` (red). This is the permanent
  calibration: it proves the guard fires *and* that it passes a known-good case, both
  directions, every CI run.
- A one-off scratch-copy demonstration pasted into the PR body: reintroduce the literal
  `ls.secretMetaCache.store(...)` call that this refactor removed, run the guard, show it red.

## 4. Item 3 — one shared race test for every cached read

`internal/storage/store/read_path_cache_race_test.go`. Table-driven, one row per cached read
method, plus one row per *writer* (item 4). Each row names:

| Field | Meaning |
|---|---|
| `site` | the package function that calls `cachedRead`/`cachedReadSameRow` (e.g. `GetLatestSecretVersion`) |
| `window` | the GORM table whose query opens the data/stamp window (e.g. `secret_versions`) |
| `setup` | fixtures |
| `mutate` | the write committed *inside* the window |
| `read` | the cached read under test |
| `wantFresh` | the assertion that the next read observes `mutate` |

The harness registers a one-shot GORM `After("gorm:query")` callback that fires when
`tx.Statement.Table == window`, commits `mutate` there, asserts the callback actually fired
(`require.False(t, armed, ...)` — a window that never opened is a vacuous test, not a pass),
and then asserts `wantFresh` on the **next** read. The in-flight read may legitimately still
answer with the pre-write value — it read before the write; what must never happen is that
answer being *cached under the post-write stamp*.

**Completeness.** An AST check in the same file enumerates every function in the package that
calls `cachedRead` or `cachedReadSameRow` and fails if any of them has no row in the table.
A new cache that forgets its race row does not compile-and-pass; it fails. (Registry pattern,
as in the GUARD-3 guards and `remote_reachability_registry_test.go`.)

**Red proof.** Not "it fails on a fixture I invented" — it has to fail on the two defects that
actually happened. Each PR's pre-fix parent (`86dea122^` for #2764, `8cd09937^` for #2767) is
checked out in a scratch worktree, the harness is dropped in, and the run is pasted:
`GetLatestSecretVersion` and `GetSecretAccessSchedule` red at the first, `RoleSetHasPermission`
red at the second. `GetSecret`'s row is expected **green** at both — it was the same-row case
from the start — and that is deliberately recorded as the known-good calibration case, not
quietly omitted.

## 5. Item 4 — invalidation coverage: every writer, enumerated

A generation-validated cache is correct only if *every* writer of a cached row advances that
row's generation in the same transaction — §1.1's first rule.

**For `secret_nodes` this item is now answered by construction rather than by enumeration, and
that is a change of kind, not of degree.** The original plan — and `#2764`'s first attempt —
was to enumerate every `UpdateColumn`/raw write to the table and machine-check the list with an
AST scan (`TestSecretCacheGeneration_CoversEveryUpdateColumnWriter`). That approach is only ever
as complete as the idioms the scanner knows about, which is this codebase's most-repeated defect
shape. A trigger removes the question: the database bumps `cache_epoch` for `Save()`,
`Updates()`, `UpdateColumn()` and raw SQL identically, so there is no writer set to enumerate
and nothing for a future writer to opt into. The obligation moves instead to **proving the
trigger exists and fires** — `TestCacheEpochTrigger_FiresForEveryPersistedColumn` (every
persisted column, both backends, red with the trigger dropped) plus the read path's per-read
presence check.

What remains for this item:

1. The same treatment for `role_permissions`, where the generation is an explicit bump rather
   than a derived stamp, so the check is different in kind: every writer of that table must
   call `bumpRolePermissionsGenerationTx` **in its own transaction**. Derive the writer set
   from the AST (every `Create`/`Delete` whose model is `models.RolePermission`) and fail on
   one that does not. This one cannot be answered by a trigger the way `secret_nodes` is: the
   signal is global rather than per-row, so there is no row whose update could carry it.
2. `secret_versions` and `secret_access_schedules` keep content-derived stamps and therefore
   keep owing an enumeration — see §1.1.1 for why a trigger is not worth its migration surface
   for those two, and for the one named residual gap on `secret_versions` (the stopped-server
   DEK rewrap).
3. The table rows in item 3, one per writer type — including a row whose only observable effect
   is the trigger's own bump, driven by raw SQL so that no GORM callback can account for it.

The method, for the record and for the `role_permissions` half:

1. Enumerate every write to `secret_nodes`, `secret_versions`, `secret_access_schedules`,
   `role_permissions` — from the models and from the package, including the idioms that do
   **not** look like a write to a naive grep: `Unscoped().Model(...).Update(...)`,
   `Select("*").Updates(...)`, `Save(...)`, `FirstOrCreate(...).Assign(...)`, cascade deletes,
   and raw SQL.
2. For each, show the generation advances in the same transaction. For the `updated_at` signal
   that mostly means GORM's own auto-timestamp callback, which fires for `Update`/`Updates`/
   `Save` but **not** for `UpdateColumn`/`UpdateColumns` — so every `UpdateColumn` on a cached
   table is a finding until shown otherwise. For `role_permissions` it means an explicit
   `bumpRolePermissionsGenerationTx` in the writer's own transaction.
3. Add a table row (item 3) per writer *type*: version create, schedule set, schedule delete,
   role-permission grant, revoke, role delete, soft-delete, restore, status transition.
4. Writers that only run with the server stopped, under the exclusive key lock, are acceptable
   without a bump only if no replica can hold a warm entry across them — **and they get named in
   the doc**, with the reason, so "we checked and decided" is distinguishable from "we missed
   it". The DEK-rotation sweep was listed here as such a writer and was wrong: a replica on
   another host sharing only the database keeps its cache across the sweep, so the sweep now
   raises `secret_versions.cache_epoch` (section 1.1).

Two specific things this enumeration was expected to have an answer for. Both now have one, on
the record:

- `IncrementSecretReadCount` / `TryIncrementSecretReadCount` mutate `read_count` on a
  `secret_versions` row that the latest-version cache holds. **Answered, and it found a real
  bug — but on the write side, not the read side.** Enforcement is indeed a live conditional
  `UPDATE` (`read_count < max_reads` evaluated inside the statement, against the stored value),
  so no limit check reads a cached counter. The defect was the opposite direction: `UpdateSecret`
  and `TransitionSecretStatus` wrote the counter back from a caller's in-memory struct, so an
  unrelated metadata edit *refunded* reads against the cap (#2843, fixed in #2871 by omitting
  the column at both full-struct writers and enforcing it with a type-checked invariant). Worth
  separating clearly from the cache work: that was a stale **write** of the column, while
  `cache_epoch` addresses a stale **read** of it. Neither fix addresses the other.
- `local_purge.go` deletes `secret_versions` rows for soft-deleted secrets. **Answered by the
  version stamp's shape rather than by the transaction boundary**: deleting version rows moves
  `count` and `max(version_number)`, so the aggregate changes and the cached entry fails its
  check on the next read whether or not the node row went in the same transaction. The node
  cache is covered independently — a soft-delete is an UPDATE, so the trigger bumps
  `cache_epoch`, and `readLiveNodeStamp` scopes `deleted_at IS NULL` so the stamp read reports
  not-found anyway.

Anything found here is a real bug and becomes its own `fix(security)` PR with a regression
test, not a footnote in this one.

## 6. Item 5 — docs

- `internal/storage/store/INVARIANTS.d/INV-STORE-read-path-cache-stamp-before-data.md`
  (fragment layout, per `docs/invariants-fragments.md`): *every read-path cache in this package
  is written only by `cachedRead`/`cachedReadSameRow`; the generation is read before the data;
  any generation-read error is a miss.* With its `Guard:` line naming the item-2 guard and the
  item-3 registry.
- `docs/security-closures.d/GUARD-6-CACHE-ORDERING.tsv` + regenerated
  `docs/security-closures.d/`, recording the bug class and the test that proves it closed.
- A short section in `internal/storage/store/INVARIANTS.md` pointing at the fragment and at
  this spec.

## 7. Coordination

PERF-7's secret-value cache uses `cachedRead`/`cachedReadSameRow` from the moment item 1's PR
is up — it does not hand-roll a fourth stamp-and-store, and the item-2 guard will fail it if it
tries. A secret-value cache is the highest-stakes member of this family: its stale read is a
rotated-or-revoked plaintext still being served, so it is also the one where the item-3 race row
is least optional.

## 8. Acceptance criteria

- Every one of the four cached reads goes through the helper; no file other than
  `read_path_cache.go` writes a cache entry, and the guard fails if one does.
- PERF-3's cache tests pass unedited **by the refactor** — see §2.5's qualification for the
  tests that changed in this series for reasons of their own.
- The item-3 table has a row for every helper call site (enforced) and for every writer type,
  and each row is shown red against the corresponding pre-fix commit — or explicitly recorded
  as a known-good green case. Every row must also be shown to run **with the cache actually
  on**: a row whose fixture lacks the `cache_epoch` trigger exercises an uncached path and
  proves nothing, which is a mistake this table has already made once.
- Every writer of a cached row either advances that row's generation, or is covered by a
  database trigger that advances it unconditionally (§1.1.1 — in which case the obligation
  becomes proving the trigger exists and fires, since there is no writer set left to
  enumerate), or is named as a documented stopped-server exception.
- `nodeGeneration`, `versionsGeneration`, `scheduleGeneration` and `rolePermGeneration` are the
  only generation types, each satisfying `cacheGeneration`; raw `time.Time` does not satisfy the
  constraint and so cannot be used as a stamp by accident.
