// Package store handles secret persistence via direct GORM database access.
//
// # Domain
//
// LocalStorage implements the core [storage.Storage] interface by accessing
// the database directly via GORM. Used by the server itself and for
// air-gapped / offline deployments.
//
// A second backend, RemoteStorage (proxying operations to a running Keyorix
// server via the REST API, used by the pre-ADR-108 thick CLI), was deleted
// entirely in ADR-108 Phase 6 step 14b-2 once the CLI switch (Phase 5) made
// it unreachable in any supported deployment. Each operation file that used
// to pair a remote_*.go with a local_*.go now stands alone.
//
// # Entry Point
//
// Start here. Read this comment, then open the single operation file you need.
// You do NOT need to read all files — each file is self-contained.
package store

import (
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
)

// maxStoragePageSize is a defense-in-depth ceiling applied directly inside
// LocalStorage's paginated queries (secrets, users, audit events), on top of
// whatever clamp (if any) the caller already applied. External HTTP/gRPC
// handlers already clamp page_size to <=100 before it reaches storage, but
// several trusted internal callers intentionally request larger single-shot
// pages (e.g. secretInventoryMaxRows/csvExportMaxRows = 10000, ListSecrets
// with OwnerID PageSize 10000). 10000 is chosen to sit above every current
// legitimate call site in the repo — this clamp is a true no-op for existing
// behavior today, and only guards a FUTURE caller that forgets to clamp
// (or passes a hostile/overflowed value) from forcing an unbounded SQL LIMIT.
const maxStoragePageSize = 10000

// clampPageSize bounds a caller-supplied page size to (0, maxStoragePageSize].
// A non-positive size is passed through as 0 rather than negative — several
// callers rely on 0 meaning "use my own default" before this clamp runs, but
// a negative value must never reach GORM's Limit(): Limit(-1) (or any
// negative) removes the LIMIT clause entirely, turning a caller-controlled
// negative page size into an unbounded query (#G44).
func clampPageSize(pageSize int) int {
	if pageSize > maxStoragePageSize {
		return maxStoragePageSize
	}
	if pageSize < 0 {
		return 0
	}
	return pageSize
}

// maxStoragePage is the maximum page number accepted by paginated queries.
// Without a ceiling, a hostile caller can force OFFSET = (page-1)*pageSize
// into the millions, which SQLite/Postgres must scan and discard before
// returning any rows — a cheap denial-of-service against the audit endpoint.
// 10000 pages × up to 100 rows/page = 1 million rows, far above any real
// audit log a single deployment would accumulate.
const maxStoragePage = 10_000

// maxUnboundedListRows caps LocalStorage list queries that have no caller-
// supplied pagination at all (no Page/PageSize/limit param in their
// signature) — a defense-in-depth ceiling so a table that grows without
// bound in production (rotation policies, SoD policies, dynamic leases,
// access-review campaigns, etc.) can't turn a routine list call into an
// unbounded full-table scan (#G44).
const maxUnboundedListRows = 10000

// clampPage bounds a caller-supplied page number to [1, maxStoragePage].
func clampPage(page int) int {
	if page < 1 {
		return 1
	}
	if page > maxStoragePage {
		return maxStoragePage
	}
	return page
}

// escapeLIKE escapes SQL LIKE wildcard metacharacters (%, _) in a caller-supplied
// string using backslash as the escape character. Callers must also append
// ESCAPE '\' to the LIKE clause so the database honours the escapes.
// Without this, a search for "foo%bar" would match any string starting with
// "foo" rather than the literal token, turning a user-controlled LIKE operand
// into a wildcard injection vector.
func escapeLIKE(s string) string {
	// Replace \ first to avoid double-escaping already-present backslashes.
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// LocalStorage implements storage.Storage via direct GORM database access.
type LocalStorage struct {
	db *gorm.DB
	// auditChainMu serializes audit-event appends so the read-chain-head +
	// insert critical section is atomic within this process (ADR-029). The
	// PostgreSQL advisory lock in LogAuditEvent extends this across processes.
	// A pointer so a transaction-scoped LocalStorage (see WithTransaction) shares the
	// SAME mutex as its parent — otherwise an audit append inside a transaction would
	// not serialize against concurrent appends on the base store.
	auditChainMu *sync.Mutex
	// auditCheckpointMu serializes WriteAuditCheckpoint's chain-walk + decide +
	// create-checkpoint sequence within this process (ADR-029/#300). The PostgreSQL
	// advisory lock in WithAuditCheckpointLock extends this across processes/replicas
	// (ADR-039 HA). A pointer for the same reason as auditChainMu — a transaction-scoped
	// LocalStorage must share its parent's mutex.
	auditCheckpointMu *sync.Mutex
	// bootstrapMu serializes BootstrapSystem's whole check-then-create sequence
	// within this process (#339/ADR-039 HA). The PostgreSQL advisory lock in
	// WithBootstrapLock extends this across processes/replicas. A pointer for the
	// same reason as auditChainMu/auditCheckpointMu — a transaction-scoped
	// LocalStorage must share its parent's mutex.
	bootstrapMu *sync.Mutex
	// namedLockMu is the in-process fallback for WithNamedLock (#1646) on a
	// non-Postgres backend (SQLite, single-process by construction): a registry
	// handing out one *sync.Mutex per lock key, mirroring PostgreSQL's
	// per-key pg_advisory_lock semantics exactly (see WithNamedLock's own doc
	// comment, FIX-5) rather than one shared mutex serializing every unrelated
	// key against every other. A pointer for the same sharing reason as every
	// other mutex on this struct.
	namedLockMu *namedLockRegistry
	// consumeClockWatermark backs consumeClockLooksRegressed (#1632): an
	// in-memory monotonic high-water mark of the latest wall-clock instant a
	// single-use-token consumption (ConsumeMFAChallenge, ConsumeWebAuthnSession)
	// has legitimately observed, in this process's lifetime. A pointer for the
	// same reason as the mutexes above — ConsumeMFAChallenge and
	// ConsumeWebAuthnSession are two distinct call paths (one via the core
	// layer's c.now(), one via a raw storage call from an HTTP handler; see
	// consumeClockLooksRegressed's doc comment) that must share ONE
	// watermark, not warm two independent ones.
	consumeClockWatermark *clockWatermark
	// rbacClockWatermark backs rbacEffectiveNow (#1632): an in-memory monotonic
	// high-water mark of the latest wall-clock instant any RBAC permission-
	// resolution query in local_rbac.go has legitimately observed. Unlike
	// consumeClockWatermark (which backs a REFUSAL of a single, discrete
	// action), this backs a CLAMP applied to a pervasive, high-volume read
	// path reached on every authorized request — see rbacEffectiveNow's doc
	// comment for why the two sites need different response shapes to the
	// same underlying fact. A pointer for the same sharing reason as every
	// other watermark/mutex field on this struct.
	rbacClockWatermark *clockWatermark
	// auditFlusher backs the batching audit-append writer (SESSION-PERF, #2403
	// follow-up, item 3) — nil on a transaction-scoped LocalStorage (see
	// WithTransaction/RemoveGlobalAdminRoleGuarded's clone construction, which
	// deliberately does NOT copy this field), falling back there to the
	// original per-call direct write (logAuditEventDirect): batching across to
	// a DIFFERENT, independent transaction would break the atomicity a
	// caller's own WithTransaction depends on. Only the root LocalStorage
	// returned by NewLocalStorage gets a real one. NOT a pointer-shared-with-
	// clones field like the mutexes above — deliberately so a forgotten update
	// to a future clone-construction site defaults to nil (the SAFE,
	// non-batching fallback), not to incorrectly sharing the root's flusher.
	auditFlusher *auditFlusherState
	// auditFlusherLingerWindow is how long runAuditFlusher deliberately waits,
	// after its first queued item, for more to arrive before committing
	// (SESSION-PERF, #2420 follow-up) — set once at construction from
	// config.DatabaseConfig.GetAuditFlusherLingerWindow(), zero value (0,
	// Go's own default) meaning "no deliberate wait." Not a pointer and not
	// shared with transaction-scoped clones: it's read-only after
	// construction and meaningless on a clone anyway (auditFlusher is nil
	// there, so runAuditFlusher never runs for it).
	auditFlusherLingerWindow time.Duration
	// rawStmts backs the H3 hand-written prepared-statement fast path
	// (PERF-3, docs/specs/read-path-caching.md; credential_lookup_raw.go) —
	// nil on a transaction-scoped LocalStorage (see WithTransaction, which
	// deliberately does NOT copy this field), same "nil on a clone, falls
	// back to the always-correct GORM path" pattern as auditFlusher above.
	// Only the root LocalStorage returned by NewLocalStorage gets a real one.
	rawStmts *rawStatements
	// auditSkipDurableSync, when true, makes the audit-commit transaction skip
	// the WAIT for a disk sync — nothing else (ADR-112 Amendment 1,
	// FASTAUDIT-1, docs/specs/fast-audit-mode.md). Set once at construction
	// from config.DatabaseConfig.InsecureAuditSkipDurableSync; zero value
	// (false, Go's own default) is the secure baseline, so a construction site
	// that forgets to call SetAuditSkipDurableSync gets DURABLE commits, never
	// the weak mode.
	//
	// Read by commitBatchAttempt and logAuditEventDirect, and acted on ONLY on
	// Postgres (`SET LOCAL synchronous_commit = off`, transaction-scoped).
	// There is no SQLite equivalent and deliberately never was in a shipped
	// build: the mode is PostgreSQL-only (Andrei's decision, 2026-10-05) and
	// config validation refuses to start a SQLite backend that sets it, so a
	// SQLite-backed LocalStorage can never have this field true. See
	// config.DatabaseConfig.InsecureAuditSkipDurableSync for the two reasons
	// (per-connection pragma relaxes every table; measured p99 regression).
	//
	// Deliberately NOT shared with transaction-scoped clones, same as
	// auditFlusherLingerWindow: read-only after construction, and a clone's
	// own audit writes go through logAuditEventDirect inside the CALLER's
	// transaction, whose durability is the caller's business, not the audit
	// chain's.
	auditSkipDurableSync bool
	// secretMetaCache backs GetSecret/GetLatestSecretVersion/GetSecretAccessSchedule's
	// read-path cache (PERF-3, docs/specs/read-path-caching.md). A pointer so a
	// transaction-scoped LocalStorage (see WithTransaction) shares the SAME cache as
	// its parent, same sharing reason as auditChainMu etc. above — see
	// secret_metadata_cache.go's own header for why this must NOT be a package-level
	// global instead.
	secretMetaCache *secretMetadataCache
	// rolePermCache backs RoleSetHasPermission's read-path cache (PERF-3,
	// docs/specs/read-path-caching.md PR-2). A pointer so a transaction-scoped
	// LocalStorage (see WithTransaction) shares the SAME cache as its parent,
	// same sharing reason as auditChainMu etc. above — see
	// role_permission_cache.go's own header for why this must NOT be a
	// package-level global instead.
	rolePermCache *rolePermissionCache
	// cacheEnabled gates every read-path cache READ and WRITE. It is set in
	// exactly ONE place — NewLocalStorage — and is deliberately never copied
	// anywhere else, so any LocalStorage derived from another (WithTransaction's
	// tx-scoped clone, and the several ad-hoc `&LocalStorage{db: tx}` literals
	// in this package and its tests) has it false by construction and bypasses the cache
	// entirely.
	//
	// This is a correctness requirement, not an optimisation. A tx-scoped store
	// reads through the TRANSACTION handle, so both the generation and the data
	// it sees are UNCOMMITTED, and it shares the parent's cache pointer. Caching
	// from inside a transaction therefore publishes an uncommitted answer into a
	// cache that outlives the transaction: if the transaction then rolls back
	// and a later COMMITTED write happens to reproduce the same generation
	// value, that rolled-back answer validates and is served. For
	// RoleSetHasPermission that is an authorization bypass — and it is not a
	// remote possibility: with the generation now a monotonic integer (see
	// bumpRolePermissionsGenerationTx), a rolled-back bump N→N+1 is reproduced
	// EXACTLY by the very next committed role_permissions write.
	// For the latest-version cache the same hazard serves a version row that never
	// committed — wrong ID, wrong ciphertext — and on SQLite even the row id can
	// repeat after a rollback, because sqlite_sequence is rolled back too.
	//
	// Phrased as a flag that must be SET to enable the cache, never one that
	// must be set to disable it, so a future constructor that forgets about it
	// fails closed (no caching) rather than open (caching from inside a
	// transaction).
	cacheEnabled bool
	// nodeStampProbe is cacheEnabled's per-cache companion for the node cache
	// specifically: the node stamp is only a stamp while secret_nodes'
	// cache_epoch trigger exists, and without it the stamp is frozen so every
	// hit would serve the row as first read. See
	// SecretNodeCacheEpochTriggerPresent for the two ways a real database ends
	// up with the column but not the trigger.
	//
	// Resolved LAZILY, on first use, not in NewLocalStorage: that constructor
	// deliberately performs no I/O, and tests rely on it (the dialect-SQL tests
	// capture every statement a handle issues and assert on the count, and one
	// of them builds an unconnected DryRun handle on purpose). nil on a derived
	// store, which therefore never trusts the stamp — same fail-closed shape as
	// cacheEnabled.
	nodeStampProbe *nodeStampProbe
}

// clockWatermark pairs a mutex with the time.Time it guards, so a single
// pointer field on LocalStorage can be shared across transaction-scoped
// copies (see WithTransaction) without copying the mutex and the time value
// out of sync with each other.
type clockWatermark struct {
	mu   sync.Mutex
	time time.Time
}

// NewLocalStorage creates a LocalStorage backed by the given *gorm.DB. The
// audit-chain batching flusher's linger window (SESSION-PERF, #2420
// follow-up) defaults to 0 (no deliberate wait) — call
// SetAuditFlusherLingerWindow to configure a nonzero value.
func NewLocalStorage(db *gorm.DB) *LocalStorage {
	return &LocalStorage{
		db:                    db,
		auditChainMu:          &sync.Mutex{},
		auditCheckpointMu:     &sync.Mutex{},
		bootstrapMu:           &sync.Mutex{},
		namedLockMu:           newNamedLockRegistry(),
		consumeClockWatermark: &clockWatermark{},
		rbacClockWatermark:    &clockWatermark{},
		auditFlusher:          &auditFlusherState{},
		rawStmts:              &rawStatements{},
		secretMetaCache:       newSecretMetadataCache(),
		rolePermCache:         newRolePermissionCache(),
		// The ONLY place this is set. See the field's doc comment: every derived
		// or transaction-scoped LocalStorage must leave it false.
		cacheEnabled: true,
		// Fail closed: without the trigger the node stamp never moves, so the
		// node cache must not be used at all. Probed on first use, not here —
		// see the field's doc comment.
		nodeStampProbe: &nodeStampProbe{},
	}
}

// SetAuditFlusherLingerWindow configures how long the audit-chain batching
// flusher deliberately waits, after its first queued item, for more to
// arrive before committing (SESSION-PERF, #2420 follow-up) — see
// config.DatabaseConfig.AuditFlusherLingerWindow's doc comment for why 0
// (the zero value, and this type's default if never called) is the right
// default, not a tuned nonzero one. Safe to call only before this
// LocalStorage starts serving traffic — runAuditFlusher reads the field
// once per batch with no synchronization, same as every other
// construction-time-only field on this type (db, the mutex pointers).
func (ls *LocalStorage) SetAuditFlusherLingerWindow(d time.Duration) {
	ls.auditFlusherLingerWindow = d
}

// SetAuditSkipDurableSync configures whether the audit-commit transaction
// skips the WAIT for a disk sync (ADR-112 Amendment 1, FASTAUDIT-1 —
// docs/specs/fast-audit-mode.md). false, the zero value and this type's
// default if this is never called, is the secure baseline: the audit record is
// durably committed before a secret value is returned. Only
// internal/storage's factory calls this, and only with
// config.DatabaseConfig.InsecureAuditSkipDurableSync, which no transport can
// set.
//
// Same constraint as SetAuditFlusherLingerWindow: safe to call only before
// this LocalStorage starts serving traffic — the field is read once per
// commit attempt with no synchronization, like every other
// construction-time-only field on this type.
func (ls *LocalStorage) SetAuditSkipDurableSync(skip bool) {
	ls.auditSkipDurableSync = skip
}

// DB returns the underlying *gorm.DB. Exposed for test helpers that need direct
// SQL access (e.g. seeding rows with custom timestamps). Do not use in production
// code — all writes must go through the Storage interface methods.
func (ls *LocalStorage) DB() *gorm.DB {
	return ls.db
}

// consumeClockRegressionTolerance bounds how far now may read EARLIER than
// consumeClockWatermark before checkConsumeClockNotRegressed refuses a
// single-use-token consumption. Mirrors internal/core's
// secretExpiryClockRegressionTolerance (#1632) -- same threat model (an
// operator, or an NTP-less clock correction, stepping the host clock back by
// an hour or more), same tolerance for ordinary NTP slew.
const consumeClockRegressionTolerance = 30 * time.Second

// consumeClockLooksRegressed reports whether now looks EARLIER than a time
// this process has already legitimately observed for a single-use-token
// consumption (ConsumeMFAChallenge, ConsumeWebAuthnSession) (#1632). Both
// consumption methods bind now directly into a SQL `expires_at > ?` bound,
// with no caching layer between the wall clock and the comparison -- a host
// clock stepped backward past a challenge/session's real expiry would let it
// be consumed for the first time past its real window (this cannot enable
// replay of an ALREADY-consumed row: the `used_at IS NULL` predicate is
// clock-independent).
//
// Returns a bool rather than an error so each caller can return its OWN
// existing "invalid or expired X" text on a regression, matching the exact
// wording its normal expiry path already uses -- a caller must not be able
// to distinguish "genuinely expired" from "clock regression detected" by
// the error text differing between the two refusal reasons.
//
// This watermark is shared by both methods rather than kept per-method,
// because they have two genuinely distinct callers each (one via the core
// layer's c.now(), one via a raw storage call from an HTTP handler that
// passes a bare time.Now() -- see users_crud.go's ConsumeMFAChallenge and
// webauthn_proxy.go's ConsumeWebAuthnSessionProxy) and the fact being
// defended against -- "has this process's OS clock been stepped backward" --
// is a single process-wide fact, not a per-method one.
//
// On a non-regressed reading, advances the watermark to now (never
// backward, for the same reason as internal/core's
// checkSecretExpiryClockNotRegressed: a second, slower backward step must
// not walk the watermark down unnoticed).
//
// Part 2 regression audit continuation (2026-09-04): .UTC() below strips any
// monotonic clock reading now carries -- both real callers named above
// (c.now()==time.Now, and a bare time.Now()) attach one. Two monotonic-
// carrying values compare using ONLY their monotonic delta (see time.Time's
// package doc), which never regresses even when the OS wall clock steps
// backward, so this comparison could never actually detect the regression
// it exists to catch without this. Same root cause as
// checkSecretExpiryClockNotRegressed's identical fix (internal/core/versions.go,
// #1635) and this function's own new authEffectiveNow sibling
// (internal/core/auth.go) -- fixed in all three at once, same underlying bug.
func (ls *LocalStorage) consumeClockLooksRegressed(now time.Time) bool {
	now = now.UTC()
	wm := ls.consumeClockWatermark
	wm.mu.Lock()
	defer wm.mu.Unlock()
	if !wm.time.IsZero() && now.Before(wm.time.Add(-consumeClockRegressionTolerance)) {
		return true
	}
	if now.After(wm.time) {
		wm.time = now
	}
	return false
}
