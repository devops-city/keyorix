// Package solewriter implements storage.database.single_writer
// (docs/specs/single-writer-cache.md): one Keyorix server declared the only
// writer of its PostgreSQL database.
//
// Three database-side mechanisms, all owned here:
//
//   - The holder lock: a session advisory lock (LockKey, scoped to the
//     database schema) held for the server's lifetime on a dedicated
//     connection. A second single-writer server cannot take it and refuses to
//     start; a server without the setting refuses to start while it is held
//     (CheckOff); admin commands cannot --force past it.
//   - The write fence: triggers on every security table (FencedTables) that
//     refuse a write from any session other than the holder's own while the
//     holder lives. The holder's sessions prove their origin with a per-boot
//     tag (config.SoleWriterSessionSetting) whose hash the holder recorded in
//     keyorix_sole_writer. With no live holder the fence lets everything
//     through, so a stopped or crashed server never blocks recovery.
//   - The write epoch: the same triggers bump keyorix_write_epoch.n in the
//     writer's own transaction, for every write that passes the fence, the
//     holder's included. The holder polls it, together with a proof that it
//     still holds the lock and a fingerprint of the installed triggers, every
//     PollInterval, and keeps a lease of LeaseDuration from the last good poll.
//
// The fence is installed and verified at start-up or the server refuses to
// start; there is no single-writer state without it. Nothing here makes a
// cache authoritative: Guard.Authoritative reports whether one may be (state
// authoritative, lease valid), and the cache layer decides.
//
// Name resolution: nothing the fence or the guard runs resolves a name through
// a writer's search_path. The fence functions carry SET search_path =
// pg_catalog, pg_temp and qualify every relation and function they use; the
// guard's own sessions pin the same search_path once they have read their
// schema (pinSessionSchema) and qualify every object with it. Otherwise a temp
// table named pg_database (pg_temp is searched before pg_catalog for
// relations), or a function or operator of the same name in a schema the
// writer lists first, would change what the fence checks
// (REVIEW-SINGLE-WRITER-2 N1).
//
// Limits, stated: the fence is a database trigger. A role that can disable,
// drop or replace triggers (the table owner, a superuser) can bypass it, even
// inside one transaction that restores everything before it commits: the
// fingerprint includes the catalog rows' xmin, the fenced tables' columns and
// any inheritance or partitioning involving a fenced table, so the poller sees
// the change within PollInterval and the guard leaves the authoritative state
// for good (until restart). A session that copied the holder's tag passes the
// fence, but its write rewrites the epoch row like any other, and the poller
// compares that row's xmin as well as its value, so moving n back in the same
// transaction is seen too. A write made after the holder lock is lost lands
// within the lease. All these windows are bounded by LeaseDuration.
//
// Not detected (docs/single-writer.md "Residual risks"): a superuser who
// writes the table files or memory below SQL (native code loaded into the
// server, the data directory, pg_resetwal) changes rows without any trigger
// or catalog change to see.
package solewriter

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/keyorixhq/keyorix/internal/config"
)

// LockKey is the first key of the two-key holder advisory lock; the second is
// hashtext(current_schema()), so two Keyorix installs in different schemas of
// one database do not collide. "KSWL".
const LockKey int32 = 0x4B53574C

// Timing. PollInterval is the epoch/lock/census poll; LeaseDuration is how
// long after the last good poll the guard may still report authoritative.
const (
	PollInterval  = 250 * time.Millisecond
	LeaseDuration = time.Second
	pollTimeout   = 500 * time.Millisecond
)

// serverPresenceLockKey mirrors internal/serverguard's key (a live server
// holds it shared for its lifetime). Read-only use here: the census.
const serverPresenceLockKey = 872342

// Object names.
const (
	HolderTable   = "keyorix_sole_writer"
	EpochTable    = "keyorix_write_epoch"
	checkFunc     = "keyorix_sole_writer_check"
	guardFunc     = "keyorix_sole_writer_guard"
	fenceOnlyFunc = "keyorix_sole_writer_fence_only"
	// TriggerPrefix names every fence trigger.
	TriggerPrefix = "trg_ksw_"
)

// State is the guard's state. Only StateAuthoritative lets a cache skip its
// confirming read (and only while the lease is valid).
type State string

const (
	StateSettling      State = "settling"
	StateAuthoritative State = "authoritative"
	StateConfirming    State = "confirming"
)

// Options tune Start; the zero value is production.
type Options struct {
	// LockWait bounds how long Start retries the holder lock (a Recreate
	// rollout's old pod can still hold it). Default 120 s.
	LockWait time.Duration
	// ExpectOwnPresence: this process already holds the serverguard presence
	// lock (the server does), so exactly one presence holder is expected.
	ExpectOwnPresence bool
	// SkipPresenceCensus disables the "no other server is attached" check.
	// Tests that share one database with other packages' servers only.
	SkipPresenceCensus bool
	// SettleTimeout bounds the fence settle. Default 30 s.
	SettleTimeout time.Duration
	// Now is the wall clock (tests). Default time.Now.
	Now func() time.Time
}

func (o *Options) defaults() {
	if o.LockWait == 0 {
		o.LockWait = 120 * time.Second
	}
	if o.SettleTimeout == 0 {
		o.SettleTimeout = 30 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// Guard is a running single-writer server's hold on its database.
type Guard struct {
	opts   Options
	db     *sql.DB
	conn   *sql.Conn
	pid    int
	schema string // the schema the security tables live in (pinSessionSchema)
	since  time.Time
	nonce  string
	bootID string

	mu           sync.Mutex
	state        State
	reason       string
	permanent    bool // left authoritative for good (until restart)
	fingerprint  string
	incarnation  string
	epoch        int64
	epochXmin    string    // the epoch row's xmin: any UPDATE changes it, a net-zero one included
	lastGoodMono time.Time // carries the monotonic reading
	lastGoodWall time.Time // wall clock only (Round(0))
	lastErr      string

	tracker *Tracker
	// The unattributed-bump canary (pollOnce): the tracker's commit count at
	// the last poll, whether the epoch moved without one, and how often that
	// was confirmed on the following poll.
	lastCommits       uint64
	unexplained       bool
	unattributedBumps int64

	onReenter atomic.Pointer[func()]

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

var current atomic.Pointer[Guard]

// Current is the process's guard, or nil when single_writer is off.
func Current() *Guard { return current.Load() }

// SetCurrentForTest replaces Current and returns a restore function.
func SetCurrentForTest(g *Guard) (restore func()) {
	prev := current.Swap(g)
	return func() { current.Store(prev) }
}

// ErrLockHeld is returned by Start when another session holds the lock.
var ErrLockHeld = errors.New("another Keyorix server holds the single-writer lock")

// Start opens the holder connection, takes the lock, checks that no other
// server is attached, and records this boot as the holder. The session tag is
// set first, so every pool the server opens afterwards carries it. The fence
// is not installed yet (the security tables may not be migrated); call
// InstallFence after migrations, then Settle and Run.
func Start(ctx context.Context, cfg *config.Config, opts Options) (*Guard, error) {
	opts.defaults()
	if st := cfg.Storage.Type; st != "postgres" && st != "postgresql" {
		return nil, fmt.Errorf("storage.database.single_writer requires storage.type postgres")
	}
	nonce, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	bootID, err := randomHex(8)
	if err != nil {
		return nil, err
	}
	if err := config.SetSoleWriterSessionTag(nonce); err != nil {
		return nil, err
	}
	// Every connection opened from here on reports its statements to the
	// tracker (tracker.go), so in-process writes invalidate synchronously.
	tr := NewTracker()
	activeTracker.Store(tr)
	config.SetSoleWriterQueryTracer(tr)
	g := &Guard{opts: opts, nonce: nonce, bootID: bootID, state: StateSettling, reason: "starting", tracker: tr,
		stop: make(chan struct{}), done: make(chan struct{})}
	cc, err := config.ResolvePostgresConnConfig(&cfg.Storage.Database)
	if err != nil {
		return nil, err
	}
	g.db = stdlibOpen(cc)
	g.db.SetMaxOpenConns(1)
	g.conn, err = g.db.Conn(ctx)
	if err != nil {
		_ = g.db.Close()
		return nil, fmt.Errorf("single_writer: open the holder connection: %w", err)
	}
	if err := g.start(ctx); err != nil {
		g.close()
		return nil, err
	}
	return g, nil
}

func (g *Guard) start(ctx context.Context) error {
	var err error
	if g.schema, err = pinSessionSchema(ctx, g.conn); err != nil {
		return err
	}
	var version int
	if err := g.conn.QueryRowContext(ctx, "SELECT pg_catalog.current_setting('server_version_num')::int").Scan(&version); err != nil {
		return fmt.Errorf("single_writer: read the server version: %w", err)
	}
	if version < 130000 {
		return fmt.Errorf("single_writer: PostgreSQL 13 or later is required (pg_current_snapshot, pg_xact_status); this server is %d", version)
	}
	// Notice a dead client (a killed pod) within ~25 s rather than the
	// kernel's 2 h, so the lock is released and a replacement can start.
	for _, s := range []string{"SET tcp_keepalives_idle = 10", "SET tcp_keepalives_interval = 5", "SET tcp_keepalives_count = 3"} {
		if _, err := g.conn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("single_writer: %s: %w", s, err)
		}
	}
	if version >= 140000 {
		if _, err := g.conn.ExecContext(ctx, "SET client_connection_check_interval = '5s'"); err != nil {
			return fmt.Errorf("single_writer: set client_connection_check_interval: %w", err)
		}
	}
	if err := g.conn.QueryRowContext(ctx, "SELECT pg_catalog.pg_backend_pid()").Scan(&g.pid); err != nil {
		return err
	}
	if err := g.acquire(ctx); err != nil {
		return err
	}
	if !g.opts.SkipPresenceCensus {
		if err := g.presenceCensus(ctx); err != nil {
			return err
		}
	}
	if err := ensureOwnTables(ctx, g.conn, g.schema); err != nil {
		return err
	}
	g.since = g.opts.Now().UTC()
	// The table name is this session's own schema (pinSessionSchema), quoted
	// as an identifier; every value is a bind parameter.
	if _, err := g.conn.ExecContext(ctx, `INSERT INTO `+qualify(g.schema, HolderTable)+` (id, holder_pid, nonce_hash, since, boot_id) VALUES (1, $1, $2, $3, $4)
ON CONFLICT (id) DO UPDATE SET holder_pid = EXCLUDED.holder_pid, nonce_hash = EXCLUDED.nonce_hash, since = EXCLUDED.since, boot_id = EXCLUDED.boot_id`, // #nosec G202 -- schema-qualified identifier from the server's own session, quoted; values are bind parameters
		g.pid, nonceHash(g.nonce), g.since, g.bootID); err != nil {
		return fmt.Errorf("single_writer: record this server as the holder: %w", err)
	}
	return nil
}

// acquire takes the holder lock, retrying until LockWait.
func (g *Guard) acquire(ctx context.Context) error {
	deadline := time.Now().Add(g.opts.LockWait)
	backoff := 250 * time.Millisecond
	for {
		var ok bool
		if err := g.conn.QueryRowContext(ctx, "SELECT pg_catalog.pg_try_advisory_lock($1, pg_catalog.hashtext($2))", LockKey, g.schema).Scan(&ok); err != nil {
			return fmt.Errorf("single_writer: take the holder lock: %w", err)
		}
		if ok {
			return nil
		}
		if time.Now().After(deadline) {
			pid, _ := holderPID(ctx, g.conn, g.schema)
			return fmt.Errorf("%w (backend pid %d); storage.database.single_writer allows exactly one server", ErrLockHeld, pid)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 5*time.Second)
	}
}

// presenceCensus refuses when another server (holding the serverguard
// presence lock) is attached to this database.
func (g *Guard) presenceCensus(ctx context.Context) error {
	var n int
	if err := g.conn.QueryRowContext(ctx, `SELECT pg_catalog.count(*) FROM pg_catalog.pg_locks
WHERE locktype = 'advisory' AND granted AND database = (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database())
  AND classid = 0 AND objid = $1 AND objsubid = 1`, serverPresenceLockKey).Scan(&n); err != nil {
		return fmt.Errorf("single_writer: count attached servers: %w", err)
	}
	if g.opts.ExpectOwnPresence {
		n--
	}
	if n > 0 {
		return fmt.Errorf("single_writer: %d other Keyorix server(s) are attached to this database; storage.database.single_writer allows exactly one", n)
	}
	return nil
}

// lockHeldExpr is true when backend pidExpr holds the holder lock for schema
// schemaExpr (both SQL expressions). The trigger passes the fenced table's own
// schema, never current_schema(): a session with another search_path writing
// schema-qualified names must still meet that schema's holder. Every name is
// qualified; the operators resolve in pg_catalog because every session that
// evaluates this has search_path pinned to pg_catalog, pg_temp.
func lockHeldExpr(pidExpr, schemaExpr string) string {
	return `EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE locktype = 'advisory' AND granted AND pid = ` + pidExpr + `
  AND database = (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database())
  AND classid = ` + fmt.Sprint(LockKey) + ` AND objid::bigint = (pg_catalog.hashtext(` + schemaExpr + `)::bigint & 4294967295) AND objsubid = 2)`
}

// pinSessionSchema returns the session's current schema (where the security
// tables live) and then pins the session's search_path to pg_catalog, pg_temp,
// so no statement the guard runs on it afterwards resolves a name or an
// operator through a schema someone else can create objects in. Every Keyorix
// object it touches afterwards is qualified with the returned schema.
func pinSessionSchema(ctx context.Context, conn *sql.Conn) (string, error) {
	var schema sql.NullString
	if err := conn.QueryRowContext(ctx, "SELECT pg_catalog.current_schema()").Scan(&schema); err != nil {
		return "", fmt.Errorf("single_writer: read the schema: %w", err)
	}
	if !schema.Valid || schema.String == "" {
		return "", fmt.Errorf("single_writer: no schema on the connection's search_path exists")
	}
	if _, err := conn.ExecContext(ctx, "SELECT pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', false)"); err != nil {
		return "", fmt.Errorf("single_writer: pin the search_path: %w", err)
	}
	return schema.String, nil
}

// qualify is schema.name, both quoted.
func qualify(schema, name string) string { return quoteIdent(schema) + "." + quoteIdent(name) }

// holderPID returns the live holder's backend pid for schema, or 0 when none
// holds the lock.
func holderPID(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, schema string) (int, error) {
	var pid sql.NullInt64
	err := q.QueryRowContext(ctx, `SELECT pid FROM pg_catalog.pg_locks WHERE locktype = 'advisory' AND granted
  AND database = (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database())
  AND classid = $1 AND objid::bigint = (pg_catalog.hashtext($2)::bigint & 4294967295) AND objsubid = 2 LIMIT 1`, LockKey, schema).Scan(&pid)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return int(pid.Int64), nil
}

// PID is the holder connection's backend pid.
func (g *Guard) PID() int { return g.pid }

// Close releases the lock (by closing its connection) and stops the poller.
func (g *Guard) Close() {
	g.stopOnce.Do(func() { close(g.stop) })
	g.close()
}

func (g *Guard) close() {
	if g.conn != nil {
		_ = g.conn.Close()
	}
	if g.db != nil {
		_ = g.db.Close()
	}
}

func stdlibOpen(cc *pgx.ConnConfig) *sql.DB { return stdlib.OpenDB(*cc) }

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func nonceHash(nonce string) string {
	s := sha256.Sum256([]byte(nonce))
	return hex.EncodeToString(s[:])
}

func logf(format string, args ...any) { log.Printf("single_writer: "+format, args...) }

// quoteList renders names as a SQL string list.
func quoteList(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = "'" + n + "'"
	}
	return strings.Join(q, ", ")
}
