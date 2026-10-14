// native_reads.go — the hottest read-path statements on Postgres run on a
// pgxpool, natively, instead of through database/sql (PGX-NATIVE-1).
//
// Three statements run on every machine-token secret read: the credential
// lookup (credential_lookup_raw.go), the same lookup folded with the node read
// (local_folded_credential.go) and the node-stamp read (local_readpath_prefetch.go).
// Through database/sql each one pays the stdlib driver's per-column value
// conversion and its reflection checks on every destination, per row. On the
// pool, pgx decodes each column straight into the destination with a scan plan
// it caches per type.
//
// What does not change:
//
//   - The SQL text, its binds and their order. The native text is the same
//     statement with gorm's ? placeholders numbered $1..$n (nativeSQL), and the
//     binds are the same values.
//   - The destinations and what is done with them: the same scan functions run
//     over either kind of rows (rowScanner), into the same variables.
//   - Statement preparation: pgx's default statement cache, as on the request
//     pool (the stdlib driver uses the same pgx connection underneath).
//   - What the gorm callbacks registered on ls.db see. The folded and node-stamp
//     statements ran through gorm and fired its Row callbacks; on the pool they
//     still fire them first, in dry-run mode (observeNativeStatement), with the
//     same SQL and binds, so statement counters and fault-injecting callbacks
//     see them as before. An error a callback sets fails the statement exactly
//     as it did through gorm. The dry run is skipped only while ls.db's Row
//     callback chain is the one it had when the pool was attached (gorm's own
//     row callback, nothing registered since): then there is nobody to see the
//     statement, and the dry run would cost about as much CPU as the native
//     path saves. Any Register/Replace/Remove rebuilds the chain, so from then
//     on every statement is observed; if the chain cannot be read, every
//     statement is observed. The plain credential lookup never went through
//     gorm (a database/sql prepared statement), so it fires none, as before.
//   - Where the statements may run: only on the root LocalStorage the factory
//     built for Postgres (SetNativeReadPool). A transaction-scoped or derived
//     store has no pool and reads through its transaction, as before; SQLite has
//     none at all.
//   - Errors: a no-row lookup still wraps sql.ErrNoRows, so every caller's
//     errors.Is check and the error text are the same.
//
// Golden tests: native_reads_test.go compares each statement's native answer
// with the database/sql / gorm answer field for field (reflect.DeepEqual) over
// every row shape, NULLs and missing rows included.
package store

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"gorm.io/gorm"
)

// SetNativeReadPool hands this storage the pgxpool its hottest read statements
// run on (see the file header). Postgres only; the pool must reach the same
// database with the same connection config as ls.db (internal/storage's factory
// opens both from one resolved config). Close closes it. Call it before serving
// traffic.
func (ls *LocalStorage) SetNativeReadPool(pool *pgxpool.Pool) {
	ls.nativeReads = pool
	ls.nativeRowChain, ls.nativeRowChainKnown = rowCallbackChain(ls.db)
}

// rowCallbackChain identifies ls.db's compiled Row callback chain: gorm
// rebuilds the slice on every Register, Replace and Remove, so its address
// changes whenever the chain does. ok is false if it cannot be read (a gorm
// version without the field), and then every native statement is observed.
func rowCallbackChain(db *gorm.DB) (chain uintptr, ok bool) {
	p := reflect.ValueOf(db.Callback().Row())
	if p.Kind() != reflect.Pointer || p.IsNil() {
		return 0, false
	}
	fns := p.Elem().FieldByName("fns")
	if !fns.IsValid() || fns.Kind() != reflect.Slice {
		return 0, false
	}
	return fns.Pointer(), true
}

// observedByCallbacks reports whether a callback was registered on ls.db
// since the pool was attached (see the file header).
func (ls *LocalStorage) observedByCallbacks() bool {
	if !ls.nativeRowChainKnown {
		return true
	}
	chain, ok := rowCallbackChain(ls.db)
	return !ok || chain != ls.nativeRowChain
}

// rowScanner is what the read-path scan functions need from a result set; both
// *sql.Rows and pgx.Rows provide it.
type rowScanner interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

// nativeSQLs holds each statement's native text once built.
var nativeSQLs sync.Map // gorm text -> native text

// nativeSQL returns q with its ? placeholders numbered $1..$n in text order,
// the form gorm's Postgres dialector sends. The read-path statements carry no ?
// inside a literal or identifier (TestNativeSQL_NumbersEveryPlaceholder pins it
// for each of them).
func nativeSQL(q string) string {
	if s, ok := nativeSQLs.Load(q); ok {
		return s.(string)
	}
	var b strings.Builder
	b.Grow(len(q) + 16)
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(q[i])
	}
	s := b.String()
	nativeSQLs.Store(q, s)
	return s
}

// observeNativeStatement runs ls.db's Row callbacks for q and args without
// executing anything (gorm dry run), so what is registered there sees the
// native statement as it saw the gorm one. It returns the error a callback set.
func (ls *LocalStorage) observeNativeStatement(ctx context.Context, q string, args []any) error {
	_, err := ls.db.WithContext(ctx).Session(&gorm.Session{DryRun: true}).Raw(q, args...).Rows()
	if errors.Is(err, gorm.ErrDryRunModeUnsupported) {
		// What a dry run of Rows() reports when no callback failed.
		return nil
	}
	return err
}

// queryNative runs the read-path statement q (gorm placeholder form) on the
// native pool, after the gorm callbacks have seen it. The caller closes the rows.
func (ls *LocalStorage) queryNative(ctx context.Context, q string, args []any) (pgx.Rows, error) {
	if ls.observedByCallbacks() {
		if err := ls.observeNativeStatement(ctx, q, args); err != nil {
			return nil, err
		}
	}
	return ls.nativeReads.Query(ctx, nativeSQL(q), args...)
}
