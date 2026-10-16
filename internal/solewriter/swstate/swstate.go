// Package swstate is the one question the storage layer asks of
// storage.database.single_writer: may a confirming read be skipped right now,
// and is an answer filled at generation g still current? It has no
// dependencies, so internal/storage/store can import it without a cycle;
// internal/solewriter registers the running guard here.
package swstate

import "sync/atomic"

// Authority answers for a running single-writer server.
type Authority interface {
	// Authoritative: the holder lock is held, the fence is intact, and the
	// lease is fresh.
	Authoritative() bool
	// BeginFill starts a fill; Store reports whether its result may be kept.
	BeginFill() Fill
	// Valid reports whether an answer filled at gen may be served.
	Valid(gen uint64) bool
}

// Fill is an in-progress fill.
type Fill interface {
	Gen() uint64
	Store() bool
}

type holder struct{ a Authority }

var current atomic.Pointer[holder]

// Set registers a (nil clears it).
func Set(a Authority) {
	if a == nil {
		current.Store(nil)
		return
	}
	current.Store(&holder{a: a})
}

// Get is the registered authority, or nil when single_writer is off. Callers
// must also check Authoritative() on every use.
func Get() Authority {
	if h := current.Load(); h != nil {
		return h.a
	}
	return nil
}
