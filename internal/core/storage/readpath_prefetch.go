// readpath_prefetch.go — a request-scoped carrier that lets a storage
// implementation answer several of one request's reads from ONE statement.
//
// A machine-token secret read asks storage the same secret's questions one after
// another: the node (generation stamp), the machine's roles at the node's scope,
// then the schedule and latest-version generation. Each is a round trip. The
// gate that is about to ask them (server/middleware) declares what it will ask
// by putting a ReadPathPrefetch on the request context; a storage that can fold
// the reads together does so on the node read and parks the answers on the
// carrier; the later calls take them from there instead of querying again. A
// storage that cannot (or any call that does not match) ignores the carrier and
// answers exactly as before, so the carrier is purely an optimisation: it never
// changes what is asked, only how many statements it takes.
//
// Freshness: the parked answers were read in the statement that validated the
// node cache entry, i.e. during this request and immediately before the
// decisions that use them. They are taken at most once (Take*), never kept past
// the request, and only handed to a call for the SAME principal and scope (or
// the same secret) they were read for.
package storage

import (
	"context"
	"sync"
)

// PrefetchedPermission is the machine-role read of ResolveMachinePermissionAt,
// parked by the node read: the role ids at Scope and the role->permission cache
// generation, from the same statement as the node stamp.
type PrefetchedPermission struct {
	MachineID uint
	Scope     Scope
	// Rows is opaque to everything but the implementation that parked it.
	Rows any
}

// PrefetchedScheduleVersion is the schedule/version-generation read of
// GetSecretScheduleAndLatestVersion, parked by the node read.
type PrefetchedScheduleVersion struct {
	SecretID uint
	// State is opaque to everything but the implementation that parked it.
	State any
}

// ReadPathPrefetch is the per-request carrier. The zero value is not usable;
// build it with NewReadPathPrefetch.
type ReadPathPrefetch struct {
	// MachineID is the machine principal whose roles to fold into the node read.
	MachineID uint
	// WantScheduleVersion asks for the schedule/version generation as well (a
	// latest-version value read only).
	WantScheduleVersion bool

	mu         sync.Mutex
	permission *PrefetchedPermission
	schedule   *PrefetchedScheduleVersion
}

type readPathPrefetchKey struct{}

// NewReadPathPrefetch returns ctx carrying a fresh carrier for machineID.
func NewReadPathPrefetch(ctx context.Context, machineID uint, wantScheduleVersion bool) context.Context {
	return context.WithValue(ctx, readPathPrefetchKey{}, &ReadPathPrefetch{
		MachineID: machineID, WantScheduleVersion: wantScheduleVersion,
	})
}

// ReadPathPrefetchFrom returns the carrier on ctx, or nil.
func ReadPathPrefetchFrom(ctx context.Context) *ReadPathPrefetch {
	p, _ := ctx.Value(readPathPrefetchKey{}).(*ReadPathPrefetch)
	return p
}

// Park stores the answers a node read produced, replacing anything earlier.
func (p *ReadPathPrefetch) Park(perm *PrefetchedPermission, sched *PrefetchedScheduleVersion) {
	p.mu.Lock()
	p.permission, p.schedule = perm, sched
	p.mu.Unlock()
}

// DropPermission discards an unconsumed parked permission read. The gate that
// declared the prefetch calls it once its own decision is made, so a role read
// can never be served to a later, unrelated authorization in the same request.
func (p *ReadPathPrefetch) DropPermission() {
	p.mu.Lock()
	p.permission = nil
	p.mu.Unlock()
}

// TakePermission returns and clears the parked permission read if it was read
// for machineID at scope; otherwise nil and the parked value is left alone.
func (p *ReadPathPrefetch) TakePermission(machineID uint, scope Scope) *PrefetchedPermission {
	p.mu.Lock()
	defer p.mu.Unlock()
	got := p.permission
	if got == nil || got.MachineID != machineID || got.Scope != scope {
		return nil
	}
	p.permission = nil
	return got
}

// TakeScheduleVersion returns and clears the parked schedule/version read if it
// was read for secretID; otherwise nil.
func (p *ReadPathPrefetch) TakeScheduleVersion(secretID uint) *PrefetchedScheduleVersion {
	p.mu.Lock()
	defer p.mu.Unlock()
	got := p.schedule
	if got == nil || got.SecretID != secretID {
		return nil
	}
	p.schedule = nil
	return got
}
