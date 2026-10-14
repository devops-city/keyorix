package storage

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// NamedLockFamily is one family of WithNamedLock keys: every key built by one
// lock-key constructor. Prefix matches the constructor's fixed text (the whole
// key when Exact). Nestable families may be held more than once at a time with
// different IDs, but only acquired in ascending ID order.
type NamedLockFamily struct {
	Prefix      string
	Exact       bool
	Nestable    bool
	Constructor string // where the key is built, for the error message
	// PendingPR names the open PR that introduces this family's constructor,
	// when the family is declared here ahead of it (so its place in the order
	// is fixed before the nesting lands). Delete it once that PR merges;
	// TestNamedLockOrder_EveryCallSiteKeyHasAFamily fails on any PendingPR
	// after NamedLockPendingExpires.
	PendingPR string
}

// NamedLockPendingExpires is the date after which no family may still carry
// a PendingPR (same expiry as the pending exemption rows C-GUARD-3 added).
const NamedLockPendingExpires = "2026-10-18"

// NamedLockOrder is the ONE declared acquisition order for every
// storage.WithNamedLock key family (C-GUARD-3 guard 3), outermost first. A
// call chain that already holds a key of family i may only acquire a key of
// family j > i, or (Nestable only) a key of the same family with a larger ID.
// Any two call chains that respect one total order cannot deadlock on these
// locks against each other — on Postgres, pg_advisory_lock waits forever, so a
// cycle here is a permanent hang of both replicas' requests, not a timeout.
//
// How the order was established (2026-10-04): every WithNamedLock call site in
// internal/core and internal/storage/store was enumerated (`grep -rn
// 'WithNamedLock(' --include=*.go`), giving the 9 constructors below; the
// whole internal/core test suite was then run with every nested acquisition
// logged. The observed nestings were
//
//	dual-control-approval -> sod-grant:user     (approve a role request)
//	project-membership    -> sod-grant:user     (membership activate grants a role)
//	last-admin-guard      -> project-admin-guard (group delete/removal)
//	project-admin-guard   -> project-admin-guard (ascending, lockProjectAdminGuardsInOrder)
//	project-admin-guard   -> sod-grant:user     (SetProjectMemberRole -> AssignUserRole)
//	sod-grant:group       -> sod-grant:user     (withGroupMemberSoDLocks)
//
// which form no cycle; the table is a total order consistent with all of them.
// Families with no observed nesting are placed by their role (coarse
// admin-count guards before per-principal grant locks; graph/environment
// locks last, they are taken around a single storage write).
//
// If the checker reports an inversion, that is a real potential deadlock in
// the code: fix the acquisition order (or file it), do NOT reorder this table
// to make the inversion legal — a reorder that makes one chain legal makes the
// chain it deadlocks with illegal, which the next run then reports.
//
// Not covered: locks other than WithNamedLock (in-process sync.Mutex fields
// such as globalAdminGuardMu, accountStateMu and secretDependencyMu; row
// locks; WithBootstrapLock/WithAuditCheckpointLock), and any call chain that
// no test drives — the runtime checker is dynamic, it sees only nestings that
// actually execute. (The static half, TestNamedLockOrder_EveryCallSiteKeyHasAFamily
// in internal/core, checks only that every key has a family, not nesting.)
var NamedLockOrder = []NamedLockFamily{
	{Prefix: "dual-control-approval:request:", Constructor: "core.dualControlLockKey"},
	{Prefix: "project-membership:", Constructor: "core.membershipLockKey", PendingPR: "#2669"},
	{Prefix: "last-admin-guard", Exact: true, Constructor: "core.lastAdminGuardLockKey"},
	{Prefix: "project-admin-guard:", Nestable: true, Constructor: "core.projectAdminGuardLockKey"},
	{Prefix: "sod-grant:group:", Nestable: true, Constructor: `core.sodGrantLockKey("group", ...)`},
	{Prefix: "sod-grant:user:", Nestable: true, Constructor: `core.sodGrantLockKey("user", ...)`},
	{Prefix: "sod-grant:machine:", Constructor: `core.sodGrantLockKey("machine", ...)`},
	{Prefix: "secret-dependency-graph:", Constructor: "core.secretDependencyGraphLockKey", PendingPR: "#2670"},
	{Prefix: "environment-secret-guard:", Constructor: "storage.EnvironmentSecretGuardLockKey"},
}

// namedLockFamilyOf returns key's rank in NamedLockOrder and its numeric ID
// components (empty for an Exact family), or rank -1 if no family matches.
func namedLockFamilyOf(key string) (int, []uint64) {
	for i, f := range NamedLockOrder {
		if f.Exact {
			if key == f.Prefix {
				return i, nil
			}
			continue
		}
		rest, ok := strings.CutPrefix(key, f.Prefix)
		if !ok {
			continue
		}
		var ids []uint64
		for p := range strings.SplitSeq(rest, ":") {
			n, err := strconv.ParseUint(p, 10, 64)
			if err != nil {
				return -1, nil
			}
			ids = append(ids, n)
		}
		return i, ids
	}
	return -1, nil
}

func idsLess(a, b []uint64) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// CheckNamedLockOrder reports whether acquiring next while holding held (in
// acquisition order) respects NamedLockOrder. A key that matches no declared
// family is itself an error: a new lock family must be placed in the order
// before it can be nested with anything. Re-acquiring a key already held is
// not an acquisition (WithNamedLock is re-entrant per key) and is allowed.
func CheckNamedLockOrder(held []string, next string) error {
	nr, nids := namedLockFamilyOf(next)
	if nr < 0 {
		return fmt.Errorf("named lock %q matches no family in storage.NamedLockOrder — declare its family there", next)
	}
	if slices.Contains(held, next) {
		return nil
	}
	for _, h := range held {
		hr, hids := namedLockFamilyOf(h)
		if hr < 0 {
			return fmt.Errorf("held named lock %q matches no family in storage.NamedLockOrder — declare its family there", h)
		}
		switch {
		case hr < nr:
			continue
		case hr == nr && NamedLockOrder[nr].Nestable && idsLess(hids, nids):
			continue
		case hr == nr:
			return fmt.Errorf("named-lock order violation: acquiring %q while holding %q — family %s may only nest with itself in ascending ID order%s",
				next, h, NamedLockOrder[nr].Constructor, map[bool]string{true: "", false: " (and is not declared Nestable)"}[NamedLockOrder[nr].Nestable])
		default:
			return fmt.Errorf("named-lock order violation: acquiring %q (%s, rank %d) while holding %q (%s, rank %d); storage.NamedLockOrder requires the reverse",
				next, NamedLockOrder[nr].Constructor, nr, h, NamedLockOrder[hr].Constructor, hr)
		}
	}
	return nil
}
