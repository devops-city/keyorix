package core

// pat_authz_metamorphic_fuzz_test.go — FuzzPATRestrictionAllows.
//
// Metamorphic fuzzing of PATRestriction.Allows (ADR-042) — the pure, no-I/O
// least-privilege decision that bounds even a global-admin's personal access
// token. Because Allows is a pure function, the oracle is exact: we compare its
// output to itself under transforms that must (or must not) change the answer.
// No hand-specified "correct" decision, no second implementation, no AI oracle.
//
// The invariants asserted (each only in the direction that cannot false-positive):
//
//   - DETERMINISM: identical inputs yield identical decisions, and Allows never
//     mutates its receiver's permission list.
//   - ORDER INVARIANCE: the decision is invariant to the order of the permission
//     allowlist (it is an OR over patterns — order must not matter).
//   - SCOPE NARROWING (deny): a project-scoped restriction denies every other
//     project; an environment-scoped one denies every other environment. A
//     violation is a token acting outside its own scope — a least-privilege escape.
//   - MONOTONICITY: adding a pattern to a NON-EMPTY allowlist only widens it, so an
//     ALLOW stays an ALLOW. (The empty allowlist means "inherit the owner's full
//     set" and therefore INVERTS this — asserted separately, not as monotonicity.)
//   - WILDCARD / EMPTY semantics: at an allowed scope, "*" and an empty allowlist
//     both permit any permission.
//
// A bug in any of these is a real authorization defect: a reorder- or
// addition-sensitive allowlist, or a scope-confinement escape.

import (
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// patFuzzVocab is a small pool of realistic permission patterns so fuzzed
// allowlists and queries actually intersect (pure-random strings almost never
// match), while raw tokens (below) still exercise the matcher's edges.
var patFuzzVocab = []string{
	"secrets.read", "secrets.write", "secrets.*", "users.read", "users.*",
	"*", "secrets.", "admin.delete", "projects.list", "a.b.c", "", ".*",
}

func FuzzPATRestrictionAllows(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x02, 0x01, 0x05, 0x01, 0x00, 0x01, 0x02})
	f.Add([]byte{0x03, 0x02, 0x02, 0x00, 0x00, 0x05, 0x01, 0x01, 0x00})
	f.Add([]byte("\x04\x05\x02\x09\x00\x02\x03\x01\x02\x03\x04\x05\x06"))
	f.Add([]byte{0x01, 0x00, 0x05, 0x03, 0x02, 0x00, 0x01, 0x03})

	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzutil.Guard(t.Fatalf, "PATRestriction.Allows algebra", func() {
			checkPATAllowsAlgebra(data)
		})
	})
}

// checkPATAllowsAlgebra decodes a PATRestriction + a query from data and asserts
// the metamorphic invariants. It panics on any violation (Guard runs it in a
// goroutine; the fuzzer records a panic as a reproducer).
func checkPATAllowsAlgebra(data []byte) {
	c := &patCursor{b: data}

	n := int(c.u8() % 9) // 0..8 permission patterns
	perms := make([]string, 0, n)
	for range n {
		if c.u8()%4 == 0 {
			perms = append(perms, c.token())
		} else {
			perms = append(perms, patFuzzVocab[int(c.u8())%len(patFuzzVocab)])
		}
	}
	projID := uint(c.u8() % 4)
	envID := uint(c.u8() % 4)

	var qperm string
	if c.u8()%4 == 0 {
		qperm = c.token()
	} else {
		qperm = patFuzzVocab[int(c.u8())%len(patFuzzVocab)]
	}
	qscope := Scope{ProjectID: uint(c.u8() % 4), EnvironmentID: uint(c.u8() % 4)}

	r := &PATRestriction{Permissions: perms, ProjectID: projID, EnvironmentID: envID}
	base := r.Allows(qperm, qscope)

	// DETERMINISM + no receiver mutation.
	if r.Allows(qperm, qscope) != base {
		panic("determinism: Allows returned different results for identical inputs")
	}
	if len(r.Permissions) != n {
		panic("mutation: Allows changed the length of its permission slice")
	}

	// ORDER INVARIANCE: reverse and rotate must not change the decision.
	if n > 1 {
		rev := make([]string, n)
		for i := range perms {
			rev[i] = perms[n-1-i]
		}
		if (&PATRestriction{Permissions: rev, ProjectID: projID, EnvironmentID: envID}).Allows(qperm, qscope) != base {
			panic(fmt.Sprintf("order-variance: reversing Permissions changed the decision (perms=%q perm=%q scope=%+v)", perms, qperm, qscope))
		}
		rot := append(append([]string{}, perms[1:]...), perms[0])
		if (&PATRestriction{Permissions: rot, ProjectID: projID, EnvironmentID: envID}).Allows(qperm, qscope) != base {
			panic(fmt.Sprintf("order-variance: rotating Permissions changed the decision (perms=%q perm=%q)", perms, qperm))
		}
	}

	// SCOPE NARROWING (deny direction): a scoped restriction denies foreign scopes.
	if projID != 0 {
		foreign := Scope{ProjectID: projID + 1, EnvironmentID: qscope.EnvironmentID}
		if r.Allows(qperm, foreign) {
			panic(fmt.Sprintf("scope-escape: project-scoped restriction (proj=%d) allowed a different project (proj=%d)", projID, foreign.ProjectID))
		}
	}
	if envID != 0 {
		sp := projID
		if sp == 0 {
			sp = qscope.ProjectID // keep the project gate passing so we isolate the env gate
		}
		foreign := Scope{ProjectID: sp, EnvironmentID: envID + 1}
		if r.Allows(qperm, foreign) {
			panic(fmt.Sprintf("scope-escape: env-scoped restriction (env=%d) allowed a different environment (env=%d)", envID, foreign.EnvironmentID))
		}
	}

	// MONOTONICITY: adding to a NON-EMPTY allowlist keeps every ALLOW an ALLOW.
	if n > 0 && base {
		for _, extra := range []string{"zzz.extra.unlikely", "another.pattern"} {
			sup := append(append([]string{}, perms...), extra)
			if !(&PATRestriction{Permissions: sup, ProjectID: projID, EnvironmentID: envID}).Allows(qperm, qscope) {
				panic(fmt.Sprintf("non-monotone: adding pattern %q turned ALLOW into DENY (perms=%q perm=%q)", extra, perms, qperm))
			}
		}
	}

	// WILDCARD "*" and EMPTY allowlist both allow-all at an allowed scope.
	if patScopePasses(projID, envID, qscope) {
		if !(&PATRestriction{Permissions: []string{"*"}, ProjectID: projID, EnvironmentID: envID}).Allows(qperm, qscope) {
			panic(fmt.Sprintf("wildcard: '*' denied %q at an allowed scope %+v", qperm, qscope))
		}
		if !(&PATRestriction{Permissions: nil, ProjectID: projID, EnvironmentID: envID}).Allows(qperm, qscope) {
			panic(fmt.Sprintf("empty-allowlist: empty Permissions denied %q at an allowed scope %+v", qperm, qscope))
		}
	}
}

// patScopePasses mirrors Allows's scope gate: whether a restriction scoped to
// (projID, envID) admits scope s at all, before any permission matching.
func patScopePasses(projID, envID uint, s Scope) bool {
	if projID != 0 && s.ProjectID != projID {
		return false
	}
	if envID != 0 && s.EnvironmentID != envID {
		return false
	}
	return true
}

// patCursor pulls bytes off the fuzz input, returning 0 once exhausted so the
// decode is total for any input length.
type patCursor struct {
	b []byte
	i int
}

func (c *patCursor) u8() byte {
	if c.i >= len(c.b) {
		return 0
	}
	v := c.b[c.i]
	c.i++
	return v
}

func (c *patCursor) token() string {
	ln := int(c.u8() % 7)
	out := make([]byte, 0, ln)
	for range ln {
		out = append(out, c.u8())
	}
	return string(out)
}
