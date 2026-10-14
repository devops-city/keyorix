package core

import (
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestSetBcryptCostForTesting_ConcurrentWithReads is #G63: bcryptCost/
// dummyBcryptHash are package-level state read on every password-hashing call
// (account.go, scim.go, users.go, auth.go). SetBcryptCostForTesting is
// exported and its doc comment's "call before any test runs" contract isn't
// enforced by anything — a call racing a concurrent read is a real,
// unsynchronized data race under `go test -race`, not just a theoretical one.
// This doesn't assert a specific value (concurrent writers make the observed
// value nondeterministic by design); it only proves no race is reported and
// nothing panics.
func TestSetBcryptCostForTesting_ConcurrentWithReads(t *testing.T) {
	t.Parallel()
	var wg sync.WaitGroup
	start := make(chan struct{})

	for range 10 {
		wg.Go(func() {
			<-start
			SetBcryptCostForTesting(bcrypt.MinCost)
		})
	}
	for range 10 {
		wg.Go(func() {
			<-start
			_, _ = bcrypt.GenerateFromPassword([]byte("probe"), int(bcryptCost.Load()))
			_ = bcrypt.CompareHashAndPassword(*dummyBcryptHash.Load(), []byte("probe"))
		})
	}
	close(start)
	wg.Wait()

	// Leave the package at MinCost regardless of which concurrent writer
	// above landed last — this package's TestMain does not itself lower the
	// cost, so leaving it at the slow production default (12) would slow
	// down every later bcrypt-hashing test in this package.
	SetBcryptCostForTesting(bcrypt.MinCost)
}
