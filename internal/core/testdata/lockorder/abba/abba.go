// Package abba is a planted lock-order inversion for
// TestLockOrder_PlantedABBAIsCaught: mutexThenNamed holds svc.mu and then
// waits for a named lock; namedThenMutex holds the same named lock and then,
// through a helper, waits for svc.mu. Run concurrently, each waits for the
// other forever.
package abba

import (
	"context"
	"fmt"
	"sync"
)

type namedLocker interface {
	WithNamedLock(ctx context.Context, lockKey string, fn func(ctx context.Context) error) error
}

type svc struct {
	mu sync.Mutex
	st namedLocker
}

func sodGrantLockKey(principalType string, principalID uint) string {
	return fmt.Sprintf("sod-grant:%s:%d", principalType, principalID)
}

func (s *svc) mutexThenNamed(ctx context.Context, userID uint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.WithNamedLock(ctx, sodGrantLockKey("user", userID), func(context.Context) error { return nil })
}

func (s *svc) namedThenMutex(ctx context.Context, userID uint) error {
	return s.st.WithNamedLock(ctx, sodGrantLockKey("user", userID), func(context.Context) error {
		s.touch()
		return nil
	})
}

func (s *svc) touch() {
	s.mu.Lock()
	s.mu.Unlock()
}
