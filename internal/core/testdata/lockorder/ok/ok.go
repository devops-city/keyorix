// Package ok is abba without the inversion, for
// TestLockOrder_PlantedABBAIsCaught: svc.mu is only ever taken inside the
// named lock.
package ok

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
