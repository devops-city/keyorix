package serverguard

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// Two holders of the key-initialisation lock never overlap: the second waits for
// the first instead of failing, which is what lets a second replica booting on a
// fresh shared key directory load the keys the first one wrote.
func TestPostgres_WithKeyInitLock_SerialisesHolders(t *testing.T) {
	cfg := pgCfg(t)
	var inside, maxInside int32
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Go(func() {
			errs[i] = WithKeyInitLock(cfg, 30*time.Second, func() error {
				n := atomic.AddInt32(&inside, 1)
				for {
					m := atomic.LoadInt32(&maxInside)
					if n <= m || atomic.CompareAndSwapInt32(&maxInside, m, n) {
						break
					}
				}
				time.Sleep(150 * time.Millisecond)
				atomic.AddInt32(&inside, -1)
				return nil
			})
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("holder %d: %v", i, err)
		}
	}
	if maxInside != 1 {
		t.Fatalf("%d holders ran fn at the same time, want 1", maxInside)
	}
}

// A holder that outlives the wait makes the next caller fail with a clear error,
// without running fn; fn's own error is returned unchanged.
func TestPostgres_WithKeyInitLock_TimesOutAndPropagates(t *testing.T) {
	cfg := pgCfg(t)
	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- WithKeyInitLock(cfg, 10*time.Second, func() error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	ran := false
	err := WithKeyInitLock(cfg, 700*time.Millisecond, func() error { ran = true; return nil })
	close(release)
	if err == nil || !strings.Contains(err.Error(), "key-initialisation lock") {
		t.Fatalf("want a key-initialisation lock timeout, got %v", err)
	}
	if ran {
		t.Fatal("fn ran without the lock")
	}
	if err := <-done; err != nil {
		t.Fatalf("first holder: %v", err)
	}
	sentinel := errors.New("boom")
	if err := WithKeyInitLock(cfg, 5*time.Second, func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("fn error not propagated: %v", err)
	}
}

// Not PostgreSQL: refused, fn not run.
func TestWithKeyInitLock_RefusesNonPostgres(t *testing.T) {
	cfg := &config.Config{Storage: config.StorageConfig{Type: "local"}}
	ran := false
	if err := WithKeyInitLock(cfg, time.Second, func() error { ran = true; return nil }); err == nil || ran {
		t.Fatalf("want refusal without running fn, got err=%v ran=%v", err, ran)
	}
}
