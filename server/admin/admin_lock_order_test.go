package admin

// The pooler check must run BEFORE the exclusive lock is taken: behind a
// transaction-mode pooler the session advisory lock stays on a server connection the
// pooler shares, and refusing afterwards cannot release it (STORAGE-FOLLOWUPS-1).
// The server orders them the same way (server/main.go).

import (
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/serverguard"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// stubLockSeams replaces both seams with recorders and restores them on cleanup.
func stubLockSeams(t *testing.T, refuse func(*config.Config) error) *[]string {
	t.Helper()
	oldRefuse, oldAcquire, oldForce := refuseTransactionPooler, acquireExclusive, forceFlag
	t.Cleanup(func() { refuseTransactionPooler, acquireExclusive, forceFlag = oldRefuse, oldAcquire, oldForce })
	forceFlag = false
	var calls []string
	refuseTransactionPooler = func(c *config.Config) error {
		calls = append(calls, "refuse")
		return refuse(c)
	}
	acquireExclusive = func(*config.Config) (*serverguard.Exclusive, error) {
		calls = append(calls, "acquire")
		return nil, errors.New("stub: lock not taken")
	}
	return &calls
}

func TestAcquireDatabaseLock_PoolerCheckRunsBeforeLock(t *testing.T) {
	calls := stubLockSeams(t, func(*config.Config) error { return nil })
	_, _ = acquireDatabaseLock(&config.Config{})
	if got := *calls; len(got) != 2 || got[0] != "refuse" || got[1] != "acquire" {
		t.Fatalf("call order = %v, want [refuse acquire]", got)
	}
}

func TestAcquireDatabaseLock_UndeclaredPoolerRefusesBeforeLock(t *testing.T) {
	refusal := &storage.UndeclaredTransactionPoolerError{PID: 7}
	calls := stubLockSeams(t, func(*config.Config) error { return refusal })
	_, err := acquireDatabaseLock(&config.Config{})
	if err == nil || !storage.IsUndeclaredTransactionPooler(err) {
		t.Fatalf("want the pooler refusal, got %v", err)
	}
	if got := *calls; len(got) != 1 || got[0] != "refuse" {
		t.Fatalf("the lock must not be taken after a refusal, calls = %v", got)
	}
}

func TestAcquireDatabaseLock_UndeclaredPoolerRefusedEvenWithForce(t *testing.T) {
	calls := stubLockSeams(t, func(*config.Config) error { return &storage.UndeclaredTransactionPoolerError{PID: 7} })
	forceFlag = true
	if _, err := acquireDatabaseLock(&config.Config{}); err == nil {
		t.Fatal("--force must not bypass the pooler refusal")
	}
	if got := *calls; len(got) != 1 {
		t.Fatalf("the lock must not be taken after a refusal, calls = %v", got)
	}
}

// A probe that could not connect is not a refusal: the lock attempt reports the
// connect failure with its own message (#2362).
func TestAcquireDatabaseLock_PoolerProbeFailureFallsThroughToLock(t *testing.T) {
	calls := stubLockSeams(t, func(*config.Config) error { return errors.New("dial tcp: refused") })
	_, _ = acquireDatabaseLock(&config.Config{})
	if got := *calls; len(got) != 2 || got[1] != "acquire" {
		t.Fatalf("calls = %v, want the lock attempt after a failed probe", got)
	}
}
