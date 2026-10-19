// secret_access_log_panic_test.go — regression for the writeAccessLog panic
// fix (found by a live FuzzStorageFaultOperations run during the
// fuzz/mfa-reauth-ops (#2392) rebase, replaying cleanly on unmodified
// origin/main): writeAccessLog discards a RETURNED error from
// CreateSecretAccessLog (matching its own "surfaced loudly" comment, which
// already does not propagate it) but had no recover() for a PANIC, so a panic
// there propagated past an already-committed audit event / primary mutation,
// misreporting a genuinely successful call as a failure.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// panicOnCreateSecretAccessLogStorage wraps a real storage.Storage and makes
// CreateSecretAccessLog panic unconditionally, mirroring the
// panicOnEnforceSessionLimitStorage stub idiom used elsewhere in this package.
func panicOnCreateSecretAccessLogStorage(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		CreateSecretAccessLog: func(_ storage.Storage, _ context.Context, _ *models.SecretAccessLog) error {
			panic("injected fault: CreateSecretAccessLog")
		},
	})
}

// TestLogSecretUpdated_AccessLogPanic_StillSucceeds: a panic in
// writeAccessLog's best-effort CreateSecretAccessLog call must not propagate
// past an already-written audit event -- confirmed red on the unfixed code
// (the panic crashes the test, exactly as the finding describes).
func TestLogSecretUpdated_AccessLogPanic_StillSucceeds(t *testing.T) {
	t.Parallel()
	c, _ := newBootstrappedCore(t)
	ctx := context.Background()

	c.storage = panicOnCreateSecretAccessLogStorage(c.storage)

	require.NotPanics(t, func() {
		c.LogSecretUpdated(ctx, 1, 1, "admin", "my-secret", "127.0.0.1", "test-agent")
	}, "a panic in the best-effort secret-access-log write must not propagate past an already-written audit event")
}
