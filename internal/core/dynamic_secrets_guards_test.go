package core

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/dynamic"
)

// #3424 (AUTHZ-GUARDS-1): three guards in dynamic_secrets.go that no test failed
// without. Each test below was watched going red with its guard removed.

// dialCountingEngine wraps a real engine and counts every call that would reach the
// target database. A guard that works must leave all three counters at zero.
type dialCountingEngine struct {
	ports.DynamicBackendEngine
	issues, revokes, renews atomic.Int32
}

func (e *dialCountingEngine) Issue(ctx context.Context, dsn, tmpl string, ttl time.Duration) (ports.DynamicCredential, string, error) {
	e.issues.Add(1)
	return e.DynamicBackendEngine.Issue(ctx, dsn, tmpl, ttl)
}

func (e *dialCountingEngine) Revoke(ctx context.Context, dsn, role string) error {
	e.revokes.Add(1)
	return e.DynamicBackendEngine.Revoke(ctx, dsn, role)
}

func (e *dialCountingEngine) Renew(ctx context.Context, dsn, role string, exp time.Time) error {
	e.renews.Add(1)
	return e.DynamicBackendEngine.Renew(ctx, dsn, role, exp)
}

// TestDynamicSecrets_RevalidateAdminDSN_IssueAndRevoke: a config whose decrypted admin
// DSN points at the cloud metadata address (stored while the private-network switch was
// on, or before the create-time guard existed) must be refused at BOTH IssueLease and
// RevokeLease once the switch is off, and the engine must never be called.
func TestDynamicSecrets_RevalidateAdminDSN_IssueAndRevoke(t *testing.T) {
	t.Parallel()
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()

	// Create the config while private targets are allowed, then tighten the switch.
	c.SetDynamicAllowPrivateTargets(true)
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "imds-config", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
		AdminDSN: "postgres://admin:pass@169.254.169.254:5432/app", DefaultTTLSeconds: 3600,
		CreatedBy: "alice", ActorID: testAdminActorID,
	})
	require.NoError(t, err)
	// A lease minted while the switch was still on, so RevokeLease has something to revoke.
	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	require.Len(t, fake.Issued, 1)
	c.SetDynamicAllowPrivateTargets(false)

	t.Run("IssueLease", func(t *testing.T) {
		_, err := c.IssueLease(ctx, cfg.ID, 0, 7)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "private or link-local")
		assert.Len(t, fake.Issued, 1, "nothing is dialled: no second credential was minted")
	})

	t.Run("RevokeLease", func(t *testing.T) {
		err := c.RevokeLease(ctx, issued.LeaseID, 7, "test")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "private or link-local")
		assert.Empty(t, fake.Revoked, "nothing is dialled: the engine was not asked to revoke")
		leases, lerr := c.ListDynamicSecretLeases(ctx, cfg.ID)
		require.NoError(t, lerr)
		for _, l := range leases {
			if l.LeaseID == issued.LeaseID {
				assert.Equal(t, "active", l.Status, "a refused revoke must not alter the lease")
				return
			}
		}
		t.Fatalf("lease %s not found", issued.LeaseID)
	})
}

// TestDynamicSecrets_IssueRefusesNoNativeExpiryBackendWithoutSweeper pins the sweeper
// gate on the backends that really have no DB-level expiry (the production engines,
// not the fake): MySQL, MongoDB and Redis. With dynamic_secrets.sweep_enabled false the
// issue must fail with the sweeper error and the engine must never be called.
func TestDynamicSecrets_IssueRefusesNoNativeExpiryBackendWithoutSweeper(t *testing.T) {
	t.Parallel()
	cases := []struct{ backend, dsn string }{
		{"mysql", "admin:pw@tcp(db.internal:3306)/app"},
		{"mongodb", "mongodb://admin:pw@db.internal:27017/admin"},
		{"redis", "rediss://admin:pw@db.internal:6379/0"},
	}
	for _, tc := range cases {
		t.Run(tc.backend, func(t *testing.T) {
			t.Parallel()
			c, _, _, _ := newDynamicTestCore(t)
			ctx := context.Background()
			real, err := dynamic.New(tc.backend, false, false)
			require.NoError(t, err)
			require.False(t, real.SupportsNativeExpiry(), "premise: %s has no native expiry", tc.backend)
			counting := &dialCountingEngine{DynamicBackendEngine: real}
			c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return counting, nil })

			cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
				Name: tc.backend + "-cfg", ProjectID: 1, EnvironmentID: 2, BackendType: tc.backend,
				AdminDSN: tc.dsn, DefaultTTLSeconds: 3600, CreatedBy: "alice", ActorID: testAdminActorID,
			})
			require.NoError(t, err)

			_, err = c.IssueLease(ctx, cfg.ID, 0, 7)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "sweep_enabled")
			assert.Zero(t, counting.issues.Load(), "no credential is minted while the sweeper is off")
			leases, lerr := c.ListDynamicSecretLeases(ctx, cfg.ID)
			require.NoError(t, lerr)
			assert.Empty(t, leases)
		})
	}
}

// TestDynamicSecrets_IssueLease_DisabledConfigMintsNothing: a Disabled config (what
// DeleteProject's cascade and an admin both set) refuses to mint.
func TestDynamicSecrets_IssueLease_DisabledConfigMintsNothing(t *testing.T) {
	t.Parallel()
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)
	_, err := c.SetDynamicSecretConfigEnabled(ctx, testAdminActorID, cfg.ID, false)
	require.NoError(t, err)

	_, err = c.IssueLease(ctx, cfg.ID, 0, 7)
	require.Error(t, err)
	assert.EqualError(t, err, "dynamic-secret config is disabled")
	assert.Empty(t, fake.Issued, "no credential is minted for a disabled config")
	leases, lerr := c.ListDynamicSecretLeases(ctx, cfg.ID)
	require.NoError(t, lerr)
	assert.Empty(t, leases)
}
