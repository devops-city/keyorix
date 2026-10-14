package core

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// freshBootstrapCore returns a non-bootstrapped core over an in-memory store.
func freshBootstrapCore(t *testing.T) *KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SystemMetadata{},
	))
	return NewKeyorixCore(store.NewLocalStorage(db))
}

func strongBootstrapReq(token string) *BootstrapRequest {
	return &BootstrapRequest{
		Username: "admin", Email: "admin@example.com",
		Password: "BootstrapPass123!", DisplayName: "Admin", Token: token,
	}
}

// TestBootstrapSystem_TokenGate pins the fix for the unauthenticated first-admin-claim
// race: /system/init must refuse unless the caller presents the configured token.
func TestBootstrapSystem_TokenGate(t *testing.T) {
	t.Parallel()
	t.Run("refuses when no server token is configured (fail closed)", func(t *testing.T) {
		c := freshBootstrapCore(t) // no SetBootstrapToken
		_, err := c.BootstrapSystem(context.Background(), strongBootstrapReq("anything"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "disabled")
		// Nothing was seeded.
		needs, nerr := c.SystemNeedsBootstrap(context.Background())
		require.NoError(t, nerr)
		assert.True(t, needs, "no admin should exist after a refused bootstrap")
	})

	t.Run("refuses a wrong token", func(t *testing.T) {
		c := freshBootstrapCore(t)
		c.SetBootstrapToken("correct-token")
		_, err := c.BootstrapSystem(context.Background(), strongBootstrapReq("wrong-token"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid bootstrap token")
		needs, _ := c.SystemNeedsBootstrap(context.Background())
		assert.True(t, needs)
	})

	t.Run("refuses a weak admin password even with the right token", func(t *testing.T) {
		c := freshBootstrapCore(t)
		c.SetBootstrapToken("correct-token")
		req := strongBootstrapReq("correct-token")
		req.Password = "admin" // below the default policy floor
		_, err := c.BootstrapSystem(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "password must")
	})

	t.Run("succeeds with the right token and a strong password", func(t *testing.T) {
		c := freshBootstrapCore(t)
		c.SetBootstrapToken("correct-token")
		res, err := c.BootstrapSystem(context.Background(), strongBootstrapReq("correct-token"))
		require.NoError(t, err)
		require.NotNil(t, res.User)
		assert.False(t, res.AlreadyInitialized)
	})

	t.Run("idempotent repeat needs no token once initialised", func(t *testing.T) {
		c := freshBootstrapCore(t)
		c.SetBootstrapToken("correct-token")
		_, err := c.BootstrapSystem(context.Background(), strongBootstrapReq("correct-token"))
		require.NoError(t, err)
		// A second call with no token returns the existing state, not an error.
		res, err := c.BootstrapSystem(context.Background(), &BootstrapRequest{})
		require.NoError(t, err)
		assert.True(t, res.AlreadyInitialized)
	})
}

// TestBootstrapSystem_ConcurrentCallsProduceExactlyOneAdmin pins the fix for #339: two
// callers who both already hold the valid bootstrap token (not an unauthenticated
// attacker — the token gate above already closes that race) but supply different
// usernames must not both observe the "fresh install" (total==0) gate and each create a
// "first admin". Only one concurrent call may actually create a user; every other
// concurrent call must observe AlreadyInitialized instead.
func TestBootstrapSystem_ConcurrentCallsProduceExactlyOneAdmin(t *testing.T) {
	t.Parallel()
	c := freshBootstrapCore(t)
	c.SetBootstrapToken("correct-token")

	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	created := 0
	errs := 0
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := &BootstrapRequest{
				Username: fmt.Sprintf("admin-%d", i), Email: fmt.Sprintf("admin-%d@example.com", i),
				Password: "BootstrapPass123!", DisplayName: "Admin", Token: "correct-token",
			}
			res, err := c.BootstrapSystem(context.Background(), req)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs++
				return
			}
			if !res.AlreadyInitialized {
				created++
			}
		}(i)
	}
	wg.Wait()

	assert.Equal(t, 0, errs, "no concurrent bootstrap call holding the valid token should error")
	assert.Equal(t, 1, created, "exactly one concurrent call may create the first admin")

	_, total, err := c.storage.ListUsers(context.Background(), &storage.UserFilter{Page: 1, PageSize: 100})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total, "the store must end up with exactly one admin user, not one per racing caller")
}
