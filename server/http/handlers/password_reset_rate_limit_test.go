// password_reset_rate_limit_test.go — regression coverage for #249: before this
// fix, POST /auth/password-reset had zero rate-limiting of any kind (no auth,
// no per-IP budget), so an unauthenticated caller could mail-bomb any
// registered address without limit. This exercises the real HTTP handler.
package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// noopDeliverer discards every setup-link delivery; only used so
// RequestPasswordReset's base-URL/channel requirements are satisfied.
type noopDeliverer struct{}

func (noopDeliverer) DeliverSetupLink(_ context.Context, _ delivery.SetupLinkRequest) (delivery.DeliveryResult, error) {
	return delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}, nil
}
func (noopDeliverer) Name() string { return "noop" }

func newPasswordResetTestCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.SetupToken{}, &models.AuditEvent{}, &models.LoginAttempt{},
	))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetCredentialDelivery(noopDeliverer{}, "https://keyorix.example.internal")
	return c
}

func doPasswordReset(h *AuthHandler, ip string) int {
	rec := httptest.NewRecorder()
	body := strings.NewReader(`{"email":"someone@example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/password-reset", body)
	req.RemoteAddr = ip + ":54321"
	h.PasswordReset(rec, req)
	return rec.Code
}

// TestPasswordReset_RateLimitedByIP proves POST /auth/password-reset now has a
// per-IP request budget: before core.PasswordResetMaxAttempts requests from one
// IP within the window all succeed (200, the enumeration-safe generic
// response); the next one is rejected with 429 rather than triggering another
// throttle-check + potential email send.
func TestPasswordReset_RateLimitedByIP(t *testing.T) {
	c := newPasswordResetTestCore(t)
	h := NewAuthHandler(c, false)
	const ip = "203.0.113.7"

	for i := range core.PasswordResetMaxAttempts {
		assert.Equal(t, http.StatusOK, doPasswordReset(h, ip), "request %d should be under the IP budget", i+1)
	}
	assert.Equal(t, http.StatusTooManyRequests, doPasswordReset(h, ip),
		"the request beyond the IP budget must be rate-limited")
}

// TestPasswordReset_RateLimitIsPerIP confirms the budget is scoped per source
// IP, not global — a different caller is unaffected by another IP's burst.
func TestPasswordReset_RateLimitIsPerIP(t *testing.T) {
	c := newPasswordResetTestCore(t)
	h := NewAuthHandler(c, false)

	for range core.PasswordResetMaxAttempts {
		assert.Equal(t, http.StatusOK, doPasswordReset(h, "203.0.113.7"))
	}
	assert.Equal(t, http.StatusTooManyRequests, doPasswordReset(h, "203.0.113.7"))

	// A different IP still gets through.
	assert.Equal(t, http.StatusOK, doPasswordReset(h, "198.51.100.9"))
}
