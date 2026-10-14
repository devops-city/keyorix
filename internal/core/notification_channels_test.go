package core

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCreateNotificationChannel_Validation(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	ctx := context.Background()

	t.Run("invalid type returns error", func(t *testing.T) {
		ch := &models.NotificationChannel{Name: "bad-type", Type: "sms", URL: "https://example.com"}
		_, err := c.CreateNotificationChannel(ctx, ch, "admin", 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid notification channel type")
	})

	t.Run("empty name returns error", func(t *testing.T) {
		ch := &models.NotificationChannel{Name: "", Type: "webhook", URL: "https://example.com"}
		_, err := c.CreateNotificationChannel(ctx, ch, "admin", 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name is required")
	})
}

func TestCreateNotificationChannel_WebhookRequiresURL(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	ctx := context.Background()

	t.Run("webhook without URL returns error", func(t *testing.T) {
		ch := &models.NotificationChannel{Name: "my-hook", Type: "webhook", URL: ""}
		_, err := c.CreateNotificationChannel(ctx, ch, "admin", 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "URL is required")
	})

	t.Run("email type without email returns error", func(t *testing.T) {
		ch := &models.NotificationChannel{Name: "my-email", Type: "email", Email: ""}
		_, err := c.CreateNotificationChannel(ctx, ch, "admin", 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "email is required")
	})

	t.Run("slack without URL returns error", func(t *testing.T) {
		ch := &models.NotificationChannel{Name: "my-slack", Type: "slack", URL: ""}
		_, err := c.CreateNotificationChannel(ctx, ch, "admin", 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "URL is required")
	})
}

// noopWebhookURLValidator bypasses the real DNS-based SSRF check in tests that
// focus on storage / field logic rather than URL security validation.
func noopWebhookURLValidator(_ string) error { return nil }

func TestNotificationChannel_CRUD(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	c.webhookURLValidator = noopWebhookURLValidator
	ctx := context.Background()

	created := &models.NotificationChannel{
		ID:     1,
		Name:   "webhook-siem",
		Type:   "webhook",
		URLEnc: plaintextURLEnc("https://siem.example.com/hook"),
		Events: "anomaly.detected,secret.expiring",
	}

	// Create
	store.On("CreateNotificationChannel", ctx, mock.MatchedBy(func(ch *models.NotificationChannel) bool {
		return ch.Name == "webhook-siem" && ch.Type == "webhook"
	})).Return(nil).Run(func(args mock.Arguments) {
		ch := args.Get(1).(*models.NotificationChannel)
		ch.ID = 1
	})
	// #2433: CreateNotificationChannel inserts, then encrypts the URL (bound to
	// the now-known ID) and persists URLEnc/URLMeta via a second
	// UpdateNotificationChannel call -- same two-step shape
	// CreateDynamicSecretConfig uses for AdminDSNEnc.
	store.On("UpdateNotificationChannel", ctx, mock.AnythingOfType("*models.NotificationChannel")).Return(nil)
	var auditEvents []*models.AuditEvent
	store.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { auditEvents = append(auditEvents, args.Get(1).(*models.AuditEvent)) }).
		Return(nil)

	result, err := c.CreateNotificationChannel(ctx, &models.NotificationChannel{
		Name:   "webhook-siem",
		Type:   "webhook",
		URL:    "https://siem.example.com/hook",
		Events: "anomaly.detected,secret.expiring",
	}, "admin", 42)
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
	assert.Equal(t, "admin", result.CreatedBy)
	require.Len(t, auditEvents, 1, "create must write one audit event")
	assert.Equal(t, EventNotificationChannelCreated, auditEvents[0].EventType)
	require.NotNil(t, auditEvents[0].UserID)
	assert.Equal(t, uint(42), *auditEvents[0].UserID)
	assert.Contains(t, auditEvents[0].Diff, "webhook-siem")

	// List
	store.On("ListNotificationChannels", ctx).Return([]*models.NotificationChannel{created}, nil)
	channels, err := c.ListNotificationChannels(ctx)
	require.NoError(t, err)
	require.Len(t, channels, 1)
	assert.Equal(t, "webhook-siem", channels[0].Name)

	// Get
	store.On("GetNotificationChannel", ctx, uint(1)).Return(created, nil)
	got, err := c.GetNotificationChannel(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, "webhook-siem", got.Name)

	// Update
	store.On("GetNotificationChannel", ctx, uint(1)).Return(created, nil).Maybe()
	store.On("UpdateNotificationChannel", ctx, mock.AnythingOfType("*models.NotificationChannel")).Return(nil)
	updated, err := c.UpdateNotificationChannel(ctx, 1, map[string]any{
		"events":  "secret.rotated",
		"enabled": false,
	}, 42)
	require.NoError(t, err)
	assert.Equal(t, "secret.rotated", updated.Events)
	assert.False(t, updated.Enabled)
	require.Len(t, auditEvents, 2, "update must write one more audit event")
	assert.Equal(t, EventNotificationChannelUpdated, auditEvents[1].EventType)

	// Delete
	store.On("DeleteNotificationChannel", ctx, uint(1)).Return(nil)
	require.NoError(t, c.DeleteNotificationChannel(ctx, 1, 42))
	require.Len(t, auditEvents, 3, "delete must write one more audit event")
	assert.Equal(t, EventNotificationChannelDeleted, auditEvents[2].EventType)

	store.AssertExpectations(t)
}

// TestCreateNotificationChannel_StorageError covers the branch where validation
// passes but the DB write returns an error.
func TestCreateNotificationChannel_StorageError(t *testing.T) {
	t.Parallel()
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	c.webhookURLValidator = noopWebhookURLValidator
	ctx := context.Background()

	st.On("CreateNotificationChannel", ctx, mock.AnythingOfType("*models.NotificationChannel")).
		Return(fmt.Errorf("db: connection refused"))

	ch := &models.NotificationChannel{Name: "hook", Type: "webhook", URL: "https://hook.example.com"}
	_, err := c.CreateNotificationChannel(ctx, ch, "admin", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
	st.AssertExpectations(t)
}

// TestUpdateNotificationChannel_GetError covers the branch where the initial
// fetch of the channel returns an error.
func TestUpdateNotificationChannel_GetError(t *testing.T) {
	t.Parallel()
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	ctx := context.Background()

	st.On("GetNotificationChannel", ctx, uint(99)).
		Return(nil, fmt.Errorf("record not found"))

	_, err := c.UpdateNotificationChannel(ctx, 99, map[string]any{"events": "secret.rotated"}, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	st.AssertExpectations(t)
}

// TestUpdateNotificationChannel_UpdateStorageError covers the branch where the
// DB write for the update itself fails.
func TestUpdateNotificationChannel_UpdateStorageError(t *testing.T) {
	t.Parallel()
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	c.webhookURLValidator = noopWebhookURLValidator
	ctx := context.Background()

	existing := &models.NotificationChannel{
		ID:     2,
		Name:   "hook",
		Type:   "webhook",
		URLEnc: plaintextURLEnc("https://hook.example.com"),
	}
	st.On("GetNotificationChannel", ctx, uint(2)).Return(existing, nil)
	st.On("UpdateNotificationChannel", ctx, mock.AnythingOfType("*models.NotificationChannel")).
		Return(fmt.Errorf("db: disk full"))

	_, err := c.UpdateNotificationChannel(ctx, 2, map[string]any{"events": "secret.rotated"}, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk full")
	st.AssertExpectations(t)
}

// TestValidateNotificationChannel_TeamsRequiresURL explicitly exercises the
// "teams" case in the URL-required switch.
func TestValidateNotificationChannel_TeamsRequiresURL(t *testing.T) {
	t.Parallel()
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	ctx := context.Background()

	ch := &models.NotificationChannel{Name: "teams-ch", Type: "teams", URL: ""}
	_, err := c.CreateNotificationChannel(ctx, ch, "admin", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "URL is required")
	assert.Contains(t, err.Error(), "teams")
}

// TestUpdateNotificationChannel_AllFieldUpdates exercises all field branches
// in UpdateNotificationChannel (name, type, url, email, events, enabled).
func TestUpdateNotificationChannel_AllFieldUpdates(t *testing.T) {
	t.Parallel()
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	c.webhookURLValidator = noopWebhookURLValidator
	ctx := context.Background()

	existing := &models.NotificationChannel{
		ID:    3,
		Name:  "old-name",
		Type:  "webhook",
		URL:   "https://old.example.com",
		Email: "",
	}
	st.On("GetNotificationChannel", ctx, uint(3)).Return(existing, nil)
	st.On("UpdateNotificationChannel", ctx, mock.AnythingOfType("*models.NotificationChannel")).Return(nil)
	st.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)

	updated, err := c.UpdateNotificationChannel(ctx, 3, map[string]any{
		"name":    "new-name",
		"type":    "webhook",
		"url":     "https://new.example.com",
		"email":   "ops@example.com",
		"events":  "secret.expiring",
		"enabled": true,
	}, 1)
	require.NoError(t, err)
	assert.Equal(t, "new-name", updated.Name)
	assert.Equal(t, "https://new.example.com", updated.URL)
	assert.Equal(t, "ops@example.com", updated.Email)
	assert.Equal(t, "secret.expiring", updated.Events)
	assert.True(t, updated.Enabled)
	st.AssertExpectations(t)
}

// TestUpdateNotificationChannel_ValidationFails exercises the case where an
// update causes validation to fail (e.g., clearing the URL of a webhook type).
func TestUpdateNotificationChannel_ValidationFails(t *testing.T) {
	t.Parallel()
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	ctx := context.Background()

	existing := &models.NotificationChannel{
		ID:   4,
		Name: "hook",
		Type: "webhook",
		URL:  "https://hook.example.com",
	}
	st.On("GetNotificationChannel", ctx, uint(4)).Return(existing, nil)

	// Clearing the URL of a webhook should fail validation.
	_, err := c.UpdateNotificationChannel(ctx, 4, map[string]any{
		"url": "",
	}, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "URL is required")
	st.AssertExpectations(t)
}

// ---- validateWebhookURL (SSRF guard) ----

func TestValidateWebhookURL_RequiresHTTPS(t *testing.T) {
	t.Parallel()
	err := validateWebhookURL("http://hooks.example.com/webhook")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

func TestValidateWebhookURL_RejectsPrivateIPs(t *testing.T) {
	t.Parallel()
	disallowed := []string{
		"https://127.0.0.1/hook",
		"https://192.168.1.100/hook",
		"https://10.0.0.1/hook",
		"https://172.16.0.1/hook",
		"https://169.254.169.254/latest/meta-data",
		"https://[::1]/hook",
	}
	for _, u := range disallowed {
		err := validateWebhookURL(u)
		require.Error(t, err, "expected error for %s", u)
		assert.Contains(t, err.Error(), "private/link-local", "wrong error for %s", u)
	}
}

func TestValidateWebhookURL_AcceptsPublicIP(t *testing.T) {
	t.Parallel()
	// 93.184.216.34 is the well-known IANA example.com address — public, non-private.
	err := validateWebhookURL("https://93.184.216.34/hook")
	require.NoError(t, err)
}

func TestValidateWebhookURL_InvalidURL(t *testing.T) {
	t.Parallel()
	err := validateWebhookURL("://bad-url")
	require.Error(t, err)
}

// ---- PII: accessed_by / ip_address must not appear in webhook payload ----

func TestDispatchToChannel_WebhookPayload_NoPII(t *testing.T) {
	t.Parallel()
	var capturedBody []byte
	tr := &fakeWebhookTransport{
		capture: func(b []byte) { capturedBody = b },
	}

	store := new(MockStorage)
	c := NewKeyorixCore(store)
	c.httpClient = &http.Client{Transport: tr}

	ch := &models.NotificationChannel{ID: 1, Name: "wh", Type: "webhook", URL: "https://fake.test/hook", Enabled: true}
	alert := &models.AnomalyAlert{
		ID: 5, Severity: "high", AlertType: "off_hours",
		Description: "late access", SecretName: "db-password",
		AccessedBy: "alice", IPAddress: "10.0.0.1",
	}
	policy := &models.AlertEscalationPolicy{ID: 1, Name: "p1"}

	err := c.dispatchToChannel(context.Background(), ch, alert, policy)
	require.NoError(t, err)

	body := string(capturedBody)
	assert.NotContains(t, body, "alice", "accessed_by must not be in webhook payload")
	assert.NotContains(t, body, "10.0.0.1", "ip_address must not be in webhook payload")
	assert.Contains(t, body, "db-password")
}
