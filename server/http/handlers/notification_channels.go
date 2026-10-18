// notification_channels.go — CRUD endpoints for runtime-managed outbound
// notification channels (webhook/slack/teams/email). The router gates the CRUD
// routes on alerts.write (the alert_operator role; system.write holders keep
// access through the one-time backfill) and GET .../retry-policy on system.read.
//
// A channel URL is a bearer credential (Slack-style tokens live in the path),
// so it is returned in full exactly once, in the create response (#3425).
// List, get and update return only scheme+host with the path elided, plus
// url_set; an update that omits "url" keeps the stored credential.
package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/netutil"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

const (
	channelNotFound        = "not found"
	channelNotFoundMessage = "Notification channel not found"
)

// NotificationChannelHandler serves the notification-channel CRUD endpoints.
type NotificationChannelHandler struct {
	coreService *core.KeyorixCore
}

// NewNotificationChannelHandler constructs a NotificationChannelHandler.
func NewNotificationChannelHandler(coreService *core.KeyorixCore) *NotificationChannelHandler {
	return &NotificationChannelHandler{coreService: coreService}
}

// elideChannelURL renders a stored channel URL for display: scheme and host
// followed by an ellipsis in place of the path, query and userinfo, which is
// where the bearer token lives (e.g. "https://hooks.slack.com/…"). Empty in,
// empty out.
func elideChannelURL(raw string) string {
	if raw == "" {
		return ""
	}
	host := netutil.RedactURLHost(raw)
	if !strings.Contains(host, "://") {
		return host // unparseable: the placeholder, never a fragment of the input
	}
	return host + "/…"
}

// channelToAPI converts a NotificationChannel model to the API wire shape.
// revealURL is true only for the create response, the one place the full URL
// is returned; every other response carries the elided form and url_set.
func channelToAPI(ch *models.NotificationChannel, revealURL bool) map[string]any {
	url := elideChannelURL(ch.URL)
	if revealURL {
		url = ch.URL
	}
	return map[string]any{
		"id":         ch.ID,
		"name":       ch.Name,
		"type":       ch.Type,
		"enabled":    ch.Enabled,
		"url":        url,
		"url_set":    ch.URL != "",
		"email":      ch.Email,
		"events":     ch.Events,
		"created_by": ch.CreatedBy,
		"created_at": ch.CreatedAt,
		"updated_at": ch.UpdatedAt,
	}
}

// List handles GET /api/v1/notification-channels.
func (h *NotificationChannelHandler) List(w http.ResponseWriter, r *http.Request) {
	channels, err := h.coreService.ListNotificationChannels(r.Context())
	if err != nil {
		log.Printf("Error listing notification channels: %v", err)
		sendError(w, "InternalError", "Failed to list notification channels", http.StatusInternalServerError, nil)
		return
	}
	out := make([]map[string]any, 0, len(channels))
	for _, ch := range channels {
		out = append(out, channelToAPI(ch, false))
	}
	sendSuccess(w, map[string]any{"channels": out}, "")
}

// Create handles POST /api/v1/notification-channels.
func (h *NotificationChannelHandler) Create(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		Enabled *bool  `json:"enabled"`
		URL     string `json:"url"`
		Email   string `json:"email"`
		Events  string `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	ch := &models.NotificationChannel{
		Name:   body.Name,
		Type:   body.Type,
		URL:    body.URL,
		Email:  body.Email,
		Events: body.Events,
	}
	if body.Enabled != nil {
		ch.Enabled = *body.Enabled
	} else {
		ch.Enabled = true
	}
	created, err := h.coreService.CreateNotificationChannel(r.Context(), ch, u.Username, u.UserID)
	if err != nil {
		if isValidationError(err) {
			sendError(w, "BadRequest", err.Error(), http.StatusBadRequest, nil)
			return
		}
		if errors.Is(err, storage.ErrDuplicateNotificationChannelName) {
			sendError(w, "ConflictError", "A notification channel with that name already exists", http.StatusConflict, nil)
			return
		}
		log.Printf("Error creating notification channel: %v", err)
		sendError(w, "InternalError", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendCreated(w, channelToAPI(created, true), "")
}

// Get handles GET /api/v1/notification-channels/{id}.
func (h *NotificationChannelHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	ch, err := h.coreService.GetNotificationChannel(r.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), channelNotFound) {
			sendError(w, "NotFound", channelNotFoundMessage, http.StatusNotFound, nil)
			return
		}
		log.Printf("Error getting notification channel %d: %v", id, err)
		sendError(w, "InternalError", "Failed to get notification channel", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, channelToAPI(ch, false), "")
}

// Update handles PUT /api/v1/notification-channels/{id}.
func (h *NotificationChannelHandler) Update(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	updated, err := h.coreService.UpdateNotificationChannel(r.Context(), id, body, u.UserID)
	if err != nil {
		if strings.Contains(err.Error(), channelNotFound) {
			sendError(w, "NotFound", channelNotFoundMessage, http.StatusNotFound, nil)
			return
		}
		if isValidationError(err) {
			sendError(w, "BadRequest", err.Error(), http.StatusBadRequest, nil)
			return
		}
		log.Printf("Error updating notification channel %d: %v", id, err)
		sendError(w, "InternalError", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, channelToAPI(updated, false), "")
}

// Delete handles DELETE /api/v1/notification-channels/{id}.
func (h *NotificationChannelHandler) Delete(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	if err := h.coreService.DeleteNotificationChannel(r.Context(), id, u.UserID); err != nil {
		if strings.Contains(err.Error(), channelNotFound) {
			sendError(w, "NotFound", channelNotFoundMessage, http.StatusNotFound, nil)
			return
		}
		log.Printf("Error deleting notification channel %d: %v", id, err)
		sendError(w, "InternalError", "Failed to delete notification channel", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"id": id, "deleted": true}, "")
}

// SetRetryPolicy handles PUT /api/v1/notification-channels/{id}/retry-policy.
// Body: {"max_retries": 5, "retry_backoff_ms": 2000}
// Response 200: {"data": {"channel_id": N, "max_retries": 5, "retry_backoff_ms": 2000}}
func (h *NotificationChannelHandler) SetRetryPolicy(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	var body struct {
		MaxRetries     int `json:"max_retries"`
		RetryBackoffMs int `json:"retry_backoff_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	cfg := core.NotificationRetryConfig{
		MaxRetries:     body.MaxRetries,
		RetryBackoffMs: body.RetryBackoffMs,
	}
	if err := h.coreService.SetNotificationRetryPolicy(r.Context(), u.UserID, id, cfg); err != nil {
		if isRetryPolicyValidationError(err) {
			sendError(w, "BadRequest", err.Error(), http.StatusBadRequest, nil)
			return
		}
		if strings.Contains(err.Error(), channelNotFound) {
			sendError(w, "NotFound", channelNotFoundMessage, http.StatusNotFound, nil)
			return
		}
		log.Printf("Error setting retry policy for notification channel %d: %v", id, err)
		sendError(w, "InternalError", "Failed to set retry policy", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{
		"channel_id":       id,
		"max_retries":      body.MaxRetries,
		"retry_backoff_ms": body.RetryBackoffMs,
	}, "")
}

// GetRetryPolicy handles GET /api/v1/notification-channels/{id}/retry-policy.
// Response 200: {"data": {"channel_id": N, "max_retries": 3, "retry_backoff_ms": 1000}}
func (h *NotificationChannelHandler) GetRetryPolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	policy, err := h.coreService.GetNotificationRetryPolicy(r.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), channelNotFound) {
			sendError(w, "NotFound", channelNotFoundMessage, http.StatusNotFound, nil)
			return
		}
		log.Printf("Error getting retry policy for notification channel %d: %v", id, err)
		sendError(w, "InternalError", "Failed to get retry policy", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{
		"channel_id":       id,
		"max_retries":      policy.MaxRetries,
		"retry_backoff_ms": policy.RetryBackoffMs,
	}, "")
}

// isRetryPolicyValidationError reports whether the error is a validation error
// from SetNotificationRetryPolicy (safe to return verbatim to the client).
func isRetryPolicyValidationError(err error) bool {
	return strings.HasPrefix(err.Error(), "invalid notification channel retry policy")
}

// isValidationError reports whether the error comes from the core validation layer
// (as opposed to a storage/infrastructure error). Validation messages are
// short, human-readable strings crafted in validateNotificationChannel; they are
// safe to send back to the client verbatim.
func isValidationError(err error) bool {
	msg := err.Error()
	return strings.HasPrefix(msg, "notification channel") ||
		strings.HasPrefix(msg, "invalid notification")
}
