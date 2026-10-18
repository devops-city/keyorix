// notifications_handler.go — self-scoped in-app notification endpoints (ADR-024).
//
// Every endpoint operates on the authenticated user's own notifications; there is
// no permission gate (mirrors the My Account endpoints). Surfaced by the header
// bell in the web client.
package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// errNotificationsUserOnly: a notification belongs to a user; a machine identity
// (UserID 0, ADR-030) has none, so the mark-read writes refuse it rather than
// answering 200/404 for a feed that cannot exist.
const errNotificationsUserOnly = "This endpoint is only available to user accounts"

// NotificationHandler serves the authenticated user's notifications.
type NotificationHandler struct {
	coreService *core.KeyorixCore
}

// NewNotificationHandler constructs a NotificationHandler.
func NewNotificationHandler(coreService *core.KeyorixCore) *NotificationHandler {
	return &NotificationHandler{coreService: coreService}
}

func notificationToAPI(n *models.Notification) map[string]any {
	out := map[string]any{
		"id":         n.ID,
		"type":       n.Type,
		"title":      n.Title,
		"message":    n.Message,
		"link":       n.Link,
		"is_read":    n.IsRead,
		"created_at": n.CreatedAt.UTC().Format(time.RFC3339),
	}
	if n.ProjectID != nil {
		out["project_id"] = *n.ProjectID
	}
	return out
}

// List handles GET /api/v1/notifications?unread=true&limit=20 — the user's
// notifications (newest first) plus the unread count for the bell badge.
func (h *NotificationHandler) List(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	unreadOnly := r.URL.Query().Get("unread") == "true"
	limit := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}

	items, err := h.coreService.ListNotifications(r.Context(), u.UserID, unreadOnly, limit)
	if err != nil {
		log.Printf("Error listing notifications: %v", err)
		sendError(w, "InternalError", "Failed to list notifications", http.StatusInternalServerError, nil)
		return
	}
	count, err := h.coreService.UnreadNotificationCount(r.Context(), u.UserID)
	if err != nil {
		log.Printf("Error counting notifications: %v", err)
		count = 0
	}

	out := make([]map[string]any, 0, len(items))
	for _, n := range items {
		out = append(out, notificationToAPI(n))
	}
	sendSuccess(w, map[string]any{"notifications": out, "unread_count": count}, "")
}

// MarkRead handles POST /api/v1/notifications/{id}/read.
func (h *NotificationHandler) MarkRead(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	if isMachineActor(r) {
		sendError(w, "Forbidden", errNotificationsUserOnly, http.StatusForbidden, nil)
		return
	}
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	if err := h.coreService.MarkNotificationRead(r.Context(), id, u.UserID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "Notification not found", http.StatusNotFound, nil)
			return
		}
		log.Printf("Error marking notification read: %v", err)
		sendError(w, "InternalError", "Failed to mark notification read", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"id": id, "is_read": true}, "")
}

// MarkAllRead handles POST /api/v1/notifications/read-all.
func (h *NotificationHandler) MarkAllRead(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	if isMachineActor(r) {
		sendError(w, "Forbidden", errNotificationsUserOnly, http.StatusForbidden, nil)
		return
	}
	if err := h.coreService.MarkAllNotificationsRead(r.Context(), u.UserID); err != nil {
		log.Printf("Error marking all notifications read: %v", err)
		sendError(w, "InternalError", "Failed to mark notifications read", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"all_read": true}, "")
}
